import json
import struct
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from reark_studio_engine import (
    ReArkAiBridgeProxy,
    audit_java_and_runtime,
    detect_and_unpack_binary,
    parse_axml_binary_manifest,
    rollback_mcp_clients,
    wire_reark_mcp_into_clients,
)
from si_reark_mcp import (
    CRYPTO_SIGNATURES,
    audit_apk_manifest,
    diagnose_win10_launch,
    diff_multiple_binaries,
    extract_high_value_strings,
    handle_mcp_request,
    inspect_binary_headers,
    scan_crypto_signatures,
)


def _build_minimal_pe(extra_payload: bytes = b"") -> bytes:
    buf = bytearray(0x280)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 1, 0, 0, 0, 0x70, 0x22)
    sec_off = 0x80 + 24 + 0x70
    buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, sec_off + 8, 0x100, 0x1000, 0x100, 0x180)
    return bytes(buf) + extra_payload


def _build_genuine_axml_utf16(strings: list[str]) -> bytes:
    pool = bytearray()
    offsets: list[int] = []
    for s in strings:
        offsets.append(len(pool))
        pool.extend(struct.pack("<H", len(s)))
        pool.extend(s.encode("utf-16-le") + b"\x00\x00")
    while len(pool) % 4:
        pool.append(0)
    idx_tbl = b"".join(struct.pack("<I", o) for o in offsets)
    sp_hdr_sz = 28
    sp_str_start = sp_hdr_sz + len(idx_tbl)
    sp_total = sp_str_start + len(pool)
    sp_chunk = (
        struct.pack("<HHI", 0x0001, sp_hdr_sz, sp_total)
        + struct.pack("<IIIII", len(strings), 0, 0, sp_str_start, 0)
        + idx_tbl
        + bytes(pool)
    )
    return struct.pack("<HHI", 0x0003, 8, 8 + len(sp_chunk)) + sp_chunk


class ReArkStudioV2Tests(unittest.TestCase):
    def test_real_pe_headers_crypto_and_strings(self) -> None:
        aes_sig = CRYPTO_SIGNATURES[0][1]
        blob = _build_minimal_pe(
            aes_sig
            + b"\x00https://api.example-reark.local/v1/license\x00VirtualProtect\x00Java_com_app_Native\x00"
        )
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "sample_app.exe"
            exe.write_bytes(blob)

            hdr = inspect_binary_headers(exe)
            self.assertTrue(hdr["ok"])
            self.assertEqual(hdr["format"], "PE32+ EXE")
            self.assertEqual(hdr["arch"], "x86_64 (AMD64)")
            self.assertEqual(hdr["sections"][0]["name"], ".text")

            cr = scan_crypto_signatures(exe)
            self.assertGreaterEqual(cr["match_count"], 1)
            self.assertEqual(cr["matches"][0]["name"], "AES S-Box")

            st = extract_high_value_strings(exe)
            self.assertIn("https://api.example-reark.local/v1/license", st["urls"])
            self.assertTrue(any("VirtualProtect" in x for x in st["api_and_jni"]))

    def test_apk_binary_axml_decoder_and_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            axml = _build_genuine_axml_utf16([
                "com.reark.targetapp",
                "android.permission.INTERNET",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "com.reark.targetapp.MainActivity",
                "https://auth.targetapp.local/session",
            ])
            parsed = parse_axml_binary_manifest(axml)
            self.assertTrue(parsed["ok"])
            self.assertTrue(parsed["is_binary_axml"])
            self.assertEqual(parsed["package_name"], "com.reark.targetapp")
            self.assertIn("android.permission.INTERNET", parsed["permissions"])
            self.assertIn("https://auth.targetapp.local/session", parsed["urls"])

            apk = td / "demo.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("AndroidManifest.xml", axml)
                zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF\x02")
                zf.writestr("classes.dex", b"dex\n035\x00")
            audit = audit_apk_manifest(apk)
            self.assertTrue(audit["ok"])
            self.assertIn("lib/arm64-v8a/libnative.so", audit["native_libs"])
            self.assertIn("android.permission.INTERNET", audit["flagged_permissions"])
            self.assertEqual(audit["axml_manifest"]["package_name"], "com.reark.targetapp")

            bin1 = td / "v1.exe"
            bin2 = td / "v2.exe"
            bin1.write_bytes(_build_minimal_pe(b"version_one_token_secret"))
            bin2.write_bytes(_build_minimal_pe(b"version_two_token_secret_extra_endpoint_https://x.local/y"))
            df = diff_multiple_binaries([bin1, bin2])
            self.assertTrue(df["ok"])
            self.assertGreater(df["size_delta_bytes"], 0)

    def test_issue36_packer_detection_and_embedded_pe_unpack(self) -> None:
        inner_pe = _build_minimal_pe(b"INNER_UNPACKED_PAYLOAD_SECRET\x00")
        outer = _build_minimal_pe(b"UPX0UPX!\x00" + b"\x90" * 0x220 + inner_pe)
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            packed = td / "packed_sample.exe"
            packed.write_bytes(outer)
            res = detect_and_unpack_binary(packed, backup_dir=td / "bkps", attempt_unpack=True)
            self.assertTrue(res["ok"])
            self.assertTrue(any("UPX" in d["packer"] for d in res["packers_detected"]))
            self.assertTrue(Path(res["backup_path"]).exists())
            self.assertTrue(res["unpacked_output"] is not None and Path(res["unpacked_output"]).exists())

    def test_issue20_live_proxy_repairs_empty_body(self) -> None:
        received_payloads: list[dict] = []

        class MockOllama(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:
                return

            def do_POST(self) -> None:
                cl = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(cl).decode("utf-8"))
                received_payloads.append(body)
                out = json.dumps({"choices": [{"message": {"content": "Decompiled OK"}}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        mock_srv = ThreadingHTTPServer(("127.0.0.1", 0), MockOllama)
        mock_port = mock_srv.server_address[1]
        threading.Thread(target=mock_srv.serve_forever, daemon=True).start()

        proxy = ReArkAiBridgeProxy(
            upstream_url=f"http://127.0.0.1:{mock_port}",
            listen_port=0,
            default_model="qwen2.5-coder:14b",
        )
        p_port = proxy.start()
        try:
            # Send genuinely EMPTY body simulating lkimuk/ReArk Issue #20 ('请求体为空')
            req = urllib.request.Request(
                f"http://127.0.0.1:{p_port}/v1/chat/completions",
                data=b"",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(resp.status, 200)
                self.assertEqual(data["choices"][0]["message"]["content"], "Decompiled OK")

            self.assertEqual(len(received_payloads), 1)
            self.assertEqual(received_payloads[0]["model"], "qwen2.5-coder:14b")
            self.assertGreater(len(received_payloads[0]["messages"]), 0)
            self.assertEqual(proxy.get_stats()["empty_bodies_repaired"], 1)
        finally:
            proxy.stop()
            mock_srv.shutdown()
            mock_srv.server_close()

    def test_issue31_mcp_wire_rollback_and_win10_jdk_doctor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            home_dir = td / "home"
            app_dir = td / "appdata"
            bkp_dir = td / "backups"
            claude_cfg = app_dir / "Claude" / "claude_desktop_config.json"
            claude_cfg.parent.mkdir(parents=True, exist_ok=True)
            claude_cfg.write_text('{"mcpServers": {"existing-tool": {"command": "node"}}}', encoding="utf-8")

            wired = wire_reark_mcp_into_clients(
                custom_home=home_dir,
                custom_appdata=app_dir,
                custom_backup_dir=bkp_dir,
            )
            self.assertEqual(wired["wired_count"], 4)
            updated_claude = json.loads(claude_cfg.read_text(encoding="utf-8"))
            self.assertIn("si-reark-mcp", updated_claude["mcpServers"])
            self.assertIn("existing-tool", updated_claude["mcpServers"])

            rolled = rollback_mcp_clients(custom_home=home_dir, custom_backup_dir=bkp_dir)
            self.assertTrue(rolled["ok"])
            restored_claude = json.loads(claude_cfg.read_text(encoding="utf-8"))
            self.assertNotIn("si-reark-mcp", restored_claude["mcpServers"])
            self.assertIn("existing-tool", restored_claude["mcpServers"])

            doc = diagnose_win10_launch(td / "win10_reark")
            self.assertTrue(doc["ok"])
            self.assertTrue(Path(doc["safe_launcher_path"]).exists())
            jdk = audit_java_and_runtime(td / "win10_reark")
            self.assertIn("has_full_jdk", jdk)

    def test_mcp_8_tools_handshake_and_call(self) -> None:
        init = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "si-reark-mcp")
        self.assertEqual(init["result"]["serverInfo"]["version"], "2.0.0")
        tools = handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tool_names = [t["name"] for t in tools["result"]["tools"]]
        self.assertEqual(len(tool_names), 8)
        self.assertIn("detect_and_unpack_binary", tool_names)
        self.assertIn("diagnose_win10_and_jdk", tool_names)

        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "mcp_target.exe"
            exe.write_bytes(_build_minimal_pe(b"https://mcp.reark.local/check"))
            call = handle_mcp_request({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "inspect_binary_headers", "arguments": {"file_path": str(exe)}},
            })
            payload = json.loads(call["result"]["content"][0]["text"])
            self.assertEqual(payload["format"], "PE32+ EXE")


if __name__ == "__main__":
    unittest.main()
