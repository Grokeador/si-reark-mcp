"""Automated verification suite for SI-ReArk-MCP against real PE/APK/HAP samples and MCP JSON-RPC."""

import io
import json
import shutil
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

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


def _build_synthetic_pe(path: Path, extra_bytes: bytes = b"") -> None:
    """Create a valid minimal PE32+ DLL header with .text and .rdata sections."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x2022)
    sec_off = 0x84 + 20 + 0xF0
    struct.pack_into("<8sIIII", buf, sec_off, b".text\x00\x00\x00", 0x100, 0x1000, 0x100, 0x200)
    struct.pack_into("<8sIIII", buf, sec_off + 40, b".rdata\x00\x00", 0x100, 0x2000, 0x100, 0x300)
    buf[0x200 : 0x200 + 32] = b"\x48\x89\x5c\x24\x08\xc3" * 5 + b"\x90\x90"
    buf[0x300 : 0x300 + 48] = b"https://api.example.internal/v2/auth\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    path.write_bytes(bytes(buf) + extra_bytes)


class SiRearkMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="si_reark_test_"))
        self.dll_v1 = self.tmp / "core_engine_v1.dll"
        self.dll_v2 = self.tmp / "core_engine_v2.dll"
        aes_sbox = CRYPTO_SIGNATURES[0][1]
        _build_synthetic_pe(self.dll_v1, extra_bytes=aes_sbox + b"\x00Java_com_app_NativeBridge_init\x00")
        _build_synthetic_pe(self.dll_v2, extra_bytes=aes_sbox + b"\x00https://telemetry-new.local/hook\x00")

        self.apk = self.tmp / "sample_app.apk"
        with zipfile.ZipFile(self.apk, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"android.permission.CAMERA\x00android.permission.SYSTEM_ALERT_WINDOW")
            zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 64)
            zf.writestr("classes.dex", b"dex\n035\x00")
            zf.writestr("META-INF/CERT.RSA", b"SIG")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pe_crypto_strings_and_apk_audit(self) -> None:
        hdr = inspect_binary_headers(self.dll_v1)
        self.assertTrue(hdr["ok"])
        self.assertEqual(hdr["format"], "PE32+ DLL")
        self.assertEqual(len(hdr["sections"]), 2)

        cry = scan_crypto_signatures(self.dll_v1)
        self.assertTrue(cry["ok"])
        self.assertGreaterEqual(cry["match_count"], 1)
        self.assertEqual(cry["matches"][0]["name"], "AES Rijndael S-Box")

        strs = extract_high_value_strings(self.dll_v1)
        self.assertTrue(any("https://api.example.internal" in u for u in strs["urls"]))
        self.assertTrue(any("Java_com_app_NativeBridge_init" in a for a in strs["api_and_jni"]))

        apk_res = audit_apk_manifest(self.apk)
        self.assertTrue(apk_res["ok"])
        self.assertIn("CAMERA", apk_res["flagged_permissions"])
        self.assertIn("lib/arm64-v8a/libnative.so", apk_res["native_libs"])

    def test_mcp_jsonrpc_and_multi_binary_diff(self) -> None:
        init_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "si-reark-mcp")

        list_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(len(list_resp["result"]["tools"]), 5)

        call_resp = handle_mcp_request({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "diff_multiple_binaries", "arguments": {"file_paths": [str(self.dll_v1), str(self.dll_v2)]}},
        })
        payload = json.loads(call_resp["result"]["content"][0]["text"])
        self.assertTrue(payload["ok"])
        self.assertTrue(any("telemetry-new.local" in s for s in payload["added_strings"]))

    def test_win10_startup_doctor_writes_safe_launcher(self) -> None:
        diag = diagnose_win10_launch(self.tmp / "ReArkApp")
        self.assertTrue(diag["ok"])
        launcher = Path(diag["safe_launcher_path"])
        self.assertTrue(launcher.exists())
        self.assertIn("--disable-gpu", launcher.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
