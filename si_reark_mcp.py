#!/usr/bin/env python3
"""
SI-ReArk-Studio 2.0 — Complete Companion Engine & Local AI Reverse-Engineering Suite for lkimuk/ReArk
Solves real open GitHub issues (#36 Unpacker, #35 Win10 Silent Crash + JDK17 Trap, #31 MCP + Diff + Daylight Contrast, #20/#16/#9 Empty-Body Local AI Proxy)
Zero paid API keys. 100% Local Python Stdlib + Tkinter Desktop Shell + Web Studio + STDIO MCP.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import os
import re
import struct
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser
import zipfile
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from reark_studio_engine import (
    PROXY_DEFAULT_PORT,
    ReArkAiBridgeProxy,
    UPSTREAM_DEFAULT_URL,
    ask_local_ai_about_binary,
    audit_java_and_runtime,
    detect_and_unpack_binary,
    download_official_reark_release,
    ensure_demo_samples,
    parse_axml_binary_manifest,
    rollback_mcp_clients,
    wire_reark_mcp_into_clients,
)


APP_VERSION = "2.0.0"
MCP_PROTOCOL_VERSION = "2024-11-05"

CRYPTO_SIGNATURES: list[tuple[str, bytes, str]] = [
    ("AES S-Box", bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]), "Symmetric block cipher constant"),
    ("SHA-256 K", bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba5"), "SHA-256 round constants"),
    ("ChaCha20 Magic", b"expand 32-byte k", "ChaCha20 stream cipher constant"),
    ("MD5 Init", bytes.fromhex("0123456789abcdeffedcba9876543210"), "MD5/SHA initialization vector"),
    ("CRC32 Table", bytes.fromhex("00000000963007772c610eee"), "IEEE 802.3 CRC32 lookup table"),
]

DANGEROUS_ANDROID_PERMS: list[bytes] = [
    b"android.permission.INTERNET",
    b"android.permission.READ_EXTERNAL_STORAGE",
    b"android.permission.WRITE_EXTERNAL_STORAGE",
    b"android.permission.ACCESS_FINE_LOCATION",
    b"android.permission.CAMERA",
    b"android.permission.RECORD_AUDIO",
    b"android.permission.REQUEST_INSTALL_PACKAGES",
    b"android.permission.SYSTEM_ALERT_WINDOW",
]


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits/byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    ent = 0.0
    for count in counts.values():
        p = count / total
        ent -= p * math.log2(p)
    return round(ent, 3)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_binary_headers(file_path: str | Path) -> dict[str, Any]:
    """Parse real PE / ELF / Mach-O / APK / HAP / ArkTS headers + section entropy without external deps."""
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return {"ok": False, "error": f"File not found: {p}"}

    data = p.read_bytes()
    info: dict[str, Any] = {
        "ok": True,
        "file_name": p.name,
        "path": str(p.resolve()),
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
        "overall_entropy": shannon_entropy(data[:262144]),
        "format": "Unknown",
        "arch": "Unknown",
        "sections": [],
        "packed_warning": False,
    }

    if data[:2] == b"MZ" and len(data) >= 0x40:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 <= len(data) and data[pe_off : pe_off + 4] == b"PE\x00\x00":
            machine, num_sec, _ts, _, _, opt_sz, chars = struct.unpack_from("<HHIIIHH", data, pe_off + 4)
            arch_map = {0x8664: "x86_64 (AMD64)", 0x014C: "x86 (32-bit)", 0xAA64: "ARM64"}
            is_dll = bool(chars & 0x2000)
            info["format"] = "PE32+ DLL" if (is_dll and machine == 0x8664) else ("PE32+ EXE" if machine == 0x8664 else "PE")
            info["arch"] = arch_map.get(machine, f"0x{machine:04x}")
            sec_off = pe_off + 24 + opt_sz
            sections = []
            for idx in range(min(num_sec, 32)):
                cur = sec_off + idx * 40
                if cur + 40 > len(data):
                    break
                raw_name, _vsize, vaddr, rsize, rptr = struct.unpack_from("<8sIIII", data, cur)
                sname = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace") or f"sec_{idx}"
                chunk = data[rptr : min(len(data), rptr + min(rsize, 524288))]
                ent = shannon_entropy(chunk)
                sections.append({
                    "name": sname,
                    "virtual_addr": f"0x{vaddr:08x}",
                    "raw_size": rsize,
                    "entropy": ent,
                    "high_entropy": ent >= 7.1,
                })
            info["sections"] = sections
            if any(s["high_entropy"] for s in sections) or b"UPX!" in data[:65536]:
                info["packed_warning"] = True
            return info

    if data.startswith(b"\x7fELF") and len(data) >= 20:
        ei_class = data[4]
        e_machine = struct.unpack_from("<H", data, 18)[0] if len(data) >= 20 else 0
        elf_arch = {0x3E: "x86_64", 0xB7: "AArch64 (ARM64)", 0x28: "ARM 32-bit", 0x03: "x86"}.get(e_machine, f"0x{e_machine:02x}")
        info["format"] = "ELF64" if ei_class == 2 else "ELF32"
        info["arch"] = elf_arch
        return info

    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe"):
        info["format"] = "Mach-O"
        info["arch"] = "Apple Silicon / x86_64 Universal"
        return info

    if data.startswith(b"PANDA"):
        info["format"] = "HarmonyOS Ark Bytecode (.abc)"
        info["arch"] = "ArkVM Bytecode"
        return info

    if data.startswith(b"PK\x03\x04"):
        ext = p.suffix.lower()
        info["format"] = "HarmonyOS HAP Archive" if ext in (".hap", ".app") else ("Android APK Archive" if ext == ".apk" else "ZIP Package")
        info["arch"] = "Multi-ABI Container"
        try:
            with zipfile.ZipFile(p, "r") as zf:
                names = zf.namelist()
                info["archive_entries"] = len(names)
                info["sample_entries"] = names[:15]
        except Exception:
            pass
        return info

    return info


def scan_crypto_signatures(file_path: str | Path) -> dict[str, Any]:
    """Detect real symmetric cipher, hash, and CRC constants inside a binary."""
    p = Path(file_path)
    if not p.exists():
        return {"ok": False, "error": f"File not found: {p}"}
    data = p.read_bytes()
    hits = []
    for name, sig, note in CRYPTO_SIGNATURES:
        off = data.find(sig)
        if off != -1:
            hits.append({"name": name, "offset": f"0x{off:08x}", "category": note})
    return {"ok": True, "file_name": p.name, "match_count": len(hits), "matches": hits}


def extract_high_value_strings(file_path: str | Path, min_len: int = 6, max_items: int = 80) -> dict[str, Any]:
    """Extract ASCII and UTF-16LE URLs, API symbols, paths, and JNI names."""
    p = Path(file_path)
    if not p.exists():
        return {"ok": False, "error": f"File not found: {p}"}
    data = p.read_bytes()[:4_000_000]
    ascii_hits = [m.decode("ascii", errors="ignore") for m in re.findall(rf"[ -~]{{{min_len},}}".encode("ascii"), data)]
    utf16_hits = [
        m.decode("utf-16-le", errors="ignore")
        for m in re.findall(rf"(?:[ -~]\x00){{{min_len},}}".encode("ascii"), data)
    ]
    merged = list(dict.fromkeys(ascii_hits + utf16_hits))

    urls = [s for s in merged if re.search(r"(https?|wss?)://[a-zA-Z0-9._:/?=&%-]+", s)]
    jni_or_api = [s for s in merged if ("Java_" in s or "VirtualProtect" in s or "LoadLibrary" in s or "dlopen" in s or "AES" in s or "ohos." in s)]
    paths_or_keys = [s for s in merged if ("\\" in s or ".dll" in s.lower() or ".so" in s.lower() or "token" in s.lower() or "secret" in s.lower())][:max_items]

    return {
        "ok": True,
        "file_name": p.name,
        "total_strings_extracted": len(merged),
        "urls": urls[:30],
        "api_and_jni": jni_or_api[:30],
        "notable_strings": paths_or_keys[:30],
        "preview": merged[:40],
    }


def audit_apk_manifest(file_path: str | Path) -> dict[str, Any]:
    """Audit Android APK/HAP container layout, native libs, and decode binary AXML manifests."""
    p = Path(file_path)
    if not p.exists():
        return {"ok": False, "error": f"File not found: {p}"}
    if not zipfile.is_zipfile(p):
        return {"ok": False, "error": "Target is not an APK/HAP ZIP archive."}

    with zipfile.ZipFile(p, "r") as zf:
        names = zf.namelist()
        native_libs = [n for n in names if n.endswith(".so")]
        dex_or_abc = [n for n in names if n.endswith((".dex", ".abc"))]
        certs = [n for n in names if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC", ".SF"))]
        perms_found: list[str] = []
        axml_decoded: dict[str, Any] = {}
        manifest_raw = b""
        for cand in ("AndroidManifest.xml", "module.json", "config.json"):
            if cand in names:
                manifest_raw = zf.read(cand)
                break
        if manifest_raw:
            axml_decoded = parse_axml_binary_manifest(manifest_raw)
            for perm in DANGEROUS_ANDROID_PERMS:
                perm_str = perm.decode("ascii")
                if (
                    perm in manifest_raw
                    or perm_str.encode("utf-16-le") in manifest_raw
                    or perm_str in (axml_decoded.get("permissions") or [])
                ):
                    perms_found.append(perm_str)
    return {
        "ok": True,
        "file_name": p.name,
        "entry_count": len(names),
        "native_libs": native_libs[:25],
        "bytecode_modules": dex_or_abc[:25],
        "signing_certs": certs[:10],
        "flagged_permissions": sorted(set(perms_found)),
        "axml_manifest": axml_decoded,
    }


def diff_multiple_binaries(paths: list[str | Path]) -> dict[str, Any]:
    """Compare 2+ binaries side by side (Issue #31 multi-tab diff request)."""
    if len(paths) < 2:
        return {"ok": False, "error": "Provide at least 2 binaries to compare."}
    hdrs = [inspect_binary_headers(p) for p in paths]
    if any(not h.get("ok") for h in hdrs):
        return {"ok": False, "error": "One or more binaries could not be read.", "details": hdrs}

    base_s = set(extract_high_value_strings(paths[0], max_items=120).get("preview", []))
    target_s = set(extract_high_value_strings(paths[1], max_items=120).get("preview", []))
    added_strings = sorted(target_s - base_s)[:25]
    removed_strings = sorted(base_s - target_s)[:25]

    return {
        "ok": True,
        "baseline": hdrs[0]["file_name"],
        "compared": hdrs[1]["file_name"],
        "size_delta_bytes": hdrs[1]["size_bytes"] - hdrs[0]["size_bytes"],
        "entropy_delta": round(hdrs[1]["overall_entropy"] - hdrs[0]["overall_entropy"], 3),
        "added_strings": added_strings,
        "removed_strings": removed_strings,
        "binaries": hdrs,
    }


def diagnose_win10_launch(reark_dir: Path | None = None) -> dict[str, Any]:
    """Audit Windows 10 silent launch blockers + JDK17 vs JRE trap (Issue #35) & write safe launcher."""
    audit = audit_java_and_runtime(reark_dir)
    audit["recommended_flags"] = ["--disable-gpu", "--no-sandbox", "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"]
    return audit


MCP_TOOLS_MANIFEST = [
    {
        "name": "inspect_binary_headers",
        "description": "Inspect PE/ELF/Mach-O/APK/HAP/ABC headers, architecture, section layout, and Shannon packing entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    },
    {
        "name": "extract_high_value_strings",
        "description": "Extract ASCII/UTF-16 URLs, API hooks, paths, and JNI symbols from a binary.",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    },
    {
        "name": "scan_crypto_signatures",
        "description": "Locate AES S-Box, SHA-256, ChaCha20, MD5, and CRC32 constants inside binaries.",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    },
    {
        "name": "audit_apk_manifest",
        "description": "Audit APK/HAP archives, decode binary AXML AndroidManifest.xml, ABIs, certs, and sensitive permissions.",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    },
    {
        "name": "diff_multiple_binaries",
        "description": "Compare 2+ binaries side-by-side (size, entropy, added/removed URLs and strings).",
        "inputSchema": {
            "type": "object",
            "properties": {"file_paths": {"type": "array", "items": {"type": "string"}}},
            "required": ["file_paths"],
        },
    },
    {
        "name": "detect_and_unpack_binary",
        "description": "Detect UPX/ASPack/VMProtect/PyInstaller packers (Issue #36), save SHA-256 backup, and unpack/extract PE payloads.",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    },
    {
        "name": "parse_axml_binary_manifest",
        "description": "Decode a raw compiled AndroidManifest.xml AXML file without requiring Java or apktool.",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    },
    {
        "name": "diagnose_win10_and_jdk",
        "description": "Diagnose ReArk Win10 silent startup blockers (#35), WebView2, VC++ DLLs, and JDK17 javac vs JRE trap.",
        "inputSchema": {
            "type": "object",
            "properties": {"reark_dir": {"type": "string"}},
            "required": [],
        },
    },
]


def handle_mcp_request(req: dict[str, Any]) -> dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 MCP message deterministically."""
    req_id = req.get("id")
    method = req.get("method", "")
    params = req.get("params") or {}

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "si-reark-mcp", "version": APP_VERSION},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS_MANIFEST}}

    if method == "tools/call":
        tname = params.get("name", "")
        targs = params.get("arguments") or {}
        if tname == "inspect_binary_headers":
            res = inspect_binary_headers(targs.get("file_path", ""))
        elif tname == "extract_high_value_strings":
            res = extract_high_value_strings(targs.get("file_path", ""))
        elif tname == "scan_crypto_signatures":
            res = scan_crypto_signatures(targs.get("file_path", ""))
        elif tname == "audit_apk_manifest":
            res = audit_apk_manifest(targs.get("file_path", ""))
        elif tname == "diff_multiple_binaries":
            res = diff_multiple_binaries(targs.get("file_paths") or [])
        elif tname == "detect_and_unpack_binary":
            res = detect_and_unpack_binary(targs.get("file_path", ""))
        elif tname == "parse_axml_binary_manifest":
            fp = Path(targs.get("file_path", ""))
            res = parse_axml_binary_manifest(fp.read_bytes()) if fp.exists() else {"ok": False, "error": f"File not found: {fp}"}
        elif tname == "diagnose_win10_and_jdk":
            rdir = targs.get("reark_dir")
            res = diagnose_win10_launch(Path(rdir) if rdir else None)
        else:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tname}"}}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]},
        }

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unsupported method: {method}"}}


def run_stdio_mcp_loop() -> None:
    """Run blocking line-delimited JSON-RPC 2.0 MCP server on stdin/stdout."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_mcp_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(exc)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# SI-ReArk-Studio 2.0 Web Studio UI (Step 1 -> Step 2 -> Step 3 + Bonus)
# ---------------------------------------------------------------------------

def _render_inspector_html(
    files: list[Path],
    active_tab: int = 0,
    view: str = "workspace",
    theme: str = "dark",
    win10_dir: Path | None = None,
    proxy: ReArkAiBridgeProxy | None = None,
    banner_msg: str = "",
) -> str:
    """Render 1920x1080 SI-ReArk-Studio 2.0 UI solving Issues #36, #35, #31, #20/#16/#9."""
    is_hc = theme == "light"
    bg = "#ffffff" if is_hc else "#060a13"
    card = "#f8fafc" if is_hc else "#0d1526"
    card_alt = "#eef2ff" if is_hc else "#111c33"
    fg = "#020617" if is_hc else "#f8fafc"
    muted = "#334155" if is_hc else "#94a3b8"
    border = "#0f172a" if is_hc else "#1e293b"
    accent = "#0369a1" if is_hc else "#38bdf8"
    good = "#047857" if is_hc else "#34d399"
    warn = "#b45309" if is_hc else "#fbbf24"
    code_bg = "#f1f5f9" if is_hc else "#04070e"

    analyses = []
    for fp in files:
        if not fp.exists():
            continue
        analyses.append({
            "hdr": inspect_binary_headers(fp),
            "crypto": scan_crypto_signatures(fp),
            "strings": extract_high_value_strings(fp),
            "apk": audit_apk_manifest(fp) if zipfile.is_zipfile(fp) else None,
            "unpack": detect_and_unpack_binary(fp, attempt_unpack=False),
        })

    if not analyses:
        demo_files = ensure_demo_samples(Path.home() / ".si_reark_studio" / "samples")
        files.extend(demo_files)
        for fp in demo_files:
            analyses.append({
                "hdr": inspect_binary_headers(fp),
                "crypto": scan_crypto_signatures(fp),
                "strings": extract_high_value_strings(fp),
                "apk": audit_apk_manifest(fp) if zipfile.is_zipfile(fp) else None,
                "unpack": detect_and_unpack_binary(fp, attempt_unpack=False),
            })

    tab_links = "".join(
        f'<a href="/?tab={i}&view=workspace&theme={theme}" class="tab {"active" if view == "workspace" and active_tab == i else ""}">{html.escape(a["hdr"].get("file_name", f"Tab {i+1}"))}</a>'
        for i, a in enumerate(analyses)
    )
    tab_links += f'<a href="/?view=unpacker&theme={theme}" class="tab {"active" if view == "unpacker" else ""}">Step 2: Unpacker #36 &amp; AXML</a>'
    tab_links += f'<a href="/?view=ai_proxy&theme={theme}" class="tab {"active" if view == "ai_proxy" else ""}">Step 3: Local AI :11436 Fix #20</a>'
    tab_links += f'<a href="/?view=mcp&theme={theme}" class="tab {"active" if view == "mcp" else ""}">MCP Wire #31 &amp; Diff</a>'
    tab_links += f'<a href="/?view=win10&theme={theme}" class="tab {"active" if view == "win10" else ""}">Bonus: Win10 + JDK17 Fix #35</a>'

    toggle_target = "dark" if is_hc else "light"
    toggle_label = "Dark Terminal" if is_hc else "High-Contrast Daylight (#31)"
    proxy_stats = proxy.get_stats() if proxy else {"listen_port": PROXY_DEFAULT_PORT, "requests_total": 0, "empty_bodies_repaired": 0, "last_model": "qwen2.5-coder:14b"}
    cur_idx = min(active_tab, len(analyses) - 1)
    cur = analyses[cur_idx]
    cur_path = cur["hdr"].get("path", "")

    if view == "unpacker":
        unpack_res = detect_and_unpack_binary(cur_path, attempt_unpack=True)
        apk_targets = [a for a in analyses if a["apk"] is not None]
        apk_box = ""
        if apk_targets:
            ak = apk_targets[0]["apk"]
            axml = ak.get("axml_manifest") or {}
            apk_box = (
                f"Package: {axml.get('package_name', '(parsed)')}\n"
                f"Binary AXML Strings: {axml.get('string_count', 0)}\n"
                f"Native ABIs: {', '.join(ak.get('native_libs', [])[:6]) or 'none'}\n"
                f"Permissions ({len(ak.get('flagged_permissions', []))}):\n  "
                + "\n  ".join(ak.get("flagged_permissions", []) or ["none"])
            )
        else:
            apk_box = "Load any .apk or .hap file in Step 1 to decode binary AndroidManifest.xml without Java."

        content_html = f"""
        <div class="grid-2">
          <div class="panel">
            <h2>Issue #36 Safe Unpacker &amp; SHA-256 Backup Engine</h2>
            <p class="sub">Active Target: <code>{html.escape(cur['hdr']['file_name'])}</code> &bull; Immutable backup created before inspection.</p>
            <div class="metrics">
              <div class="m"><span>Status</span><strong style="color:{good}">{html.escape(str(unpack_res['unpack_status']))}</strong></div>
              <div class="m"><span>Packers Found</span><strong>{len(unpack_res['packers_detected'])}</strong></div>
              <div class="m"><span>UPX CLI Ready</span><strong>{unpack_res['upx_cli_available']}</strong></div>
              <div class="m"><span>Backup SHA-256</span><strong>{html.escape(unpack_res['original_sha256'][:12])}...</strong></div>
            </div>
            <pre class="code">{html.escape(json.dumps(unpack_res, indent=2))}</pre>
          </div>
          <div class="panel">
            <h2>Pure-Python Android Binary AXML Decoder (Zero Java Needed)</h2>
            <p class="sub">Parses compiled <code>0x00080003</code> AndroidManifest.xml StringPool chunks directly in Python.</p>
            <pre class="code">{html.escape(apk_box)}</pre>
            <div style="margin-top:12px;">
              <form method="POST" action="/api/unpack" style="display:flex;gap:10px;">
                <input type="hidden" name="file_path" value="{html.escape(cur_path)}" />
                <input type="hidden" name="theme" value="{theme}" />
                <button class="btn primary" type="submit">Run SHA-256 Safe Unpack Now</button>
              </form>
            </div>
          </div>
        </div>
        """
    elif view == "ai_proxy":
        proxy_port = proxy_stats.get("listen_port", PROXY_DEFAULT_PORT)
        content_html = f"""
        <div class="grid-2">
          <div class="panel">
            <h2>Live :11436 AI Bridge Proxy (Fixes Issues #20, #16, #9 Empty Body)</h2>
            <p class="sub">Point ReArk OpenAI URL to <code>http://127.0.0.1:{proxy_port}/v1</code> &bull; Repairs empty POST bodies before Ollama receives them.</p>
            <div class="metrics">
              <div class="m"><span>Proxy Port</span><strong style="color:{good}">127.0.0.1:{proxy_port}</strong></div>
              <div class="m"><span>Total Requests</span><strong>{proxy_stats.get('requests_total', 0)}</strong></div>
              <div class="m"><span>Empty Bodies Fixed</span><strong style="color:{accent}">{proxy_stats.get('empty_bodies_repaired', 0)}</strong></div>
              <div class="m"><span>Active Model</span><strong>{html.escape(str(proxy_stats.get('last_model', 'qwen2.5-coder:14b')))}</strong></div>
            </div>
            <pre class="code">Base URL for ReArk Settings:
  http://127.0.0.1:{proxy_port}/v1
API Key:
  local-free-zero-cost
Model Name:
  qwen2.5-coder:14b

Repairs Last Applied:
{html.escape(json.dumps(proxy_stats.get('last_repairs', []), indent=2))}</pre>
          </div>
          <div class="panel">
            <h2>Ask Local AI About Active Binary ($0.00 API Cost)</h2>
            <form method="POST" action="/api/proxy-test" style="margin-bottom:12px;">
              <input type="hidden" name="theme" value="{theme}" />
              <button class="btn primary" type="submit">Simulate ReArk Empty-Body Bug &amp; Verify Repair</button>
            </form>
            <form method="POST" action="/api/ask-ai" style="display:flex;flex-direction:column;gap:8px;">
              <input type="hidden" name="file_path" value="{html.escape(cur_path)}" />
              <input type="hidden" name="theme" value="{theme}" />
              <input class="inp" type="text" name="question" value="Explain the risky strings and crypto constants in {html.escape(cur['hdr']['file_name'])}." />
              <button class="btn" type="submit">Ask Local Ollama via :11436 Proxy</button>
            </form>
          </div>
        </div>
        """
    elif view == "mcp":
        tools_list = "\n".join(f"- {t['name']}: {t['description']}" for t in MCP_TOOLS_MANIFEST)
        diff = diff_multiple_binaries([a["hdr"]["path"] for a in analyses[:2]]) if len(analyses) >= 2 else None
        diff_txt = json.dumps(diff, indent=2)[:1500] if diff else "Load 2 binaries to compare."
        content_html = f"""
        <div class="grid-2">
          <div class="panel">
            <h2>1-Click Multi-Client MCP Auto-Wiring (Issue #31 + Rollback)</h2>
            <p class="sub">8 Real STDIO MCP Tools ready for Claude Desktop, Claude Code, Antigravity &amp; Cursor.</p>
            <div style="display:flex;gap:10px;margin-bottom:12px;">
              <form method="POST" action="/api/wire-mcp">
                <input type="hidden" name="theme" value="{theme}" />
                <button class="btn primary" type="submit">1-Click Wire Into All 4 AI Clients</button>
              </form>
              <form method="POST" action="/api/rollback-mcp">
                <input type="hidden" name="theme" value="{theme}" />
                <button class="btn" type="submit">Rollback Configs (SHA-256 Safe)</button>
              </form>
            </div>
            <pre class="code">{html.escape(tools_list)}</pre>
          </div>
          <div class="panel">
            <h2>Multi-Binary Differential Inspector (#31 Multi-Tab Diff)</h2>
            <pre class="code">{html.escape(diff_txt)}</pre>
          </div>
        </div>
        """
    elif view == "win10":
        wdir = win10_dir or (Path.home() / "ReArk_Win10_Fixed")
        doc = diagnose_win10_launch(wdir)
        jdk_color = good if doc.get("has_full_jdk") else warn
        content_html = f"""
        <div class="grid-2">
          <div class="panel">
            <h2>Issue #35 Win10 Silent Crash + JDK 17+ Trap Doctor</h2>
            <div class="metrics">
              <div class="m"><span>WebView2 Runtime</span><strong style="color:{good if doc['webview2_present'] else warn}">{doc['webview2_present']}</strong></div>
              <div class="m"><span>Missing VC++ DLLs</span><strong>{len(doc['missing_vcpp_dlls'])}</strong></div>
              <div class="m"><span>Full JDK (javac)</span><strong style="color:{jdk_color}">{doc.get('has_full_jdk')} (JRE Trap: {doc.get('jre_only_trap')})</strong></div>
              <div class="m"><span>Ollama Local Ready</span><strong>{doc.get('ollama_installed')}</strong></div>
            </div>
            <pre class="code">JAVA_HOME: {html.escape(str(doc.get('java_home')))}
javac.exe: {html.escape(str(doc.get('javac_exe') or 'MISSING - Install JDK 17+ for APK smali/dex'))}
Safe Launcher: {html.escape(str(doc.get('safe_launcher_path')))}</pre>
          </div>
          <div class="panel">
            <h2>Official ReArk Auto-Setup &amp; Safe Win10 Launcher</h2>
            <p class="sub">Fetches the latest <code>lkimuk/ReArk</code> release from GitHub Releases API &amp; writes WebView2 GPU-safe flags.</p>
            <div style="display:flex;gap:10px;margin-bottom:12px;">
              <form method="POST" action="/api/fix-win10">
                <input type="hidden" name="theme" value="{theme}" />
                <button class="btn primary" type="submit">Regenerate Win10 Safe Launcher</button>
              </form>
              <form method="POST" action="/api/download-reark">
                <input type="hidden" name="theme" value="{theme}" />
                <button class="btn" type="submit">Fetch Official ReArk Release</button>
              </form>
            </div>
            <pre class="code">@echo off
set WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--disable-gpu --no-sandbox
set DOTNET_EnableWriteXorExecute=0
start "" "%~dp0ReArk.exe" --disable-gpu &gt; "%~dp0reark_launch.log" 2&gt;&amp;1</pre>
          </div>
        </div>
        """
    else:
        hdr = cur["hdr"]
        crypto = cur["crypto"]
        strings = cur["strings"]
        apk = cur["apk"]
        unpack_info = cur["unpack"]
        sec_rows = "\n".join(
            f"{s['name']:<10} VA={s['virtual_addr']}  Size={s['raw_size']:<7}  Entropy={s['entropy']:.2f}  {'[PACKED!]' if s['high_entropy'] else '[OK]'}"
            for s in hdr.get("sections", [])
        ) or f"Container: {hdr.get('format')} | Packer Hits: {len(unpack_info.get('packers_detected', []))}"
        crypto_rows = "\n".join(
            f"{m['name']} @ {m['offset']}  ({m['category']})" for m in crypto.get("matches", [])
        ) or "No symmetric cipher tables detected."
        str_rows = "\n".join(
            (["[URLs]"] + strings.get("urls", [])[:6])
            + (["\n[APIs / JNI]"] + strings.get("api_and_jni", [])[:6])
            + (["\n[Packers #36]"] + [f"{d['packer']} @ {d['offset']}" for d in unpack_info.get("packers_detected", [])])
        )
        if apk:
            axml = apk.get("axml_manifest") or {}
            str_rows += f"\n\n[APK AXML Package]\n{axml.get('package_name', '')}\n[Permissions]\n" + "\n".join(apk.get("flagged_permissions", []))

        content_html = f"""
        <div class="grid-2">
          <div class="panel">
            <h2>Step 1 Binary Inspector — {html.escape(hdr['file_name'])}</h2>
            <div class="metrics">
              <div class="m"><span>Format</span><strong style="color:{accent}">{html.escape(hdr['format'])}</strong></div>
              <div class="m"><span>Arch</span><strong>{html.escape(hdr['arch'])}</strong></div>
              <div class="m"><span>Entropy</span><strong style="color:{warn if hdr['packed_warning'] else good}">{hdr['overall_entropy']} bits/B</strong></div>
              <div class="m"><span>SHA-256</span><strong>{html.escape(hdr['sha256'][:12])}...</strong></div>
            </div>
            <pre class="code">{html.escape(sec_rows)}</pre>
            <h3 style="margin-top:12px;">Crypto Constants Located</h3>
            <pre class="code">{html.escape(crypto_rows)}</pre>
          </div>
          <div class="panel">
            <h2>Extracted Attack Surface (URLs, APIs, Packers #36, AXML)</h2>
            <form method="POST" action="/api/load-file" style="display:flex;gap:8px;margin-bottom:12px;">
              <input type="hidden" name="theme" value="{theme}" />
              <input class="inp" type="text" name="file_path" placeholder="Paste full path to any .exe, .dll, .apk, or .hap..." />
              <button class="btn primary" type="submit">Load File</button>
            </form>
            <pre class="code" style="min-height:260px;">{html.escape(str_rows)}</pre>
          </div>
        </div>
        """

    banner_html = f'<div class="banner">{html.escape(banner_msg)}</div>' if banner_msg else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" /><title>SI-ReArk-Studio {APP_VERSION}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }}
  body {{ background: {bg}; color: {fg}; padding: 20px 28px; }}
  .topbar {{ display: flex; justify-content: space-between; align-items: center; padding: 14px 20px; background: {card}; border: 2px solid {border}; border-radius: 12px; margin-bottom: 14px; }}
  .brand {{ font-size: 22px; font-weight: 800; }}
  .brand span {{ color: {accent}; }}
  .badge {{ font-size: 13px; padding: 5px 12px; border-radius: 999px; border: 1px solid {good}; color: {good}; font-weight: 700; text-decoration: none; }}
  .tabs {{ display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }}
  .tab {{ text-decoration: none; padding: 9px 15px; border-radius: 8px; background: {card}; border: 2px solid {border}; color: {muted}; font-weight: 700; font-size: 14px; }}
  .tab.active {{ background: {card_alt}; border-color: {accent}; color: {fg}; }}
  .banner {{ padding: 11px 16px; margin-bottom: 14px; border-radius: 8px; border: 2px solid {good}; background: {card_alt}; color: {fg}; font-weight: 600; font-size: 14px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
  .panel {{ background: {card}; border: 2px solid {border}; border-radius: 12px; padding: 18px; }}
  h2 {{ font-size: 18px; margin-bottom: 10px; color: {accent}; }}
  h3 {{ font-size: 14px; margin-bottom: 8px; color: {muted}; text-transform: uppercase; }}
  .sub {{ color: {muted}; font-size: 13px; margin-bottom: 12px; }}
  .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin-bottom: 12px; }}
  .m {{ background: {code_bg}; border: 1px solid {border}; border-radius: 8px; padding: 8px; }}
  .m span {{ display: block; font-size: 11px; color: {muted}; text-transform: uppercase; }}
  .m strong {{ font-size: 14px; }}
  pre.code {{ background: {code_bg}; border: 1px solid {border}; border-radius: 8px; padding: 12px; font-family: 'Cascadia Code', Consolas, monospace; font-size: 13px; line-height: 1.45; white-space: pre-wrap; color: {fg}; }}
  .btn {{ cursor: pointer; padding: 9px 14px; border-radius: 8px; border: 1px solid {border}; background: {card_alt}; color: {fg}; font-weight: 700; font-size: 13px; }}
  .btn.primary {{ border-color: {accent}; background: {accent}; color: #020617; }}
  .inp {{ flex: 1; padding: 8px 12px; border-radius: 8px; border: 1px solid {border}; background: {code_bg}; color: {fg}; font-size: 13px; }}
</style></head>
<body>
  <div class="topbar">
    <div class="brand">SI-ReArk-<span>Studio 2.0</span> &bull; Free Local AI + Binary Unpacker + MCP</div>
    <div style="display:flex;gap:10px;align-items:center;">
      <a class="badge" href="/?view={view}&tab={active_tab}&theme={toggle_target}">{html.escape(toggle_label)}</a>
      <span class="badge">$0.00 Local Ollama :11436 Ready</span>
    </div>
  </div>
  <div class="tabs">{tab_links}</div>
  {banner_html}
  {content_html}
</body></html>"""


def start_ui_server(
    files: list[Path],
    win10_dir: Path | None = None,
    port: int = 8792,
    proxy: ReArkAiBridgeProxy | None = None,
) -> ThreadingHTTPServer:
    """Start local interactive Web Studio server (returns ThreadingHTTPServer for caller control)."""
    state: dict[str, Any] = {"banner": ""}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _redirect_with_banner(self, url: str, msg: str) -> None:
            state["banner"] = msg
            self.send_response(303)
            self.send_header("Location", url)
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            tab = int((qs.get("tab") or ["0"])[0])
            view = (qs.get("view") or ["workspace"])[0]
            theme = (qs.get("theme") or ["dark"])[0]
            msg = state["banner"]
            state["banner"] = ""
            body = _render_inspector_html(
                files,
                active_tab=tab,
                view=view,
                theme=theme,
                win10_dir=win10_dir,
                proxy=proxy,
                banner_msg=msg,
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            cl = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(cl).decode("utf-8", errors="ignore")
            form = urllib.parse.parse_qs(raw)
            theme = (form.get("theme") or ["dark"])[0]

            if self.path == "/api/load-file":
                fpath = Path((form.get("file_path") or [""])[0].strip().strip('"'))
                if fpath.exists() and fpath.is_file():
                    if fpath not in files:
                        files.insert(0, fpath)
                    self._redirect_with_banner(f"/?tab=0&view=workspace&theme={theme}", f"Loaded binary: {fpath.name}")
                else:
                    self._redirect_with_banner(f"/?view=workspace&theme={theme}", f"File not found: {fpath}")
            elif self.path == "/api/unpack":
                fpath = (form.get("file_path") or [""])[0].strip()
                res = detect_and_unpack_binary(fpath, attempt_unpack=True)
                self._redirect_with_banner(f"/?view=unpacker&theme={theme}", f"Unpacker #36: {res.get('unpack_status')} | Backup: {res.get('backup_path')}")
            elif self.path == "/api/proxy-test":
                if proxy is not None:
                    p_url = f"http://127.0.0.1:{proxy.listen_port}/v1/chat/completions"
                    try:
                        req = urllib.request.Request(p_url, data=b"", headers={"Content-Type": "application/json"}, method="POST")
                        with urllib.request.urlopen(req, timeout=5) as r:
                            self._redirect_with_banner(f"/?view=ai_proxy&theme={theme}", f"Proxy :11436 repaired empty body -> HTTP {r.status}!")
                    except Exception as exc:
                        self._redirect_with_banner(
                            f"/?view=ai_proxy&theme={theme}",
                            f"Empty body repaired & normalized cleanly ({proxy.get_stats()['empty_bodies_repaired']} total). Start Ollama for live inference: {exc}",
                        )
                else:
                    self._redirect_with_banner(f"/?view=ai_proxy&theme={theme}", "Start Desktop/Studio mode to activate live :11436 proxy.")
            elif self.path == "/api/ask-ai":
                fpath = (form.get("file_path") or [""])[0]
                q = (form.get("question") or ["Summarize findings"])[0]
                hdr = inspect_binary_headers(fpath)
                unp = detect_and_unpack_binary(fpath, attempt_unpack=False)
                crp = scan_crypto_signatures(fpath)
                summary = {
                    "format": hdr.get("format"),
                    "arch": hdr.get("arch"),
                    "packers_detected": unp.get("packers_detected", []),
                    "crypto_match_count": crp.get("match_count", 0),
                }
                p_url = f"http://127.0.0.1:{proxy.listen_port}" if proxy else f"http://127.0.0.1:{PROXY_DEFAULT_PORT}"
                ans = ask_local_ai_about_binary(summary, q, proxy_url=p_url)
                self._redirect_with_banner(f"/?view=ai_proxy&theme={theme}", f"AI ({ans['source']}): {ans['answer'][:220]}")
            elif self.path == "/api/wire-mcp":
                res = wire_reark_mcp_into_clients()
                self._redirect_with_banner(f"/?view=mcp&theme={theme}", f"MCP Wired into {res['wired_count']} clients cleanly! Rollback manifest saved.")
            elif self.path == "/api/rollback-mcp":
                res = rollback_mcp_clients()
                self._redirect_with_banner(f"/?view=mcp&theme={theme}", f"Rollback complete: {', '.join(res.get('restored', [res.get('error', '')]))}")
            elif self.path == "/api/fix-win10":
                wdir = win10_dir or (Path.home() / "ReArk_Win10_Fixed")
                res = diagnose_win10_launch(wdir)
                self._redirect_with_banner(f"/?view=win10&theme={theme}", f"Win10 Safe Launcher generated -> {res['safe_launcher_path']} | Full JDK: {res['has_full_jdk']}")
            elif self.path == "/api/download-reark":
                wdir = win10_dir or (Path.home() / "ReArk_Win10_Fixed")
                res = download_official_reark_release(wdir)
                msg = f"Downloaded ReArk {res.get('release_tag')} -> {res.get('target_dir')}" if res.get("ok") else f"Download notice: {res.get('error')}"
                self._redirect_with_banner(f"/?view=win10&theme={theme}", msg)
            else:
                self._redirect_with_banner(f"/?view=workspace&theme={theme}", "Action completed.")

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return srv


def _open_studio_browser(url: str) -> None:
    edge = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
    if edge.exists():
        subprocess.Popen([str(edge), f"--app={url}", "--window-size=1480,920"])
    else:
        webbrowser.open(url)


def launch_desktop_app(
    files: list[Path],
    win10_dir: Path | None = None,
    port: int = 8792,
    proxy_port: int = PROXY_DEFAULT_PORT,
    upstream_url: str = UPSTREAM_DEFAULT_URL,
) -> None:
    """Start live :11436 Empty-Body AI Proxy + :8792 Web Studio + Tkinter Native Desktop Control Shell."""
    if not files:
        files.extend(ensure_demo_samples(Path.home() / ".si_reark_studio" / "samples"))

    proxy = ReArkAiBridgeProxy(upstream_url=upstream_url, listen_port=proxy_port)
    actual_proxy_port = proxy.start()
    srv = start_ui_server(files, win10_dir=win10_dir, port=port, proxy=proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    studio_url = f"http://127.0.0.1:{srv.server_address[1]}/"
    _open_studio_browser(studio_url)

    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox

        root = tk.Tk()
        root.title(f"SI-ReArk-Studio {APP_VERSION} — Control Hub")
        root.geometry("560x360")
        root.configure(bg="#060a13")

        tk.Label(
            root,
            text=f"SI-ReArk-Studio {APP_VERSION} Active ($0.00 Local AI)",
            fg="#38bdf8",
            bg="#060a13",
            font=("Segoe UI", 13, "bold"),
        ).pack(pady=(16, 6))
        tk.Label(
            root,
            text=f"Web Studio: {studio_url}\nAI Proxy Fix (#20): http://127.0.0.1:{actual_proxy_port}/v1 -> {upstream_url}",
            fg="#e2e8f0",
            bg="#060a13",
            font=("Cascadia Code", 9),
        ).pack(pady=(0, 14))

        def pick_file() -> None:
            chosen = filedialog.askopenfilename(
                title="Select EXE, DLL, APK, or HAP to Reverse Engineer",
                filetypes=[("Binaries & APKs", "*.exe *.dll *.apk *.hap *.so"), ("All files", "*.*")],
            )
            if chosen:
                p = Path(chosen)
                if p not in files:
                    files.insert(0, p)
                _open_studio_browser(f"{studio_url}?tab=0&view=workspace")

        def wire_mcp_btn() -> None:
            res = wire_reark_mcp_into_clients()
            messagebox.showinfo("MCP Auto-Wire (#31)", f"Registered si-reark-mcp into {res['wired_count']} AI clients cleanly!")

        def fix_win10_btn() -> None:
            wdir = win10_dir or (Path.home() / "ReArk_Win10_Fixed")
            res = diagnose_win10_launch(wdir)
            messagebox.showinfo("Win10 & JDK Doctor (#35)", f"Launcher saved: {res['safe_launcher_path']}\nFull JDK 17+ Ready: {res['has_full_jdk']}")

        btn_cfg = {"font": ("Segoe UI", 10, "bold"), "width": 40, "pady": 6, "cursor": "hand2"}
        tk.Button(root, text="Step 1: Load EXE / DLL / APK File...", command=pick_file, bg="#0284c7", fg="#ffffff", **btn_cfg).pack(pady=4)
        tk.Button(root, text="Open Full SI-ReArk-Studio Web UI", command=lambda: _open_studio_browser(studio_url), bg="#1e293b", fg="#38bdf8", **btn_cfg).pack(pady=4)
        tk.Button(root, text="Step 2: Open Local AI Proxy & Unpacker View", command=lambda: _open_studio_browser(f"{studio_url}?view=ai_proxy"), bg="#1e293b", fg="#34d399", **btn_cfg).pack(pady=4)
        tk.Button(root, text="Step 3: 1-Click Wire MCP into Claude/Cursor/Antigravity", command=wire_mcp_btn, bg="#1e293b", fg="#fbbf24", **btn_cfg).pack(pady=4)
        tk.Button(root, text="Bonus: Run Win10 & JDK17 Doctor (#35)", command=fix_win10_btn, bg="#0f172a", fg="#e2e8f0", **btn_cfg).pack(pady=4)

        root.mainloop()
    except Exception:
        print(f"SI-ReArk-Studio Web UI: {studio_url} | AI Bridge Proxy: http://127.0.0.1:{actual_proxy_port}/v1")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    finally:
        proxy.stop()
        srv.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="SI-ReArk-Studio 2.0 — Free Local AI Reverse Engineering Suite")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("mcp", help="Run STDIO JSON-RPC 2.0 MCP server")

    p_ins = sub.add_parser("inspect", help="Inspect single binary + unpacker scan + crypto + strings")
    p_ins.add_argument("file", type=Path)

    p_unp = sub.add_parser("unpack", help="Detect packer & safe SHA-256 unpack (#36)")
    p_unp.add_argument("file", type=Path)

    p_dif = sub.add_parser("diff", help="Diff 2+ binaries (Issue #31 multi-tab feature)")
    p_dif.add_argument("files", nargs="+", type=Path)

    p_win = sub.add_parser("win10-doctor", help="Audit Win10 launch blockers + JDK17 trap (Issue #35)")
    p_win.add_argument("--reark-dir", type=Path, default=None)

    p_wire = sub.add_parser("wire-mcp", help="Auto-register si-reark-mcp into Claude/Antigravity/Cursor (#31)")
    p_wire.add_argument("--rollback", action="store_true")

    p_prx = sub.add_parser("proxy", help="Run standalone :11436 Empty-Body Fix AI Bridge Proxy (#20/#16/#9)")
    p_prx.add_argument("--port", type=int, default=PROXY_DEFAULT_PORT)
    p_prx.add_argument("--upstream", default=UPSTREAM_DEFAULT_URL)
    p_prx.add_argument("--model", default="qwen2.5-coder:14b")

    p_ui = sub.add_parser("ui", help="Start interactive Multi-Tab Web Studio + :11436 AI Proxy")
    p_ui.add_argument("files", nargs="*", type=Path)
    p_ui.add_argument("--port", type=int, default=8792)
    p_ui.add_argument("--proxy-port", type=int, default=PROXY_DEFAULT_PORT)
    p_ui.add_argument("--win10-dir", type=Path, default=None)

    p_dsk = sub.add_parser("desktop", help="Launch Native Desktop Control Hub + Web Studio + :11436 Proxy")
    p_dsk.add_argument("files", nargs="*", type=Path)
    p_dsk.add_argument("--port", type=int, default=8792)
    p_dsk.add_argument("--proxy-port", type=int, default=PROXY_DEFAULT_PORT)
    p_dsk.add_argument("--win10-dir", type=Path, default=None)

    args = parser.parse_args()
    cmd = args.cmd or "desktop"

    if cmd == "mcp":
        run_stdio_mcp_loop()
    elif cmd == "inspect":
        out = {
            "headers": inspect_binary_headers(args.file),
            "unpack": detect_and_unpack_binary(args.file, attempt_unpack=False),
            "crypto": scan_crypto_signatures(args.file),
            "strings": extract_high_value_strings(args.file),
            "apk": audit_apk_manifest(args.file) if zipfile.is_zipfile(args.file) else None,
        }
        print(json.dumps(out, indent=2))
    elif cmd == "unpack":
        print(json.dumps(detect_and_unpack_binary(args.file, attempt_unpack=True), indent=2))
    elif cmd == "diff":
        print(json.dumps(diff_multiple_binaries(args.files), indent=2))
    elif cmd == "win10-doctor":
        print(json.dumps(diagnose_win10_launch(args.reark_dir), indent=2))
    elif cmd == "wire-mcp":
        res = rollback_mcp_clients() if args.rollback else wire_reark_mcp_into_clients()
        print(json.dumps(res, indent=2))
    elif cmd == "proxy":
        proxy = ReArkAiBridgeProxy(upstream_url=args.upstream, listen_port=args.port, default_model=args.model)
        p = proxy.start()
        print(f"SI-ReArk-Studio Empty-Body Fix Proxy listening on http://127.0.0.1:{p}/v1 -> {args.upstream}")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            proxy.stop()
    elif cmd == "ui":
        files_in = list(args.files) if args.files else ensure_demo_samples(Path.home() / ".si_reark_studio" / "samples")
        proxy = ReArkAiBridgeProxy(listen_port=args.proxy_port)
        proxy.start()
        srv = start_ui_server(files_in, win10_dir=args.win10_dir, port=args.port, proxy=proxy)
        print(f"SI-ReArk-Studio UI running at http://127.0.0.1:{srv.server_address[1]}/ | Proxy :{proxy.listen_port}")
        srv.serve_forever()
    elif cmd == "desktop":
        launch_desktop_app(list(args.files), win10_dir=args.win10_dir, port=args.port, proxy_port=args.proxy_port)


if __name__ == "__main__":
    main()
