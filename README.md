# SI-ReArk-Studio 2.0 (`si-reark-mcp`)

**Free, Zero-API-Key Local AI Reverse-Engineering Suite & Companion Engine for [`lkimuk/ReArk`](https://github.com/lkimuk/ReArk).**

Built completely in zero-dependency Python Stdlib (`pe/elf/apk` inspection, pure-Python AXML binary manifest decoder, local HTTP AI repair proxy, Web Studio, Tkinter Desktop Control Hub, and 8-tool STDIO MCP server) — solving the top open community issues in `lkimuk/ReArk`:

| ReArk Community Pain / Open Issue | What SI-ReArk-Studio 2.0 Actually Solves |
|---|---|
| **Issues #20, #16, #9** — *"Request body is empty" (`Agent 报错：“请求体为空”`)* | **Live Local AI Repair Proxy (`127.0.0.1:11436` -> `:11434`)**: Repairs empty/malformed POST bodies, injects missing `model` / `messages` / `num_ctx=32768`, disables broken chunked streaming cleanly, and tracks live repair telemetry. |
| **Issue #36** — *Packer & Unpacking Support (`可以加个脱壳功能不`)* | **SHA-256 Safe Unpacker Engine**: Detects `UPX`, `ASPack`, `VMProtect`, `Themida`, `MPRESS`, `PyInstaller`, and `ConfuserEx`, saves an immutable SHA-256 `.bak` copy, runs `upx -d` automatically when available, and extracts clean embedded `MZ...PE\x00\x00` payloads from overlays. |
| **Issue #35** — *Windows 10 Silent Launch Crash + APK JDK Trap* | **Win10 + JDK 17+ Launch Doctor & Release Fetcher**: Checks Edge WebView2, VC++ 2015-2022 DLLs, non-ASCII path hazards, and distinguishes full `JDK (javac.exe)` from bare `JRE`, plus 1-click official ReArk download & `launch_reark_win10_safe.cmd` generation. |
| **Issue #31** — *MCP Server, Multi-Tab Diff & Contrast Toggle* | **1-Click 4-Client MCP Auto-Wire + Rollback + Daylight Mode**: Registers **8 real MCP tools** into Claude Desktop, Claude Code, Antigravity, and Cursor with SHA-256 backups, 1-click rollback, Multi-Binary Tab Diff, and High-Contrast Daylight mode. |
| **Compiled Android `AndroidManifest.xml` unreadable in plain tools** | **Pure-Python Binary AXML (`0x00080003`) Decoder**: Extracts package name, permissions, activities, and URLs straight out of compiled `.apk` manifests with zero Java required. |

---

## Quick Start (3 Steps + Bonus)

### Step 1 — 1-Click Launch (Zero Terminal Knowledge Needed)
Double-click `Launch_SI_ReArk_Studio.bat` (or run `python si_reark_mcp.py desktop`).
It launches the **Tkinter Control Hub**, starts the **Web Studio (`http://127.0.0.1:8792`)**, and runs the **AI Repair Proxy (`http://127.0.0.1:11436/v1`)** in parallel with sample PE + APK binaries ready to inspect immediately.

### Step 2 — Unpack `#36` & Decode Binary APK AXML
Load any `.exe`, `.dll`, `.apk`, or `.hap` directly from the UI or desktop file picker to inspect PE sections, Shannon entropy, AES/SHA-256/ChaCha20 crypto constants, unpackers, and compiled Android `AndroidManifest.xml` permissions.

### Step 3 — Fix ReArk Agent Empty Body `#20` + Wire MCP `#31`
In ReArk's Local LLM settings, set:
- **Base URL**: `http://127.0.0.1:11436/v1`
- **Model**: `qwen2.5-coder:14b` (or any pulled Ollama model)
- **API Key**: `local-free-zero-cost`

Click **1-Click Wire Into All 4 AI Clients** in the MCP tab (or run `python si_reark_mcp.py wire-mcp`) to add 8 reverse-engineering tools directly to Claude Desktop, Claude Code, Antigravity, and Cursor.

### Bonus — Fix Win10 Silent Crash & JDK 17+ Trap `#35`
Open the **Win10 + JDK17 Fix #35** tab (or run `python si_reark_mcp.py win10-doctor --reark-dir C:\ReArk`) to check your Java JDK `javac.exe` path, download the latest official ReArk Windows release, and generate `launch_reark_win10_safe.cmd`.

---

## Verification
```powershell
python -m unittest test_reark_mcp.py -v
```
