# SI-ReArk-MCP

Open-source **Model Context Protocol (MCP) Server, Multi-Binary Tabbed Inspector, High-Contrast Daylight Accessibility Mode & Windows 10 Startup Doctor** for **[ReArk (`lkimuk/ReArk`)](https://github.com/lkimuk/ReArk)**.

ReArk brings AI-assisted binary, HarmonyOS NEXT (`.hap`/`.abc`), Android (`.apk`), iOS (`.ipa`), and PE/ELF static analysis in one desktop app — and ReArk users requested an MCP server, multi-binary tabs, higher readability contrast (Issue **#31**), plus a fix for Windows 10 silent startup failures (Issue **#35**). **SI-ReArk-MCP** delivers all three in pure zero-dependency Python.

## Features Implemented

| Module | GitHub Issue Addressed | What It Delivers |
| --- | --- | --- |
| **1. Standard `stdio` MCP Server (`5` Tools)** | **Issue #31** | Connects PE/ELF/Mach-O/APK/HAP static headers, Shannon packing entropy, AES/SHA-256/ChaCha20 signature scanning, URL/JNI string extraction, and multi-binary diffing directly to Claude Code, Cursor, or `$0.00` local Ollama |
| **2. Multi-Binary Tabs + High-Contrast Daylight Mode** | **Issue #31** | Inspect and diff multiple binaries side-by-side in simultaneous tabs with a 1-click **High-Contrast Daylight** toggle (`#020617` on `#ffffff`) replacing dim gray-on-black text |
| **3. Windows 10 Silent Startup Doctor** | **Issue #35** | Audits WebView2 Runtime, VC++ x64 DLLs, UTF-8 paths, and writes `launch_reark_win10_safe.cmd` with `--disable-gpu --no-sandbox` + diagnostic logging |

## Quick Start

```bash
# 1. Start the stdio MCP Server for Claude Code / Ollama / Cursor
python si_reark_mcp.py mcp

# 2. Launch Multi-Binary Tabbed Web Inspector (supports ?theme=light High-Contrast mode)
python si_reark_mcp.py ui --files target_v1.dll target_v2.dll app.apk --port 8792

# 3. Run Windows 10 Silent Launch Doctor inside your ReArk folder
python si_reark_mcp.py win10-doctor --reark-dir "C:\Path\To\ReArk"

# 4. Run CLI inspection or binary diff
python si_reark_mcp.py inspect target.dll
python si_reark_mcp.py diff old.dll new.dll
```

## Automated Tests

```bash
python -m unittest test_reark_mcp.py -v
```
