@echo off
title SI-ReArk-Studio 2.0 - Free Local AI Reverse Engineering Suite
echo ========================================================================
echo   SI-ReArk-Studio 2.0 - Starting Desktop Hub + AI Bridge Proxy (:11436)
echo   Zero Paid API Keys | Solves ReArk Issues #36, #35, #31, #20, #16, #9
echo ========================================================================
cd /d "%~dp0"
python "%~dp0si_reark_mcp.py" desktop %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Python 3.10+ is required. Verify with: python --version
    pause
)
