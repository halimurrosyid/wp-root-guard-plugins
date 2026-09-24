@echo off
setlocal enabledelayedexpansion

REM =============================================================
REM build-zip.bat — Packaging WordPress Plugin WP Root Guard
REM =============================================================
REM Skrip batch Windows untuk memanggil build-zip.ps1 secara aman.
REM Mendukung double-click pada Windows Explorer maupun via CMD.
REM =============================================================

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%build-zip.ps1"

if not exist "%PS_SCRIPT%" (
    echo [x] Berkas build-zip.ps1 tidak ditemukan di: %PS_SCRIPT%
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
set "EXIT_CODE=%ERRORLEVEL%"

if %EXIT_CODE% neq 0 (
    echo.
    echo [x] Proses build gagal dengan kode keluar: %EXIT_CODE%
    if not defined CI (
        pause
    )
    exit /b %EXIT_CODE%
)

if not defined CI (
    echo.
    echo Tekan tombol apa saja untuk keluar...
    pause >nul
)

exit /b 0
