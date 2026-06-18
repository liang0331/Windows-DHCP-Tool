@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo  Windows DHCP Tool - Build Script
echo ============================================================
echo.

:: Step 1: Install dependencies
echo [1/3] Installing dependencies...
pip install customtkinter psutil pyinstaller
if %errorlevel% neq 0 (
    echo ERROR: pip install failed. Make sure Python and pip are in PATH.
    pause
    exit /b 1
)
echo.

:: Step 2: Clean previous build artifacts
echo [2/3] Cleaning previous build...
if exist build   rmdir /s /q build
if exist dist    rmdir /s /q dist
if exist DHCPTool.spec del /f /q DHCPTool.spec
echo.

:: Step 3: Run PyInstaller
echo [3/3] Building EXE with PyInstaller...
pyinstaller ^
    --onefile ^
    --windowed ^
    --uac-admin ^
    --name DHCPTool ^
    --manifest app.manifest ^
    --collect-all customtkinter ^
    --hidden-import psutil ^
    --hidden-import dhcp_server ^
    --hidden-import ui_app ^
    main.py

if %errorlevel% neq 0 (
    echo ERROR: PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Build complete!
echo  Output: dist\DHCPTool.exe
echo.
echo  NOTE: DHCPTool.exe requires Administrator privileges to
echo        bind UDP port 67. Windows will prompt for UAC on
echo        first launch.
echo ============================================================
pause
