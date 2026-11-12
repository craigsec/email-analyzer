@echo off
title Email Analyzer setup
cd /d "%~dp0"
if not exist "%~dp0setup\install.ps1" (
    echo.
    echo  The setup files are missing next to Install.bat.
    echo  Right-click the zip ^> Extract All, then run Install.bat from the extracted folder.
    echo.
    pause
    exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0setup\install.ps1"
if errorlevel 1 (
    echo.
    echo  Setup could not start. Take a screenshot of this window and send it to ICT.
    echo.
    pause
)
