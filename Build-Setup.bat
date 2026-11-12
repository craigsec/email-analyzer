@echo off
title Build Email-Analyzer-Setup
cd /d "%~dp0"
echo.
echo  Building Email-Analyzer-Setup-^<version^>.exe  (offline installer)
echo  --------------------------------------------------------
rem Layout: this file and the program (Email-Analyzer\) are in Developer\;
rem the finished Email-Analyzer-Setup-<version>.exe is written to ..\Install\
set "APPDIR=%~dp0Email-Analyzer"
if not exist "%~dp0..\Install" mkdir "%~dp0..\Install"
for %%D in ("%~dp0..\Install") do set "OUTDIR=%%~fD"
set "OFF=%APPDIR%\offline"

if not exist "%APPDIR%\qr_check.py" (
    echo  The program folder was not found: %APPDIR%
    pause
    exit /b 1
)

rem The libraries and Python are not kept in the kit (about 80 MB of downloads that nobody edits).
rem They are fetched here, once, then reused by later builds.
if not exist "%OFF%\wheels\*.whl" (
    echo  Step 1 of 3: downloading the libraries listed in requirements.txt
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fetch-wheels.ps1" -AppDir "%APPDIR%"
    if errorlevel 1 (
        echo.
        echo  Could not download the libraries. This PC needs internet and Python 3.11-3.14 for the build
        echo  ^(only the build needs internet, not the PCs you install on^).
        pause
        exit /b 1
    )
) else (
    echo  Step 1 of 3: libraries already downloaded, using them.
)

if not exist "%OFF%\python-installer.exe" (
    echo  Step 2 of 3: getting Python for the offline installer
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0fetch-python.ps1" -OutDir "%OFF%"
    if errorlevel 1 (
        echo.
        echo  Could not download Python. Check the internet connection on THIS PC
        echo  ^(only the build needs internet, not the PCs you install on^).
        pause
        exit /b 1
    )
) else (
    echo  Step 2 of 3: Python already downloaded, using it.
    echo  ^(Delete Developer\Email-Analyzer\offline\python-installer.exe to fetch the newest one.^)
)

echo.
echo  Step 3 of 3: packing Setup.exe
set "ISCC="
for %%P in ("%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "%ProgramFiles%\Inno Setup 6\ISCC.exe" "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe") do (
    if exist %%P set "ISCC=%%~P"
)
if not defined ISCC (
    echo  Inno Setup 6 is not installed. Installing it now with winget...
    winget install --id JRSoftware.InnoSetup -e --scope user --silent --accept-package-agreements --accept-source-agreements
    for %%P in ("%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "%ProgramFiles%\Inno Setup 6\ISCC.exe" "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe") do (
        if exist %%P set "ISCC=%%~P"
    )
)
if not defined ISCC (
    echo.
    echo  Could not find or install Inno Setup 6.
    echo  Download it from https://jrsoftware.org/isdl.php , install it, then run this again.
    echo.
    pause
    exit /b 1
)
"%ISCC%" /Q "Email-Analyzer-Setup.iss"
if errorlevel 1 (
    echo.
    echo  Build failed. Send a screenshot of this window to whoever maintains the tool.
    pause
    exit /b 1
)

rem ---------------------------------------------------------------- signing (optional)
rem Signing needs the company's code-signing certificate. Copy sign-settings.example.bat to
rem sign-settings.bat and fill it in. Without that file the installer is built unsigned.
set "SETUP="
for /f "delims=" %%F in ('dir /b /o-d "%OUTDIR%\Email-Analyzer-Setup-*.exe" 2^>nul') do if not defined SETUP set "SETUP=%OUTDIR%\%%F"
set "SIGN_THUMBPRINT="
set "SIGN_DLIB="
set "SIGN_METADATA="
set "SIGN_TIMESTAMP=http://timestamp.digicert.com"
if exist "%~dp0sign-settings.bat" call "%~dp0sign-settings.bat"
if not defined SIGN_THUMBPRINT if not defined SIGN_METADATA goto :unsigned

set "SIGNTOOL="
for /f "delims=" %%S in ('where signtool.exe 2^>nul') do if not defined SIGNTOOL set "SIGNTOOL=%%S"
if not defined SIGNTOOL for /f "delims=" %%S in ('dir /b /s "%ProgramFiles(x86)%\Windows Kits\10\bin\signtool.exe" 2^>nul ^| findstr /i "\\x64\\"') do set "SIGNTOOL=%%S"
if not defined SIGNTOOL goto :nosigntool

echo.
echo  Step 3: signing the installer
if defined SIGN_METADATA goto :sign_cloud
"%SIGNTOOL%" sign /sha1 %SIGN_THUMBPRINT% /fd SHA256 /tr "%SIGN_TIMESTAMP%" /td SHA256 /d "Email Analyzer" "%SETUP%"
goto :sign_check
:sign_cloud
"%SIGNTOOL%" sign /v /fd SHA256 /tr "%SIGN_TIMESTAMP%" /td SHA256 /dlib "%SIGN_DLIB%" /dmdf "%SIGN_METADATA%" /d "Email Analyzer" "%SETUP%"
:sign_check
if errorlevel 1 goto :signfailed
"%SIGNTOOL%" verify /pa "%SETUP%"
if errorlevel 1 goto :signfailed
echo  Signed and verified.
goto :done

:nosigntool
echo.
echo  sign-settings.bat was found, but signtool.exe is not installed on this PC.
echo  Install the "Windows SDK Signing Tools" ^(part of the Windows SDK^), then run this again.
echo  THE INSTALLER BELOW IS NOT SIGNED.
goto :done

:signfailed
echo.
echo  SIGNING FAILED. Is the certificate token plugged in, or are you signed in to Azure?
echo  THE INSTALLER BELOW IS NOT SIGNED. Do not hand it out as the signed version.
goto :done

:unsigned
echo.
echo  Not signed: no sign-settings.bat. Windows SmartScreen may warn on first run.
echo  See HOW-TO-BUILD.txt, "SIGNING THE INSTALLER".

:done
echo.
echo  Done:  %SETUP%
echo  This single file installs with NO internet: Python and all libraries are inside.
echo.
explorer "%OUTDIR%"
pause
