@echo off
rem Same as Check-Email.bat. Offline is the default since v2.1; kept so old shortcuts still work.
if "%~1"=="" (
    echo.
    echo  Drag a PDF or image onto Check-Email-Offline.bat
    echo  Links are checked without visiting them.
    echo.
    pause
    exit /b 0
)
call "%~dp0Check-Email.bat" %* --no-scan
