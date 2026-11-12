@echo off
setlocal
set "HERE=%~dp0"
set "PY=%HERE%.venv\Scripts\python.exe"

if not exist "%PY%" (
    echo First run: setting up Python environment, this takes a minute...
    py -3 -m venv "%HERE%.venv" 2>nul || python -m venv "%HERE%.venv"
    if not exist "%PY%" (
        echo Python 3 not found. Install it from python.org, tick "Add to PATH", then try again.
        pause
        exit /b 1
    )
    "%PY%" -m pip install -q --upgrade pip
    "%PY%" -m pip install -q -r "%HERE%requirements.txt"
)

if "%~1"=="" (
    echo.
    echo  Drag an email, PDF or image onto Check-Email.bat  ^(offline check^)
    echo  or run:  Check-Email.bat "C:\path\file.eml"   [--lookups] [--live]
    echo           Check-Email.bat --paste
    echo.
    pause
    exit /b 0
)

"%PY%" "%HERE%qr_check.py" %*
echo.
pause
