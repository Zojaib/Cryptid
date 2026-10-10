@echo off
rem Cryptid without the window, for scripts and scheduled backups.  Example:  cryptid_cli.bat verify D:\Cloud
set "PY=%USERPROFILE%\.cryptid\venv\Scripts\python.exe"
if not exist "%PY%" (
    echo Run requirements.bat first.
    exit /b 1
)
"%PY%" "%~dp0cryptid_cli.py" %*
