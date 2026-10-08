@echo off
cd /d "%~dp0"
set "PYW=%USERPROFILE%\.cryptid\venv\Scripts\pythonw.exe"
if not exist "%PYW%" (
    echo Run requirements.bat first.
    pause
    exit /b 1
)
start "" "%PYW%" cryptid_gui.py %*
