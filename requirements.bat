@echo off
setlocal
cd /d "%~dp0"

rem Private Python environment in a SHORT path (long folder names break the PySide6 install on Windows).
set "VENV=%USERPROFILE%\.cryptid\venv"
if exist "%VENV%\Scripts\python.exe" goto :haveenv
echo === Creating a private Python environment ===
python -m venv "%VENV%"
if errorlevel 1 goto :fail
:haveenv
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip
"%VENV%\Scripts\python.exe" -m pip install cryptography argon2-cffi zstandard send2trash "PySide6-Essentials>=6.6,<6.12"
if errorlevel 1 goto :fail

echo.
echo Done. Start the app by double-clicking run_cryptid.bat
pause
exit /b 0

:fail
echo.
echo Installation failed - see the messages above.
echo If it mentions a path that is too long, enable Windows long paths once (as administrator):
echo   reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f
echo then restart the computer and run this file again.
pause
exit /b 1
