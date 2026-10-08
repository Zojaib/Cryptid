@echo off
setlocal
cd /d "%~dp0"

rem Private Python environment in a SHORT path. Windows (and the Microsoft Store Python in
rem particular) fails to install PySide6 into very long folder names.
set "VENV=%USERPROFILE%\.cryptid\venv"
if exist "%VENV%\Scripts\python.exe" goto :haveenv
echo === Creating a private Python environment ===
python -m venv "%VENV%"
if errorlevel 1 goto :fail
:haveenv
set "PY=%VENV%\Scripts\python.exe"

echo === Installing build dependencies ===
"%PY%" -m pip install --upgrade pip
"%PY%" -m pip install cryptography argon2-cffi zstandard send2trash "PySide6-Essentials>=6.6,<6.12" pyinstaller
if errorlevel 1 goto :fail

echo.
echo === Building Cryptid ===
"%PY%" -m PyInstaller --noconfirm --clean --windowed --name Cryptid ^
    --collect-all argon2 --collect-all _argon2_cffi_bindings ^
    --collect-all send2trash ^
    cryptid_gui.py
if errorlevel 1 goto :fail

echo.
echo Done. Run:  dist\Cryptid\Cryptid.exe
echo To share it, copy the whole dist\Cryptid folder.
pause
exit /b 0

:fail
echo.
echo Build failed - see the messages above.
echo If it mentions a path that is too long, enable Windows long paths once (as administrator):
echo   reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f
echo then restart the computer and run this file again.
pause
exit /b 1
