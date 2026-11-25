@echo off
rem Build LiveURLDeduper.exe and embed myicon.ico as the exe icon.
rem Usage: build_exe.bat [path\to\icon]        (default: myicon.ico next to this script)
rem        png/jpg also work -- tools\prepare_icon.py converts them to a real .ico.
rem NOTE: keep this file pure ASCII -- cmd.exe parses .bat with the OEM codepage,
rem       UTF-8 Chinese text would break the lines.
setlocal EnableExtensions
pushd "%~dp0"

set "PY=python"
where python >nul 2>nul
if errorlevel 1 set "PY=py"

echo [1/5] Checking Python...
%PY% -c "import sys" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.9+ and add it to PATH.
    goto :fail
)

echo [2/5] Checking dependencies...
%PY% -c "import requests, PyInstaller" >nul 2>nul
if errorlevel 1 (
    echo       Installing requests + pyinstaller ...
    %PY% -m pip install -r requirements.txt pyinstaller
    if errorlevel 1 goto :fail
)

echo [3/5] Preparing icon...
set "ICON=%~1"
if not defined ICON set "ICON=myicon.ico"
for %%I in ("%ICON%") do set "ICON=%%~fI"
if not exist "%ICON%" (
    echo [ERROR] Icon not found: %ICON%
    echo         Put myicon.ico next to this script, or run: build_exe.bat path\to\your\icon
    goto :fail
)
rem Normalize to build\app.ico (copy if already ICO, convert if png/jpg).
rem The spec picks it up through LIVEURLDEDUPER_ICON.
%PY% tools\prepare_icon.py "%ICON%" "build\app.ico"
if errorlevel 1 goto :fail
set "ICON=%CD%\build\app.ico"
set "LIVEURLDEDUPER_ICON=%ICON%"
echo       Icon: %ICON%

echo [4/5] Checking whether the previous exe is still running...
if exist "dist\LiveURLDeduper.exe" (
    rem Use Python instead of tasklist^|find: some machines have an MSYS "find" in PATH.
    %PY% -c "import os,subprocess,sys; tl=os.path.join(os.environ.get('SystemRoot',r'C:\Windows'),'System32','tasklist.exe'); out=subprocess.run([tl,'/FI','IMAGENAME eq LiveURLDeduper.exe'],capture_output=True).stdout; sys.exit(0 if b'LiveURLDeduper.exe' in out else 1)"
    if not errorlevel 1 (
        echo [ERROR] dist\LiveURLDeduper.exe is running. Close that window, then run this script again.
        goto :fail
    )
)

echo [5/5] Building...
%PY% -m PyInstaller --noconfirm --clean --log-level=WARN LiveURLDeduper.spec
if errorlevel 1 goto :fail

if not exist "dist\LiveURLDeduper.exe" (
    echo [ERROR] Build finished but dist\LiveURLDeduper.exe is missing.
    goto :fail
)

echo.
for %%F in ("dist\LiveURLDeduper.exe") do echo Done: %%~fF  ^(%%~zF bytes^)
echo Icon: %ICON%
popd
exit /b 0

:fail
echo.
echo Build failed. See the messages above.
popd
exit /b 1
