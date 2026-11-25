@echo off
rem Launch the GUI without a console window. Keep this file pure ASCII.
setlocal
pushd "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 (
    start "" python -m liveurldeduper
) else (
    start "" pythonw -m liveurldeduper
)
popd
