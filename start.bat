@echo off
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel% equ 0 (
  python app.py
) else (
  py -3 app.py
)
pause
