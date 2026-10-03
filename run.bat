@echo off
title LazySOC - Zero-Effort Threat Triage
echo ===================================================
echo   Starting LazySOC Modern Cyber UI...
echo ===================================================
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python server.py
pause
