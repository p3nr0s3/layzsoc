@echo off
title Slothery - Custom Modern Web UI
echo ===================================================
echo   Starting Slothery Custom Modern Web UI...
echo ===================================================
cd /d "%~dp0"
call .venv\Scripts\activate.bat
python server.py
pause
