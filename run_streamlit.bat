@echo off
title Slothery - Streamlit UI
echo ===================================================
echo   Starting Slothery Streamlit UI...
echo ===================================================
cd /d "%~dp0"
call .venv\Scripts\activate.bat
streamlit run app.py
pause
