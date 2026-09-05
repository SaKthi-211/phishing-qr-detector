@echo off
title CyberShield - Phishing & QR Detector
echo ============================================
echo   CyberShield - Starting up...
echo ============================================

REM Check whether dependencies are already installed
python -c "import flask" 2>NUL
if errorlevel 1 (
    echo [*] First-time setup - installing dependencies, this may take a moment...
    pip install -r requirements.txt
) else (
    echo [*] Dependencies already installed, skipping...
)

REM Open the browser automatically after a short delay
start "" cmd /c "timeout /t 2 >nul && start http://127.0.0.1:5000"

echo [*] Server starting... http://127.0.0.1:5000
python app.py

pause
