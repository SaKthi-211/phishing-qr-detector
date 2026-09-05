#!/bin/bash
# CyberShield launcher - double-click this (or run ./run_mac_linux.sh in a terminal)
echo "============================================"
echo "  CyberShield - Starting up..."
echo "============================================"

cd "$(dirname "$0")"

# Check whether dependencies are already installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "[*] First-time setup - installing dependencies, this may take a moment..."
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
else
    echo "[*] Dependencies already installed, skipping..."
fi

# Open the browser automatically after a short delay
(sleep 2 && (open http://127.0.0.1:5000 2>/dev/null || xdg-open http://127.0.0.1:5000 2>/dev/null)) &

echo "[*] Server starting... http://127.0.0.1:5000"
python3 app.py
