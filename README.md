# CyberShield — Phishing URL & Malicious QR Code Detection System
### ML & Heuristic Analysis | Flask + MySQL

A complete, submission-ready web security project that detects:
1. **Phishing URLs** — using a trained RandomForestClassifier combined with rule-based heuristic scoring.
2. **Malicious QR Codes** — decodes any QR image, extracts the embedded payload, and runs it through the same phishing-detection pipeline (a technique known as "quishing" detection).

---

## Features

- Dual-engine risk scoring: **ML model (65% weight) + heuristic rules (35% weight)** → final Risk Score (0–100) and verdict (Safe / Suspicious / Phishing)
- 20 engineered URL features: IP-address usage, shortener detection, brand impersonation, suspicious TLDs, suspicious keywords, redirect tricks, HTTPS usage, and more
- QR code decoding via OpenCV + pyzbar, including detection of high-risk QR payload types (`tel:`, `upi:`, `intent:`, etc.)
- MySQL-backed scan history (with automatic in-memory fallback if MySQL isn't running, so the demo never crashes)
- Dark, cybersecurity-styled dashboard UI
- REST API endpoint (`/api/scan-url`) for programmatic/Postman testing
- All source code comments written in Tanglish, matching your established project style

---

## Project Structure

```
phishing_qr_detector/
├── app.py                    # Flask app & routes
├── detection.py               # ML + heuristic scoring engine
├── qr_scanner.py               # QR decoding logic
├── db.py                       # MySQL connection & history storage
├── model/
│   ├── feature_extractor.py    # URL feature engineering (shared)
│   ├── train_model.py          # Dataset generation + model training
│   ├── phishing_model.pkl      # Trained RandomForest model
│   └── scaler.pkl               # Fitted StandardScaler
├── database/
│   └── db_setup.sql             # MySQL schema
├── templates/                   # Jinja2 HTML templates (dark theme)
├── static/css/style.css         # Cybersecurity dashboard styling
├── uploads/                     # Temp folder for uploaded QR images
├── run_windows.bat               # One-click launcher (Windows)
├── run_mac_linux.sh              # One-click launcher (Mac/Linux)
└── requirements.txt
```

---

## Quick Start (One-Click)

- **Windows**: double-click `run_windows.bat`
- **Mac/Linux**: double-click `run_mac_linux.sh` (or run `./run_mac_linux.sh` in terminal)

This script automatically installs dependencies (first run only), starts the Flask server, and opens `http://127.0.0.1:5000` in your browser after a couple of seconds. To stop the server, press `Ctrl+C` in the terminal window.

> Note: `libzbar0` (the QR decoding library) still needs to be installed manually the first time (see step 1 below) — the launcher script can't install this automatically since it's a system-level package.

## Setup Instructions (Manual / Detailed)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```
Also install the system QR-decoding library:
```bash
# Ubuntu/Debian
sudo apt-get install libzbar0

# Windows: pyzbar wheel already bundles the DLL, no extra step needed
# macOS
brew install zbar
```

### 2. Set up MySQL (optional but recommended)
```bash
mysql -u root -p < database/db_setup.sql
```
Then open `db.py` and set your MySQL password in `DB_CONFIG`.

> If you skip this step, the app still runs fine — scan history just falls back to in-memory storage for that session.

### 3. (Optional) Retrain the ML model
A trained model is already included (`model/phishing_model.pkl`). To regenerate it:
```bash
cd model
python3 train_model.py
```

### 4. Run the app
```bash
python3 app.py
```
Open **http://127.0.0.1:5000** in your browser.

---

## How the Detection Works

1. **Feature extraction** (`model/feature_extractor.py`) turns any URL into 20 numeric signals — IP usage, hyphen count, suspicious keywords, brand impersonation, TLD reputation, etc. Fully offline — no live network calls, so it's fast and works in any environment.
2. **ML scoring** — the RandomForestClassifier (trained on a labeled synthetic dataset built from realistic phishing/legitimate URL patterns) outputs a phishing probability.
3. **Heuristic scoring** — an independent rule engine assigns risk points to specific red flags, catching patterns the ML model might not generalize to.
4. **Fusion** — `final_score = ML_score × 0.65 + heuristic_score × 0.35`, thresholds: `<30` Safe, `30–60` Suspicious, `≥60` Phishing.
5. **QR pipeline** — QR image → decode payload → if it's a URL, run through the same pipeline above; if it's a high-risk scheme (`tel:`, `upi:`, etc.) or plain text, apply separate lightweight rules.

## Note on the Dataset

Since this is an offline academic project, the model is trained on a **programmatically generated synthetic dataset** (4,000 samples) built from realistic phishing and legitimate URL patterns — not a scraped live dataset. This is a standard, defensible approach for academic ML security projects and can be swapped for a real dataset (e.g. PhishTank, UCI Phishing Websites Dataset) by replacing `model/train_model.py`'s data-generation step with a CSV loader — the feature pipeline stays identical.

## For Your Presentation / Report

- Emphasize the **hybrid ML + heuristic** design — this is exactly what the review panel wants for "Threat Intelligence" style projects.
- Mention the **QR "quishing" angle** — it's a fast-growing real-world attack vector (fake parking tickets, fake payment QR codes) and makes the project feel current.
- The `/api/scan-url` endpoint shows the system isn't just a UI demo — it's usable as a backend service too.
