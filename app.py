"""
app.py
-------
Main Flask application. Routes:
  /              -> URL scan form + result
  /qr-scan       -> QR code image upload + result
  /history       -> Past scans list (MySQL / fallback)
  /api/scan-url  -> JSON API (optional programmatic use)

To run:
  python3 app.py
Then open http://127.0.0.1:5000 in your browser.
"""

import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename

from detection import analyze_url
from qr_scanner import decode_qr_image
import db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "webp"}

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"  # for demo use only
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB max upload

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
db.init_db_if_needed()  # creates the table if DB is reachable, otherwise skips silently


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Please enter a URL!", "warning")
            return redirect(url_for("index"))

        result = analyze_url(url)
        db.save_scan("url", url, result["verdict"], result["risk_score"])

    return render_template("index.html", result=result)


@app.route("/qr-scan", methods=["GET", "POST"])
def qr_scan():
    result = None
    qr_error = None
    decoded_payload = None

    if request.method == "POST":
        if "qr_image" not in request.files:
            flash("Please select an image file!", "warning")
            return redirect(url_for("qr_scan"))

        file = request.files["qr_image"]
        if file.filename == "":
            flash("Please select an image file!", "warning")
            return redirect(url_for("qr_scan"))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            qr_result = decode_qr_image(filepath)

            if not qr_result["success"]:
                qr_error = qr_result["error"]
            else:
                decoded_payload = qr_result["raw_data"]

                if qr_result["qr_type"] == "high_risk_scheme":
                    # Not a URL, but a high-risk scheme (tel:, upi:, intent:,
                    # etc.) - the ML model was trained on URL features, so
                    # we flag these directly as suspicious instead.
                    result = {
                        "url": decoded_payload,
                        "verdict": "Suspicious",
                        "risk_score": 55.0,
                        "ml_score": 0,
                        "heuristic_score": 55.0,
                        "reasons": [
                            f"QR contains a high-risk scheme instead of a URL "
                            f"({decoded_payload.split(':')[0]}:) - verify the source "
                            f"before proceeding."
                        ],
                    }
                elif qr_result["qr_type"] == "url":
                    result = analyze_url(decoded_payload)
                else:
                    result = {
                        "url": decoded_payload,
                        "verdict": "Safe",
                        "risk_score": 5.0,
                        "ml_score": 0,
                        "heuristic_score": 5.0,
                        "reasons": ["QR contains plain text data, not a URL - low risk."],
                    }

                db.save_scan("qr", decoded_payload, result["verdict"], result["risk_score"])

            os.remove(filepath)  # temp file cleanup
        else:
            qr_error = "Invalid file type. Only PNG/JPG/JPEG/BMP/WEBP are allowed."

    return render_template("qr_scan.html", result=result, qr_error=qr_error, decoded_payload=decoded_payload)


@app.route("/history")
def history():
    records = db.get_history(limit=100)
    return render_template("history.html", records=records)


@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    """Simple JSON API for programmatic access (test with Postman/curl)."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url field required"}), 400

    result = analyze_url(url)
    db.save_scan("url", url, result["verdict"], result["risk_score"])
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
