"""
qr_scanner.py
--------------
This module takes a QR code image and decodes the data embedded in it
(usually a URL). We use pyzbar + OpenCV for fast, reliable QR decoding.

Malicious QR codes are commonly used in "quishing" (QR + phishing)
attacks - an attacker pastes a fake QR sticker over a real one (e.g. on
a parking meter or payment poster), and scanning it redirects the
victim to a phishing site. This module extracts that QR payload and
passes it on to the phishing detection pipeline.
"""

import cv2

try:
    from pyzbar.pyzbar import decode as zbar_decode
except (ImportError, OSError):
    zbar_decode = None

# Schemes other than a plain URL (payment app deep links, WiFi config,
# tel:, sms:, etc.) are commonly abused in QR-based attacks - these are
# flagged as high-risk schemes.
HIGH_RISK_SCHEMES = ["tel:", "sms:", "smsto:", "market:", "intent:", "upi:"]


def decode_qr_image(image_path: str) -> dict:
    """Takes a QR image file path, decodes it, and returns a result
    dict: {success, raw_data, qr_type, error}"""

    image = cv2.imread(image_path)
    if image is None:
        return {"success": False, "raw_data": None, "qr_type": None,
                "error": "Could not open the image file. Please check the format (PNG/JPG)."}

     # Convert to grayscale for OpenCV - improves decoding accuracy
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    decoded_objects = zbar_decode(gray) if zbar_decode else []

    if not decoded_objects and zbar_decode:
        # fallback: try the original color image if grayscale decode fails
        decoded_objects = zbar_decode(image)

    if decoded_objects:
        raw_data = decoded_objects[0].data.decode("utf-8", errors="ignore")
    else:
        raw_data, _, _ = cv2.QRCodeDetector().detectAndDecode(image)

    if not raw_data:
        return {"success": False, "raw_data": None, "qr_type": None,
                "error": "No QR code could be detected. Try a clearer, straighter image."}

    qr_type = classify_payload(raw_data)

    return {"success": True, "raw_data": raw_data, "qr_type": qr_type, "error": None}


def classify_payload(raw_data: str) -> str:
    """Classifies the type of QR payload - URL, high-risk scheme,
    or plain text."""
    lowered = raw_data.strip().lower()

    if lowered.startswith(("http://", "https://")):
        return "url"

    for scheme in HIGH_RISK_SCHEMES:
        if lowered.startswith(scheme):
            return "high_risk_scheme"

    if lowered.startswith("www."):
        return "url"

    return "plain_text"
