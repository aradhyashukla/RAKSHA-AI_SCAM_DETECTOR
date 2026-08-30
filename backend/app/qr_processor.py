"""
qr_processor.py
----------------
Decodes QR codes from uploaded images and, if the QR contains a UPI
payment deep link, parses out its fields for scoring.

We use OpenCV's built-in QRCodeDetector instead of pyzbar deliberately:
pyzbar depends on the system 'zbar' library, which is a common source of
install pain on Windows (DLL not found errors). OpenCV is pure pip-install
and already covers plain single QR decoding, which is all we need here.

A UPI QR typically encodes a string like:
    upi://pay?pa=merchant@okhdfcbank&pn=Some%20Shop&am=499&cu=INR&tn=Payment

Fields:
    pa = payee VPA (the UPI ID money will go to)   <- most important for scam checks
    pn = payee name (as displayed to the user)
    am = amount
    cu = currency
    tn = transaction note
"""

import cv2
import numpy as np
from urllib.parse import urlparse, parse_qs
from typing import Optional


def decode_qr_from_bytes(image_bytes: bytes) -> Optional[str]:
    """
    Decodes a QR code from raw image bytes. Returns the decoded string,
    or None if no QR code was found in the image.
    """
    np_arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if img is None:
        return None

    detector = cv2.QRCodeDetector()
    data, points, _ = detector.detectAndDecode(img)
    if data:
        return data

    # Fallback 1: some QR images are low-contrast or have colored
    # backgrounds. Try again on a grayscale + adaptive-threshold version.
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 35, 11
    )
    data, points, _ = detector.detectAndDecode(thresh)
    if data:
        return data

    # Fallback 2: OpenCV's detector needs a white "quiet zone" margin
    # around the QR pattern. Tightly-cropped uploads (e.g. a screenshot
    # cropped right to the code's edge) can fail decode purely because
    # that margin is missing. Pad with white and retry.
    padded = cv2.copyMakeBorder(gray, 25, 25, 25, 25, cv2.BORDER_CONSTANT, value=255)
    data, points, _ = detector.detectAndDecode(padded)
    return data if data else None


def parse_upi_link(qr_text: str) -> Optional[dict]:
    """
    If qr_text is a UPI payment deep link (upi://pay?...), parse out its
    fields. Returns None if it's not a UPI link (e.g. it's a plain URL,
    or garbage/unrecognized text — the caller should handle those as
    plain text through the normal /analyze pipeline instead).
    """
    if not qr_text.lower().startswith("upi://"):
        return None

    parsed = urlparse(qr_text)
    params = parse_qs(parsed.query)

    return {
        "payee_vpa": params.get("pa", [None])[0],
        "payee_name": params.get("pn", [None])[0],
        "amount": params.get("am", [None])[0],
        "currency": params.get("cu", ["INR"])[0],
        "note": params.get("tn", [None])[0],
    }
