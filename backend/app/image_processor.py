"""
image_processor.py
-------------------
Extracts text from uploaded screenshots (SMS/WhatsApp/email screenshots)
using Tesseract OCR.

Raw phone-camera-of-a-screen or low-res screenshots often OCR badly with
zero preprocessing (this was flagged as a hard part on the whiteboard).
We apply a few cheap, high-value preprocessing steps before handing the
image to Tesseract:
    1. Convert to grayscale (color is noise for OCR)
    2. Upscale small images (Tesseract struggles below ~300dpi-equivalent)
    3. Adaptive threshold to binarize (helps with chat-bubble backgrounds)

This is NOT a full document-scanning pipeline — it's tuned specifically
for "phone screenshot of a chat app" input, which is our actual use case.
"""

import os
import cv2
import numpy as np
import pytesseract

# In the Docker deployment (see Dockerfile), Tesseract-OCR is installed via
# apt and is already correctly on PATH, so no override is needed there —
# hardcoding a Windows path here would break the container.
#
# On Windows, pytesseract does NOT reliably find tesseract.exe on PATH even
# after installing it, so local development needs an explicit override.
# Set a TESSERACT_CMD environment variable for local Windows dev instead of
# editing this file, e.g. in PowerShell:
#   $env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
# (set it in every new terminal, or add it to your system environment
# variables so it's always there).
_tesseract_cmd = os.environ.get("TESSERACT_CMD")
if _tesseract_cmd:
    pytesseract.pytesseract.tesseract_cmd = _tesseract_cmd


def preprocess_for_ocr(image_bytes: bytes) -> np.ndarray:
    np_arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not decode image — unsupported format or corrupted file")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Upscale if the image is small — screenshots forwarded through
    # WhatsApp are often compressed down and lose OCR-readable detail.
    height, width = gray.shape
    if width < 1000:
        scale = 1000 / width
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    # Slight blur to reduce JPEG compression noise before thresholding
    denoised = cv2.medianBlur(gray, 3)

    thresh = cv2.adaptiveThreshold(
        denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 15
    )
    return thresh


def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Runs OCR on an uploaded screenshot and returns extracted plain text.
    Tries preprocessed image first; if that yields suspiciously little
    text, falls back to OCR on the raw image (preprocessing sometimes
    hurts on already-clean screenshots).
    """
    try:
        processed = preprocess_for_ocr(image_bytes)
        text = pytesseract.image_to_string(processed, lang="eng").strip()

        if len(text) < 10:
            np_arr = np.frombuffer(image_bytes, np.uint8)
            raw_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            fallback_text = pytesseract.image_to_string(raw_img, lang="eng").strip()
            if len(fallback_text) > len(text):
                text = fallback_text
    except pytesseract.pytesseract.TesseractNotFoundError:
        # Without this, an unhandled TesseractNotFoundError propagates as a
        # raw 500 that FastAPI/CORS doesn't attach headers to properly,
        # which the browser reports as "failed to fetch" — i.e. it looks
        # exactly like "can't reach the backend" even though the server is
        # up. Converting it to a clean ValueError lets main.py's existing
        # `except ValueError` turn this into a proper 400 with a real,
        # actionable message instead.
        raise ValueError(
            "Tesseract OCR is not installed or not on PATH. Install it from "
            "https://github.com/UB-Mannheim/tesseract/wiki and, on Windows, "
            "set pytesseract.pytesseract.tesseract_cmd to its install path "
            "in image_processor.py."
        )

    return text
