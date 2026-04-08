# backend/app/routes/scan_image.py
from __future__ import annotations
from ..engine.scorer import analyse_url  # Keep the 's' here
import io
import cv2
import numpy as np
from flask import Blueprint, request, jsonify

from ..limiter import limiter
from ..logger import get_logger
from ..engine.resolver import resolve # ✅ Added: Use the 11-pillar resolver
from ..engine.scorer import analyse_url # ✅ Added: The 11-pillar engine

bp = Blueprint("scan_image", __name__, url_prefix="/api/v1")
log = get_logger("scan_image")

_MAX_BYTES = 5 * 1024 * 1024  # 5 MB

@bp.route("/scan-image", methods=["POST"])
@limiter.limit("10 per minute")
def scan_image():
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    file = request.files["file"]
    
    # ✅ FIXED: Read once and reuse. In the previous code, the second 
    # file.read() would return an empty byte string because the pointer was at EOF.
    raw_bytes = file.read(_MAX_BYTES + 1)

    if len(raw_bytes) > _MAX_BYTES:
        return jsonify({"error": "Image exceeds 5 MB limit"}), 413

    # 1. Magic-byte validation
    _MAGIC = {
        b'\xff\xd8\xff': 'jpeg',
        b'\x89PNG':      'png',
        b'RIFF':         'webp',
        b'BM':           'bmp',
    }
    detected_format = next((t for sig, t in _MAGIC.items() if raw_bytes[:len(sig)] == sig), None)
    if not detected_format:
        return jsonify({"error": "File type not recognised — submit JPEG, PNG, WEBP, or BMP"}), 415

    # 2. Decode bytes to OpenCV Image
    arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({"error": "Could not decode image — file may be corrupted"}), 400

    # Pre-processing
    grey = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.adaptiveThreshold(
        grey, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 11, 2,
    )

    found_payloads: list[dict] = []

    # ── 3a. Detection Phase (OpenCV + WeChat Fallback) ────────────────
    detector = cv2.QRCodeDetector()
    
    # Try Standard Detector (Thresholded)
    ok, decoded_list, bboxes, _ = detector.detectAndDecodeMulti(thresh)
    
    # Fallback: WeChat Detector (Handles high-density / damaged codes)
    if not ok or not decoded_list:
        try:
            wechat = cv2.wechat_qrcode_WeChatQRCode()
            decoded_list, bboxes = wechat.detectAndDecode(img)
        except AttributeError:
            pass # contrib module not installed

    # ── 3b. Analysis Phase (The Merge) ───────────────────────────────
    # We don't just return the URL anymore; we return the full security audit
    if decoded_list:
        for payload, bbox in zip(decoded_list, bboxes):
            if payload and payload.strip():
                # 🔥 THE MERGE: Run the 11-pillar analysis on the detected code
                analysis_result = analyse_url(payload)
                
                found_payloads.append({
                    "payload": payload,
                    "analysis": analysis_result, # Full risk score, label, and checks
                    "detector": "wechat_qrcode" if "wechat" in locals() else "standard",
                    "bbox": bbox.tolist() if bbox is not None else None,
                })

    log.info("Image scan completed", extra={
        "found": len(found_payloads), 
        "ip": request.remote_addr
    })

    return jsonify({
        "found": len(found_payloads), 
        "codes": found_payloads
    }), 200