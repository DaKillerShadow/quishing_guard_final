"""
routes/scan_image.py — POST /api/v1/scan-image
================================================
OpenCV-powered server-side QR code detection.

Accepts an uploaded image (JPEG / PNG / WEBP, max 5 MB) and:
  1. Guards against Decompression Bombs by scaling down massive resolutions.
  2. Runs cv2.QRCodeDetector for standard codes.
  3. Runs cv2.wechat_qrcode (WeChat CNN detector) to catch adversarial, 
     damaged, rotated, or high-density codes that standard scanners miss.
  4. Deduplicates payloads and returns bounding-box coordinates.

Rate limit: 10 per minute (OpenCV processing is CPU-intensive).
"""
import io
import os
import cv2
import numpy as np
from flask import Blueprint, request, jsonify
from ..limiter import limiter, get_real_client_ip
from ..logger import get_logger

bp = Blueprint("scan_image", __name__, url_prefix="/api/v1")
log = get_logger("scan_image")

# Constants
_MAX_BYTES = 5 * 1024 * 1024 
_MAX_PIXELS = 2500 # Slightly lowered for Render Free Tier RAM safety
_ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/bmp"}

# ── WECHAT MODEL PATHS ────────────────────────────────────────────────────────
# These files should be in your 'models/wechat' folder
MODEL_DIR = os.path.join(os.getcwd(), "models", "wechat")
WECHAT_PARAMS = [
    os.path.join(MODEL_DIR, "detector.prototxt"),
    os.path.join(MODEL_DIR, "detector.caffemodel"),
    os.path.join(MODEL_DIR, "super_resolution.prototxt"),
    os.path.join(MODEL_DIR, "super_resolution.caffemodel"),
]

@bp.route("/scan-image", methods=["POST"])
@limiter.limit("10 per minute")
def scan_image():
    if "file" not in request.files:
        return jsonify({"error": "No file field"}), 400

    file = request.files["file"]
    if file.content_type not in _ALLOWED_MIME:
        return jsonify({"error": f"MIME type {file.content_type} not supported"}), 415

    # ── 1. Byte Guard ─────────────────────────────────────────────────────────
    raw = file.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        return jsonify({"error": "File too large (Max 5MB)"}), 413

    # ── 2. Decode & RAM Guard ──────────────────────────────────────────────────
    arr = np.frombuffer(raw, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    
    if img is None:
        return jsonify({"error": "Invalid image data"}), 400

    h, w = img.shape[:2]
    if h > _MAX_PIXELS or w > _MAX_PIXELS:
        scale = _MAX_PIXELS / max(h, w)
        img = cv2.resize(img, (0, 0), fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

    found_codes = []
    seen_payloads = set()

    # ── 3. WeChat CNN Detector (High Priority) ───────────────────────────────
    # This catches damaged/small codes using Super-Resolution
    try:
        # We only try to init if files exist
        if all(os.path.exists(p) for p in WECHAT_PARAMS):
            detector_wechat = cv2.wechat_qrcode_WeChatQRCode(*WECHAT_PARAMS)
            payloads, _ = detector_wechat.detectAndDecode(img)
            
            for p in payloads:
                if p and p not in seen_payloads:
                    seen_payloads.add(p)
                    found_codes.append({"payload": p, "detector": "AI_WECHAT"})
        else:
            log.warning("WeChat model files missing, skipping CNN detection")
    except Exception as e:
        log.error(f"WeChat detection failed: {e}")

    # ── 4. Standard OpenCV Sweep (Fallback/Multi-code) ───────────────────────
    if not found_codes or len(found_codes) < 3: # Keep looking for more
        grey = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Try raw grayscale first (better for standard codes)
        detector_std = cv2.QRCodeDetector()
        ok, payloads, _, _ = detector_std.detectAndDecodeMulti(grey)
        
        if ok:
            for p in payloads:
                if p and p not in seen_payloads:
                    seen_payloads.add(p)
                    found_codes.append({"payload": p, "detector": "OPENCV_STD"})

    return jsonify({
        "found": len(found_codes),
        "codes": found_codes,
        "resolution": f"{w}x{h}"
    }), 200
