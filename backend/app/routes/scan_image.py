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
from __future__ import annotations
import io
from flask import Blueprint, request, jsonify

# BUG FIX: Imported proxy-aware IP helper
from ..limiter import limiter, get_real_client_ip
from ..logger  import get_logger

bp  = Blueprint("scan_image", __name__, url_prefix="/api/v1")
log = get_logger("scan_image")

_MAX_BYTES    = 5 * 1024 * 1024   # 5 MB limit on disk
_MAX_PIXELS   = 3000              # Max dimension to prevent RAM exhaustion
_ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/bmp"}


@bp.route("/scan-image", methods=["POST"])
@limiter.limit("10 per minute")
def scan_image():
    # ── 1. Validate upload ─────────────────────────────────────────────
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    file = request.files["file"]
    if file.content_type not in _ALLOWED_MIME:
        return jsonify({
            "error": f"Unsupported content type '{file.content_type}'. "
                     f"Use JPEG, PNG, WEBP, or BMP."
        }), 415

    raw = file.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        return jsonify({"error": "Image exceeds 5 MB limit"}), 413

    # ── 2. Decode with OpenCV ──────────────────────────────────────────
    try:
        import cv2
        import numpy as np
    except ImportError:
        log.error("OpenCV not installed — pip install opencv-python-headless")
        return jsonify({"error": "Image processing unavailable on this server"}), 503

    # Decode bytes → numpy array
    arr = np.frombuffer(raw, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({"error": "Could not decode image — file may be corrupted"}), 400

    # ── 3. Decompression Bomb Guard (Pixel Limiter) ────────────────────
    h, w = img.shape[:2]
    if h > _MAX_PIXELS or w > _MAX_PIXELS:
        scale = _MAX_PIXELS / max(h, w)
        img = cv2.resize(img, (0, 0), fx=scale, fy=scale, interpolation=cv2.INTER_AREA)

    # Convert to grayscale and apply adaptive thresholding
    grey = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.adaptiveThreshold(
        grey, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )

    found_codes: list[dict] = []
    seen_payloads = set()

    # ── 4a. WeChat QRCode detector (CNN Super-Resolution) ──────────────
    # We run the best detector FIRST to catch adversarial codes.
    try:
        wechat = cv2.wechat_qrcode_WeChatQRCode()
        texts, bboxes_w = wechat.detectAndDecode(img)
        for payload, bbox in zip(texts, bboxes_w):
            if payload and payload not in seen_payloads:
                seen_payloads.add(payload)
                found_codes.append({
                    "payload":  payload,
                    "detector": "wechat_qrcode",
                    "bbox":     bbox.tolist() if bbox is not None else None,
                })
    except AttributeError:
        pass   # contrib module not installed — graceful fallback

    # ── 4b. Standard OpenCV QRCodeDetector (Sweep for remaining) ───────
    # We still run this to catch anything WeChat somehow missed (Trojan Guard)
    detector = cv2.QRCodeDetector()
    ok, decoded_list, bboxes, _ = detector.detectAndDecodeMulti(thresh)
    
    if ok and decoded_list:
        for payload, bbox in zip(decoded_list, bboxes):
            if payload and payload not in seen_payloads:
                seen_payloads.add(payload)
                found_codes.append({
                    "payload":  payload,
                    "detector": "QRCodeDetector",
                    "bbox":     bbox.tolist() if bbox is not None else None,
                })

    # ── 4c. Retry on raw grayscale if nothing was found ────────────────
    if not found_codes:
        ok2, decoded2, bboxes2, _ = detector.detectAndDecodeMulti(grey)
        if ok2 and decoded2:
            for payload, bbox in zip(decoded2, bboxes2):
                if payload and payload not in seen_payloads:
                    seen_payloads.add(payload)
                    found_codes.append({
                        "payload":  payload,
                        "detector": "QRCodeDetector_grey",
                        "bbox":     bbox.tolist() if bbox is not None else None,
                    })

    client_ip = get_real_client_ip()
    log.info("Image scan completed",
             extra={"found": len(found_codes), "ip": client_ip})

    return jsonify({"found": len(found_codes), "codes": found_codes}), 200
