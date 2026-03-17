"""
routes/scan_image.py — POST /api/v1/scan-image
================================================
OpenCV-powered server-side QR code detection.

Accepts an uploaded image (JPEG / PNG / WEBP, max 5 MB) and:
  1. Converts to grayscale + applies adaptive thresholding
  2. Runs cv2.QRCodeDetector for standard codes
  3. Falls back to cv2.wechat_qrcode if available (WeChat detector —
     handles damaged, rotated, split, and high-density codes)
  4. Returns all decoded payloads with bounding-box coordinates

Why server-side matters for the report:
  - The Flutter mobile_scanner plugin uses AVFoundation (iOS) and
    MLKit (Android), which are designed for live camera feeds.
    They can miss adversarial compositions: split QR codes, codes
    embedded inside other images, and very high-density (Version 40)
    codes with damage.
  - OpenCV's wechat_qrcode super-resolution model handles these cases.
  - Moving decoding to the backend means the same detection quality
    regardless of phone model or OS version.

Rate limit: 10 per minute (OpenCV processing is CPU-intensive).

Request:
  POST /api/v1/scan-image
  Content-Type: multipart/form-data
  file=@qrcode.jpg

Success 200:
  {
    "found": 2,
    "codes": [
      {
        "payload":  "https://example.com",
        "detector": "wechat_qrcode",
        "bbox":     [[x1,y1],[x2,y2],[x3,y3],[x4,y4]]
      },
      ...
    ]
  }

No QR found 200:
  { "found": 0, "codes": [] }

Error 400 / 415 / 413:
  { "error": "..." }
"""
from __future__ import annotations
import io
from flask import Blueprint, request, jsonify

from ..limiter import limiter
from ..logger  import get_logger

bp  = Blueprint("scan_image", __name__, url_prefix="/api/v1")
log = get_logger("scan_image")

_MAX_BYTES    = 5 * 1024 * 1024   # 5 MB
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

    # Decode bytes → numpy array → greyscale
    arr  = np.frombuffer(raw, dtype=np.uint8)
    img  = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({"error": "Could not decode image — file may be corrupted"}), 400

    grey = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Adaptive threshold improves detection on low-contrast / shadowed codes
    thresh = cv2.adaptiveThreshold(
        grey, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 11, 2,
    )

    found_codes: list[dict] = []

    # ── 2a. Standard OpenCV QRCodeDetector ────────────────────────────
    detector = cv2.QRCodeDetector()

    # detectAndDecodeMulti handles images containing more than one QR code
    ok, decoded_list, bboxes, _ = detector.detectAndDecodeMulti(thresh)
    if ok and decoded_list:
        for payload, bbox in zip(decoded_list, bboxes):
            if payload:
                found_codes.append({
                    "payload":  payload,
                    "detector": "QRCodeDetector",
                    "bbox":     bbox.tolist() if bbox is not None else None,
                })

    # ── 2b. WeChat QRCode detector (super-resolution, better recall) ──
    #   Available in opencv-contrib-python. Falls back gracefully if absent.
    if not found_codes:
        try:
            wechat = cv2.wechat_qrcode_WeChatQRCode()
            texts, bboxes_w = wechat.detectAndDecode(img)
            for payload, bbox in zip(texts, bboxes_w):
                if payload:
                    found_codes.append({
                        "payload":  payload,
                        "detector": "wechat_qrcode",
                        "bbox":     bbox.tolist() if bbox is not None else None,
                    })
        except AttributeError:
            pass   # contrib module not installed — not an error

    # ── 2c. Retry on original image if thresholded version found nothing ─
    if not found_codes:
        ok2, decoded2, bboxes2, _ = detector.detectAndDecodeMulti(grey)
        if ok2 and decoded2:
            for payload, bbox in zip(decoded2, bboxes2):
                if payload:
                    found_codes.append({
                        "payload":  payload,
                        "detector": "QRCodeDetector_grey",
                        "bbox":     bbox.tolist() if bbox is not None else None,
                    })

    log.info("Image scan completed",
             extra={"found": len(found_codes), "ip": request.remote_addr})

    return jsonify({"found": len(found_codes), "codes": found_codes}), 200
