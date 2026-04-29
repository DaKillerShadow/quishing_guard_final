"""
scan_image.py — POST /api/v1/scan-image (v2.7.3)
=================================================
Decodes QR codes from a multipart image upload, then runs the full analysis
pipeline on each decoded URL.

Fixes applied (Batch 2):
  RTE-03  Reputation check added — blocklisted/allowlisted flags now passed
          to analyse_url() for every decoded payload. Previously defaulted to
          False, meaning blocklisted domains scanned via image got heuristic
          scores instead of the mandatory risk_score=100.
  RTE-04  Audit log (ScanLog) written for each analysed QR code — eliminates
          the blind spot where image-endpoint scans were invisible to the admin
          dashboard and incident investigation.
  RTE-11  get_real_client_ip() used instead of request.remote_addr for logging
          and audit records — behind Render's load balancer, remote_addr is
          always the proxy IP, not the real client.

Pre-existing fixes retained:
  F-02  Double resolve eliminated.
  M-1   Removed duplicate analyse_url import.
  M-2   detector_label computed once before the loop.
  H-1   Payload validated before analysis.
  M-5   url_prefix removed from Blueprint constructor.
"""

from __future__ import annotations

import io
import cv2
import numpy as np
from flask import Blueprint, request, jsonify

from ..limiter           import limiter, get_real_client_ip  # AUDIT FIX [RTE-11]
from ..logger            import get_logger
from ..engine.scorer     import analyse_url, trace_redirects
from ..engine.reputation import is_allowlisted, is_blocklisted  # AUDIT FIX [RTE-03]
from ..utils.validators  import validate_url_payload
from ..models.db_models  import ScanLog, generate_scan_id        # AUDIT FIX [RTE-04]
from ..database          import db                               # AUDIT FIX [RTE-04]

bp  = Blueprint("scan_image", __name__)
log = get_logger("scan_image")

_MAX_BYTES = 5 * 1024 * 1024  # 5 MB


@bp.route("/scan-image", methods=["POST"])
@limiter.limit("10 per minute")
def scan_image():
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    file      = request.files["file"]
    raw_bytes = file.read(_MAX_BYTES + 1)

    if len(raw_bytes) > _MAX_BYTES:
        return jsonify({"error": "Image exceeds 5 MB limit"}), 413

    # ── 1. Magic-byte validation ──────────────────────────────────────────────
    _MAGIC = {
        b"\xff\xd8\xff": "jpeg",
        b"\x89PNG":      "png",
        b"RIFF":         "webp",
        b"BM":           "bmp",
    }
    detected_format = next(
        (t for sig, t in _MAGIC.items() if raw_bytes[: len(sig)] == sig), None
    )
    if not detected_format:
        return jsonify({
            "error": "File type not recognised — submit JPEG, PNG, WEBP, or BMP"
        }), 415

    # ── 2. Decode bytes to OpenCV image ───────────────────────────────────────
    arr = np.frombuffer(raw_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({"error": "Could not decode image — file may be corrupted"}), 400

    grey   = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    thresh = cv2.adaptiveThreshold(
        grey, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 11, 2,
    )

    found_payloads:   list[dict] = []
    skipped_payloads: list[dict] = []

    # ── 3a. Detection phase (OpenCV + WeChat fallback) ────────────────────────
    detector = cv2.QRCodeDetector()
    ok, decoded_list, bboxes, _ = detector.detectAndDecodeMulti(thresh)

    used_wechat = False
    if not ok or not decoded_list:
        try:
            wechat = cv2.wechat_qrcode_WeChatQRCode()
            decoded_list, bboxes = wechat.detectAndDecode(img)
            if decoded_list:
                used_wechat = True
        except AttributeError:
            pass  # contrib module not installed

    # ── 3b. Analysis phase ────────────────────────────────────────────────────
    detector_label = "wechat_qrcode" if used_wechat else "standard"
    # AUDIT FIX [RTE-11]: Use proxy-aware IP helper for all logging/audit writes.
    client_ip = get_real_client_ip()

    if decoded_list:
        for payload, bbox in zip(decoded_list, bboxes):
            if payload and payload.strip():
                bbox_data = bbox.tolist() if bbox is not None else None

                # H-1: Validate payload before passing to the scoring engine.
                is_valid, reason = validate_url_payload(payload)
                if not is_valid:
                    skipped_payloads.append({
                        "payload":     payload,
                        "skip_reason": reason,
                        "detector":    detector_label,
                        "bbox":        bbox_data,
                    })
                    continue

                # AUDIT FIX [RTE-03]: Perform reputation check per payload.
                # Without this, blocklisted domains scanned via image bypassed
                # the mandatory risk_score=100 override entirely.
                allowlisted = is_allowlisted(payload)
                blocklisted = is_blocklisted(payload)

                # F-02: Resolve once, pass trace_data into analyse_url.
                trace           = trace_redirects(payload)
                analysis_result = analyse_url(
                    payload,
                    blocklisted=blocklisted,   # RTE-03
                    allowlisted=allowlisted,   # RTE-03
                    trace_data=trace,
                )

                # AUDIT FIX [RTE-04]: Write audit log for every analysed payload.
                # Previously image-endpoint scans were completely invisible to
                # the admin dashboard and post-incident investigation queries.
                scan_id = generate_scan_id()
                try:
                    new_log = ScanLog(
                        id           = scan_id,
                        raw_url      = payload,
                        resolved_url = analysis_result.get("resolved_url", payload),
                        risk_score   = analysis_result["risk_score"],
                        risk_label   = analysis_result["risk_label"],
                        top_threat   = analysis_result.get("top_threat", ""),
                        hop_count    = analysis_result.get("hop_count", 0),
                        client_ip    = client_ip,  # RTE-11
                    )
                    db.session.add(new_log)
                    db.session.commit()
                except Exception as db_err:
                    db.session.rollback()
                    log.error("Audit log failed for image scan %s: %s", scan_id, db_err)

                found_payloads.append({
                    "payload":  payload,
                    "analysis": analysis_result,
                    "detector": detector_label,
                    "bbox":     bbox_data,
                })

    log.info(
        "Image scan completed",
        extra={
            "found":   len(found_payloads),
            "skipped": len(skipped_payloads),
            "ip":      client_ip,           # RTE-11
        },
    )

    response: dict = {
        "found": len(found_payloads),
        "codes": found_payloads,
    }
    if skipped_payloads:
        response["skipped"] = skipped_payloads

    return jsonify(response), 200
