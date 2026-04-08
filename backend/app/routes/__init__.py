# routes/__init__.py

from .auth import bp as auth_bp
from .analyse import bp as analyse_bp
from .report import bp as report_bp
# ── NEW: Register the OpenCV Image Scanner ──
from .scan_image import bp as scan_image_bp

# DO NOT import scorer here! 
# (Keeps the route layer decoupled from the heavy heuristic logic)
