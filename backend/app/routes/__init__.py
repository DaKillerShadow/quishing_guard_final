# This file should only export your Blueprints
from .auth       import bp as auth_bp
from .analyse    import bp as analyse_bp
from .report     import bp as report_bp
from .health     import bp as health_bp
from .admin      import bp as admin_bp
from .scan_image import bp as scan_image_bp
# DO NOT import scorer here!
