/**
 * scanner.js — QR Code Scanner
 *
 * Wraps the browser Camera API (MediaDevices.getUserMedia) + jsQR library
 * to provide real-time, frame-by-frame QR code decoding.
 *
 * Also supports:
 *   - Gallery import (File API → Canvas → jsQR decode)
 *   - Torch toggle (via MediaTrackCapabilities)
 *   - Debouncing (2.5 s cooldown to prevent duplicate scans)
 */

export class QRScanner {
  constructor({ videoEl, canvasEl, onDetected, onStatusChange, onError }) {
    this._video        = videoEl;
    this._canvas       = canvasEl;
    this._ctx          = canvasEl.getContext('2d', { willReadFrequently: true });
    this._onDetected   = onDetected;
    this._onStatus     = onStatusChange;
    this._onError      = onError;

    this._stream       = null;
    this._track        = null;
    this._torchOn      = false;
    this._torchSupp    = false;
    this._raf          = null;
    this._active       = false;
    this._lastCode     = null;
    this._lastAt       = 0;
    this._DEBOUNCE_MS  = 2500;
  }

  // ── Lifecycle ───────────────────────────────────────────────────────────────

  async start() {
    this._onStatus?.('Requesting camera permission…');
    try {
      this._stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' }, width: { ideal: 1920 } },
        audio: false,
      });
      this._video.srcObject = this._stream;
      await this._video.play();

      this._track    = this._stream.getVideoTracks()[0] || null;
      this._torchSupp = !!this._track?.getCapabilities?.()?.torch;

      this._active = true;
      this._onStatus?.('Point at a QR code');
      this._scanLoop();
    } catch (err) {
      this._active = false;
      const msgs = {
        NotAllowedError:  'Camera permission denied. Use Gallery or Demo mode.',
        NotFoundError:    'No camera found. Use Gallery or Demo mode.',
        OverconstrainedError: 'Camera constraints not met. Retrying…',
      };
      const msg = msgs[err.name] || `Camera error: ${err.message}`;
      this._onStatus?.(msg);
      this._onError?.(msg);
    }
  }

  pause() {
    this._active = false;
    if (this._raf) { cancelAnimationFrame(this._raf); this._raf = null; }
    this._lastCode = null;
    this._onStatus?.('Scanner paused');
  }

  resume() {
    if (!this._stream) { this.start(); return; }
    this._active = true;
    this._lastCode = null;
    this._onStatus?.('Point at a QR code');
    this._scanLoop();
  }

  stop() {
    this.pause();
    if (this._stream) {
      this._stream.getTracks().forEach(t => t.stop());
      this._stream = null;
    }
    this._video.srcObject = null;
  }

  // ── Torch ───────────────────────────────────────────────────────────────────

  get torchSupported() { return this._torchSupp; }
  get torchState()     { return this._torchOn; }

  async toggleTorch() {
    if (!this._track || !this._torchSupp) return false;
    try {
      this._torchOn = !this._torchOn;
      await this._track.applyConstraints({ advanced: [{ torch: this._torchOn }] });
      return this._torchOn;
    } catch {
      this._torchOn = false;
      return false;
    }
  }

  // ── Gallery import ──────────────────────────────────────────────────────────

  async scanFile(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => {
        URL.revokeObjectURL(url);
        const { naturalWidth: w, naturalHeight: h } = img;
        this._canvas.width  = w;
        this._canvas.height = h;
        this._ctx.drawImage(img, 0, 0);
        const data = this._ctx.getImageData(0, 0, w, h);
        const code = jsQR(data.data, w, h, { inversionAttempts: 'dontInvert' });
        if (code?.data) resolve(code.data);
        else reject(new Error('No QR code found in the selected image.'));
      };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Could not load image.')); };
      img.src = url;
    });
  }

  // ── Internal scan loop ──────────────────────────────────────────────────────

  _scanLoop() {
    if (!this._active) return;
    this._raf = requestAnimationFrame(() => {
      const v = this._video;
      if (!v || v.readyState !== HTMLMediaElement.HAVE_ENOUGH_DATA) {
        this._scanLoop();
        return;
      }

      const w = v.videoWidth, h = v.videoHeight;
      if (this._canvas.width !== w || this._canvas.height !== h) {
        this._canvas.width = w; this._canvas.height = h;
      }

      this._ctx.drawImage(v, 0, 0, w, h);
      const imageData = this._ctx.getImageData(0, 0, w, h);
      const code      = jsQR(imageData.data, w, h, { inversionAttempts: 'dontInvert' });

      if (code?.data) {
        const now = Date.now();
        if (code.data !== this._lastCode || now - this._lastAt > this._DEBOUNCE_MS) {
          this._lastCode = code.data;
          this._lastAt   = now;
          this._active   = false;
          this._onStatus?.('✓ QR code detected!');
          this._onDetected?.(code.data);
          return;
        }
      }

      this._scanLoop();
    });
  }
}
