"""A loopback barcode decoder that stands in for Chrome's missing ``BarcodeDetector``.

CONTRACT_V2 section V3 step 3. Desktop Chrome on Windows has no ``BarcodeDetector`` — it is an
Android/macOS/ChromeOS platform API — so the recording machine cannot run Lens's real in-browser
decode. Rather than fake the scan, the capture script injects a shim that hands Lens's own frames
to **this** process, which decodes them with zxing-cpp and answers in exactly the shape the real
API returns. The pixels on screen are therefore genuinely decoded; only the decoder lives beside
the browser instead of inside it.

zxing-cpp is a **capture-time** tool (``pip install --user zxing-cpp``). It must never appear in
``requirements.txt`` or ``pyproject.toml``: the product itself has no such dependency, and the
video must not imply that it does.

Two ways in, because the page under test is served over HTTPS and a browser will not let an HTTPS
page ``fetch()`` a plain-HTTP loopback URL (mixed content):

1. :func:`decode_data_url` — call it straight from Python. This is the one to wire to Playwright's
   ``page.expose_binding``, and it is the path the capture script should prefer.
2. the HTTP server — ``with decode_sidecar() as side: ...`` starts it on an ephemeral loopback
   port and stops it cleanly on the way out. Useful for an HTTP page, for curl, and for debugging.

The response shape mirrors ``BarcodeDetector.detect()``: a list of detected codes, each with
``rawValue``, ``format``, ``boundingBox`` (``x``/``y``/``width``/``height``, plus the ``top``/
``right``/``bottom``/``left`` a ``DOMRectReadOnly`` also carries) and four ``cornerPoints`` in
``{x, y}`` form, ordered top-left, top-right, bottom-right, bottom-left. Coordinates are in the
pixel space of the image that was posted — which is the downscaled grab canvas ``lens.js`` hands
its detector, so the numbers land back in the space the caller is already working in.

Usage::

    python video/decode_sidecar.py video/build/scene_camera.png     # decode one file
    python video/decode_sidecar.py --serve                          # run until Ctrl-C
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import logging
import re
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from typing import Any, Iterator, Sequence

logger = logging.getLogger("decode_sidecar")

#: Loopback only. This process will decode anything it is handed, so it is never offered to the LAN.
HOST = "127.0.0.1"

#: A 480x270 PNG is ~100 KB; this is generous for a full-resolution frame and still bounded.
MAX_BODY_BYTES = 24 * 1024 * 1024

_DATA_URL = re.compile(r"^data:(?P<mime>[\w.+/-]+)?(?P<b64>;base64)?,", re.IGNORECASE)

#: zxing-cpp's format names -> the lower-snake spellings the BarcodeDetector spec uses.
#: Anything unlisted is reported as "unknown", which is what the spec says for a format the
#: implementation cannot name — never a zxing-only string a page would not recognise.
FORMAT_NAMES: dict[str, str] = {
    "Aztec": "aztec",
    "Codabar": "codabar",
    "Code39": "code_39",
    "Code93": "code_93",
    "Code128": "code_128",
    "DataBar": "databar",
    "DataBarExpanded": "databar_expanded",
    "DataMatrix": "data_matrix",
    "EAN8": "ean_8",
    "EAN13": "ean_13",
    "ITF": "itf",
    "MaxiCode": "maxi_code",
    "MicroQRCode": "qr_code",
    "PDF417": "pdf417",
    "QRCode": "qr_code",
    "RMQRCode": "qr_code",
    "UPCA": "upc_a",
    "UPCE": "upc_e",
}


class DecodeError(ValueError):
    """The request was not something this endpoint can decode."""


# --------------------------------------------------------------------------- decoding


def _zxing() -> Any:
    try:
        import zxingcpp
    except ImportError as exc:  # pragma: no cover - documented as installed on this machine
        raise DecodeError(
            "zxing-cpp is not installed. It is a capture-time tool only: "
            "pip install --user zxing-cpp (never add it to requirements.txt)."
        ) from exc
    return zxingcpp


def _format_name(raw: Any) -> str:
    name = str(raw).replace(" ", "").replace("-", "").replace("_", "")
    for key, value in FORMAT_NAMES.items():
        if key.lower() == name.lower():
            return value
    return "unknown"


def _points(position: Any) -> list[dict[str, float]]:
    """Four corners, top-left first, in the order the BarcodeDetector spec lists them."""
    corners = []
    for attr in ("top_left", "top_right", "bottom_right", "bottom_left"):
        point = getattr(position, attr, None)
        if point is None:
            return []
        corners.append({"x": float(point.x), "y": float(point.y)})
    return corners


def _bounding_box(points: Sequence[dict[str, float]]) -> dict[str, float]:
    if not points:
        return {"x": 0.0, "y": 0.0, "width": 0.0, "height": 0.0,
                "top": 0.0, "right": 0.0, "bottom": 0.0, "left": 0.0}
    xs = [p["x"] for p in points]
    ys = [p["y"] for p in points]
    left, right, top, bottom = min(xs), max(xs), min(ys), max(ys)
    return {
        "x": left, "y": top, "width": right - left, "height": bottom - top,
        "top": top, "right": right, "bottom": bottom, "left": left,
    }


def decode_image(image: Any) -> list[dict[str, Any]]:
    """Decode a PIL image into the ``BarcodeDetector.detect()`` shape, largest code first.

    Largest first because ``lens.js`` takes the first hit: if a frame ever holds two codes, the
    one filling the reticle is the one the person is pointing at.
    """
    import numpy as np

    zxingcpp = _zxing()
    grey = np.asarray(image.convert("L"))
    out: list[dict[str, Any]] = []
    for hit in zxingcpp.read_barcodes(grey):
        if not hit.text and not getattr(hit, "bytes", None):
            continue
        points = _points(getattr(hit, "position", None))
        out.append({
            "rawValue": hit.text,
            "format": _format_name(hit.format),
            "boundingBox": _bounding_box(points),
            "cornerPoints": points,
        })
    out.sort(key=lambda h: h["boundingBox"]["width"] * h["boundingBox"]["height"], reverse=True)
    return out


def decode_png_bytes(payload: bytes) -> list[dict[str, Any]]:
    from PIL import Image, UnidentifiedImageError

    try:
        with Image.open(BytesIO(payload)) as image:
            image.load()
            return decode_image(image)
    except UnidentifiedImageError as exc:
        raise DecodeError("the payload is not an image this decoder understands") from exc


def decode_data_url(value: str) -> list[dict[str, Any]]:
    """Decode a ``data:image/png;base64,...`` URL — the form ``canvas.toDataURL()`` produces.

    This is the function to expose to the page through ``page.expose_binding`` when the page is
    HTTPS: an HTTPS page may not ``fetch()`` a plain-HTTP loopback URL, so the HTTP server below
    would be blocked as mixed content before it ever saw the frame.
    """
    text = str(value or "").strip()
    if not text:
        raise DecodeError("empty payload")
    match = _DATA_URL.match(text)
    if match is None:
        raise DecodeError("expected a data: URL such as data:image/png;base64,...")
    body = text[match.end():]
    if not match.group("b64"):
        raise DecodeError("only base64 data URLs are supported")
    try:
        payload = base64.b64decode(body, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"the base64 payload is malformed: {exc}") from exc
    if not payload:
        raise DecodeError("the data URL carries no bytes")
    if len(payload) > MAX_BODY_BYTES:
        raise DecodeError("payload too large")
    return decode_png_bytes(payload)


# --------------------------------------------------------------------------- the server


@dataclass
class Stats:
    requests: int = 0
    decoded: int = 0
    empty: int = 0
    errors: int = 0
    last_value: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, hits: list[dict[str, Any]]) -> None:
        with self._lock:
            self.requests += 1
            if hits:
                self.decoded += 1
                self.last_value = str(hits[0]["rawValue"])
            else:
                self.empty += 1

    def record_error(self) -> None:
        with self._lock:
            self.requests += 1
            self.errors += 1

    def as_dict(self) -> dict[str, Any]:
        return {"requests": self.requests, "decoded": self.decoded, "empty": self.empty,
                "errors": self.errors, "last_value": self.last_value}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HomeSOCDecodeSidecar/1.0"
    stats: Stats                      # bound by decode_sidecar()

    # -- plumbing ------------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - base class name
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # The shim runs inside the page, so the browser asks permission before it may read the
        # answer. Everything here is loopback-only and holds nothing but the frame just posted.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise DecodeError("Content-Length is not a number") from None
        if length <= 0:
            raise DecodeError("empty request body")
        if length > MAX_BODY_BYTES:
            raise DecodeError(f"request body is larger than {MAX_BODY_BYTES} bytes")
        return self.rfile.read(length)

    # -- routes --------------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in ("/", "/health"):
            self._send(200, {"ok": True, "decoder": "zxing-cpp", "stats": self.stats.as_dict()})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path not in ("/", "/decode"):
            self._send(404, {"error": "not found"})
            return
        try:
            raw = self._read_body()
            text = raw.decode("utf-8", "strict")
            if text.lstrip().startswith("{"):
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise DecodeError(f"the body is not valid JSON: {exc}") from exc
                text = str(parsed.get("image") or parsed.get("data") or parsed.get("dataUrl") or "")
            hits = decode_data_url(text)
        except (DecodeError, UnicodeDecodeError) as exc:
            self.stats.record_error()
            self._send(400, {"error": str(exc), "barcodes": []})
            return
        except Exception as exc:  # pragma: no cover - a decoder crash must not kill the capture
            logger.exception("decode failed")
            self.stats.record_error()
            self._send(500, {"error": f"{type(exc).__name__}: {exc}", "barcodes": []})
            return
        self.stats.record(hits)
        self._send(200, {"barcodes": hits})


@dataclass(frozen=True)
class Sidecar:
    """A running decoder. ``url`` is what the injected shim should post to."""

    host: str
    port: int
    stats: Stats

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/decode"

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"


@contextmanager
def decode_sidecar(port: int = 0, *, host: str = HOST) -> Iterator[Sidecar]:
    """Run the decoder on a loopback port for the life of the ``with`` block.

    ``port=0`` takes an ephemeral port, so two captures can run side by side. The server is a
    daemon thread and is always shut down and closed on the way out, including on an exception —
    a capture run must never leave a socket listening behind it.
    """
    _zxing()  # fail here, with a clear message, rather than on the first frame
    stats = Stats()
    handler = type("_BoundHandler", (_Handler,), {"stats": stats})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="decode-sidecar", daemon=True)
    thread.start()
    bound = Sidecar(host=host, port=int(server.server_address[1]), stats=stats)
    logger.info("decode sidecar listening on %s", bound.url)
    try:
        yield bound
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)
        logger.info("decode sidecar stopped after %d request(s), %d decoded",
                    stats.requests, stats.decoded)


# --------------------------------------------------------------------------- CLI


def _data_url_for(path: Path) -> str:
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    # One positional, two meanings, because this is started by another package's code: a path is
    # a file to decode, a bare number is the port to listen on. Serving is the default — running
    # this script with no arguments at all has to leave a decoder listening, not print a usage
    # message, or the capture that launched it sits waiting for an endpoint that never appears.
    parser.add_argument("target", nargs="?", help="a PNG to decode, or a port number to serve on")
    parser.add_argument("--serve", action="store_true", help="serve (the default)")
    parser.add_argument("--host", default=HOST, help=f"bind address (default: {HOST}; loopback only)")
    parser.add_argument("--port", type=int, default=0, help="port to serve on (default: ephemeral)")
    parser.add_argument("--decode", type=Path, default=None, help="decode this PNG and exit")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    port = args.port
    image = args.decode
    if args.target is not None:
        if str(args.target).isdigit():
            port = int(args.target)
        else:
            image = Path(args.target)

    if image is not None:
        if not image.exists():
            print(f"error: {image} does not exist", file=sys.stderr)
            return 2
        hits = decode_data_url(_data_url_for(image))
        print(json.dumps({"barcodes": hits}, indent=2))
        return 0 if hits else 1

    host = args.host
    if host not in ("127.0.0.1", "localhost", "::1"):
        # The decoder will decode anything it is handed and is a capture-time convenience; it is
        # never exposed beyond this machine, whatever the caller asks for.
        print(f"error: refusing to bind {host}: the decode sidecar is loopback-only",
              file=sys.stderr)
        return 2

    with decode_sidecar(port, host=host) as side:
        print(f"POST a PNG data URL to {side.url}  (Ctrl-C to stop)", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            print()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DecodeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
