"""L4 Proof-of-Ownership via reverse TCP connection (outbound check).

Flow
----
1. Caller calls ``start_listener(token)`` → returns the ``ReverseVerifyServer``
   context-manager (also a port number).
2. User is shown the instruction:
       curl "http://<your-public-IP>:<port>/verify?token=<token>"
   where <your-public-IP> is the IP of the machine running this tool.
3. The embedded HTTP server receives the request, checks:
       a. The token matches.
       b. The source IP of the request equals the target IP being verified.
4. ``server.wait(timeout)`` blocks until success or timeout, then returns
   ``(success: bool, source_ip: str | None)``.
5. On success the caller calls ``token.mark_verified(ip, token, "reverse_connect")``.

Limitations & known gaps (documented honestly)
-----------------------------------------------
- **Game servers / databases** that cannot run curl/wget: the user needs any
  outbound HTTP client on the target.  If none is available, ``--unsafe`` is
  the correct fallback.
- **NAT / firewall**: the machine running this tool must be reachable from the
  target server on the chosen port.  Cloud VMs work; laptops behind NAT often
  don't.  A future version can add a relay mode.
- **IPv6**: source-IP comparison is done after stripping ``::ffff:`` prefix so
  IPv4-mapped addresses work correctly.
"""

import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# Port range to try when binding the listener
_PORT_RANGE = range(18_000, 18_020)

# How many seconds to poll for a verified connection by default
DEFAULT_TIMEOUT = 300  # 5 minutes


def _pick_free_port() -> int:
    for port in _PORT_RANGE:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    raise RuntimeError(
        f"Could not bind to any port in {_PORT_RANGE.start}–{_PORT_RANGE.stop - 1}. "
        "Free a port or adjust _PORT_RANGE."
    )


def _normalize_ip(raw: str) -> str:
    """Strip port and IPv4-in-IPv6 prefix (``::ffff:1.2.3.4`` → ``1.2.3.4``)."""
    ip = raw.split(":")[0] if "." in raw else raw
    # Remove IPv4-mapped IPv6 prefix
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    return ip.strip()


class _Handler(BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 handler that checks token + source IP."""

    # Set by ReverseVerifyServer before the server starts
    expected_token: str = ""
    expected_ip:    str = ""
    result:  "dict"     = {}          # shared dict: {"ok": bool, "src_ip": str}
    event:   threading.Event = None   # type: ignore[assignment]

    def do_GET(self):                  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/verify":
            self._respond(404, "Not Found")
            return

        params    = parse_qs(parsed.query)
        token_got = (params.get("token") or [""])[0].strip()
        src_ip    = _normalize_ip(self.client_address[0])

        if token_got != self.server.expected_token:
            self._respond(403, "Invalid token")
            return

        if self.server.expected_ip and src_ip != _normalize_ip(self.server.expected_ip):
            self._respond(403,
                          f"Source IP mismatch: got {src_ip}, "
                          f"expected {self.server.expected_ip}")
            return

        # Success
        self._respond(200, "Verification successful. You may close this connection.")
        self.server.result["ok"]     = True
        self.server.result["src_ip"] = src_ip
        self.server.event.set()

    def _respond(self, code: int, body: str) -> None:
        encoded = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):   # suppress default access log
        pass


class ReverseVerifyServer:
    """Context-manager that runs the verification HTTP listener in a daemon thread."""

    def __init__(self, token: str, expected_ip: str = "") -> None:
        self.token       = token
        self.expected_ip = expected_ip
        self.port        = _pick_free_port()
        self._result: dict = {"ok": False, "src_ip": None}
        self._event  = threading.Event()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self) -> "ReverseVerifyServer":
        self._server = HTTPServer(("0.0.0.0", self.port), _Handler)
        # Attach state to the server object so the handler can reach it
        self._server.expected_token = self.token       # type: ignore[attr-defined]
        self._server.expected_ip    = self.expected_ip  # type: ignore[attr-defined]
        self._server.result         = self._result      # type: ignore[attr-defined]
        self._server.event          = self._event       # type: ignore[attr-defined]
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="poo-reverse-listener"
        )
        self._thread.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ── Public API ────────────────────────────────────────────────────────

    def wait(self, timeout: float = DEFAULT_TIMEOUT) -> tuple[bool, str | None]:
        """Block until verification succeeds or *timeout* seconds elapse.

        Returns ``(success, source_ip)`` where *source_ip* is the IP that
        connected (or None on timeout).
        """
        self._event.wait(timeout)
        return self._result["ok"], self._result.get("src_ip")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None

    @property
    def verified(self) -> bool:
        return self._result["ok"]

    @property
    def source_ip(self) -> str | None:
        return self._result.get("src_ip")

    # ── Internal ──────────────────────────────────────────────────────────

    def _serve(self) -> None:
        if self._server:
            self._server.serve_forever()


def get_local_ip() -> str:
    """Best-effort: return the outbound IP of this machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
