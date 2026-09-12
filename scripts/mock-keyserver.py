#!/usr/bin/env python3
"""A minimal HKP keyserver, for testing scripts/key-handoff.sh offline.

`gpg --send-keys` and `gpg --recv-keys` speak HKP: an upload is a form POST to
/pks/add carrying `keytext`, and a fetch is GET /pks/lookup?op=get&search=0x...
returning an armored key. That is the entire surface this implements.

It exists so the publication path in key-handoff.sh is exercised against a real
keyserver conversation rather than a stubbed function, while the test suite
stays offline and deterministic. Failure modes are selectable, because the cases
worth testing are the ones where a keyserver accepts an upload and then does not
serve the key back the way it was sent.

    mock-keyserver.py --state DIR [--reject-upload] [--not-found]
                      [--serve FILE] [--port N]

Prints "listening <port>" on stdout once bound, so a caller can read the port
off an ephemeral bind rather than guessing one and racing another test.

Never point this at anything real. It has no authentication and no TLS.
"""

from __future__ import annotations

import argparse
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


class Options:
    """Selectable behaviour, shared with the request handler."""

    def __init__(
        self, state: Path, reject_upload: bool, not_found: bool, serve: Path | None
    ):
        self.state = state
        self.reject_upload = reject_upload
        self.not_found = not_found
        self.serve = serve
        self.lock = threading.Lock()

    @property
    def uploads_dir(self) -> Path:
        path = self.state / "uploads"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def record_upload(self, keytext: str) -> None:
        with self.lock:
            index = len(list(self.uploads_dir.glob("*.asc")))
            (self.uploads_dir / f"{index:04d}.asc").write_text(
                keytext, encoding="utf-8"
            )

    def served_key(self) -> str | None:
        """What a lookup should return.

        --serve pins a fixed answer, which is how "the upload succeeded but the
        keyserver is still handing out the unrevoked key" gets tested. Otherwise
        the answer is the most recent upload, which is what a real keyserver
        does with a revocation: merge it in and serve the result.
        """
        if self.serve is not None:
            return self.serve.read_text(encoding="utf-8")
        with self.lock:
            uploads = sorted(self.uploads_dir.glob("*.asc"))
        if not uploads:
            return None
        return uploads[-1].read_text(encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    options: Options

    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: ARG002
        """Silence the default stderr access log; the tests assert on files."""

    def _respond(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        if urlparse(self.path).path != "/pks/add":
            self._respond(404, b"not found\n", "text/plain")
            return
        if self.options.reject_upload:
            self._respond(500, b"upload rejected\n", "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0"))
        fields = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        keytext = fields.get("keytext", [""])[0]
        if not keytext.strip():
            self._respond(400, b"no keytext\n", "text/plain")
            return
        self.options.record_upload(keytext)
        self._respond(200, b"key accepted\n", "text/plain")

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        parsed = urlparse(self.path)
        if parsed.path != "/pks/lookup":
            self._respond(404, b"not found\n", "text/plain")
            return
        query = parse_qs(parsed.query)
        if query.get("op", [""])[0] != "get":
            self._respond(501, b"unsupported op\n", "text/plain")
            return
        if self.options.not_found:
            self._respond(404, b"No keys found\n", "text/plain")
            return
        key = self.options.served_key()
        if key is None:
            self._respond(404, b"No keys found\n", "text/plain")
            return
        self._respond(200, key.encode("utf-8"), "application/pgp-keys")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state", required=True, type=Path, help="directory for recorded uploads"
    )
    parser.add_argument("--port", type=int, default=0, help="0 binds an ephemeral port")
    parser.add_argument(
        "--reject-upload", action="store_true", help="fail every /pks/add"
    )
    parser.add_argument("--not-found", action="store_true", help="404 every lookup")
    parser.add_argument(
        "--serve", type=Path, help="always serve this file, ignoring uploads"
    )
    args = parser.parse_args()

    args.state.mkdir(parents=True, exist_ok=True)
    Handler.options = Options(
        args.state, args.reject_upload, args.not_found, args.serve
    )

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"listening {server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
