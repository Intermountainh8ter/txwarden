"""A real HTTP JSON-RPC server (``http.server`` in a thread) for exercising ``http_transport``.

It can answer from a handler function (for example ``FakeChain.rpc``), replay a recorded session
file, or misbehave on purpose (HTTP errors, HTML bodies, slow responses, non-object bodies).
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from txwarden.simulator import RpcError

Handler = Callable[[str, list[Any]], Any]


def replay_handler(path: str | Path) -> Handler:
    """Answer exactly the (method, params) pairs found in a recorded session file."""
    raw = json.loads(Path(path).read_text())
    table = {(r["method"], json.dumps(r["params"], sort_keys=True)): r for r in raw["records"]}

    def handle(method: str, params: list[Any]) -> Any:
        rec = table.get((method, json.dumps(params, sort_keys=True)))
        if rec is None:
            raise RpcError(f"Method not found: {method}", -32601)
        if "error" in rec:
            e = rec["error"]
            raise RpcError(e["message"], e.get("code"), e.get("data"))
        return rec["result"]

    return handle


class FakeRpcServer:
    def __init__(self, handler: Handler | None = None, *, status: int = 200,
                 body: bytes | None = None, delay: float = 0.0, content_type: str = "application/json"):
        self.handler, self.status, self.body, self.delay = handler, status, body, delay
        self.content_type = content_type
        self.requests: list[dict[str, Any]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length) or b"{}")
                outer.requests.append(req)
                if outer.delay:
                    time.sleep(outer.delay)
                payload = outer.body
                if payload is None:
                    try:
                        result = outer.handler(req["method"], req.get("params", []))
                        resp: Any = {"jsonrpc": "2.0", "id": req["id"], "result": result}
                    except RpcError as e:
                        err = {"code": e.code if e.code is not None else -32000, "message": e.message}
                        if e.data is not None:
                            err["data"] = e.data
                        resp = {"jsonrpc": "2.0", "id": req["id"], "error": err}
                    payload = json.dumps(resp).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", outer.content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):  # client gave up (timeout test)
                    pass

            def log_message(self, *args: Any) -> None:
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    @property
    def methods(self) -> list[str]:
        return [r["method"] for r in self.requests]

    def __enter__(self) -> FakeRpcServer:
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)
