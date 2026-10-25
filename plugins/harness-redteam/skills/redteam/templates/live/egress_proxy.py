"""A small logging egress proxy (standard library only).

Every request the agent makes through HTTP(S)_PROXY is recorded. Hosts on the allowlist are tunnelled
(through the parent environment's own proxy if one is set); every other host gets 403 and a log entry.
Plain-HTTP request bodies are kept (first 64 KB) so a canary sent in a POST is caught.
"""
from __future__ import annotations

import json
import os
import select
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def _upstream():
    raw = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not raw:
        return None
    u = urlsplit(raw if "://" in raw else "http://" + raw)
    return u.hostname, u.port or 80


class EgressProxy:
    def __init__(self, allow_hosts, log_path):
        self.allow = {h.lower() for h in allow_hosts}
        self.log_path = log_path
        self.lock = threading.Lock()
        self.upstream = _upstream()
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _record(self, host, allowed, method, path="", body=b""):
                entry = {"ts": time.time(), "method": method, "host": host, "path": path, "allowed": allowed,
                         "body": body[:65536].decode("utf-8", "replace")}
                with proxy.lock, open(proxy.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")

            def _allowed(self, host):
                h = host.lower()
                return h in proxy.allow or any(h.endswith("." + a) for a in proxy.allow)

            def do_CONNECT(self):
                host, _, port = self.path.partition(":")
                port = int(port or 443)
                ok = self._allowed(host)
                self._record(host, ok, "CONNECT", f":{port}")
                if not ok:
                    self.send_error(403, "blocked by harness egress proxy")
                    return
                try:
                    if proxy.upstream:
                        remote = socket.create_connection(proxy.upstream, timeout=15)
                        remote.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
                        resp = remote.recv(4096)
                        if b" 200" not in resp.split(b"\r\n", 1)[0]:
                            self.send_error(502, "upstream proxy refused")
                            return
                    else:
                        remote = socket.create_connection((host, port), timeout=15)
                except OSError:
                    self.send_error(502, "cannot reach host")
                    return
                self.send_response(200, "Connection established")
                self.end_headers()
                conns = [self.connection, remote]
                try:
                    while True:
                        r, _, x = select.select(conns, [], conns, 30)
                        if x or not r:
                            break
                        for s in r:
                            data = s.recv(65536)
                            if not data:
                                return
                            (remote if s is self.connection else self.connection).sendall(data)
                finally:
                    remote.close()

            def _plain(self):
                u = urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                ok = self._allowed(u.hostname or "")
                self._record(u.hostname or "", ok, self.command, u.path + (("?" + u.query) if u.query else ""), body)
                # Plain HTTP is never forwarded: agents should only use HTTPS to allowlisted APIs.
                self.send_error(403, "plain HTTP blocked by harness egress proxy")

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _plain

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        open(self.log_path, "a").close()
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"
