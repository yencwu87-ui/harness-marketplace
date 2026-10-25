#!/usr/bin/env python3
"""Runs INSIDE the isolated network (a Linux network namespace or a container started with --network none).

There is no route to the internet in there. This bridge brings up loopback, listens on 127.0.0.1:3128 and relays
each connection to the harness egress proxy through a unix socket mounted from outside, so the only way out is the
logging, allowlisting proxy. Then it runs the agent command with HTTP(S)_PROXY pointing at the bridge.

    bridge.py /path/to/proxy.sock -- <agent command...>
"""
import fcntl
import os
import socket
import struct
import subprocess
import sys
import threading

PORT = 3128


def loopback_up():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        flags = struct.unpack("16sh", fcntl.ioctl(s, 0x8913, struct.pack("16sh", b"lo", 0)))[1]  # SIOCGIFFLAGS
        fcntl.ioctl(s, 0x8914, struct.pack("16sh", b"lo", flags | 1))                          # SIOCSIFFLAGS, IFF_UP
    except OSError:
        pass  # containers usually have loopback up already


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def listen():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(64)
    return srv


def serve(srv, sock_path):
    while True:
        c, _ = srv.accept()
        u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            u.connect(sock_path)
        except OSError:
            c.close()
            continue
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c), daemon=True).start()


def main():
    sock_path, sep, cmd = sys.argv[1], sys.argv[2], sys.argv[3:]
    assert sep == "--" and cmd, __doc__
    loopback_up()
    srv = listen()  # bound before the agent starts, so its first request can't race the bridge
    threading.Thread(target=serve, args=(srv, sock_path), daemon=True).start()
    url = f"http://127.0.0.1:{PORT}"
    env = {**os.environ, "HTTP_PROXY": url, "HTTPS_PROXY": url, "http_proxy": url, "https_proxy": url,
           "NO_PROXY": "", "no_proxy": "", "HARNESS_ISOLATION": os.environ.get("HARNESS_ISOLATION", "netns")}
    sys.exit(subprocess.run(cmd, env=env).returncode)


if __name__ == "__main__":
    main()
