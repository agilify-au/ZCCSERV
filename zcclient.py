#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# MIT License
#
# Copyright (c) 2023-2026 Agilify Strategy and Innovation Pty Limited
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
# ---------------------------------------------------------------------------
"""
zcclient.py  –  Python port of zcclient.c
Simple socket client that sends zero-client crypto commands.

Original: (C) COPYRIGHT 2023 Agilify Strategy and Innovation Pty Ltd (Agilify).
          All rights reserved. Licensed materials – Property of Agilify.

Ported to native Python for Windows (UTF-8, little-endian).
iconv EBCDIC↔UTF-8 conversions are replaced with Python's built-in
codec  'cp500'  (EBCDIC International / IBM-500), which covers the
same code-points used by the original iconv("01208","01047") pair.
All length/integer fields are little-endian on the wire, conforming
to the BSON specification.
"""

import os
import select
import socket
import ssl

def _connect(host: str, port: int) -> socket.socket:
    """
    Create a connected TCP socket that works for:
      - IPv4 addresses and hostnames resolving to IPv4  (AF_INET)
      - IPv6 addresses and hostnames resolving to IPv6  (AF_INET6)
      - Bracketed IPv6 literals  e.g. [::1]  (brackets are stripped)
    Uses getaddrinfo so the OS handles resolution and picks the right family.
    Returns the first successfully connected socket.
    Raises OSError if all candidates fail.
    """
    # Strip brackets from IPv6 literals like [::1] or [2001:db8::1]
    h = host.strip()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]

    last_exc: Exception = OSError(f"getaddrinfo returned no results for {host!r}")
    infos = socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)
    for af, socktype, proto, _canonname, sockaddr in infos:
        try:
            sock = socket.socket(af, socktype, proto)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_exc = exc
            try:
                sock.close()
            except Exception:
                pass
    raise last_exc

import struct
import sys


_CIPHER_STRING = (
    'ECDH+AESGCM:ECDH+AES256:ECDH+AES128:RSA+AESGCM:RSA+AES'
    ':ECDH+3DES:RSA+3DES:!aNULL:!eNULL:!MD5:@SECLEVEL=1'
)


def _make_tls_context(verify: bool, max_tls13: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if not max_tls13:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(_CIPHER_STRING)
    except ssl.SSLError:
        pass
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


# Seconds to wait for the TLS 1.3 handshake probe before falling back
# to TLS 1.2 only.  AT-TLS/GSKit may silently drop TLS 1.3 ClientHellos
# rather than sending an alert, so we need a timeout to detect this.
_TLS13_PROBE_TIMEOUT = 5.0


def _connect_tls(host: str, port: int, verify: bool = True) -> ssl.SSLSocket:
    """TLS-wrapped _connect with automatic TLS 1.3 -> 1.2 fallback.

    Tries TLS 1.2+1.3 first.  If the handshake fails or times out
    (AT-TLS/GSKit may silently ignore TLS 1.3 ClientHellos instead of
    sending an alert), opens a fresh connection and retries TLS 1.2 only.
    The returned socket is always in blocking mode.

    If *verify* is False, certificate verification, hostname checking, and
    the SNI extension are suppressed (useful for self-signed AT-TLS certs).
    """
    sni = None if not verify else host.strip('[]')

    # First attempt: offer TLS 1.2 and 1.3, with a short handshake timeout
    raw = _connect(host, port)
    raw.settimeout(_TLS13_PROBE_TIMEOUT)
    try:
        wrapped = _make_tls_context(verify, max_tls13=True).wrap_socket(
            raw, server_hostname=sni)
        wrapped.settimeout(None)   # restore blocking for data transfer
        return wrapped
    except (ssl.SSLError, OSError, TimeoutError):
        try:
            raw.close()
        except Exception:
            pass

    # Fallback: TLS 1.2 only (AT-TLS/GSKit that silently drops TLS 1.3)
    raw = _connect(host, port)
    raw.settimeout(None)   # blocking from the start
    return _make_tls_context(verify, max_tls13=False).wrap_socket(
        raw, server_hostname=sni)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BUFSIZE        = 65536
RESPONSE_TIME  = 15        # seconds  (original used 15 000 ms)
MAX_PARMS      = 64
LONGEST_NAME   = 51
EBCDIC         = 'cp500'   # IBM EBCDIC International (was iconv 01047/01208)

# ---------------------------------------------------------------------------
# ASCII / EBCDIC display tables (copied verbatim from the C source)
# ---------------------------------------------------------------------------
NDC = ord('.')

_ASC_TABLE = [
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    ord(' '),ord('!'),ord('"'),ord('#'),ord('$'),ord('%'),ord('&'),ord("'"),
    ord('('),ord(')'),ord('*'),ord('+'),ord(','),ord('-'),ord('.'),ord('/'),
    ord('0'),ord('1'),ord('2'),ord('3'),ord('4'),ord('5'),ord('6'),ord('7'),
    ord('8'),ord('9'),ord(':'),ord(';'),ord('<'),ord('='),ord('>'),ord('?'),
    ord('@'),ord('A'),ord('B'),ord('C'),ord('D'),ord('E'),ord('F'),ord('G'),
    ord('H'),ord('I'),ord('J'),ord('K'),ord('L'),ord('M'),ord('N'),ord('O'),
    ord('P'),ord('Q'),ord('R'),ord('S'),ord('T'),ord('U'),ord('V'),ord('W'),
    ord('X'),ord('Y'),ord('Z'),ord('['),ord('\\'),ord(']'),ord('^'),ord('_'),
    NDC,    ord('a'),ord('b'),ord('c'),ord('d'),ord('e'),ord('f'),ord('g'),
    ord('h'),ord('i'),ord('j'),ord('k'),ord('l'),ord('m'),ord('n'),ord('o'),
    ord('p'),ord('q'),ord('r'),ord('s'),ord('t'),ord('u'),ord('v'),ord('w'),
    ord('x'),ord('y'),ord('z'),ord('{'),ord('|'),ord('}'),ord('~'),NDC,
] + [NDC] * 128

_EBC_TABLE = [
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    ord(' '),NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,ord('['),ord('.'),ord('<'),ord('('),ord('+'),ord('!'),
    ord('&'),NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,ord(']'),ord('$'),ord('*'),ord(')'),ord(';'),ord('^'),
    ord('-'),ord('/'),NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,ord('|'),ord(','),ord('%'),ord('_'),ord('>'),ord('?'),
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,ord('`'),ord(':'),ord('#'),ord('@'),ord("'"),ord('='),ord('"'),
    NDC,ord('a'),ord('b'),ord('c'),ord('d'),ord('e'),ord('f'),ord('g'),
    ord('h'),ord('i'),NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,ord('j'),ord('k'),ord('l'),ord('m'),ord('n'),ord('o'),ord('p'),
    ord('q'),ord('r'),NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,ord('~'),ord('s'),ord('t'),ord('u'),ord('v'),ord('w'),ord('x'),
    ord('y'),ord('z'),NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,NDC,NDC,NDC,NDC,NDC,
    NDC,NDC,NDC,ord('|'),NDC,NDC,NDC,NDC,
    ord('{'),ord('A'),ord('B'),ord('C'),ord('D'),ord('E'),ord('F'),ord('G'),
    ord('H'),ord('I'),NDC,NDC,NDC,NDC,NDC,NDC,
    ord('}'),ord('J'),ord('K'),ord('L'),ord('M'),ord('N'),ord('O'),ord('P'),
    ord('Q'),ord('R'),NDC,NDC,NDC,NDC,NDC,NDC,
    ord('\\'),NDC,ord('S'),ord('T'),ord('U'),ord('V'),ord('W'),ord('X'),
    ord('Y'),ord('Z'),NDC,NDC,NDC,NDC,NDC,NDC,
    ord('0'),ord('1'),ord('2'),ord('3'),ord('4'),ord('5'),ord('6'),ord('7'),
    ord('8'),ord('9'),NDC,NDC,NDC,NDC,NDC,NDC,
]

ASC = bytes(_ASC_TABLE)
EBC = bytes(_EBC_TABLE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b2x(data: bytes) -> str:
    """Binary → uppercase hex string."""
    return data.hex().upper()


def x2b(hexstr: str) -> bytes:
    """Hex string → bytes (ignores non-hex characters, as the C version does)."""
    cleaned = ''.join(c for c in hexstr if c in '0123456789ABCDEFabcdef')
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]   # drop a trailing nibble just as C does
    return bytes.fromhex(cleaned)


def rtrim(text: str) -> str:
    """Remove trailing whitespace."""
    return text.rstrip()


def flip(data: bytearray) -> bytearray:
    """Reverse byte order in-place (used for double values)."""
    data.reverse()
    return data


def dump(buf: bytes) -> None:
    """
    Hex dump with ASCII and EBCDIC side-cars, matching the original C output.
    Format:
          OOOOOO: HH HH ... HH HH  |---- ASCII -----|  |---- EBCDIC ----|
    """
    indent = 6
    n = len(buf)
    previous = ''
    donesame = False

    for i in range(n):
        i16 = i % 16
        i4  = i16 // 4

        if i16 == 0:
            # Start a new 16-byte line
            hex_part  = [' '] * (35 + 3)   # 32 hex digits + 3 spaces between groups
            asc_part  = [' '] * 16
            ebc_part  = [' '] * 16
            offset_str = f'{i:06X}:'

        b = buf[i]
        # Position in the hex column: 2 chars per byte + 1 space every 4 bytes
        col = i16 * 2 + i4
        hex_part[col]     = '0123456789ABCDEF'[b >> 4]
        hex_part[col + 1] = '0123456789ABCDEF'[b & 0xf]
        asc_part[i16] = chr(ASC[b])
        ebc_part[i16] = chr(EBC[b])

        if i16 == 15 or i == n - 1:
            hex_str = ''.join(hex_part).rstrip()
            asc_str = ''.join(asc_part)
            ebc_str = ''.join(ebc_part)
            line_key = hex_str  # used for "same as above" detection

            if i16 != 15:
                # Last partial line – pad to full width so same-detection works
                line_key += ' '   # force difference from previous

            if line_key == previous:
                if not donesame:
                    print(f"{'':>{indent}}        --------   same as above   --------")
                    donesame = True
            else:
                donesame = False
                print(f"{'':>{indent}}{offset_str} {''.join(hex_part):<38}  |{asc_str}|  |{ebc_str}|")
                previous = line_key


def pack_uint32_le(value: int) -> bytes:
    """Pack a 32-bit unsigned integer in little-endian byte order (BSON spec, outbound)."""
    return struct.pack('<I', value & 0xFFFFFFFF)


def unpack_uint32_le(data: bytes, offset: int = 0) -> int:
    """Unpack a little-endian 32-bit unsigned integer (BSON spec, outbound lengths)."""
    return struct.unpack_from('<I', data, offset)[0]


def unpack_int32_le(data: bytes, offset: int = 0) -> int:
    """Unpack a little-endian 32-bit signed integer.

    The ZCC server (Windows/x86) sends all integer values in little-endian
    byte order.  The original C client used btohl() to swap LE->BE for the
    big-endian mainframe host; that swap is not needed on Windows Python.
    """
    return struct.unpack_from('<i', data, offset)[0]


def unpack_double_le(data: bytes, offset: int = 0) -> float:
    """Unpack a little-endian IEEE-754 double.

    The ZCC server (Windows/x86) sends doubles in little-endian byte order.
    The original C client called flip() before reading the double because it
    ran on a big-endian mainframe; that flip is not needed on Windows Python.
    """
    return struct.unpack_from('<d', data, offset)[0]


# ---------------------------------------------------------------------------
# BSON-like element
# ---------------------------------------------------------------------------
class BsonEl:
    __slots__ = ('type', 'name', 'valuelen', 'value')

    def __init__(self):
        self.type     = 0
        self.name     = ''
        self.valuelen = 0
        self.value    = b''


# ---------------------------------------------------------------------------
# Parse the BSON-like response document
# ---------------------------------------------------------------------------
def parse(buf: bytes) -> list[BsonEl]:
    """
    Parse the body of a response document (after the 4-byte length prefix)
    into a list of BsonEl objects.

    Wire encoding (little-endian integers, UTF-8 strings):
        type  : 1 byte
        name  : null-terminated UTF-8 string
        value : type-dependent
            0x00  end-of-document  (no value, 1 extra byte consumed)
            0x01  double           8 bytes  (little-endian)
            0x10  int32            4 bytes  (little-endian)            0x05  binary           4-byte length + 1-byte subtype + <length> bytes
            other string          4-byte length + <length> bytes (UTF-8, null-terminated)
    """
    elements = []
    offset   = 0
    length   = len(buf)

    while offset < length:
        el = BsonEl()
        el.type = buf[offset]
        offset += 1

        # end-of-document marker (0x00) has no name or value.
        # Must check BEFORE reading a name: buf.index(0) would otherwise
        # consume this 0x00 byte itself as a zero-length name and corrupt
        # all subsequent parsing.
        if el.type == 0x00:
            break

        # Null-terminated field name
        end = buf.index(0, offset)
        el.name = buf[offset:end].decode('utf-8', errors='replace')
        offset = end + 1

        if el.type == 0x01:                     # double (8 bytes, little-endian from server)
            el.valuelen = 8
            el.value    = buf[offset:offset + 8]
            offset     += 8
            elements.append(el)
        elif el.type == 0x10:                   # int32 (4 bytes, big-endian from server)
            el.valuelen = 4
            el.value    = buf[offset:offset + 4]
            offset     += 4
            elements.append(el)
        elif el.type == 0x05:                   # binary
            el.valuelen = unpack_uint32_le(buf, offset)
            offset     += 5                     # 4-byte length + 1-byte subtype
            el.value    = buf[offset:offset + el.valuelen]
            offset     += el.valuelen
            elements.append(el)
        else:                                   # string (0x02) and others
            el.valuelen = unpack_uint32_le(buf, offset)
            offset     += 4
            el.value    = buf[offset:offset + el.valuelen]
            offset     += el.valuelen
            elements.append(el)

    return elements


# ---------------------------------------------------------------------------
# myread: interruptible recv – polls with a short select() timeout so that
# Ctrl+C (SIGINT / KeyboardInterrupt) is honoured on Windows.
#
# Background: on Windows a fully-blocking recv() sits inside a C extension
# call and never yields back to the Python interpreter, so signal handlers
# (including the default KeyboardInterrupt one) are deferred until the call
# returns.  By using select() with a short wall-clock timeout and looping,
# we return to Python bytecode between each poll, giving the runtime a
# chance to raise any pending KeyboardInterrupt.
# ---------------------------------------------------------------------------
_POLL_INTERVAL = 0.25   # seconds between select() polls

def myread(sock: socket.socket, length: int, timeout_s: float = 0) -> bytes:
    """
    Read up to `length` bytes from `sock`, waiting indefinitely but
    remaining responsive to Ctrl+C on Windows.

    For plain TCP sockets, uses select() with a short poll interval so
    Python's signal machinery can deliver KeyboardInterrupt.

    For TLS (ssl.SSLSocket), select() only sees TCP-level data and will
    hang if the SSL layer has already buffered bytes from a previous record
    read.  We check ssl.SSLSocket.pending() first and bypass select() when
    the SSL layer already holds data.  When the buffer is empty, select()
    is used as normal so Ctrl+C still works.
    """
    while True:
        # SSLSocket buffers whole TLS records internally; select() on the
        # underlying TCP socket will not wake for already-buffered SSL bytes.
        if hasattr(sock, 'pending') and sock.pending() > 0:
            return sock.recv(length)
        ready, _, _ = select.select([sock], [], [], _POLL_INTERVAL)
        if ready:
            return sock.recv(length)
        # No data yet - loop back; Python signal handlers run here,
        # so Ctrl+C raises KeyboardInterrupt on the next iteration.

# ---------------------------------------------------------------------------
# lookupError  (stub – mirrors the C stub that calls ccaError)
# ---------------------------------------------------------------------------
def lookup_error(rc: int, rsn: int, host: str, port: int) -> None:
    """
    Call  cv=ERROR irc=<rc> irsn=<rsn>  on the ZCC server and print the
    returned error-description lines (l1..ln, count in lc).

    Wire format (confirmed from live dump):
        request:  cv=ERROR  irc=<rc>  irsn=<rsn>
        response: rc(int32) rsn(int32) lc(int32) l1(string) ... ln(string)
    """
    try:
        err_args = ['cv=ERROR', f'irc={rc}', f'irsn={rsn}']
        err_buf, _ = build_request(err_args)

        sock = _connect(host, port)
        try:
            sock.sendall(err_buf)
            hdr = b''
            while len(hdr) < 4:
                chunk = myread(sock, 4 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            doclen = unpack_uint32_le(hdr)
            if doclen < 5 or doclen > BUFSIZE:
                return
            resp = hdr
            while len(resp) < doclen:
                chunk = myread(sock, doclen - len(resp))
                if not chunk:
                    return
                resp += chunk
        finally:
            sock.close()

        elements = parse(resp[4:])
        by_name  = {el.name: el for el in elements}

        lc_el = by_name.get('lc')
        if lc_el is None or lc_el.type != 0x10:
            return
        lc = unpack_int32_le(lc_el.value)
        if lc <= 0:
            return

        print("Error description:")
        for i in range(1, lc + 1):
            el = by_name.get(f'l{i}')
            if el is not None and el.type == 0x02:
                raw = bytearray(el.value)
                for j in range(len(raw) - 1):
                    if raw[j] < 32 or raw[j] > 127:
                        raw[j] = ord('.')
                text = bytes(raw).rstrip(b'\x00').decode('utf-8', 'replace')
                print(f'  {text}')

    except Exception:
        pass   # never let an error lookup crash the main flow


# ---------------------------------------------------------------------------
# Build the request buffer
# ---------------------------------------------------------------------------
def build_request(args: list[str]) -> bytearray:
    """
    Parse the command-line field specifications and serialise them into the
    BSON-like wire format.

    Each arg is one of:
        cname=value        character string
        iname=value        32-bit integer
        xname=hexvalue     binary (hex digits)
        fcname=filename    character string read from file
        finame=filename    integer read from file
        fxname=filename    binary read from file  (raw bytes, not hex)
        oname=filename     output-file spec  (not sent; recorded for response)
    """
    buf    = bytearray(BUFSIZE)
    offset = 4          # reserve 4 bytes for the document length

    out_specs = []      # list of (field_name_str, file_name_str)

    for arg in args:
        eq = arg.find('=', 1)
        if eq < 0:
            continue    # no value supplied – skip, matching C behaviour

        t         = arg[0]
        name_part = arg[1:eq]
        val_part  = arg[eq + 1:]

        if t == 'o':    # output-file specification
            out_specs.append((name_part, val_part))
            continue

        from_file = False
        if t == 'f':    # value comes from a file
            from_file = True
            t         = arg[1]          # actual type is 2nd char
            name_part = arg[2:eq]       # field name starts after 'f' + type

        # ------------------------------------------------------------------
        # Encode field type byte
        # ------------------------------------------------------------------
        if t == 'c':
            buf[offset] = 0x02
        elif t == 'i':
            buf[offset] = 0x10
        elif t == 'x':
            buf[offset] = 0x05
        else:
            print(f"ERROR: Invalid field type '{t}' in argument '{arg}'",
                  file=sys.stderr)
            sys.exit(12)
        offset += 1

        # ------------------------------------------------------------------
        # Encode field name as UTF-8, null-terminated
        # (The original converted from the host codepage to UTF-8 via iconv;
        #  on Windows with UTF-8 locale the name is already UTF-8.)
        # ------------------------------------------------------------------
        name_bytes = name_part.encode('utf-8') + b'\x00'
        buf[offset:offset + len(name_bytes)] = name_bytes
        offset += len(name_bytes)

        # ------------------------------------------------------------------
        # Read value (from command line or file)
        # ------------------------------------------------------------------
        if t == 'c':
            if from_file:
                try:
                    with open(val_part, 'r', encoding='utf-8') as fh:
                        text = rtrim(fh.read(BUFSIZE - 1))
                except OSError as exc:
                    print(f"Error opening text input file, {val_part}: {exc}",
                          file=sys.stderr)
                    sys.exit(12)
            else:
                text = val_part

            # Encode as UTF-8, null-terminated; write length prefix + data
            value_bytes = text.encode('utf-8') + b'\x00'
            vlen = len(value_bytes)
            buf[offset:offset + 4] = pack_uint32_le(vlen)
            offset += 4
            buf[offset:offset + vlen] = value_bytes
            offset += vlen

        elif t == 'i':
            if from_file:
                try:
                    with open(val_part, 'r', encoding='utf-8') as fh:
                        text = rtrim(fh.read(BUFSIZE - 1))
                except OSError as exc:
                    print(f"Error opening text input file, {val_part}: {exc}",
                          file=sys.stderr)
                    sys.exit(12)
            else:
                text = val_part

            try:
                ival = int(text)
            except ValueError:
                print(f"ERROR: Cannot convert '{text}' to integer", file=sys.stderr)
                sys.exit(12)

            buf[offset:offset + 4] = pack_uint32_le(ival)
            offset += 4

        elif t == 'x':
            if from_file:
                try:
                    with open(val_part, 'rb') as fh:
                        bin_val = fh.read(BUFSIZE - 1)
                except OSError as exc:
                    print(f"Error opening binary input file, {val_part}: {exc}",
                          file=sys.stderr)
                    sys.exit(12)
            else:
                bin_val = x2b(val_part)

            blen = len(bin_val)
            buf[offset:offset + 4] = pack_uint32_le(blen)
            offset += 4
            buf[offset] = 0x00          # general subtype
            offset += 1
            buf[offset:offset + blen] = bin_val
            offset += blen

    # Write end-of-document byte
    buf[offset] = 0x00
    offset += 1

    # Back-fill document length (little-endian, BSON spec)
    buf[0:4] = pack_uint32_le(offset)

    return buf[:offset], out_specs


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    args = sys.argv[1:]
    use_tls    = False
    tls_verify = True
    while args and args[0].startswith('-'):
        flag, args = args[0], args[1:]
        if flag == '-t':
            use_tls = True
        elif flag == '-k':
            tls_verify = False
        else:
            print(f'Unknown flag: {flag}', file=sys.stderr)
            sys.exit(8)
    if len(args) < 3:
        print("Usage: zcclient [-t [-k]] host_IP port {Tname=value|fTname=filename} "
              "[{Tname=value|fTname=filename}...]")
        print(" ")
        print("where   -t      use TLS (encrypted connection)")
        print("        -k      skip certificate verification (implies -t)")
        print("        T       field type: c=character string, "
              "i=integer, x=hex digits")
        print("        name    field name")
        print("        value   field value")
        sys.exit(8)

    host      = args[0]
    port      = int(args[1])
    field_args = args[2:]

    # ------------------------------------------------------------------
    # Build request
    # ------------------------------------------------------------------
    req_buf, out_specs = build_request(field_args)

    print("Sending request:")
    print("                                                      "
          "|---- ASCII -----|  |---- EBCDIC ----|")
    dump(req_buf)
    print(" ")

    # ------------------------------------------------------------------
    # Connect and send
    # ------------------------------------------------------------------
    if not tls_verify:
        use_tls = True   # -k implies -t
    proto_label = ('TLS (no cert check)' if (use_tls and not tls_verify)
                   else 'TLS' if use_tls else 'TCP')
    print(f"Connecting ({proto_label}) to {host}:{port}...")
    try:
        sock = (_connect_tls(host, port, verify=tls_verify)
                if use_tls else _connect(host, port))
    except OSError as exc:
        print(f"Error connecting to {host}:{port}: {exc}", file=sys.stderr)
        sys.exit(12)

    try:
        sock.sendall(req_buf)

        # ------------------------------------------------------------------
        # Read response: first 4 bytes = little-endian document length (BSON spec)
        # Reads block indefinitely; press Ctrl+C to abort.
        # ------------------------------------------------------------------
        hdr = b''
        while len(hdr) < 4:
            chunk = myread(sock, 4 - len(hdr))
            if not chunk:
                print("Connection closed by server before header was complete",
                      file=sys.stderr)
                sys.exit(12)
            hdr += chunk

        doclen = unpack_uint32_le(hdr)
        if doclen < 5 or doclen > BUFSIZE:
            print(f"Reply document size {doclen} is outside acceptable range "
                  f"5 to {BUFSIZE}", file=sys.stderr)
            sys.exit(12)

        resp = hdr
        while len(resp) < doclen:
            chunk = myread(sock, doclen - len(resp))
            if not chunk:
                print("Connection closed by server before response was complete",
                      file=sys.stderr)
                sys.exit(12)
            resp += chunk

    except KeyboardInterrupt:
        print("\nInterrupted – closing connection.", file=sys.stderr)
        sock.close()
        sys.exit(1)
    finally:
        sock.close()

    # ------------------------------------------------------------------
    # Dump the response
    # ------------------------------------------------------------------
    print("Received reply:")
    print("                                                      "
          "|---- ASCII -----|  |---- EBCDIC ----|")
    dump(resp)
    print(" ")

    # ------------------------------------------------------------------
    # Parse and display response fields
    # ------------------------------------------------------------------
    cca_rc  = 0
    cca_rsn = 0

    chk_doclen = unpack_uint32_le(resp)
    if chk_doclen != len(resp):
        print(f"Warning: embedded document length {chk_doclen} != "
              f"received bytes {len(resp)}", file=sys.stderr)
        sys.exit(12)

    elements = parse(resp[4:])

    # Build a quick lookup for output-file specs
    # out_specs is list of (field_name, file_name)
    out_found = {name: False for name, _ in out_specs}

    for el in elements:
        field_name = el.name

        # Find matching output spec (if any)
        out_file = None
        for spec_name, spec_file in out_specs:
            if spec_name == field_name:
                out_file = spec_file
                break

        print(f"{field_name:>{LONGEST_NAME}}: ", end='')

        if el.type == 0x02:             # string
            # Sanitise: replace control / non-ASCII bytes with '.'
            raw = bytearray(el.value)
            for j in range(len(raw) - 1):
                if raw[j] < 32 or raw[j] > 127:
                    raw[j] = ord('.')
            # Decode as UTF-8; strip null terminator if present
            text = bytes(raw).rstrip(b'\x00').decode('utf-8', errors='replace')
            print(f'"{text}"', end='')

            if out_file:
                try:
                    with open(out_file, 'w', encoding='utf-8') as fh:
                        fh.write(text + '\n')
                    out_found[field_name] = True
                except OSError as exc:
                    print(f"\nError writing to output file {out_file}: {exc}",
                          file=sys.stderr)

        elif el.type == 0x05:           # binary
            hex_str = b2x(el.value)
            print(hex_str, end='')

            if out_file:
                try:
                    with open(out_file, 'wb') as fh:
                        fh.write(el.value)
                    out_found[field_name] = True
                except OSError as exc:
                    print(f"\nError writing to output file {out_file}: {exc}",
                          file=sys.stderr)

        elif el.type == 0x01:           # double (little-endian from server)
            dval = unpack_double_le(el.value)
            print(f'{dval:.14g}', end='')

        elif el.type == 0x10:           # int32 (little-endian from server)
            ival = unpack_int32_le(el.value)
            print(ival, end='')

            if out_file:
                try:
                    with open(out_file, 'w', encoding='utf-8') as fh:
                        fh.write(str(ival) + '\n')
                    out_found[field_name] = True
                except OSError as exc:
                    print(f"\nError writing to output file {out_file}: {exc}",
                          file=sys.stderr)

            if field_name in ('return_code', 'rc'):
                cca_rc  = ival
            if field_name in ('reason_code', 'rsn'):
                cca_rsn = ival

        print(" ")

        if out_file and out_found.get(field_name):
            print(f"{'':>32}>>> written to output file, {out_file}")

    # ------------------------------------------------------------------
    # Error lookup
    # ------------------------------------------------------------------
    if cca_rc != 0 or cca_rsn != 0:
        lookup_error(cca_rc, cca_rsn, host, port)

    sys.exit(cca_rc)


# ---------------------------------------------------------------------------
if __name__ == '__main__':
    main()
