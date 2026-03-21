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
zccgui.py  -  Guided ZCC GUI client
Cross-platform (Windows / macOS / Linux) using tkinter + ttk (built-in).

Workflow
--------
1. Enter host / port
2. Choose a verb category from the left panel
3. Choose a verb from the right panel
4. App calls  cv=<VERB>?  to introspect parameters
5. A dynamic form is built from the JSON metadata in wire order
6. User fills in the input parameters and clicks Execute
7. App calls the verb for real and displays the decoded response
8. If rc or rsn are non-zero, calls cv=ERROR irc=<rc> irsn=<rsn>
   and displays the error text lines (l1..ln, count in lc)

Changes from previous version
------------------------------
* Parameters shown in the order supplied by the VERB? response (wire order)
* All list/parameter panes are horizontally scrollable; hovering a truncated
  row shows a flyover tooltip with the full value
* Non-zero rc/rsn triggers an ERROR lookup call whose text is displayed

Requires only:  zcclient.py  in the same directory.
No third-party packages needed.
"""

import argparse
import dataclasses
import io
import json
import pathlib
import socket
import ssl
import urllib.request
import webbrowser

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

import time
import threading
import tkinter as tk
import tkinter.font as _tkfont
from contextlib import redirect_stdout
from tkinter import filedialog, messagebox, scrolledtext, ttk


try:
    import zcclient as zcc
except ImportError:
    import sys
    sys.exit("zcclient.py not found - place it in the same directory as zccgui.py")

# ---------------------------------------------------------------------------
# Verb catalogue  (from app.js)
# ---------------------------------------------------------------------------
VERB_DATA: dict[str, list[dict[str, str]]] = {
    'Managing symmetric cryptographic keys': [
        {'key': 'CSNBCKI',  'desc': 'Clear Key Import'},
        {'key': 'CSNBCVG',  'desc': 'Control Vector Generate'},
        {'key': 'CSNBCVT',  'desc': 'Control Vector Translate'},
        {'key': 'CSNBCVE',  'desc': 'Cryptographic Variable Encipher'},
        {'key': 'CSNBDKX',  'desc': 'Data Key Export'},
        {'key': 'CSNBDKM',  'desc': 'Data Key Import'},
        {'key': 'CSNBDCM',  'desc': 'Derive ICC MK'},
        {'key': 'CSNBDSK',  'desc': 'Derive Session Key'},
        {'key': 'CSNBDKG',  'desc': 'Diversified Key Generate'},
        {'key': 'CSNBDKG2', 'desc': 'Diversified Key Generate2'},
        {'key': 'CSNBDDK',  'desc': 'Diversify Directed Key'},
        {'key': 'CSNDEDH',  'desc': 'ECC Diffie-Hellman'},
        {'key': 'CSNBGIM',  'desc': 'Generate Issuer MK'},
        {'key': 'CSNBKET',  'desc': 'Key Encryption Translate'},
        {'key': 'CSNBKEX',  'desc': 'Key Export'},
        {'key': 'CSNBKGN',  'desc': 'Key Generate'},
        {'key': 'CSNBKGN2', 'desc': 'Key Generate2'},
        {'key': 'CSNBKIM',  'desc': 'Key Import'},
        {'key': 'CSNBKPI',  'desc': 'Key Part Import'},
        {'key': 'CSNBKPI2', 'desc': 'Key Part Import2'},
        {'key': 'CSNBKYT',  'desc': 'Key Test'},
        {'key': 'CSNBKYT2', 'desc': 'Key Test2'},
        {'key': 'CSNBKYTX', 'desc': 'Key Test Extended'},
        {'key': 'CSNBKTB',  'desc': 'Key Token Build'},
        {'key': 'CSNBKTB2', 'desc': 'Key Token Build2'},
        {'key': 'CSNBKTR',  'desc': 'Key Translate'},
        {'key': 'CSNBKTR2', 'desc': 'Key Translate2'},
        {'key': 'CSNBCKM',  'desc': 'Multiple Clear Key Import'},
        {'key': 'CSNBSKM',  'desc': 'Multiple Secure Key Import'},
        {'key': 'CSNDPKD',  'desc': 'PKA Decrypt'},
        {'key': 'CSNDPKE',  'desc': 'PKA Encrypt'},
        {'key': 'CSNBPEX',  'desc': 'Prohibit Export'},
        {'key': 'CSNBPEXX', 'desc': 'Prohibit Export Extended'},
        {'key': 'CSNBRNG',  'desc': 'Random Number Generate'},
        {'key': 'CSNBRNGL', 'desc': 'Random Number Generate Long'},
        {'key': 'CSNBRKX',  'desc': 'Remote Key Export'},
        {'key': 'CSNBRKA',  'desc': 'Restrict Key Attribute'},
        {'key': 'CSNBSKI',  'desc': 'Secure Key Import'},
        {'key': 'CSNBSKI2', 'desc': 'Secure Key Import2'},
        {'key': 'CSNDSYX',  'desc': 'Symmetric Key Export'},
        {'key': 'CSNDSXD',  'desc': 'Symmetric Key Export with Data'},
        {'key': 'CSNDSYG',  'desc': 'Symmetric Key Generate'},
        {'key': 'CSNBSYI',  'desc': 'Symmetric Key Import'},
        {'key': 'CSNBSYI2', 'desc': 'Symmetric Key Import2'},
        {'key': 'CSNDTBC',  'desc': 'Trusted Block Create'},
        {'key': 'CSNBUKD',  'desc': 'Unique Key Derive'},
    ],
    'Protecting data': [
        {'key': 'CSNBCTT2', 'desc': 'Cipher Text Translate2'},
        {'key': 'CSNBDEC',  'desc': 'Decipher'},
        {'key': 'CSNBDCO',  'desc': 'Decode'},
        {'key': 'CSNBENC',  'desc': 'Encipher'},
        {'key': 'CSNBECO',  'desc': 'Encode'},
        {'key': 'CSNBSAD',  'desc': 'Symmetric Algorithm Decipher'},
        {'key': 'CSNBSAE',  'desc': 'Symmetric Algorithm Encipher'},
        {'key': 'CSNBSYD',  'desc': 'Symmetric Key Decipher'},
        {'key': 'CSNBSYE',  'desc': 'Symmetric Key Encipher'},
    ],
    'Verifying data integrity and authenticating messages': [
        {'key': 'CSNBHMG',  'desc': 'HMAC Generate'},
        {'key': 'CSNBHMV',  'desc': 'HMAC Verify'},
        {'key': 'CSNBMGN',  'desc': 'MAC Generate'},
        {'key': 'CSNBMGN2', 'desc': 'MAC Generate2'},
        {'key': 'CSNBMVR',  'desc': 'MAC Verify'},
        {'key': 'CSNBMVR2', 'desc': 'MAC Verify2'},
        {'key': 'CSNBMDG',  'desc': 'MDC Generate'},
        {'key': 'CSNBMMS',  'desc': 'Multi-MAC Scheme'},
        {'key': 'CSNBOWH',  'desc': 'One-Way Hash'},
        {'key': 'CSNBSMG',  'desc': 'Symmetric MAC Generate'},
        {'key': 'CSNBSMV',  'desc': 'Symmetric MAC Verify'},
    ],
    'Financial services': [
        {'key': 'CSNBAPG',  'desc': 'Authentication Parameter Generate'},
        {'key': 'CSNBCPE',  'desc': 'Clear PIN Encrypt'},
        {'key': 'CSNBPGN',  'desc': 'Clear PIN Generate'},
        {'key': 'CSNBCPA',  'desc': 'Clear PIN Generate Alternate'},
        {'key': 'CSNBCKC',  'desc': 'CVV Key Combine'},
        {'key': 'CSNBESC',  'desc': 'EMV Scripting Service'},
        {'key': 'CSNBEAC',  'desc': 'EMV Transaction (ARQC/ARPC) Service'},
        {'key': 'CSNBEVF',  'desc': 'EMV Verification Functions'},
        {'key': 'CSNBEPG',  'desc': 'Encrypted PIN Generate'},
        {'key': 'CSNBPTR',  'desc': 'Encrypted PIN Translate'},
        {'key': 'CSNBPTR2', 'desc': 'Encrypted PIN Translate2'},
        {'key': 'CSNBPTRE', 'desc': 'Encrypted PIN Translate Extended'},
        {'key': 'CSNBPVR',  'desc': 'Encrypted PIN Verify'},
        {'key': 'CSNBPVR2', 'desc': 'Encrypted PIN Verify2'},
        {'key': 'CSNBFLD',  'desc': 'Field Level Decipher'},
        {'key': 'CSNBFLE',  'desc': 'Field Level Encipher'},
        {'key': 'CSNBFFXD', 'desc': 'Format Preserving Algorithms Decipher'},
        {'key': 'CSNBFFXE', 'desc': 'Format Preserving Algorithms Encipher'},
        {'key': 'CSNBFFXT', 'desc': 'Format Preserving Algorithms Translate'},
        {'key': 'CSNBFPED', 'desc': 'FPE Decipher'},
        {'key': 'CSNBFPEE', 'desc': 'FPE Encipher'},
        {'key': 'CSNBFPET', 'desc': 'FPE Translate'},
        {'key': 'CSNBPCU',  'desc': 'PIN Change/Unblock'},
        {'key': 'CSNBPFO',  'desc': 'Recover PIN from Offset'},
        {'key': 'CSNBSKY',  'desc': 'Secure Messaging for Keys'},
        {'key': 'CSNBSPN',  'desc': 'Secure Messaging for PINs'},
        {'key': 'CSNDSBC',  'desc': 'SET Block Compose'},
        {'key': 'CSNDSBD',  'desc': 'SET Block Decompose'},
        {'key': 'CSNBTRV',  'desc': 'Transaction Validation'},
        {'key': 'CSNBCSG',  'desc': 'VISA CVV Service Generate'},
        {'key': 'CSNBCSV',  'desc': 'VISA CVV Service Verify'},
    ],
    'Financial services for DK PIN methods': [
        {'key': 'CSNBDDPG', 'desc': 'DK Deterministic PIN Generate'},
        {'key': 'CSNBDMP',  'desc': 'DK Migrate PIN'},
        {'key': 'CSNBDPMT', 'desc': 'DK PAN Modify in Transaction'},
        {'key': 'CSNBDPT',  'desc': 'DK PAN Translate'},
        {'key': 'CSNBDPC',  'desc': 'DK PIN Change'},
        {'key': 'CSNBDPV',  'desc': 'DK PIN Verify'},
        {'key': 'CSNBDPNU', 'desc': 'DK PRW Card Number Update'},
        {'key': 'CSNBDCU2', 'desc': 'DK PRW Card Number Update2'},
        {'key': 'CSNBDPCG', 'desc': 'DK PRW CMAC Generate'},
        {'key': 'CSNBDRPG', 'desc': 'DK Random PIN Generate'},
        {'key': 'CSNBDRG2', 'desc': 'DK Random PIN Generate2'},
        {'key': 'CSNBDRP',  'desc': 'DK Regenerate PRW'},
    ],
    'X9.143 (TR-31) symmetric key management': [
        {'key': 'CSNBT31C', 'desc': 'TR-31 Create'},
        {'key': 'CSNBT31I', 'desc': 'TR-31 Import'},
        {'key': 'CSNBT31O', 'desc': 'TR-31 Optional Data Build'},
        {'key': 'CSNBT31R', 'desc': 'TR-31 Optional Data Read'},
        {'key': 'CSNBT31P', 'desc': 'TR-31 Parse'},
        {'key': 'CSNBT31X', 'desc': 'TR-31 Translate'},
    ],
    'TR-34 symmetric key management': [
        {'key': 'CSNDT34B', 'desc': 'TR-34 Bind-Begin'},
        {'key': 'CSNDT34C', 'desc': 'TR-34 Bind-Complete'},
        {'key': 'CSNDT34D', 'desc': 'TR-34 Key Distribution'},
        {'key': 'CSNDT34R', 'desc': 'TR-34 Key Receive'},
    ],
    'Using digital signatures': [
        {'key': 'CSNDDSG', 'desc': 'Digital Signature Generate'},
        {'key': 'CSNDDSV', 'desc': 'Digital Signature Verify'},
    ],
    'Managing PKA cryptographic keys': [
        {'key': 'CSNDPKG',  'desc': 'PKA Key Generate'},
        {'key': 'CSNDPKI',  'desc': 'PKA Key Import'},
        {'key': 'CSNDPKB',  'desc': 'PKA Key Token Build'},
        {'key': 'CSNDKTC',  'desc': 'PKA Key Token Change'},
        {'key': 'CSNDPKT',  'desc': 'PKA Key Translate'},
        {'key': 'CSNDPKX',  'desc': 'PKA Public Key Extract'},
        {'key': 'CSNDPIC',  'desc': 'Public Infrastructure Certificate'},
        {'key': 'CSNDRKD',  'desc': 'Retained Key Delete'},
        {'key': 'CSNDRKL',  'desc': 'Retained Key List'},
    ],
    'Key data set management': [
        {'key': 'CSNBKRC',  'desc': 'CKDS Key Record Create'},
        {'key': 'CSNBKRC2', 'desc': 'CKDS Key Record Create2'},
        {'key': 'CSNBKRD',  'desc': 'CKDS Key Record Delete'},
        {'key': 'CSNBKRR',  'desc': 'CKDS Key Record Read'},
        {'key': 'CSNBKRR2', 'desc': 'CKDS Key Record Read2'},
        {'key': 'CSNBKRW',  'desc': 'CKDS Key Record Write'},
        {'key': 'CSNBKRW2', 'desc': 'CKDS Key Record Write2'},
        {'key': 'CSFCRC',   'desc': 'Coordinated KDS Administration'},
        {'key': 'CSFMPS',   'desc': 'ICSF Multi-Purpose Service'},
        {'key': 'CSFKDSL',  'desc': 'Key Data Set List'},
        {'key': 'CSFKDMR',  'desc': 'Key Data Set Metadata Read'},
        {'key': 'CSFKDMW',  'desc': 'Key Data Set Metadata Write'},
        {'key': 'CSFRRT',   'desc': 'Key Data Set Record Retrieve'},
        {'key': 'CSFKDU',   'desc': 'Key Data Set Update'},
        {'key': 'CSNDKRC',  'desc': 'PKDS Key Record Create'},
        {'key': 'CSNDKRD',  'desc': 'PKDS Key Record Delete'},
        {'key': 'CSNDKRR',  'desc': 'PKDS Key Record Read'},
        {'key': 'CSNDKRR2', 'desc': 'PKDS Key Record Read2'},
        {'key': 'CSNDKRW',  'desc': 'PKDS Key Record Write'},
    ],
    'Utilities': [
        {'key': 'CSNBXBC',  'desc': 'Nibble to Character Conversion'},
        {'key': 'CSNBXCB',  'desc': 'Character to Nibble Conversion'},
        {'key': 'CSNBXAE',  'desc': 'ASCII to EBCDIC Conversion'},
        {'key': 'CSNBXEA',  'desc': 'EBCDIC to ASCII Conversion'},
        {'key': 'CSFSTAT',  'desc': 'Cryptographic Usage Statistic'},
        {'key': 'CSFIQA',   'desc': 'ICSF Query Algorithm'},
        {'key': 'CSFIQF',   'desc': 'ICSF Query Facility'},
        {'key': 'CSFIQF2',  'desc': 'ICSF Query Facility2'},
        {'key': 'CSNB9ED',  'desc': 'X9.9 Data Editing'},
    ],
    'Trusted Interfaces': [
        {'key': 'CSFPCI', 'desc': 'PCI Interface'},
    ],
    'Using PKCS #11 tokens and objects': [
        {'key': 'CSFPDMK', 'desc': 'PKCS #11 Derive Multiple Keys'},
        {'key': 'CSFPDVK', 'desc': 'PKCS #11 Derive Key'},
        {'key': 'CSFPGAV', 'desc': 'PKCS #11 Get Attribute Value'},
        {'key': 'CSFPGKP', 'desc': 'PKCS #11 Generate Key Pair'},
        {'key': 'CSFPGSK', 'desc': 'PKCS #11 Generate Secret Key'},
        {'key': 'CSFPHMG', 'desc': 'PKCS #11 Generate Keyed MAC'},
        {'key': 'CSFPHMV', 'desc': 'PKCS #11 Verify Keyed MAC'},
        {'key': 'CSFPOWH', 'desc': 'PKCS #11 One-Way Hash, Sign, or Verify'},
        {'key': 'CSFPPKS', 'desc': 'PKCS #11 Private Key Sign'},
        {'key': 'CSFPPKV', 'desc': 'PKCS #11 Public Key Verify'},
        {'key': 'CSFPPRF', 'desc': 'PKCS #11 Pseudo-Random Function'},
        {'key': 'CSFPSAV', 'desc': 'PKCS #11 Set Attribute Value'},
        {'key': 'CSFPSKD', 'desc': 'PKCS #11 Secret Key Decrypt'},
        {'key': 'CSFPSKE', 'desc': 'PKCS #11 Secret Key Encrypt'},
        {'key': 'CSFPSKR', 'desc': 'PKCS #11 Secret Key Reencrypt'},
        {'key': 'CSFPTRC', 'desc': 'PKCS #11 Token Record Create'},
        {'key': 'CSFPTRD', 'desc': 'PKCS #11 Token Record Delete'},
        {'key': 'CSFPTRL', 'desc': 'PKCS #11 Token Record List'},
        {'key': 'CSFPUWK', 'desc': 'PKCS #11 Unwrap Key'},
        {'key': 'CSFPWPK', 'desc': 'PKCS #11 Wrap Key'},
    ],
    'Using PKCS #11 key structure and raw key callable services': [
        {'key': 'CSFPGK2', 'desc': 'PKCS #11 Generate Secret Key2'},
        {'key': 'CSFPPD2', 'desc': 'PKCS #11 Private Key Structure Decrypt'},
        {'key': 'CSFPPS2', 'desc': 'PKCS #11 Private Key Structure Sign'},
        {'key': 'CSFPPE2', 'desc': 'PKCS #11 Public Key Structure Encrypt'},
        {'key': 'CSFPPV2', 'desc': 'PKCS #11 Public Key Structure Verify'},
    ],
}

CATEGORIES = list(VERB_DATA.keys())

# ---------------------------------------------------------------------------
# Persistent config  (pane widths, host/port saved between sessions)
# ---------------------------------------------------------------------------
_CONFIG_PATH  = pathlib.Path.home() / '.zccgui_config.json'
_HISTORY_PATH = pathlib.Path.home() / '.zccgui_history.json'

_DEFAULT_CONFIG = {
    'left_width': 220, 'cv_split_frac': 0.5, 'hist_height': 120,
    'maximized': 0, 'name_mode': 'long',
    'host': '127.0.0.1', 'port': '8080',
    'dark_mode': 0,
    'tls': 0,
    'tls_noverify': 0,
    'geometry': '1150x840',
}
_INT_KEYS   = {'left_width', 'hist_height', 'dark_mode', 'maximized', 'tls', 'tls_noverify'}
_FLOAT_KEYS = {'cv_split_frac'}


def _load_config() -> dict:
    try:
        data = json.loads(_CONFIG_PATH.read_text(encoding='utf-8'))
        cfg = dict(_DEFAULT_CONFIG)
        for k, v in data.items():
            if k not in _DEFAULT_CONFIG:
                continue
            if k in _INT_KEYS:
                cfg[k] = int(v)
            elif k in _FLOAT_KEYS:
                cfg[k] = float(v)
            else:
                cfg[k] = str(v)
        return cfg
    except Exception:
        return dict(_DEFAULT_CONFIG)


def _save_config(cfg: dict) -> None:
    try:
        _CONFIG_PATH.write_text(json.dumps(cfg), encoding='utf-8')
    except Exception:
        pass


# ---------------------------------------------------------------------------
# History serialisation helpers
# ---------------------------------------------------------------------------
_HISTORY_MAX = 200   # cap saved entries so the file stays manageable


def _serialise_history(history: list) -> list:
    """Convert a list of HistoryEntry objects to serialisable dicts.

    Bytes fields (req_buf, resp_buf) are stored as hex strings.
    BsonEl objects are omitted and reconstructed on load via zcc.parse().
    Drafts are excluded.  The returned list is capped to _HISTORY_MAX entries.
    """
    records = []
    for entry in history:
        if entry.draft_id is not None:
            continue
        records.append({
            'verb':        entry.verb,
            'args':        entry.args,
            'cmd_str':     entry.cmd_str,
            'param_metas': entry.param_metas,
            'param_vals':  entry.param_vals,
            'param_sobs':  entry.param_sobs,
            'cca_rc':      entry.cca_rc,
            'cca_rsn':     entry.cca_rsn,
            'req_hex':     entry.req_buf.hex()  if entry.req_buf  else '',
            'resp_hex':    entry.resp_buf.hex() if entry.resp_buf else '',
            'err_lines':   entry.err_lines,
            'ts':          getattr(entry, 'ts', '??:??:??'),
        })
    return records[-_HISTORY_MAX:]


def _deserialise_history(records: list) -> list:
    """Convert a list of dicts back to (HistoryEntry, lb_text, lb_colour) triples."""
    results = []
    for rec in records:
        try:
            req_buf  = bytes.fromhex(rec.get('req_hex',  '') or '')
            resp_buf = bytes.fromhex(rec.get('resp_hex', '') or '')
            try:
                elements = zcc.parse(resp_buf[4:]) if len(resp_buf) > 4 else []
            except Exception:
                elements = []
            entry = HistoryEntry(
                verb        = rec['verb'],
                args        = rec['args'],
                cmd_str     = rec.get('cmd_str', ''),
                param_metas = rec.get('param_metas', []),
                param_vals  = rec.get('param_vals',  []),
                param_sobs  = rec.get('param_sobs',  []),
                output_segs = [],
                cca_rc      = int(rec.get('cca_rc',  0)),
                cca_rsn     = int(rec.get('cca_rsn', 0)),
                req_buf     = req_buf,
                resp_buf    = resp_buf,
                elements    = elements,
                err_lines   = rec.get('err_lines', []),
            )
            entry.ts = rec.get('ts', '??:??:??')
            rc      = entry.cca_rc
            rsn     = entry.cca_rsn
            marker  = '✓' if rc == 0 else '✗'
            ts      = entry.ts
            lb_text = (f'  {ts}  {marker}  rc={rc:>3}  rsn={rsn:>6}'
                       f'  {entry.verb:<12}  ' + ' '.join(entry.args[1:]))
            lb_clr  = None if rc == 0 else CLR_RED
            results.append((entry, lb_text, lb_clr))
        except Exception:
            continue
    return results


def _save_history(history: list, path=None) -> None:
    """Write completed history entries to *path* (defaults to _HISTORY_PATH)."""
    if path is None:
        path = _HISTORY_PATH
    try:
        pathlib.Path(path).write_text(
            json.dumps(_serialise_history(history), indent=None), encoding='utf-8')
    except Exception:
        pass


def _load_history(path=None) -> list:
    """Load history from *path* (defaults to _HISTORY_PATH).

    Returns a list of (HistoryEntry, lb_text, lb_colour) triples,
    or an empty list if the file is missing or malformed.
    """
    if path is None:
        path = _HISTORY_PATH
    try:
        records = json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
    except Exception:
        return []
    return _deserialise_history(records)


# ---------------------------------------------------------------------------
# Colours / fonts
# ---------------------------------------------------------------------------
# Agilify brand palette
# Primary: Red #BE2B20, Grey #575757, Black #000000, White #FFFFFF
CLR_BG      = '#FFFFFF'   # white - main background
CLR_PANEL   = '#F5F5F5'   # near-white - panel / sidebar background
CLR_ACCENT  = '#BE2B20'   # Agilify red - primary accent
CLR_ACCENT2 = '#575757'   # Agilify grey - secondary / success neutral
CLR_FG      = '#000000'   # black - primary text
CLR_FG_DIM  = '#575757'   # Agilify grey - secondary text
CLR_SEL     = '#F5E6E5'   # pale red tint - listbox selection background
CLR_SEL_FG  = '#BE2B20'   # selected-item foreground (accent red in light mode)
CLR_BTN_FG  = '#000000'   # button / unselected-tab text
CLR_ENTRY   = '#FFFFFF'   # white - entry background
CLR_BORDER     = '#D8D8D8'   # light grey - borders / separators
CLR_INPUT_BORDER = '#D8D8D8' # entry / button border ring
CLR_RED     = '#BE2B20'   # Agilify red - errors
CLR_YELLOW  = '#B8640A'   # warm amber - warnings (accessible on white)
CLR_MONO_BG = '#F9F9F9'   # off-white - output pane background
CLR_TIP_BG  = '#000000'   # black - tooltip background
CLR_TIP_FG  = '#FFFFFF'   # white - tooltip text

# ---------------------------------------------------------------------------
# Dark-mode palette and global-colour switcher
# ---------------------------------------------------------------------------
_LIGHT = dict(
    BG='#FFFFFF', PANEL='#F5F5F5', MONO_BG='#F9F9F9', ENTRY='#FFFFFF',
    FG='#000000', FG_DIM='#575757', ACCENT2='#575757',
    BORDER='#D8D8D8', SEL='#F5E6E5',
    YELLOW='#B8640A', TIP_BG='#000000', TIP_FG='#FFFFFF',
    SEL_FG='#BE2B20',  # selected-item fg = accent red
    BTN_FG='#000000',
    INPUT_BORDER='#D8D8D8',
)
_DARK = dict(
    BG='#1C1C1C', PANEL='#252525', MONO_BG='#141414', ENTRY='#2A2A2A',
    FG='#D4D4D4', FG_DIM='#8A8A8A', ACCENT2='#8A8A8A',
    BORDER='#3C3C3C', SEL='#7A1A14',
    YELLOW='#CC8833', TIP_BG='#0A0A0A', TIP_FG='#D4D4D4',
    SEL_FG='#E8E8E8',  # selected-item fg = near-white (legible on dark sel bg)
    BTN_FG='#FFFFFF',
    INPUT_BORDER='#FFFFFF',
)


def _set_theme_colors(dark):
    global CLR_BG, CLR_PANEL, CLR_MONO_BG, CLR_ENTRY
    global CLR_FG, CLR_FG_DIM, CLR_ACCENT2
    global CLR_BORDER, CLR_SEL, CLR_YELLOW, CLR_TIP_BG, CLR_TIP_FG
    global CLR_SEL_FG, CLR_BTN_FG, CLR_INPUT_BORDER
    p = _DARK if dark else _LIGHT
    CLR_BG      = p['BG'];      CLR_PANEL   = p['PANEL']
    CLR_MONO_BG = p['MONO_BG']; CLR_ENTRY   = p['ENTRY']
    CLR_FG      = p['FG'];      CLR_FG_DIM  = p['FG_DIM']
    CLR_ACCENT2 = p['ACCENT2']; CLR_BORDER  = p['BORDER']
    CLR_SEL     = p['SEL'];     CLR_YELLOW  = p['YELLOW']
    CLR_TIP_BG  = p['TIP_BG']; CLR_TIP_FG  = p['TIP_FG']
    CLR_SEL_FG  = p['SEL_FG']
    CLR_BTN_FG  = p['BTN_FG']
    CLR_INPUT_BORDER = p['INPUT_BORDER']


# Fonts: Public Sans -> Segoe UI -> Calibri -> TkDefaultFont (best available)
# Headings use bold caps to approximate Calder Script all-caps style
_SANS = 'Segoe UI'        # Windows; falls back gracefully on macOS/Linux
FONT_UI      = (_SANS, 10)
FONT_BOLD    = (_SANS, 10, 'bold')
FONT_HEADING = (_SANS, 11, 'bold')   # rendered in upper-case in labels
FONT_SMALL   = (_SANS, 9)

# Pick the best available monospace font.  Consolas is ClearType-optimised
# and ships with Windows Vista+; it renders far more crisply than Courier New
# at small sizes.  Cascadia Mono ships with Windows Terminal / Win 11.
# Lucida Console is the oldest but still pixel-hinted and legible.
def _best_mono_font(size: int = 10) -> tuple:
    """Pick the best available monospace font for this platform.
    Consolas is ClearType-optimised and ships with Windows Vista+; it renders
    far more crisply than Courier New at small sizes.  Falls back gracefully
    through Cascadia Mono -> Lucida Console -> DejaVu Sans Mono -> Courier New."""
    try:
        available = set(_tkfont.families())
    except Exception:
        available = set()
    for name in ('Consolas', 'Cascadia Mono', 'Lucida Console',
                 'DejaVu Sans Mono', 'Courier New'):
        if name in available:
            return (name, size)
    return ('TkFixedFont', size)

FONT_MONO = ('Courier New', 10)   # placeholder; resolved after Tk root created


# ---------------------------------------------------------------------------
# Agilify logo - base64-encoded PNG, embedded so no external file is needed
# ---------------------------------------------------------------------------
import base64 as _base64
_AGILIFY_LOGO_B64 = (
    "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"
    "AABJRU5ErkJggg=="
)


def _make_logo_image(height: int = 40, bg_color: str = '#FFFFFF'):
    """Return a tk.PhotoImage of the Agilify wordmark composited onto bg_color.

    The source PNG has a transparent background; we composite it onto bg_color
    so the logo blends perfectly in both light and dark mode.
    """
    import io
    from PIL import Image, ImageTk
    data = _base64.b64decode(_AGILIFY_LOGO_B64)
    img  = Image.open(io.BytesIO(data)).convert('RGBA')
    # The embedded PNG is already at the correct scale; just composite
    h = bg_color.lstrip('#')
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    bg = Image.new('RGBA', img.size, (r, g, b, 255))
    bg.paste(img, mask=img.split()[3])
    return ImageTk.PhotoImage(bg.convert('RGB'))

def _make_moon_image(size=28, moon_color='#BE2B20', bg_color='#FFFFFF'):
    """Draw a solid crescent moon composited onto bg_color.

    Uses 4x supersampling for smooth antialiased edges.
    The crescent is formed by subtracting an offset disk from a full disk.
    """
    import io
    from PIL import Image, ImageDraw, ImageTk
    S = size * 4
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    h = moon_color.lstrip('#')
    mc = (int(h[0:2],16), int(h[2:4],16), int(h[4:6],16), 255)
    pad = S // 8
    # Full disk
    draw.ellipse([pad, pad, S-pad, S-pad], fill=mc)
    # Cutout disk shifted right + slightly up to carve the crescent
    sx, sy = S // 5, -S // 16
    draw.ellipse([pad+sx, pad+sy, S-pad+sx, S-pad+sy], fill=(0, 0, 0, 0))
    img = img.resize((size, size), Image.LANCZOS)
    # Composite onto bg
    bh = bg_color.lstrip('#')
    r, g, b = int(bh[0:2],16), int(bh[2:4],16), int(bh[4:6],16)
    bg = Image.new('RGBA', (size, size), (r, g, b, 255))
    bg.paste(img, mask=img.split()[3])
    return ImageTk.PhotoImage(bg.convert('RGB'))




# ---------------------------------------------------------------------------
# History entry - everything needed to replay a previous invocation
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class HistoryEntry:
    verb:        str
    args:        list
    cmd_str:     str
    param_metas: list
    param_vals:  list
    param_sobs:  list
    output_segs: list
    cca_rc:      int
    cca_rsn:     int
    draft_id:    str | None = None   # non-None -> draft (in-progress) entry
    req_buf:     bytes = dataclasses.field(default_factory=bytes)
    resp_buf:    bytes = dataclasses.field(default_factory=bytes)
    elements:    list  = dataclasses.field(default_factory=list)
    err_lines:   list  = dataclasses.field(default_factory=list)


# ===========================================================================
# Protocol helpers
# ===========================================================================

def _blocking_recv(sock: socket.socket, n: int) -> bytes:
    """Receive up to *n* bytes with no timeout (fully blocking).

    Setting timeout=None means the *only* way to unblock this call is for
    the socket to be closed or shut down from another thread -- exactly what
    ``_SocketHolder.cancel()`` does.  There is deliberately no internal
    timeout; the user controls expiry via the Cancel button.
    """
    sock.settimeout(None)
    return sock.recv(n)



def _bind_paste_replace(entry: 'tk.Entry') -> None:
    """Bind <<Paste>> on *entry* so that pasting replaces any selection.

    On Linux/X11, tkinter does not automatically delete the selected text
    before inserting clipboard content, so a double-click-then-paste
    appends rather than replaces.  This binding corrects that.
    On Windows and macOS the default behaviour is already correct, so the
    binding is harmless there.
    """
    def _on_paste(event):
        try:
            if entry.selection_present():
                entry.delete(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            pass
    entry.bind('<<Paste>>', _on_paste, add='+')

def zcc_call(host: str, port: int, args: list[str], holder=None, tls: bool = False, verify: bool = True):
    """Send one ZCC request; return (elements, raw_response_bytes).

    If *holder* is a :class:`_SocketHolder`, it is given the live socket so
    the caller can cancel the operation by calling ``holder.cancel()``.
    Reads are fully blocking with no internal timeout; cancellation is the
    user's responsibility via the Cancel button in the progress popup.
    """
    req_buf, _ = zcc.build_request(args)
    # Use the persistent connection; fall back to a one-shot socket on error.
    try:
        sock = _persistent_conn.get(host, port, tls, verify)
    except Exception:
        _persistent_conn.invalidate()
        sock = _connect_tls(host, port, verify=verify) if tls else _connect(host, port)
    if holder is not None:
        holder.set_sock(sock)
    try:
        sock.sendall(req_buf)

        # Read the 4-byte little-endian document-length header
        hdr = b''
        while len(hdr) < 4:
            chunk = _blocking_recv(sock, 4 - len(hdr))
            if not chunk:
                raise ConnectionError('Connection closed by server')
            hdr += chunk

        doclen = zcc.unpack_uint32_le(hdr)
        if doclen < 5 or doclen > zcc.BUFSIZE:
            raise ValueError(f'Reply document size {doclen} out of range')

        # Read the rest of the document
        resp = hdr
        while len(resp) < doclen:
            chunk = _blocking_recv(sock, doclen - len(resp))
            if not chunk:
                raise ConnectionError('Connection closed by server')
            resp += chunk

    except Exception:
        _persistent_conn.invalidate()
        raise
    return zcc.parse(resp[4:]), resp


def el_to_display(el: zcc.BsonEl) -> str:
    """Render a BsonEl value as a human-readable string."""
    if el.type == 0x02:
        raw = bytearray(el.value)
        for j in range(len(raw) - 1):
            if raw[j] < 32 or raw[j] > 127:
                raw[j] = ord('.')
        return bytes(raw).rstrip(b'\x00').decode('utf-8', 'replace')
    elif el.type == 0x05:
        return zcc.b2x(el.value)
    elif el.type == 0x01:
        return f'{zcc.unpack_double_le(el.value):.14g}'
    elif el.type == 0x10:
        return str(zcc.unpack_int32_le(el.value))
    return f'(type 0x{el.type:02X}, {el.valuelen} bytes)'


def capture_dump(buf: bytes) -> str:
    sio = io.StringIO()
    with redirect_stdout(sio):
        zcc.dump(buf)
    return sio.getvalue()


def parse_param_meta(elements: list[zcc.BsonEl]) -> list[dict]:
    """
    Parse the '?' introspection response into a list of parameter dicts,
    preserving the exact wire order returned by the backend.
    Each string element (except v/rc/rsn/zcc_time) holds a JSON object:
        {"dir":"in  ","opt":"N","type":"integer        ","name":"rule_array_count"}
    """
    params = []
    skip = {'v', 'rc', 'rsn', 'zcc_time', 'return_code', 'reason_code'}
    for el in elements:
        if el.name in skip:
            continue
        if el.type == 0x02:
            raw = bytearray(el.value)
            for j in range(len(raw) - 1):
                if raw[j] < 32 or raw[j] > 127:
                    raw[j] = ord('.')
            text = bytes(raw).rstrip(b'\x00').decode('utf-8', 'replace')
            try:
                meta = json.loads(text)
                meta['dir']   = meta.get('dir',  '').strip()
                meta['type']  = meta.get('type', '').strip()
                meta['opt']   = meta.get('opt',  'N').strip()
                meta['name']  = meta.get('name', el.name).strip()
                meta['sname'] = el.name.strip()   # short / wire-level name
                params.append(meta)
            except (json.JSONDecodeError, KeyError):
                pass
    # Wire order preserved - no sort
    return params


def fetch_error_text(host: str, port: int, rc: int, rsn: int,
                     holder=None, tls: bool = False, verify: bool = True) -> list[str]:
    """
    Call  cv=ERROR irc=<rc> irsn=<rsn>  and return the error text lines.
    lc  holds the line count; l1..ln hold the text.
    Returns an empty list if the call fails or returns no lines.
    """
    try:
        elements, _ = zcc_call(host, port,
                               ['cv=ERROR', f'irc={rc}', f'irsn={rsn}'],
                               holder=holder, tls=tls, verify=verify)
        by_name = {el.name: el for el in elements}
        lc_el = by_name.get('lc')
        if lc_el is None or lc_el.type != 0x10:
            return []
        lc = zcc.unpack_int32_le(lc_el.value)
        lines = []
        for i in range(1, lc + 1):
            el = by_name.get(f'l{i}')
            if el is not None:
                lines.append(el_to_display(el))
        return lines
    except Exception:
        return []



# ===========================================================================
# Splash screen
# ===========================================================================
_SPLASH_SHOWN = False   # only show once per process

_LEGAL_TEXT = (
    "MIT License\n"
    "\n"
    "Copyright (c) 2023-2026 Agilify Strategy and Innovation Pty Limited\n"
    "\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:\n"
    "\n"
    "The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n"
    "\n"
    "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE."
)


def _show_splash(root):
    """Display the Agilify splash / legal-notice screen.

    The window auto-dismisses after _SPLASH_TIMEOUT_S seconds and also
    closes immediately when the user clicks OK.  The splash is modal
    (grabs all input) and is shown only once per process.
    """
    global _SPLASH_SHOWN
    if _SPLASH_SHOWN:
        return
    _SPLASH_SHOWN = True

    import tkinter as _tk
    from tkinter import scrolledtext as _st

    WIN_W, WIN_H = 680, 500
    splash = _tk.Toplevel(root)
    splash.title("Agilify - Legal Notice")
    splash.resizable(False, False)
    splash.transient(root)

    # Centre on screen
    root.update_idletasks()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    splash.geometry(f"{WIN_W}x{WIN_H}+{(sw - WIN_W)//2}+{(sh - WIN_H)//2}")
    splash.configure(bg='#FFFFFF')
    splash.protocol('WM_DELETE_WINDOW', lambda: None)   # block X button

    # Red accent stripe at top
    _tk.Frame(splash, bg='#BE2B20', height=5).pack(fill='x')

    # Agilify logo (scaled larger than banner)
    logo_lbl = None
    try:
        logo_img = _make_logo_image(70, bg_color='#FFFFFF')
        logo_lbl = _tk.Label(splash, image=logo_img, bg='#FFFFFF', borderwidth=0)
        logo_lbl.image = logo_img   # keep reference alive
        logo_lbl.pack(pady=(20, 4))
    except Exception:
        _tk.Label(splash, text='Agilify', bg='#FFFFFF', fg='#BE2B20',
                  font=('Segoe UI', 22, 'bold')).pack(pady=(20, 4))

    _tk.Label(splash, text='ZERO-CLIENT CRYPTO (ZCC) TEST HARNESS',
              bg='#FFFFFF', fg='#BE2B20',
              font=('Segoe UI', 10, 'bold')).pack(pady=(0, 2))

    _tk.Label(splash, text='Agilify Strategy and Innovation',
              bg='#FFFFFF', fg='#575757',
              font=('Segoe UI', 9)).pack()

    _tk.Frame(splash, bg='#D8D8D8', height=1).pack(fill='x', padx=24, pady=(14, 0))

    # Legal text in a read-only ScrolledText
    txt = _st.ScrolledText(
        splash, wrap='word', width=72, height=9,
        bg='#F9F9F9', fg='#000000',
        font=('Segoe UI', 9),
        relief='flat', bd=0,
        padx=14, pady=10,
        state='normal')
    txt.insert('1.0', _LEGAL_TEXT)
    txt.configure(state='disabled')
    txt.pack(fill='both', expand=True, padx=24, pady=(10, 0))

    def _close():
        try:
            splash.destroy()
        except Exception:
            pass

    splash.after(5000, _close)   # auto-dismiss after 5 seconds
    splash.update()              # paint before returning

# ===========================================================================
# Persistent connection
# ===========================================================================

class _PersistentConn:
    """Keeps a single socket open across multiple ZCC calls.

    Optimistic: assumes the socket stays alive until a real I/O error
    proves otherwise.  ssl.SSLSocket non-blocking probes are unreliable
    (they raise ssl.SSLWantReadError, not BlockingIOError), so we skip
    the liveness check entirely.  zcc_call calls invalidate() on any
    exception, which closes the socket so the next call reconnects.
    The indicator dot turns green on connect and grey on close/error.
    """

    def __init__(self):
        self._sock      = None
        self._host      = None
        self._port      = None
        self._tls       = None
        self._verify    = None
        self._indicator = None   # tk.Label set by the GUI after _build_ui

    def _settings_changed(self, host, port, tls, verify):
        return (host   != self._host  or port   != self._port or
                tls    != self._tls   or verify != self._verify)

    def _close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._set_indicator(False)

    def _set_indicator(self, connected: bool):
        if self._indicator is not None:
            try:
                self._indicator.configure(
                    fg='#2E7D32' if connected else CLR_BORDER)
            except Exception:
                pass

    def get(self, host: str, port: int, tls: bool, verify: bool):
        """Return the persistent socket, creating it if needed."""
        if self._settings_changed(host, port, tls, verify):
            self._close()
        if self._sock is None:
            if tls:
                self._sock = _connect_tls(host, port, verify=verify)
            else:
                self._sock = _connect(host, port)
            self._host   = host;  self._port   = port
            self._tls    = tls;   self._verify = verify
            self._set_indicator(True)
        return self._sock

    def invalidate(self):
        """Force close -- called on any I/O failure or user cancel."""
        self._close()
_persistent_conn = _PersistentConn()


# ===========================================================================
# _SocketHolder  - thread-safe cancellable socket reference
# ===========================================================================
class _SocketHolder:
    """
    Passed into ``zcc_call`` so the GUI can abort a network operation at
    any time by calling ``cancel()``.

    Thread safety: the internal lock ensures that ``set_sock`` and
    ``cancel`` can be called concurrently without races.  If ``cancel``
    is called before ``set_sock``, the socket is dropped immediately when
    it is registered.
    """

    def __init__(self):
        self._lock      = threading.Lock()
        self._sock      = None
        self._cancelled = False

    # Called from the worker thread each time a new socket is opened.
    def set_sock(self, sock: socket.socket) -> None:
        with self._lock:
            self._sock = sock
            if self._cancelled:
                self._drop(sock)

    # Called from the main/GUI thread when the user presses Cancel.
    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            if self._sock is not None:
                self._drop(self._sock)

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @staticmethod
    def _drop(sock: socket.socket) -> None:
        """Shut down and close *sock*, silencing all errors."""
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass


# ===========================================================================
# ProgressPopup  - elapsed-time dialog with a Cancel button
# ===========================================================================
class ProgressPopup:
    """
    Shows a modal progress dialog after the operation has taken more than
    ``DELAY_MS`` milliseconds.  The dialog displays a live elapsed-time
    counter and a **Cancel** button that immediately drops the connection.

    Usage::

        holder = _SocketHolder()
        popup  = ProgressPopup(parent, holder, title='Executing CSNBKGN...')
        # ... start worker thread that calls zcc_call(..., holder=holder) ...
        # In the completion callback (always on the main thread):
        popup.dismiss()
    """

    DELAY_MS = 1000   # show popup after this many ms
    TICK_MS  =  100   # refresh the elapsed label every this many ms

    def __init__(self, parent: tk.Misc, holder: _SocketHolder,
                 title: str = 'Working...'):
        self._parent = parent
        self._holder = holder
        self._title  = title
        self._start  = time.monotonic()

        self._win:      tk.Toplevel | None = None
        self._lbl_time: tk.Label    | None = None
        self._show_id = parent.after(self.DELAY_MS, self._show)
        self._tick_id = None

    # -- Internal ---------------------------------------------------------

    def _show(self) -> None:
        self._show_id = None
        win = tk.Toplevel(self._parent)
        win.title('Working...')
        win.resizable(False, False)
        win.transient(self._parent)
        win.grab_set()
        win.protocol('WM_DELETE_WINDOW', self._on_cancel)
        win.configure(bg=CLR_BG)

        # Centre over parent
        self._parent.update_idletasks()
        px = self._parent.winfo_rootx() + self._parent.winfo_width()  // 2
        py = self._parent.winfo_rooty() + self._parent.winfo_height() // 2
        win.geometry(f'340x148+{px - 170}+{py - 74}')

        # Red accent stripe at the top
        tk.Frame(win, bg=CLR_ACCENT, height=4).pack(fill='x')

        inner = tk.Frame(win, bg=CLR_BG, padx=22, pady=14)
        inner.pack(fill='both', expand=True)

        tk.Label(inner, text=self._title,
                 bg=CLR_BG, fg=CLR_FG,
                 font=FONT_BOLD, anchor='w').pack(fill='x')

        tk.Label(inner, text='Waiting for server response...',
                 bg=CLR_BG, fg=CLR_FG_DIM,
                 font=FONT_SMALL, anchor='w').pack(fill='x', pady=(2, 0))

        self._lbl_time = tk.Label(
            inner, text='Elapsed:  0.0 s',
            bg=CLR_BG, fg=CLR_ACCENT2,
            font=(_SANS, 10, 'bold'), anchor='w')
        self._lbl_time.pack(fill='x', pady=(6, 0))

        tk.Frame(inner, bg=CLR_BORDER, height=1).pack(fill='x', pady=(10, 0))

        btn_row = tk.Frame(inner, bg=CLR_BG)
        btn_row.pack(fill='x', pady=(8, 0))

        tk.Button(
            btn_row,
            text='✕  Cancel request',
            bg=CLR_ACCENT, fg='#FFFFFF',
            font=FONT_BOLD,
            relief='flat', bd=0,
            padx=14, pady=5,
            cursor='hand2',
            activebackground='#8B1F16',
            activeforeground='#FFFFFF',
            command=self._on_cancel,
        ).pack(side='right')

        self._win = win
        self._tick()

    def _tick(self) -> None:
        if self._win is None or not self._win.winfo_exists():
            return
        elapsed = time.monotonic() - self._start
        self._lbl_time.configure(text=f'Elapsed:  {elapsed:.1f} s')
        self._tick_id = self._parent.after(self.TICK_MS, self._tick)

    def _on_cancel(self) -> None:
        """User clicked Cancel (or closed the window): drop the connection."""
        self._holder.cancel()
        # Dismissal happens in the worker's completion callback so the
        # error message still reaches _execute_error / _introspect_error.

    # -- Public -----------------------------------------------------------

    def dismiss(self) -> None:
        """Hide and destroy the popup.  Safe to call even if never shown."""
        if self._show_id is not None:
            self._parent.after_cancel(self._show_id)
            self._show_id = None
        if self._tick_id is not None:
            self._parent.after_cancel(self._tick_id)
            self._tick_id = None
        if self._win is not None:
            try:
                self._win.grab_release()
                self._win.destroy()
            except Exception:
                pass
            self._win = None


# ===========================================================================
# Tooltip  - lightweight flyover popup for truncated values
# ===========================================================================
class Tooltip:
    """
    Attach to any widget.  After DELAY ms of hovering, a popup label
    appears near the cursor with the full text.  Dismisses on Leave.
    """
    DELAY = 600   # ms before popup appears

    def __init__(self, widget: tk.Widget, text_func):
        """
        text_func: callable() -> str  (called at show time so value is current)
        """
        self._widget    = widget
        self._text_func = text_func
        self._tip_win: tk.Toplevel | None = None
        self._after_id = None
        widget.bind('<Enter>', self._on_enter, add='+')
        widget.bind('<Leave>', self._on_leave, add='+')
        widget.bind('<ButtonPress>', self._on_leave, add='+')

    def _on_enter(self, _e):
        self._after_id = self._widget.after(self.DELAY, self._show)

    def _on_leave(self, _e):
        if self._after_id:
            self._widget.after_cancel(self._after_id)
            self._after_id = None
        self._hide()

    def _show(self):
        text = self._text_func()
        if not text:
            return
        x = self._widget.winfo_rootx() + 10
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._tip_win = tw = tk.Toplevel(self._widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f'+{x}+{y}')
        # Wrap long text at 120 chars per line
        wrapped = '\n'.join(
            text[i:i+120] for i in range(0, min(len(text), 2400), 120)
        )
        lbl = tk.Label(tw, text=wrapped, bg=CLR_TIP_BG, fg=CLR_TIP_FG,
                       font=FONT_MONO, justify='left',
                       relief='flat',  bd=0, highlightthickness=1, highlightbackground=CLR_INPUT_BORDER, padx=6, pady=4)
        lbl.pack()

    def _hide(self):
        if self._tip_win:
            self._tip_win.destroy()
            self._tip_win = None


# ===========================================================================
# TwoWayScrollFrame  - canvas with both vertical AND horizontal scrollbars
# ===========================================================================
class TwoWayScrollFrame(tk.Frame):
    """
    A Frame whose content can scroll both vertically and horizontally.
    Place child widgets in  self.inner.
    """
    def __init__(self, parent, **kw):
        bg = kw.pop('bg', CLR_PANEL)
        super().__init__(parent, bg=bg, **kw)

        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        vsb = ttk.Scrollbar(self, orient='vertical',   command=self.canvas.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        self.canvas.grid(row=0, column=0, sticky='nsew')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win  = self.canvas.create_window((0, 0), window=self.inner,
                                               anchor='nw')
        self.inner.bind('<Configure>', self._on_inner_configure)

        # Vertical mouse-wheel on the canvas itself
        self.canvas.bind('<MouseWheel>', self._on_vert_wheel)
        self.canvas.bind('<Button-4>',   self._on_vert_wheel)
        self.canvas.bind('<Button-5>',   self._on_vert_wheel)

    def _on_inner_configure(self, _e):
        self.canvas.configure(scrollregion=self.canvas.bbox('all'))

    def _on_vert_wheel(self, e):
        if e.num == 4:
            self.canvas.yview_scroll(-1, 'units')
        elif e.num == 5:
            self.canvas.yview_scroll(1, 'units')
        else:
            self.canvas.yview_scroll(int(-1 * (e.delta / 120)), 'units')

    def bind_mousewheel(self, widget: tk.Widget):
        """Bind vertical wheel on a child widget to scroll the canvas."""
        widget.bind('<MouseWheel>', self._on_vert_wheel, add='+')
        widget.bind('<Button-4>',   self._on_vert_wheel, add='+')
        widget.bind('<Button-5>',   self._on_vert_wheel, add='+')



# ===========================================================================
# RuleArrayRow  - specialised input row for rule_array parameters
# ===========================================================================
# rule_array is a concatenated sequence of 8-character keywords, each padded
# with spaces to exactly 8 bytes.  The widget presents a 3-row × 5-column
# grid of 8-character Entry boxes (15 keyword slots).

def _pack_rule_array(text: str) -> str:
    """Convert space-separated keywords into a concatenated 8-char padded string."""
    tokens = text.split()
    return ''.join(f'{t:<8}' for t in tokens)


_RA_ROWS = 3
_RA_COLS = 5   # 3 × 5 = 15 keyword slots


class RuleArrayRow(tk.Frame):
    """Input row for rule_array: 3×5 grid of 8-char Entry boxes."""
    # Set by ZccGui after build; shared by all instances
    _name_mode_var: tk.StringVar | None = None

    def __init__(self, parent, meta: dict, scroll_frame: TwoWayScrollFrame,
                 **kw):
        super().__init__(parent, bg=kw.get('bg', CLR_PANEL))
        self.meta = meta
        self._scroll_frame = scroll_frame
        bg = kw.get('bg', CLR_PANEL)

        direction = meta['dir']
        optional  = meta['opt'] == 'Y'
        is_input  = direction in ('in', 'both')

        # -- column 0: direction badge --------------------------------
        badge_text = {'in': ' IN ', 'out': ' OUT', 'both': 'BOTH'}.get(
            direction, direction)
        badge_clr  = {'in': CLR_ACCENT, 'out': CLR_FG_DIM,
                      'both': '#8B1F16'}.get(direction, CLR_FG_DIM)
        badge = tk.Label(self, text=badge_text, bg=badge_clr, fg='#FFFFFF',
                         font=FONT_SMALL, width=4, relief='flat')
        badge.grid(row=0, column=0, padx=(4, 6), pady=3, sticky='nw')
        scroll_frame.bind_mousewheel(badge)

        # -- column 1: parameter name (spans all grid rows) -----------
        req_marker = '' if optional else ' *'
        sname = meta.get('sname', '')
        sname_suffix = f'  ({sname})' if sname and sname != meta['name'] else ''
        lbl = tk.Label(self, text=f"{meta['name']}{req_marker}{sname_suffix}",
                       bg=bg, fg=CLR_FG, font=FONT_BOLD, anchor='nw', width=28)
        lbl.grid(row=0, column=1, rowspan=_RA_ROWS, padx=4, sticky='nw')
        scroll_frame.bind_mousewheel(lbl)
        Tooltip(lbl, lambda: 'Fill keyword slots (each max 8 chars, space-padded automatically).')

        # -- column 2: type label -------------------------------------
        tlbl = tk.Label(self, text='rule array',
                        bg=bg, fg=CLR_FG_DIM,
                        font=FONT_SMALL, anchor='nw', width=18)
        tlbl.grid(row=0, column=2, rowspan=_RA_ROWS, padx=4, sticky='nw')
        scroll_frame.bind_mousewheel(tlbl)

        # -- column 3: 3×5 grid of 8-char keyword entries -------------
        self._cell_vars: list[tk.StringVar] = []
        self._cells:     list[tk.Entry]     = []

        if is_input:
            grid_frame = tk.Frame(self, bg=bg)
            grid_frame.grid(row=0, column=3, rowspan=_RA_ROWS,
                            padx=4, pady=3, sticky='w')
            scroll_frame.bind_mousewheel(grid_frame)

            for r in range(_RA_ROWS):
                for c in range(_RA_COLS):
                    var = tk.StringVar()
                    self._cell_vars.append(var)
                    e = tk.Entry(
                        grid_frame, textvariable=var,
                        bg=CLR_ENTRY, fg=CLR_FG,
                        insertbackground=CLR_ACCENT,
                        relief='flat',  bd=0,
                        highlightthickness=1,
                        highlightbackground=CLR_INPUT_BORDER,
                        highlightcolor=CLR_ACCENT,
                        font=FONT_MONO,
                        width=9,        # 8 chars + 1 for cursor comfort
                        justify='left')
                    e.grid(row=r, column=c, padx=(0, 3), pady=(0, 2))
                    self._cells.append(e)
                    scroll_frame.bind_mousewheel(e)
                    _bind_paste_replace(e)
                    # Tab order: left-to-right, top-to-bottom (default)
        else:
            out_lbl = tk.Label(self, text='(output)', bg=bg,
                               fg=CLR_FG_DIM, font=FONT_SMALL)
            out_lbl.grid(row=0, column=3, padx=4, sticky='w')
            scroll_frame.bind_mousewheel(out_lbl)

        self.columnconfigure(3, weight=1)
        scroll_frame.bind_mousewheel(self)

    # -- Synthetic StringVar that aggregates all cells -----------------
    # _update_draft traces on 'var'; we expose a virtual var that returns
    # the space-joined keywords so the existing trace machinery works.

    class _AggVar:
        """Quacks like tk.StringVar for the purposes of trace_add / get / set."""
        def __init__(self, row: 'RuleArrayRow'):
            self._row = row
            self._traces: list = []
            self._tk_vars: list[tk.StringVar] = []   # populated after cells exist

        def _attach(self, cell_vars: list):
            self._tk_vars = cell_vars
            for cv in cell_vars:
                cv.trace_add('write', self._on_cell_write)

        def _on_cell_write(self, *_):
            for cb in self._traces:
                try:
                    cb()
                except Exception:
                    pass

        def trace_add(self, mode, callback):
            # Store callback; called whenever any cell changes
            self._traces.append(callback)

        def get(self) -> str:
            """Return space-joined non-empty keywords (draft preview format)."""
            return ' '.join(
                v.get().strip() for v in self._tk_vars if v.get().strip()
            )

        def set(self, value: str):
            """Populate cells from a space-separated string of keywords."""
            tokens = value.split()
            for i, cv in enumerate(self._tk_vars):
                cv.set(tokens[i] if i < len(tokens) else '')

    @property
    def var(self) -> _AggVar:
        if not hasattr(self, '_agg_var'):
            self._agg_var = RuleArrayRow._AggVar(self)
            self._agg_var._attach(self._cell_vars)
        return self._agg_var

    def to_arg(self) -> str | None:
        if self.meta['dir'] == 'out':
            return None
        keywords = [v.get().strip() for v in self._cell_vars if v.get().strip()]
        if not keywords:
            return None
        packed = ''.join(f'{kw:<8}' for kw in keywords)
        mode = (ParamRow._name_mode_var.get()
                if ParamRow._name_mode_var else 'long')
        name = (self.meta.get('sname') or self.meta['name']
                if mode == 'short' else self.meta['name'])
        return f'c{name}={packed}'

    def is_valid(self) -> bool:
        if self.meta['dir'] == 'out':
            return True
        if self.meta['opt'] == 'Y':
            return True
        return any(v.get().strip() for v in self._cell_vars)


# ===========================================================================
# ParamRow  - one parameter row in the form
# ===========================================================================
class ParamRow(tk.Frame):
    """Direction badge | name | type | entry/browse -- all in one row."""
    # Set by ZccGui after build; shared by all instances
    _name_mode_var: tk.StringVar | None = None

    def __init__(self, parent, meta: dict, scroll_frame: TwoWayScrollFrame,
                 **kw):
        super().__init__(parent, bg=kw.get('bg', CLR_PANEL))
        self.meta        = meta
        self._from_file  = False
        self._scroll_frame = scroll_frame

        direction = meta['dir']
        ptype     = meta['type']
        optional  = meta['opt'] == 'Y'
        is_input  = direction in ('in', 'both')

        # -- direction badge ------------------------------------------
        badge_text = {'in': ' IN ', 'out': ' OUT', 'both': 'BOTH'}.get(
            direction, direction)
        badge_clr = {'in': CLR_ACCENT, 'out': CLR_FG_DIM,
                     'both': '#8B1F16'}.get(direction, CLR_FG_DIM)
        badge = tk.Label(self, text=badge_text, bg=badge_clr, fg='#FFFFFF',
                         font=FONT_SMALL, width=4, relief='flat')
        badge.grid(row=0, column=0, padx=(4, 6), pady=3, sticky='w')
        scroll_frame.bind_mousewheel(badge)

        # -- name -----------------------------------------------------
        req_marker = '' if optional else ' *'
        sname = meta.get('sname', '')
        sname_suffix = f'  ({sname})' if sname and sname != meta['name'] else ''
        lbl = tk.Label(self,
                       text=f"{meta['name']}{req_marker}{sname_suffix}",
                       bg=kw.get('bg', CLR_PANEL),
                       fg=CLR_FG if is_input else CLR_FG_DIM,
                       font=FONT_BOLD if is_input else FONT_UI,
                       anchor='w', width=28)
        lbl.grid(row=0, column=1, padx=4, sticky='w')
        scroll_frame.bind_mousewheel(lbl)
        Tooltip(lbl, lambda m=meta: f"{m['name']}  ({m['dir']}, {m['type']})")

        # -- type hint -------------------------------------------------
        tlbl = tk.Label(self, text=ptype, bg=kw.get('bg', CLR_PANEL),
                        fg=CLR_FG_DIM, font=FONT_SMALL, anchor='w', width=18)
        tlbl.grid(row=0, column=2, padx=4, sticky='w')
        scroll_frame.bind_mousewheel(tlbl)

        # -- string_or_binary radio buttons (row 1, col 2 - below type label) --
        # 'type_label' always stays in row 0 col 2 so every row's entry
        # widget lands at exactly the same x position (col 3, row 0).
        # For SOB params the compact char/hex pair lives in row 1 col 2.
        self._sob_var: tk.StringVar | None = None
        entry_col  = 3   # fixed for ALL param types
        browse_col = 4

        if is_input and ptype == 'string_or_binary':
            self._sob_var = tk.StringVar(value='x')
            rb_frame = tk.Frame(self, bg=kw.get('bg', CLR_PANEL))
            rb_frame.grid(row=1, column=2, padx=(4, 0), pady=(0, 2), sticky='w')
            scroll_frame.bind_mousewheel(rb_frame)
            for rb_text, rb_val in (('char', 'c'), ('hex', 'x')):
                rb = tk.Radiobutton(
                    rb_frame, text=rb_text, variable=self._sob_var,
                    value=rb_val, bg=kw.get('bg', CLR_PANEL), fg=CLR_FG,
                    selectcolor=CLR_ENTRY, activebackground=kw.get('bg', CLR_PANEL),
                    activeforeground=CLR_FG, font=FONT_SMALL,
                    relief='flat', bd=0)
                rb.pack(side='left', padx=(0, 6))
                scroll_frame.bind_mousewheel(rb)

        # -- value entry -----------------------------------------------
        self.var = tk.StringVar()
        self._err_lbl: tk.Label | None = None   # inline error message label
        self._entry_col = entry_col

        if is_input:
            # Integer fields are short; everything else gets a wide entry.
            entry_width = 10 if 'integer' in ptype else 62
            self.entry = tk.Entry(self, textvariable=self.var,
                                  bg=CLR_ENTRY, fg=CLR_FG,
                                  insertbackground=CLR_ACCENT,
                                  relief='flat',  bd=0,
                                  highlightthickness=1,
                                  highlightbackground=CLR_INPUT_BORDER,
                                  highlightcolor=CLR_ACCENT,
                                  font=FONT_MONO, width=entry_width)
            self.entry.grid(row=0, column=entry_col, padx=4, pady=3,
                            sticky='ew' if entry_width == 48 else 'w')
            scroll_frame.bind_mousewheel(self.entry)
            _bind_paste_replace(self.entry)
            Tooltip(self.entry, lambda: self.var.get())
            if entry_width == 48:
                self.columnconfigure(entry_col, weight=1)

            # Live validation for integer and binary (hex) types
            if 'integer' in ptype:
                self.var.trace_add('write', self._validate_integer)
            elif ptype == 'string_or_binary':
                # Watch both the value and the radio-button var
                self.var.trace_add('write', self._validate_sob)
                if self._sob_var:
                    self._sob_var.trace_add('write', self._validate_sob)
            elif 'binary' in ptype:
                # Pure binary fields are always hex
                self.var.trace_add('write', self._validate_binary)
        else:
            out_lbl = tk.Label(self, text='(output)',
                               bg=kw.get('bg', CLR_PANEL),
                               fg=CLR_FG_DIM, font=FONT_SMALL)
            out_lbl.grid(row=0, column=entry_col, padx=4, sticky='w')
            scroll_frame.bind_mousewheel(out_lbl)

        scroll_frame.bind_mousewheel(self)

    # -- Validation helpers --------------------------------------------
    @staticmethod
    def _is_valid_hex(val: str) -> bool:
        """Even number of hex digits (spaces stripped, case-insensitive)."""
        v = val.strip().replace(' ', '')
        return len(v) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in v)

    @staticmethod
    def _is_valid_int(val: str) -> bool:
        """Optional leading minus, then digits; or 0x/0X hex prefix."""
        v = val.strip()
        if not v:
            return True   # empty is allowed (caught by is_valid for required)
        try:
            int(v, 0)     # accepts decimal, 0x hex, 0o octal
            return True
        except ValueError:
            return False

    def _set_entry_error(self, msg: str | None):
        """Show/clear the red border and inline error message."""
        if msg:
            self.entry.configure(highlightbackground=CLR_RED,
                                 highlightcolor=CLR_RED,
                                 highlightthickness=1)
            if self._err_lbl is None:
                self._err_lbl = tk.Label(
                    self, text='', bg=self.cget('bg'),
                    fg=CLR_RED, font=(_SANS, 8))
                self._err_lbl.grid(row=1, column=self._entry_col,
                                   padx=4, sticky='w')
                self._scroll_frame.bind_mousewheel(self._err_lbl)
            self._err_lbl.configure(text=msg)
        else:
            self.entry.configure(highlightbackground=CLR_INPUT_BORDER,
                                 highlightcolor=CLR_ACCENT,
                                 highlightthickness=1)
            if self._err_lbl is not None:
                self._err_lbl.destroy()
                self._err_lbl = None

    def _validate_integer(self, *_):
        val = self.var.get().strip()
        if val and not self._is_valid_int(val):
            self._set_entry_error('Must be a valid integer (e.g. 42, -7, 0xFF)')
        else:
            self._set_entry_error(None)

    def _validate_sob(self, *_):
        """Validate string_or_binary and pure binary entries."""
        val  = self.var.get().strip()
        mode = self._sob_var.get() if self._sob_var else 'x'
        if mode == 'x' and val:
            v = val.replace(' ', '')
            if not all(c in '0123456789abcdefABCDEF' for c in v):
                self._set_entry_error('Binary value must contain hex digits only')
            elif len(v) % 2 != 0:
                self._set_entry_error(
                    f'Hex string must have an even number of digits '
                    f'(currently {len(v)})')
            else:
                self._set_entry_error(None)
        else:
            self._set_entry_error(None)

    def _validate_binary(self, *_):
        """Validate a pure binary (always hex) field."""
        val = self.var.get().strip()
        if not val:
            self._set_entry_error(None)
            return
        v = val.replace(' ', '')
        if not all(c in '0123456789abcdefABCDEF' for c in v):
            self._set_entry_error('Must contain hex digits only (0-9, A-F)')
        elif len(v) % 2 != 0:
            self._set_entry_error(
                f'Even number of hex digits required (currently {len(v)})')
        else:
            self._set_entry_error(None)

    def to_arg(self) -> str | None:
        if self.meta['dir'] == 'out':
            return None
        ptype = self.meta['type']
        mode  = (ParamRow._name_mode_var.get()
                 if ParamRow._name_mode_var else 'long')
        name  = (self.meta.get('sname') or self.meta['name']
                 if mode == 'short' else self.meta['name'])
        val   = self.var.get().strip()
        if not val:
            return None
        if 'integer' in ptype:
            t = 'i'
        elif ptype == 'string_or_binary':
            t = self._sob_var.get() if self._sob_var else 'c'
        elif 'binary' in ptype:
            t = 'x'
        else:
            t = 'c'
        prefix = f'f{t}' if self._from_file else t
        return f'{prefix}{name}={val}'

    def is_valid(self) -> bool:
        if self.meta['dir'] == 'out':
            return True
        ptype = self.meta['type']
        val   = self.var.get().strip()
        # Format validation (regardless of optional/required)
        if val:
            if 'integer' in ptype and not self._is_valid_int(val):
                return False
            mode = self._sob_var.get() if self._sob_var else None
            # For string_or_binary, only validate as hex when Binary is selected.
            # 'binary' in ptype also matches 'string_or_binary', so check mode first.
            is_hex_field = (mode == 'x') or (ptype != 'string_or_binary' and 'binary' in ptype)
            if is_hex_field:
                if not self._is_valid_hex(val):
                    return False
        # Required-field check
        if self.meta['opt'] != 'Y':
            return bool(val)
        return True


# ===========================================================================
# HScrollListbox  - Listbox with a horizontal scrollbar underneath
# ===========================================================================
class HScrollListbox(tk.Frame):
    """Listbox with vertical + horizontal scrollbars."""

    def __init__(self, parent, **kw):
        bg = kw.pop('bg', CLR_PANEL)
        lb_kw = {k: v for k, v in kw.items()
                 if k in ('font', 'selectbackground', 'selectforeground',
                          'activestyle', 'exportselection')}
        super().__init__(parent, bg=bg)

        self.lb = tk.Listbox(
            self, bg=bg, fg=CLR_FG, relief='flat', bd=0,
            highlightthickness=0, **lb_kw)

        vsb = ttk.Scrollbar(self, orient='vertical',   command=self.lb.yview)
        hsb = ttk.Scrollbar(self, orient='horizontal', command=self.lb.xview)
        self.lb.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        self.lb.grid(row=0, column=0, sticky='nsew')
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # Tooltip on the listbox: show full text of hovered item
        self._tip: Tooltip | None = None
        self._hovered_idx: int | None = None
        self.lb.bind('<Motion>',  self._on_motion)
        self.lb.bind('<Leave>',   self._on_lb_leave)
        self._tip_win: tk.Toplevel | None = None
        self._after_id = None

    # -- Tooltip-on-hover for listbox items ----------------------------
    def _on_motion(self, e):
        idx = self.lb.nearest(e.y)
        if idx == self._hovered_idx:
            return
        self._cancel_tip()
        self._hovered_idx = idx
        self._after_id = self.lb.after(Tooltip.DELAY, lambda: self._show_tip(idx))

    def _on_lb_leave(self, _e):
        self._cancel_tip()
        self._hovered_idx = None

    def _cancel_tip(self):
        if self._after_id:
            self.lb.after_cancel(self._after_id)
            self._after_id = None
        if self._tip_win:
            self._tip_win.destroy()
            self._tip_win = None

    def _show_tip(self, idx: int):
        try:
            text = self.lb.get(idx).strip()
        except Exception:
            return
        if not text:
            return
        x = self.lb.winfo_rootx() + self.lb.winfo_width() + 4
        y = self.lb.winfo_rooty() + 4
        self._tip_win = tw = tk.Toplevel(self.lb)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f'+{x}+{y}')
        tk.Label(tw, text=text, bg=CLR_TIP_BG, fg=CLR_TIP_FG,
                 font=FONT_UI, justify='left',
                 relief='flat',  bd=0, highlightthickness=1, highlightbackground=CLR_INPUT_BORDER, padx=6, pady=4).pack()

    # Delegate common Listbox methods
    def insert(self, idx, *args): self.lb.insert(idx, *args)
    def delete(self, *args):      self.lb.delete(*args)
    def get(self, *args):         return self.lb.get(*args)
    def curselection(self):       return self.lb.curselection()
    def bind(self, seq, func, **kw): self.lb.bind(seq, func, **kw)
    def configure(self, **kw):    self.lb.configure(**kw)
    def itemconfig(self, idx, **kw): self.lb.itemconfig(idx, **kw)
    def see(self, idx):           self.lb.see(idx)
    def size(self):               return self.lb.size()



# ---------------------------------------------------------------------------
# Agilify "A" icon - used for the window/taskbar icon (wm_iconphoto)
# ---------------------------------------------------------------------------
_AGILIFY_ICON_B64 = {
    16: "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAABZUlEQVR4nJVSTS8DURS9771pMyUsJNjQRISNiIQdS4kfIRGxYCmIRJM2XQmxF0JELIigqTRI/QrsUE01Vf2wKCbSqZk391k0npm2kvYu3zn33HPPfUQIAfWUEEAIACj/wgDCsvIXEVPTOkfH3H39EqpRyLkQIrm1GfUoV4ryvrMtIVpDHZEwVozHExvrLQOD7o42oqoSrdFQ9vOwskxcrp7FJdR1sO1ZuYOwLMJY5ugwG44MHey3Do/wL53QP13HBLQsQmnpNf3o97VPjHdNz2CxSJhDscoSIbFggGta9+xcKf2ip1JAiR13WKKM5cKh/HmYetT7hXk0TaqqrKlZIFY1IAKlRqEQCwZUr7fX5ycAwJiefH5aWyXMZus3eRSId1OTlwDZ0JlM/fP2JqIoH3u78sV2ONPMnJ68XUfLh0PDQM6/87n08ZGRSEgWafQvOWPlXFhWBQ9NU7IBoO4JMsmG2ADwAyx18aM30xF+AAAAAElFTkSuQmCC",
    32: "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAC60lEQVR4nO2VTUhUURTHz7n3znPU8ePljLpQc5FULoKWRW2KMKxFRK0jKDWCiAj6EDFFSwiziCKIsqIW0S5saS1tUaAQ0ZgmOkWgI690ct7Mu/eeFs8+cN6MjiW18G7fuf/f+fjfd5CIYCWPWP7VBZkRAWOpUfhfVkAEAI5lvTnepONx5FxLyfPyNvc+AL//LwBIa+R8pLN9su+pr9gkrUlKUVQIWqcGZw0gpZDz6ef9nx499FdUuqIkJc8PeMZ7jCWjPAGinJ0dbjnPDIOk1LZNRKQ1eaWfNYC0RsY+XO6KhcMsJ4fn5ZnbtmvbRsR0V7IAuM358nIgcud2TmlpcmqqqvFYyY6danYWOP9jABEgatsON59FLtTcXGD9hqqGJjkzk0E9C4DbnLFrPTODg6KgQMXjNa1tKIROJDL0Z6kA15czQ0PjN64boVAyOlW+b3+ofg8AoFjEh0sAEAERSTncfIaUIqWMNSXrWlo9Xb8cgJv+xK2b1sCAzzST0Wj1qdP+igqVSJDWC/9IKWeRAl31b8PhsZ5uo6TEsaxQ3e6qo40AwHNzAQANIzNjsZdMBETh5nNqbk4UFyPD4K66r69fkVIAgJzbkQn0+eYZXsPOBHCN//He3ekX/UYwRErx/MDopQ7tOL+kOOeBAEkJAOBVSVqA68v4xPho10VRWERaq1gMtAZEQPwpxQAgo5HSfyMCxoZbmh3L8pmmTiTMLVuZ3/+r40TAWDwyYUcikP4peAO0lEyIz08eTz7ryykrS0ajpfV7N/XeT40cu3pltKNdmGZ2ACZEMjo12tnhM01yHF9RUc2FNiAipfDHXiQpQQhSCoVAzjHNDyNNi6R8e/JELPzOCAWT0emN3T25a6tdrd+yYMiYtm3HsgiAO46nX1MASgHnsZH3gFhx6LBOJoxgsPJIAxDhgp2OCACB2tryAwd5fj4ahue0/93SJ60BCADnc0/nEyLSGhCJiHmNYcUryHInrwJWAR7nOzS8a7D4vrTcAAAAAElFTkSuQmCC",
    48: "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAIAAADYYG7QAAAEXElEQVR4nO2YT0wcVRzHf783b3anM+wsEDh0sTaKkF5omrTRi+GoxquNsal6MxoTU9MYgaUQ/hmp/+rBPwcb4sFIPBijUWw0RnvQaEyq9tKyIGBooIVdWVaWZXfmvZ+HtxD+LbOzC1sOfDOX+fPefOb37/3mIRHBfhK72wCbxfduapISgABw3SVCxgCx8CDAvXIZ0c4vLqS9sRARIKbHxtzkAnKuvhkRpeMYDQ1Gwz0VBSIpkbGlmzd+f/xRyuWAMVBAnOfi8ca2jgcudFcQiAiISMrRaLvMLPNwNQmh7iDnzDBQ13eeYJezjKRETbs1dPnfqz/xcDW5rkLccFQMSNFkJicn3hjUq1dt4zO0d9VCRAAw2hV1UovIuTpdc1mlgUgI1LSZ4U/nr3yrV9fkORjjVVUkZcWBpETGsjMz46/18VCIhEDOneRC5Kkz4ZOnRDqNrNgX7Q4QEQFirKc7NzfHgkEAkCuZQ0fuvf+VNpnLoZ8w2oW0V86689WXd774XK+tJddFjbvp9LG3LnHbFsvLvuK6bAsRIWIukRjr6dIsSyWas5ise+Sxw6efBCLk/r65XCCSEhgbH+hbmZ5mhgFEJAS3rKaePgDfOV8ukHJW/IfvZ4c/yTuLc2dh4ehL56ymZnLdEuYsA4gIEN3/UrELnRgIEhEyJpaW7BMnjr7worJcRYHUIjpxcTA9FtNME6QEABKiqbdf+c5XcpULpJy18MvP00OXA+ucFTlztvbhVnW3tJlLAiICRJHJxDo7UGMAAIgymw1GGho7Oku2TelAyllT776Tuv6XZlWpUyeZbHy1LVBfLx2HiEgIdXgu75vkuzCqSpP6849/Pnx/tQxqbip1+InTkbPPAAALBNY/v7bK7g2Q6r8cZzTaTkIgYyQESYm6Hmo5Pj/yjbLW2tMAmEvEUde3MhWKM39AyjxTH7yX/O3XQH19vtIQsWBw4s1BmXO2VkLNNJlhENGmG4WWWx9AimZp9Obkpbf1mpoNjQ6RZlqatU0sk5Tbu6xA4BcNpLpPKWPRdpnJcNsmIfKTqkbMT9Ozg4rNsnyz/PFQ4uqPPBxWNCQEOY4C3aZ3LqKD3qqiLKRCNTM19ffF1/U1Gtfltt3y0ZBeUwNyu99CImB44/y5xWvXuGXtJhAQAWOx7qiTTKruXdXl5t7+6gcf2nmoZlrgx5veQCo/Zz8bnhsZCdTVrRaexdrW1sjTz5LrFlxEiQDRb2x5AClnZW/fHh/o57YNUqp3MD3Q3DuAjFHhBM7/3m86vFREUCPGuqIrszOocek6AODE40eeez7UclzVRo/hq2tIkSvJThaSrss4nxv5ev67K0akgYRAFpTZrH3y1H0vn4cNRbmgmGFopqkdMoExzTQ9f6W9t2Ny83PkuKAxtddDQuh2WKuq8kRRchIJmcsCMgAgKXkoxEOhsoC2V6nbP54qIu39FP6iht+dHbRSte82PQ+AvHQA5KUDIC8dAHlp3wH9DwaFanRyC7+TAAAAAElFTkSuQmCC",
    64: "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",
}

def _make_icon_images() -> list:
    """Return a list of tk.PhotoImage objects (largest first) for wm_iconphoto."""
    from PIL import Image, ImageTk
    import io
    imgs = []
    for sz in (64, 48, 32, 16):
        data = _base64.b64decode(_AGILIFY_ICON_B64[sz])
        img  = Image.open(io.BytesIO(data))
        imgs.append(ImageTk.PhotoImage(img))
    return imgs


# ===========================================================================
# AgilifyLogo  - canvas-drawn "A" mark matching the Agilify brand identity
# ===========================================================================
class AgilifyLogo(tk.Canvas):
    """
    Draws the Agilify geometric "A" mark:
      - Two thick angled legs meeting at a sharp apex
      - A horizontal crossbar one-third up from the base
    All proportions derived from the brand identity document.
    """

    def __init__(self, parent, size: int = 36, color: str = CLR_ACCENT,
                 bg: str = CLR_BG, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=bg, highlightthickness=0, bd=0, **kw)
        self._size  = size
        self._color = color
        self._draw()

    def _draw(self):
        s = self._size
        c = self._color
        self.delete('all')

        # All coordinates are expressed as fractions of `s` so the mark
        # scales cleanly at any size.
        #
        # The "A" geometry (origin = top-left of canvas):
        #
        #         apex (0.50, 0.04)
        #        /                \
        #       /                  \
        #  (0.08, 0.94)      (0.92, 0.94)
        #
        # Leg thickness achieved by giving each leg four vertices (a thin
        # parallelogram).  The crossbar sits at ~42 % of the height.
        #
        # Left leg  (outer-left -> apex -> inner-apex -> inner-left)
        lw = 0.18   # leg half-width at base
        apex_x, apex_y   = 0.50, 0.04
        base_l, base_r   = 0.08, 0.92
        base_y           = 0.94
        cross_frac        = 0.56   # crossbar vertical position (fraction down)
        cross_h           = 0.11   # crossbar height

        # Left leg vertices
        ll = [
            base_l * s,               base_y * s,          # outer base left
            (base_l + lw) * s,        base_y * s,          # inner base left
            (apex_x + 0.04) * s,      apex_y * s,          # inner apex
            (apex_x - 0.04) * s,      apex_y * s,          # outer apex
        ]
        # Right leg vertices
        rl = [
            (base_r - lw) * s,        base_y * s,          # inner base right
            base_r * s,               base_y * s,          # outer base right
            (apex_x + 0.04) * s,      apex_y * s,          # outer apex
            (apex_x - 0.04) * s,      apex_y * s,          # inner apex
        ]

        # Crossbar: spans between the inner edges of the two legs at cross_frac
        # Interpolate inner-edge x positions at that height
        t = cross_frac
        il_x = (base_l + lw) + t * ((apex_x + 0.04) - (base_l + lw))
        ir_x = (base_r - lw) + t * ((apex_x - 0.04) - (base_r - lw))
        cb = [
            il_x * s,                 (cross_frac) * s,
            ir_x * s,                 (cross_frac) * s,
            ir_x * s,                 (cross_frac + cross_h) * s,
            il_x * s,                 (cross_frac + cross_h) * s,
        ]

        self.create_polygon(ll, fill=c, outline='')
        self.create_polygon(rl, fill=c, outline='')
        self.create_polygon(cb, fill=c, outline='')


# ===========================================================================
# IBM Documentation search helper
# ===========================================================================
_IBM_DOCS_BASE = 'https://www.ibm.com/docs/en/zos/3.2.0'

# Static lookup table: verb name -> full IBM z/OS 3.2.0 documentation URL
VERB_HELP_URLS: dict[str, str] = {
    'CSNBCKI':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-clear-key-import-csnbcki-csnecki',
    'CSNBCVG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-control-vector-generate-csnbcvg-csnecvg',
    'CSNBCVT':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-control-vector-translate-csnbcvt-csnecvt',
    'CSNBCVE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-cryptographic-variable-encipher-csnbcve-csnecve',
    'CSNBDKX':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-data-key-export-csnbdkx-csnedkx',
    'CSNBDKM':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-data-key-import-csnbdkm-csnedkm',
    'CSNBDCM':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-derive-icc-mk-csnbdcm-csnedcm',
    'CSNBDSK':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-derive-session-key-csnbdsk-csnedsk',
    'CSNBDKG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-diversified-key-generate-csnbdkg-csnedkg',
    'CSNBDKG2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-diversified-key-generate2-csnbdkg2-csnedkg2',
    'CSNBDDK':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-diversify-directed-key-csnbddk-csneddk',
    'CSNDEDH':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-ecc-diffie-hellman-csndedh-csnfedh',
    'CSNBGIM':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-generate-issuer-mk-csnbgim-csnegim',
    'CSNBKET':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-encryption-translate-csnbket-csneket',
    'CSNBKEX':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-export-csnbkex-csnekex',
    'CSNBKGN':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-generate-csnbkgn-csnekgn',
    'CSNBKGN2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-generate2-csnbkgn2-csnekgn2',
    'CSNBKIM':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-generate2-csnbkgn2-csnekgn2',
    'CSNBKPI':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-part-import-csnbkpi-csnekpi',
    'CSNBKPI2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-part-import2-csnbkpi2-csnekpi2',
    'CSNBKYT':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-test-csnbkyt-csnekyt',
    'CSNBKYT2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-test-csnbkyt-csnekyt',
    'CSNBKYTX': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-test-extended-csnbkytx-csnekytx',
    'CSNBKTB':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-token-build-csnbktb-csnektb',
    'CSNBKTB2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-token-build2-csnbktb2-csnektb2',
    'CSNBKTR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-translate-csnbktr-csnektr',
    'CSNBKTR2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-key-translate2-csnbktr2-csnektr2',
    'CSNBCKM':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-multiple-clear-key-import-csnbckm-csneckm',
    'CSNBSKM':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-multiple-secure-key-import-csnbskm-csneskm',
    'CSNDPKD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-decrypt-csndpkd-csnfpkd',
    'CSNDPKE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-encrypt-csndpke-csnfpke',
    'CSNBPEX':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-prohibit-export-csnbpex-csnepex',
    'CSNBPEXX': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-prohibit-export-extended-csnbpexx-csnepexx',
    'CSNBRNG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-random-number-generate-csnbrng-csnerng-csnbrngl-csnerngl',
    'CSNBRNGL': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-random-number-generate-csnbrng-csnerng-csnbrngl-csnerngl',
    'CSNBRKX':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-remote-key-export-csndrkx-csnfrkx',
    'CSNBRKA':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-restrict-key-attribute-csnbrka-csnerka',
    'CSNBSKI':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-secure-key-import-csnbski-csneski',
    'CSNBSKI2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-secure-key-import2-csnbski2-csneski2',
    'CSNDSYX':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-symmetric-key-export-csndsyx-csnfsyx',
    'CSNDSXD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-symmetric-key-export-data-csndsxd-csnfsxd',
    'CSNDSYG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-symmetric-key-generate-csndsyg-csnfsyg',
    'CSNBSYI':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-symmetric-key-import-csndsyi-csnfsyi',
    'CSNBSYI2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-symmetric-key-import2-csndsyi2-csnfsyi2',
    'CSNDTBC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-trusted-block-create-csndtbc-csnftbc',
    'CSNBUKD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-unique-key-derive-csnbukd-csneukd',
    'CSNBCTT2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-cipher-text-translate2-csnbctt2-csnbctt3-csnectt2-csnectt3',
    'CSNBDEC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-decipher-csnbdec-csnbdec1-csnedec-csnedec1',
    'CSNBDCO':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-decode-csnbdco-csnedco',
    'CSNBENC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-encipher-csnbenc-csnbenc1-csneenc-csneenc1',
    'CSNBECO':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-encode-csnbeco-csneeco',
    'CSNBSAD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-symmetric-algorithm-decipher-csnbsad-csnbsad1-csnesad-csnesad1',
    'CSNBSAE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-symmetric-algorithm-encipher-csnbsae-csnbsae1-csnesae-csnesae1',
    'CSNBSYD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-symmetric-key-decipher-csnbsyd-csnbsyd1-csnesyd-csnesyd1',
    'CSNBSYE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=data-symmetric-key-encipher-csnbsye-csnbsye1-csnesye-csnesye1',
    'CSNBHMG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-hmac-generate-csnbhmg-csnbhmg1-csnehmg-csnehmg1',
    'CSNBHMV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-hmac-verify-csnbhmv-csnbhmv1-csnehmv-csnehmv1',
    'CSNBMGN':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-mac-generate-csnbmgn-csnbmgn1-csnemgn-csnemgn1',
    'CSNBMGN2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-mac-generate2-csnbmgn2-csnbmgn3-csnemgn2-csnemgn3',
    'CSNBMVR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-mac-verify-csnbmvr-csnbmvr1-csnemvr-csnemvr1',
    'CSNBMVR2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-mac-verify2-csnbmvr2-csnbmvr3-csnemvr2-csnemvr3',
    'CSNBMDG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-mdc-generate-csnbmdg-csnbmdg1-csnemdg-csnemdg1',
    'CSNBMMS':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-multi-mac-scheme-csnbmms-csnemms',
    'CSNBOWH':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=vdiam-one-way-hash-generate-csnbowh-csnbowh1-csneowh-csneowh1',
    'CSNBSMG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-symmetric-mac-generate-csnbsmg-csnbsmg1-csnesmg-csnesmg1',
    'CSNBSMV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=messages-symmetric-mac-verify-csnbsmv-csnbsmv1-csnesmv-csnesmv1',
    'CSNBAPG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-authentication-parameter-generate-csnbapg-csneapg',
    'CSNBCPE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-clear-pin-encrypt-csnbcpe-csnecpe',
    'CSNBPGN':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-clear-pin-generate-csnbpgn-csnepgn',
    'CSNBCPA':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-clear-pin-generate-alternate-csnbcpa-csnecpa',
    'CSNBCKC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-cvv-key-combine-csnbckc-csneckc',
    'CSNBESC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-emv-scripting-service-csnbesc-csneesc',
    'CSNBEAC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-emv-transaction-arqcarpc-service-csnbeac-csneeac',
    'CSNBEVF':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-emv-verification-functions-csnbevf-csneevf',
    'CSNBEPG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-encrypted-pin-generate-csnbepg-csneepg',
    'CSNBPTR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-encrypted-pin-translate-csnbptr-csneptr',
    'CSNBPTR2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-encrypted-pin-translate2-csnbptr2-csneptr2',
    'CSNBPTRE': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-encrypted-pin-translate-enhanced-csnbptre-csneptre',
    'CSNBPVR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-encrypted-pin-verify-csnbpvr-csnepvr',
    'CSNBPVR2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-encrypted-pin-verify2-csnbpvr2-csnepvr2',
    'CSNBFLD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-field-level-decipher-csnbfld-csnefld',
    'CSNBFLE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-field-level-encipher-csnbfle-csnefle',
    'CSNBFFXD': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-format-preserving-algorithms-decipher-csnbffxd-csneffxd',
    'CSNBFFXE': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-format-preserving-algorithms-encipher-csnbffxe-csneffxe',
    'CSNBFFXT': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-format-preserving-algorithms-translate-csnbffxt-csneffxt',
    'CSNBFPED': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-fpe-decipher-csnbfped-csnefped',
    'CSNBFPEE': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-fpe-encipher-csnbfpee-csnefpee',
    'CSNBFPET': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-fpe-translate-csnbfpet-csnefpet',
    'CSNBPCU':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-pin-changeunblock-csnbpcu-csnepcu',
    'CSNBPFO':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-recover-pin-from-offset-csnbpfo-csnepfo',
    'CSNBSKY':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-secure-messaging-keys-csnbsky-csnesky',
    'CSNBSPN':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-secure-messaging-pins-csnbspn-csnespn',
    'CSNDSBC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-set-block-compose-csndsbc-csnfsbc',
    'CSNDSBD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-set-block-decompose-csndsbd-csnfsbd',
    'CSNBTRV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-transaction-validation-csnbtrv-csnetrv',
    'CSNBCSG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-visa-cvv-service-generate-csnbcsg-csnecsg',
    'CSNBCSV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-visa-cvv-service-verify-csnbcsv-csnecsv',
    'CSNBDDPG': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-deterministic-pin-generate-csnbddpg-csneddpg',
    'CSNBDMP':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-migrate-pin-csnbdmp-csnedmp',
    'CSNBDPMT': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-pan-modify-in-transaction-csnbdpmt-csnedpmt',
    'CSNBDPT':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-pan-translate-csnbdpt-csnedpt',
    'CSNBDPC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-pin-change-csnbdpc-csnedpc',
    'CSNBDPV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-pin-verify-csnbdpv-csnedpv',
    'CSNBDPNU': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-prw-card-number-update-csnbdpnu-csnedpnu',
    'CSNBDCU2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-prw-card-number-update2-csnbdcu2-csnedcu2',
    'CSNBDPCG': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-prw-cmac-generate-csnbdpcg-csnedpcg',
    'CSNBDRPG': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-random-pin-generate-csnbdrpg-csnedrpg',
    'CSNBDRG2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-random-pin-generate2-csnbdrg2-csnedrg2',
    'CSNBDRP':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=methods-dk-regenerate-prw-csnbdrp-csnedrp',
    'CSNBT31C': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-31-create-csnbt31c-csnet31c',
    'CSNBT31I': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-31-import-csnbt31i-csnet31i',
    'CSNBT31O': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-31-optional-data-build-csnbt31o-csnet31o',
    'CSNBT31R': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-31-optional-data-read-csnbt31r-csnet31r',
    'CSNBT31P': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-31-parse-csnbt31p-csnet31p',
    'CSNBT31X': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=xt3skm-tr-31-translate-csnbt31x-csnet31x-previously-called-tr-31-export',
    'CSNDT34B': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-34-bind-begin-csndt34b-csnft34b',
    'CSNDT34C': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-34-bind-complete-csndt34c-csnft34c',
    'CSNDT34D': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-34-key-distribution-csndt34d-csnft34d',
    'CSNDT34R': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-tr-34-key-receive-csndt34r-csnft34r',
    'CSNDDSG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=signatures-digital-signature-generate-csnddsg-csnfdsg',
    'CSNDDSV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=signatures-digital-signature-verify-csnddsv-csnfdsv',
    'CSNDPKG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-key-generate-csndpkg-csnfpkg',
    'CSNDPKI':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-key-import-csndpki-csnfpki',
    'CSNDPKB':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-key-token-build-csndpkb-csnfpkb',
    'CSNDKTC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-key-token-change-csndktc-csnfktc',
    'CSNDPKT':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-key-translate-csndpkt-csnfpkt',
    'CSNDPKX':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-pka-public-key-extract-csndpkx-csnfpkx',
    'CSNDPIC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-public-infrastructure-certificate-csndpic-csnfpic',
    'CSNDRKD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-retained-key-delete-csndrkd-csnfrkd',
    'CSNDRKL':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=keys-retained-key-list-csndrkl-csnfrkl',
    'CSNBKRC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-ckds-key-record-create-csnbkrc-csnekrc',
    'CSNBKRC2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-ckds-key-record-create2-csnbkrc2-csnekrc2',
    'CSNBKRD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-ckds-key-record-delete-csnbkrd-csnekrd',
    'CSNBKRR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-ckds-key-record-read-csnbkrr-csnekrr',
    'CSNBKRR2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-ckds-key-record-read2-csnbkrr2-csnekrr2',
    'CSNBKRW':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-ckds-key-record-write-csnbkrw-csnekrw',
    'CSNBKRW2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-ckds-key-record-write2-csnbkrw2-csnekrw2',
    'CSFCRC':   'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-coordinated-kds-administration-csfcrc-csfcrc6',
    'CSFMPS':   'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-icsf-multi-purpose-service-csfmps-csfmps6',
    'CSFKDSL':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-key-data-set-list-csfkdsl-csfkdsl6',
    'CSFKDMR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-key-data-set-metadata-read-csfkdmr-csfkdmr6',
    'CSFKDMW':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-key-data-set-metadata-write-csfkdmw-csfkdmw6',
    'CSFRRT':   'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-key-data-set-record-retrieve-csfrrt-csfrrt6',
    'CSFKDU':   'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-key-data-set-update-csfkdu-csfkdu6',
    'CSNDKRC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-pkds-key-record-create-csndkrc-csnfkrc',
    'CSNDKRD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-pkds-key-record-delete-csndkrd-csnfkrd',
    'CSNDKRR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=kdsm-pkds-key-record-read-pkds-key-record-read2-csndkrr-csndkrr2-csnfkrr-csnfkrr2',
    'CSNDKRR2': 'https://www.ibm.com/docs/en/zos/3.2.0?topic=kdsm-pkds-key-record-read-pkds-key-record-read2-csndkrr-csndkrr2-csnfkrr-csnfkrr2',
    'CSNDKRW':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=management-pkds-key-record-write-csndkrw-csnfkrw',
    'CSNBXBC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-characternibble-conversion-csnbxbc-csnbxcb',
    'CSNBXCB':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-characternibble-conversion-csnbxbc-csnbxcb',
    'CSNBXAE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-code-conversion-csnbxea-csnbxae',
    'CSNBXEA':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-code-conversion-csnbxea-csnbxae',
    'CSFSTAT':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=u-cryptographic-usage-statistic-csfstat-csfstat6',
    'CSFIQA':   'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-icsf-query-algorithm-csfiqa-csfiqa6',
    'CSFIQF':   'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-icsf-query-facility-csfiqf-csfiqf6',
    'CSFIQF2':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-icsf-query-facility2-csfiqf2-csfiqf26',
    'CSNB9ED':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=utilities-x99-data-editing-csnb9ed',
    'CSFPCI':   'https://www.ibm.com/docs/en/zos/3.2.0?topic=interfaces-pci-interface-csfpci-csfpci6',
    'CSFPDMK':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-derive-multiple-keys-csfpdmk-csfpdmk6',
    'CSFPDVK':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-derive-key-csfpdvk-csfpdvk6',
    'CSFPGAV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-get-attribute-value-csfpgav-csfpgav6',
    'CSFPGKP':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-generate-key-pair-csfpgkp-csfpgkp6',
    'CSFPGSK':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-generate-secret-key-csfpgsk-csfpgsk6',
    'CSFPHMG':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-generate-keyed-mac-csfphmg-csfphmg6',
    'CSFPHMV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-verify-keyed-mac-csfphmv-csfphmv6',
    'CSFPOWH':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=up1to-pkcs-11-one-way-hash-sign-verify-csfpowh-csfpowh6',
    'CSFPPKS':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-private-key-sign-csfppks-csfppks6',
    'CSFPPKV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-public-key-verify-csfppkv-csfppkv6',
    'CSFPPRF':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-pseudo-random-function-csfpprf-csfpprf6',
    'CSFPSAV':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-set-attribute-value-csfpsav-csfpsav6',
    'CSFPSKD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-secret-key-decrypt-csfpskd-csfpskd6',
    'CSFPSKE':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-secret-key-encrypt-csfpske-csfpske6',
    'CSFPSKR':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-secret-key-reencrypt-csfpskr-csfpskr6',
    'CSFPTRC':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-token-record-create-csfptrc-csfptrc6',
    'CSFPTRD':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-token-record-delete-csfptrd-csfptrd6',
    'CSFPTRL':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-token-record-list-csfptrl-csfptrl6',
    'CSFPUWK':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-unwrap-key-csfpuwk-csfpuwk6',
    'CSFPWPK':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=objects-pkcs-11-wrap-key-csfpwpk-csfpwpk6',
    'CSFPGK2':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=services-pkcs-11-generate-secret-key2-csfpgk2-csfpgk26',
    'CSFPPD2':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=up1ksrkcs-pkcs-11-private-key-structure-decrypt-csfppd2-csfppd26',
    'CSFPPS2':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=up1ksrkcs-pkcs-11-private-key-structure-sign-csfpps2-csfpps26',
    'CSFPPE2':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=up1ksrkcs-pkcs-11-public-key-structure-encrypt-csfppe2-csfppe26',
    'CSFPPV2':  'https://www.ibm.com/docs/en/zos/3.2.0?topic=up1ksrkcs-pkcs-11-public-key-structure-verify-csfppv2-csfppv26',
}


def _ibm_help_url(verb: str) -> str | None:
    """Return the static IBM docs URL for *verb*, or None if not in the table."""
    return VERB_HELP_URLS.get(verb.upper())


# ===========================================================================
# Main application
# ===========================================================================
class ZccGui(tk.Tk):

    def __init__(self, host: str = '127.0.0.1', port: str = '8080'):
        super().__init__()
        # Resolve best monospace font now that the Tk display connection exists
        global FONT_MONO
        FONT_MONO = _best_mono_font(10)
        self.title('Zero-Client Crypto (ZCC) Test Harness')
        self.minsize(900, 600)

        # Load config and apply dark-mode palette BEFORE any widget or
        # ttk style is created, so the very first paint uses the right colours.
        self._cfg = _load_config()
        self._dark = bool(self._cfg.get('dark_mode', 0))
        if self._dark:
            _set_theme_colors(True)
        self._dark_var = tk.BooleanVar(value=self._dark)
        self._btn_dark = None        # set in _build_ui
        self._border_frames = []  # Frame wrappers acting as button borders
        self._moon_img = None        # crescent moon button image

        self.configure(bg=CLR_BG)

        style = ttk.Style(self)
        style.theme_use('clam')
        # Scrollbars: minimal, brand-neutral
        style.configure('TScrollbar', background=CLR_BORDER,
                        troughcolor=CLR_PANEL, arrowcolor=CLR_FG_DIM,
                        borderwidth=0, relief='flat')
        style.map('TScrollbar', background=[('active', CLR_ACCENT)])
        # Notebook: white background, red underline on selected tab
        style.configure('TNotebook', background=CLR_BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=CLR_PANEL,
                        foreground=CLR_BTN_FG, padding=[12, 5],
                        font=(_SANS, 10))
        style.map('TNotebook.Tab',
                  background=[('selected', CLR_BG)],
                  foreground=[('selected', CLR_ACCENT)],
                  font=[('selected', (_SANS, 10, 'bold'))])
        # Sash colour = brand border grey
        style.configure('TPanedwindow', background=CLR_BORDER)
        style.configure('Sash', sashthickness=5, sashpad=0,
                        background=CLR_BORDER)

        self._host = tk.StringVar(value=self._cfg.get('host', host))
        self._port = tk.StringVar(value=self._cfg.get('port', port))
        self._tls          = tk.BooleanVar(value=bool(self._cfg.get('tls', 0)))
        self._tls_noverify = tk.BooleanVar(value=bool(self._cfg.get('tls_noverify', 0)))
        # Invalidate persistent connection whenever connection settings change
        for _v in (self._host, self._port, self._tls, self._tls_noverify):
            _v.trace_add('write', lambda *_: _persistent_conn.invalidate())
        self._selected_verb: str | None = None
        self._param_rows: list[ParamRow] = []
        self._last_cmd_str: str = ''
        self._name_mode: tk.StringVar | None = None  # 'long' or 'short'
        self._history: list[HistoryEntry] = []
        self._last_output_segs: list[tuple[str,str]] = []
        self._drafts: dict[str, str] = {}   # verb -> draft_id in _history

        # Restore window size.  Apply size-only geometry (strip position on
        # macOS to avoid off-screen placement); then maximise if saved.
        _saved_geom = self._cfg.get('geometry', '1150x840')
        try:
            import re as _re
            _m = _re.match(r'(\d+x\d+)', _saved_geom)
            self.geometry(_m.group(1) if _m else '1150x840')
        except Exception:
            self.geometry('1150x840')
        if self._cfg.get('maximized'):
            def _do_maximise():
                try:
                    self.wm_state('zoomed')        # Windows / macOS
                except Exception:
                    pass
                try:
                    self.wm_attributes('-zoomed', True)   # Linux EWMH
                except Exception:
                    pass
            self.after(0, _do_maximise)

        self._build_ui()
        # Wire the connection indicator to the persistent connection
        _persistent_conn._indicator = self._conn_indicator
        # Share name-mode StringVar with row classes
        ParamRow._name_mode_var    = self._name_mode
        RuleArrayRow._name_mode_var = self._name_mode
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        # Always run a full theme pass after the window is mapped so that
        # system-default widget properties (e.g. macOS native button colours)
        # are overridden with the correct palette values regardless of theme.
        _dark = self._dark
        self.after(120, lambda: self._apply_theme(_dark))
        # Window / taskbar icon
        try:
            self._icon_imgs = _make_icon_images()  # keep refs to prevent GC
            self.wm_iconphoto(True, *self._icon_imgs)
        except Exception:
            pass  # Pillow not available
        # Restore history from previous session
        self._restore_history()
        # Show splash after the main window is fully built and visible
        self.after(50, lambda: _show_splash(self))

    # -----------------------------------------------------------------------
    # History restore (called once after _build_ui)
    # -----------------------------------------------------------------------
    def _restore_history(self):
        """Load persisted history entries and populate _history + _hist_lb."""
        restored = _load_history()
        for entry, lb_text, lb_clr in restored:
            self._history.append(entry)
            self._hist_lb.insert('end', lb_text)
            if lb_clr:
                self._hist_lb.itemconfig('end', fg=lb_clr,
                                         selectforeground=lb_clr)
        if restored:
            self._hist_lb.see('end')

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------
    def _build_ui(self):
        # -- Top bar ------------------------------------------------------
        # Top bar: white left section with logo-style title, red right accent strip
        top = tk.Frame(self, bg=CLR_BG, pady=0)
        top.pack(fill='x')
        # Red left accent bar (brand stripe)
        tk.Frame(top, bg=CLR_ACCENT, width=6).pack(side='left', fill='y')
        # Agilify logo mark + title
        self._logo_lbl = None
        try:
            self._logo_img = _make_logo_image(40, bg_color=CLR_BG)
            self._logo_lbl = tk.Label(top, image=self._logo_img, bg=CLR_BG,
                                      borderwidth=0)
            self._logo_lbl.pack(side='left', padx=(10, 4), pady=6)
        except Exception:
            pass  # Pillow not available - skip logo
        tk.Label(top, text='ZERO-CLIENT CRYPTO (ZCC) TEST HARNESS',
                 bg=CLR_BG, fg=CLR_ACCENT,
                 font=(_SANS, 12, 'bold'), padx=10, pady=10).pack(side='left')
        # Thin vertical divider
        tk.Frame(top, bg=CLR_BORDER, width=1).pack(side='left', fill='y',
                                                    pady=6, padx=8)
        tk.Label(top, text='HOST', bg=CLR_BG, fg=CLR_FG_DIM,
                 font=(_SANS, 8, 'bold')).pack(side='left', padx=(4, 2))
        _host_entry = tk.Entry(top, textvariable=self._host, width=30,
                 bg=CLR_BG, fg=CLR_FG, insertbackground=CLR_ACCENT,
                 relief='flat', bd=0, highlightthickness=1,
                 highlightcolor=CLR_ACCENT, highlightbackground=CLR_INPUT_BORDER,
                 font=FONT_UI)
        _bind_paste_replace(_host_entry)
        _host_entry.pack(side='left', padx=(0, 8), pady=8)
        tk.Label(top, text='PORT', bg=CLR_BG, fg=CLR_FG_DIM,
                 font=(_SANS, 8, 'bold')).pack(side='left', padx=(0, 2))
        _port_entry = tk.Entry(top, textvariable=self._port, width=7,
                 bg=CLR_BG, fg=CLR_FG, insertbackground=CLR_ACCENT,
                 relief='flat', bd=0, highlightthickness=1,
                 highlightcolor=CLR_ACCENT, highlightbackground=CLR_INPUT_BORDER,
                 font=FONT_UI)
        _bind_paste_replace(_port_entry)
        _port_entry.pack(side='left', pady=8)
        tk.Label(top, text='TLS', bg=CLR_BG, fg=CLR_FG_DIM,
                 font=(_SANS, 8, 'bold')).pack(side='left', padx=(8, 2))
        def _on_tls_toggle(*_):
            if self._tls.get():
                self._lbl_noverify.pack(side='left', padx=(6, 2))
                self._cb_noverify.pack(side='left', pady=8)
            else:
                self._lbl_noverify.pack_forget()
                self._cb_noverify.pack_forget()
        tk.Checkbutton(
            top, variable=self._tls,
            bg=CLR_BG, fg=CLR_FG,
            selectcolor=CLR_ENTRY,
            activebackground=CLR_BG,
            activeforeground=CLR_ACCENT,
            relief='flat', bd=0, cursor='hand2',
            command=_on_tls_toggle
        ).pack(side='left', pady=8)
        self._lbl_noverify = tk.Label(top, text='Skip cert', bg=CLR_BG,
                 fg=CLR_FG_DIM, font=(_SANS, 8, 'bold'))
        self._cb_noverify = tk.Checkbutton(
            top, variable=self._tls_noverify,
            bg=CLR_BG, fg=CLR_FG,
            selectcolor=CLR_ENTRY,
            activebackground=CLR_BG,
            activeforeground=CLR_ACCENT,
            relief='flat', bd=0, cursor='hand2'
        )
        # Show skip-cert controls only when TLS is active
        if self._tls.get():
            self._lbl_noverify.pack(side='left', padx=(6, 2))
            self._cb_noverify.pack(side='left', pady=8)
        # Invisible placeholder label preserves conn_indicator reference
        self._conn_indicator = tk.Label(top, text='', bg=CLR_BG)
        # Dark-mode skull toggle
        try:
            self._moon_img = _make_moon_image(28, '#BE2B20', CLR_BG)
        except Exception:
            self._moon_img = None
        self._btn_dark = tk.Checkbutton(
            top, image=self._moon_img if self._moon_img else None,
            text=('' if self._moon_img else '🌙'),
            compound='center',
            variable=self._dark_var,
            indicatoron=False,
            font=(_SANS, 17),
            fg=CLR_ACCENT,
            bg=CLR_BG,
            selectcolor=CLR_PANEL,
            activebackground=CLR_PANEL,
            activeforeground=CLR_ACCENT,
            relief='flat', bd=2,
            padx=10, pady=3,
            cursor='hand2',
            command=self._toggle_dark_mode,
        )
        self._btn_dark.pack(side='right', padx=(0, 10), pady=3)
        Tooltip(self._btn_dark, lambda: (
            'Dark mode ON - click to return to light mode'
            if self._dark else
            'Click to activate dark mode'))
        # Bottom border line under top bar
        tk.Frame(self, bg=CLR_ACCENT, height=2).pack(fill='x')

        # -- Outer vertical PanedWindow (main area / history) ------------
        self._vpw = ttk.PanedWindow(self, orient='vertical')
        self._vpw.pack(fill='both', expand=True)

        # Top pane holds the horizontal 3-column layout
        _main_frame = tk.Frame(self._vpw, bg=CLR_BG)
        self._vpw.add(_main_frame, weight=1)

        # -- Inner horizontal PanedWindow (left-column / right) -----------
        # The left column contains a classic tk.PanedWindow (not ttk) stacking
        # Category above Verb -- tk.PanedWindow supports minsize, ttk does not.
        self._pw = ttk.PanedWindow(_main_frame, orient='horizontal')
        self._pw.pack(fill='both', expand=True)

        left_w        = self._cfg.get('left_width',    None)   # None -> compute from %
        cv_split_frac = self._cfg.get('cv_split_frac', 0.4)    # cat = 40% of left-col height

        # -- Pane 0: left column (category + verb stacked) ----------------
        left_col = tk.Frame(self._pw, bg=CLR_PANEL, width=left_w or 230)
        left_col.rowconfigure(0, weight=1)
        left_col.columnconfigure(0, weight=1)
        self._pw.add(left_col, weight=0)

        # Use classic tk.PanedWindow for the vertical cat/verb split so we
        # can set minsize and sashwidth without ttk limitations.
        self._cvpw = tk.PanedWindow(left_col, orient='vertical',
                                    bg=CLR_BORDER, sashwidth=5,
                                    sashrelief='flat', showhandle=False)
        self._cvpw.pack(fill='both', expand=True)

        # Category sub-pane
        cat_frame = tk.Frame(self._cvpw, bg=CLR_PANEL)
        cat_frame.rowconfigure(2, weight=1)
        cat_frame.columnconfigure(0, weight=1)
        self._cvpw.add(cat_frame, stretch='always', minsize=60)

        tk.Label(cat_frame, text='CATEGORY', bg=CLR_PANEL, fg=CLR_FG,
                 font=(_SANS, 9, 'bold'), anchor='w', padx=10, pady=7).grid(
                     row=0, column=0, sticky='ew')
        tk.Frame(cat_frame, bg=CLR_BORDER, height=1).grid(
            row=1, column=0, sticky='ew')

        self._cat_lb = HScrollListbox(
            cat_frame, font=FONT_UI,
            selectbackground=CLR_SEL, selectforeground=CLR_SEL_FG,
            activestyle='none', exportselection=False)
        self._cat_lb.grid(row=2, column=0, sticky='nsew')

        for cat in CATEGORIES:
            self._cat_lb.insert('end', f'  {cat}')
        self._cat_lb.bind('<<ListboxSelect>>', self._on_category_select)

        # Verb sub-pane
        verb_frame = tk.Frame(self._cvpw, bg=CLR_PANEL)
        verb_frame.rowconfigure(2, weight=1)
        verb_frame.columnconfigure(0, weight=1)
        self._cvpw.add(verb_frame, stretch='always', minsize=60)

        tk.Label(verb_frame, text='VERB', bg=CLR_PANEL, fg=CLR_FG,
                 font=(_SANS, 9, 'bold'), anchor='w', padx=10, pady=7).grid(
                     row=0, column=0, sticky='ew')
        tk.Frame(verb_frame, bg=CLR_BORDER, height=1).grid(
            row=1, column=0, sticky='ew')

        self._verb_lb = HScrollListbox(
            verb_frame, font=FONT_MONO,
            selectbackground=CLR_SEL, selectforeground=CLR_SEL_FG,
            activestyle='none', exportselection=False)
        self._verb_lb.grid(row=2, column=0, sticky='nsew')
        self._verb_lb.bind('<<ListboxSelect>>', self._on_verb_select)

        # -- Pane 1: right panel ------------------------------------------
        right = tk.Frame(self._pw, bg=CLR_BG)
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)
        self._pw.add(right, weight=1)

        # -- Bottom pane: history -----------------------------------------
        hist_h = self._cfg.get('hist_height', None)   # None -> compute from %

        hist_outer = tk.Frame(self._vpw, bg=CLR_PANEL)
        self._vpw.add(hist_outer, weight=0)

        # Header row
        hist_hdr = tk.Frame(hist_outer, bg=CLR_PANEL)
        hist_hdr.pack(fill='x')
        tk.Label(hist_hdr, text='HISTORY', bg=CLR_PANEL, fg=CLR_FG,
                 font=(_SANS, 9, 'bold'), anchor='w', padx=10, pady=5).pack(side='left')

        _btn_kw = dict(font=(_SANS, 9), relief='flat', bd=0,
                       activebackground=CLR_PANEL, cursor='hand2',
                       padx=8)
        def _hist_btn(text, cmd, pack_padx):
            f = tk.Frame(hist_hdr, bg=CLR_INPUT_BORDER)
            self._border_frames.append(f)
            tk.Button(f, text=text, bg=CLR_BG, fg=CLR_FG_DIM,
                      command=cmd, **_btn_kw).pack(padx=1, pady=1)
            f.pack(side='right', padx=pack_padx, pady=3)
        _hist_btn('CLEAR',    self._clear_history,    (0, 6))
        _hist_btn('LOAD...',    self._load_history_from, 3)
        _hist_btn('SAVE...',    self._save_history_as,   (3, 4))
        tk.Frame(hist_outer, bg=CLR_BORDER, height=1).pack(fill='x')

        # Listbox with horizontal + vertical scroll
        self._hist_lb = HScrollListbox(
            hist_outer, font=FONT_MONO,
            selectbackground=CLR_SEL, selectforeground=CLR_SEL_FG,
            activestyle='none', exportselection=False)
        self._hist_lb.pack(fill='both', expand=True)
        self._hist_lb.bind('<<ListboxSelect>>', self._on_history_select)

        # Restore saved sash positions after geometry is realised.
        # When starting maximised the zoom is deferred, so _cvpw.winfo_height()
        # will keep changing until the WM has finished resizing.  We poll until
        # two successive measurements agree before placing the cv sash.
        # Restore sash positions after the window is fully mapped.
        # We bind to <Configure> which fires on Linux once the WM has
        # positioned and sized the window -- far more reliable than polling.
        # A short after() delay lets any post-map resize settle first.
        _sash_restored = [False]

        def _do_restore_sashes():
            if _sash_restored[0]:
                return
            try:
                total = self._pw.winfo_width()
                cv_h  = self._cvpw.winfo_height()
                win_h = self._vpw.winfo_height()
                if total < 10 or cv_h < 10 or win_h < 10:
                    self.after(100, _do_restore_sashes)
                    return
                _sash_restored[0] = True
                lw = left_w if left_w is not None else max(60, int(total * 0.20))
                self._pw.sashpos(0, lw)
                cv_y = int(cv_h * cv_split_frac)
                self._cvpw.sash_place(0, 0, cv_y)
                hh = hist_h if hist_h is not None else max(40, int(win_h * 0.20))
                if win_h > hh + 50:
                    self._vpw.sashpos(0, win_h - hh)
            except Exception:
                pass

        def _on_first_configure(event):
            # Unbind immediately -- we only want the first real Configure
            try:
                self.unbind('<Configure>')
            except Exception:
                pass
            # Short delay so post-map WM resizes settle
            self.after(150, _do_restore_sashes)

        self.bind('<Configure>', _on_first_configure)
        # Fallback: also schedule directly in case <Configure> fires early
        self.after(400, _do_restore_sashes)

        self._verb_title = tk.Label(
            right, text='SELECT A CATEGORY AND VERB',
            bg=CLR_BG, fg=CLR_FG_DIM, font=(_SANS, 10, 'bold'),
            anchor='w', padx=12, pady=9)
        self._verb_title.grid(row=0, column=0, sticky='ew')
        tk.Frame(right, bg=CLR_BORDER, height=1).grid(
            row=1, column=0, sticky='ew')

        nb_frame = tk.Frame(right, bg=CLR_BG)
        nb_frame.grid(row=2, column=0, sticky='nsew')
        nb_frame.rowconfigure(0, weight=1)
        nb_frame.columnconfigure(0, weight=1)

        nb = ttk.Notebook(nb_frame)
        nb.grid(row=0, column=0, sticky='nsew')

        # -- Tab 1: Parameters --------------------------------------------
        self._tab_params = tk.Frame(nb, bg=CLR_BG)
        nb.add(self._tab_params, text='  Parameters  ')
        # row 0 = button bar, row 1 = name-mode bar, row 2 = scroll area, row 3 = legend
        self._tab_params.rowconfigure(2, weight=1)
        self._tab_params.columnconfigure(0, weight=1)

        # -- Row 0: hint label + EXECUTE + RELOAD ---------------------
        ph = tk.Frame(self._tab_params, bg=CLR_BG)
        ph.grid(row=0, column=0, sticky='ew', padx=8, pady=(6, 2))

        self._lbl_params_hint = tk.Label(
            ph, text='Choose a verb to see its parameters.',
            bg=CLR_BG, fg=CLR_FG_DIM, font=FONT_UI)
        self._lbl_params_hint.pack(side='left')

        self._btn_execute = tk.Button(
            ph, text='▶  Execute   ⇧↵', bg=CLR_ACCENT, fg='#FFFFFF',
            font=(_SANS, 10, 'bold'), relief='flat', padx=18, pady=5,
            activebackground='#8B1F16', activeforeground='#FFFFFF',
            disabledforeground='#D8A5A2',
            state='disabled', cursor='hand2', command=self._on_execute)
        self._btn_execute.pack(side='right', padx=4)

        _f_introspect = tk.Frame(ph, bg=CLR_INPUT_BORDER)
        self._border_frames.append(_f_introspect)
        self._btn_introspect = tk.Button(
            _f_introspect, text='RELOAD', bg=CLR_BG, fg=CLR_FG_DIM,
            font=(_SANS, 10), relief='flat', bd=0, padx=12, pady=4,
            activebackground=CLR_PANEL, activeforeground=CLR_FG,
            state='disabled', cursor='hand2', command=self._reload_params)
        self._btn_introspect.pack(padx=1, pady=1)
        _f_introspect.pack(side='right', padx=4)

        _f_ibm = tk.Frame(ph, bg=CLR_INPUT_BORDER)
        self._border_frames.append(_f_ibm)
        self._btn_ibm_help = tk.Button(
            _f_ibm, text='IBM Help ↗', bg=CLR_BG, fg=CLR_FG_DIM,
            font=(_SANS, 10), relief='flat', bd=0, padx=12, pady=4,
            activebackground=CLR_PANEL, activeforeground=CLR_FG,
            state='disabled', cursor='hand2', command=self._open_ibm_help)
        self._btn_ibm_help.pack(padx=1, pady=1)
        _f_ibm.pack(side='right', padx=4)

        # -- Row 1: parameter-name mode radio buttons ------------------
        self._name_mode = tk.StringVar(value=self._cfg.get('name_mode', 'long'))
        nm_bar = tk.Frame(self._tab_params, bg=CLR_BG)
        nm_bar.grid(row=1, column=0, sticky='ew', padx=8, pady=(0, 4))
        tk.Frame(nm_bar, bg=CLR_BORDER, height=1).pack(fill='x', pady=(0, 4))
        nm_inner = tk.Frame(nm_bar, bg=CLR_BG)
        nm_inner.pack(fill='x')
        tk.Label(nm_inner, text='Command-line parameter names:',
                 bg=CLR_BG, fg=CLR_FG_DIM,
                 font=(_SANS, 9)).pack(side='left', padx=(0, 8))
        for rb_text, rb_val, rb_desc in (
                ('Long names',  'long',  'e.g.  irule_array_count=2'),
                ('Short names', 'short', 'e.g.  irac=2')):
            tk.Radiobutton(
                nm_inner, text=rb_text, variable=self._name_mode,
                value=rb_val, bg=CLR_BG, fg=CLR_FG,
                selectcolor=CLR_ENTRY, activebackground=CLR_BG,
                activeforeground=CLR_ACCENT, font=(_SANS, 9),
                relief='flat', bd=0, cursor='hand2').pack(side='left', padx=(0, 2))
            tk.Label(nm_inner, text=rb_desc, bg=CLR_BG, fg=CLR_FG_DIM,
                     font=(_SANS, 8)).pack(side='left', padx=(0, 16))

        # Two-way scrollable parameter area
        self._params_sf = TwoWayScrollFrame(self._tab_params, bg=CLR_BG)
        self._params_sf.grid(row=2, column=0, sticky='nsew', padx=4, pady=4)

        # Legend
        legend = tk.Frame(self._tab_params, bg=CLR_BG)
        legend.grid(row=3, column=0, sticky='ew', padx=12, pady=(0, 4))
        for lbl_text, lbl_bg, lbl_fg, desc in [
            (' IN ', CLR_ACCENT,  '#FFFFFF', 'input  '),
            ('BOTH', '#8B1F16',   '#FFFFFF', 'input + output  '),
            (' OUT', CLR_FG_DIM,  '#FFFFFF', 'output only  '),
        ]:
            tk.Label(legend, text=lbl_text, bg=lbl_bg, fg=lbl_fg,
                     font=FONT_SMALL).pack(side='left', padx=2)
            tk.Label(legend, text=desc, bg=CLR_BG, fg=CLR_FG_DIM,
                     font=FONT_SMALL).pack(side='left')
        tk.Label(legend, text='* = required', bg=CLR_BG, fg=CLR_RED,
                 font=FONT_SMALL).pack(side='left', padx=6)

        # -- Tab 2: Output ------------------------------------------------
        self._tab_output = tk.Frame(nb, bg=CLR_MONO_BG)
        nb.add(self._tab_output, text='  Output  ')
        self._tab_output.rowconfigure(0, weight=1)
        self._tab_output.columnconfigure(0, weight=1)

        # Output text with both scrollbars
        self._txt_output = tk.Text(
            self._tab_output, bg=CLR_MONO_BG, fg=CLR_FG,
            insertbackground=CLR_FG, font=FONT_MONO,
            relief='flat', state='disabled', wrap='none')
        out_vsb = ttk.Scrollbar(self._tab_output, orient='vertical',
                                command=self._txt_output.yview)
        out_hsb = ttk.Scrollbar(self._tab_output, orient='horizontal',
                                command=self._txt_output.xview)
        self._txt_output.configure(yscrollcommand=out_vsb.set,
                                   xscrollcommand=out_hsb.set)
        out_vsb.grid(row=0, column=1, sticky='ns')
        out_hsb.grid(row=1, column=0, sticky='ew')
        self._txt_output.grid(row=0, column=0, sticky='nsew', padx=(4, 0),
                              pady=(4, 0))

        # Colour tags
        self._txt_output.tag_configure('hdr',  foreground=CLR_ACCENT,
                                       font=(_SANS, 10, 'bold'))
        self._txt_output.tag_configure('ok',   foreground='#2E7D32')  # accessible green
        self._txt_output.tag_configure('err',  foreground=CLR_RED,
                                       font=(_SANS, 10, 'bold'))
        self._txt_output.tag_configure('rc_err', foreground=CLR_RED)  # plain red for rc/rsn values
        self._txt_output.tag_configure('warn', foreground=CLR_YELLOW)
        self._txt_output.tag_configure('name', foreground=CLR_FG)
        self._txt_output.tag_configure('val',  foreground=CLR_FG)
        self._txt_output.tag_configure('dim',  foreground=CLR_FG)
        self._txt_output.tag_configure('mono', font=FONT_MONO,
                                       foreground=CLR_FG)
        self._txt_output.tag_configure('errtxt', foreground=CLR_RED,
                                       font=FONT_UI)

        btn_row = tk.Frame(self._tab_output, bg=CLR_MONO_BG)
        btn_row.grid(row=2, column=0, columnspan=2, sticky='ew',
                     padx=4, pady=(0, 4))
        _f_oclear = tk.Frame(btn_row, bg=CLR_INPUT_BORDER)
        self._border_frames.append(_f_oclear)
        tk.Button(_f_oclear, text='CLEAR', bg=CLR_BG, fg=CLR_FG,
                  font=(_SANS, 9), relief='flat', bd=0, padx=10,
                  activebackground=CLR_PANEL, cursor='hand2',
                  command=self._clear_output).pack(padx=1, pady=1)
        _f_oclear.pack(side='right', padx=4)
        self._lbl_cmd_display = tk.Label(
            btn_row, text='', bg=CLR_MONO_BG, fg=CLR_FG,
            font=FONT_MONO, anchor='w')
        self._lbl_cmd_display.pack(side='left', padx=(4, 0), fill='x',
                                   expand=True)
        _f_copy = tk.Frame(btn_row, bg=CLR_INPUT_BORDER)
        self._border_frames.append(_f_copy)
        self._btn_copy_cmd = tk.Button(
            _f_copy, text='COPY COMMAND', bg=CLR_BG, fg=CLR_FG,
            font=(_SANS, 9), relief='flat', bd=0, padx=10, state='disabled',
            activebackground=CLR_PANEL, cursor='hand2',
            command=self._copy_command)
        self._btn_copy_cmd.pack(padx=1, pady=1)
        _f_copy.pack(side='left', padx=4)

        # Status bar
        sb_frame = tk.Frame(self, bg=CLR_BORDER, height=1)
        sb_frame.pack(fill='x', side='bottom')
        status_bar = tk.Frame(self, bg=CLR_BG)
        status_bar.pack(fill='x', side='bottom')
        tk.Frame(status_bar, bg=CLR_ACCENT, width=4).pack(side='left', fill='y')
        self._statusbar = tk.Label(
            status_bar, text='Ready.', bg=CLR_BG, fg=CLR_FG_DIM,
            font=(_SANS, 9), anchor='w', padx=10, pady=4)
        self._statusbar.pack(side='left', fill='x', expand=True)

        self._notebook = nb

    # -----------------------------------------------------------------------
    # Save state and close
    # -----------------------------------------------------------------------
    def _on_close(self):
        try:
            # Detect maximised state cross-platform
            zoomed = False
            try:
                zoomed = self.wm_state() == 'zoomed'
            except Exception:
                pass
            if not zoomed:
                try:
                    zoomed = bool(self.wm_attributes('-zoomed'))
                except Exception:
                    pass
            self._cfg['maximized'] = 1 if zoomed else 0
            try:
                self._cfg['geometry'] = self.geometry()
            except Exception:
                pass
            self._cfg['left_width'] = self._pw.sashpos(0)
            self._cfg['name_mode']  = self._name_mode.get()
            self._cfg['host']       = self._host.get().strip()
            self._cfg['port']       = self._port.get().strip()
            self._cfg['dark_mode']  = int(self._dark)
            self._cfg['tls']            = int(self._tls.get())
            self._cfg['tls_noverify']   = int(self._tls_noverify.get())
            try:
                cv_h = self._cvpw.winfo_height()
                cv_y = self._cvpw.sash_coord(0)[1]
                if cv_h > 0:
                    self._cfg['cv_split_frac'] = max(0.05, min(0.95,
                                                    cv_y / cv_h))
            except Exception:
                pass
            try:
                win_h  = self._vpw.winfo_height()
                vsath  = self._vpw.sashpos(0)
                self._cfg['hist_height'] = max(40, win_h - vsath)
            except Exception:
                pass
            _save_config(self._cfg)
            _save_history(self._history)
        except Exception:
            pass
        _persistent_conn.invalidate()
        self.destroy()

    # -----------------------------------------------------------------------
    # Dark-mode toggle
    # -----------------------------------------------------------------------
    def _toggle_dark_mode(self):
        self._dark = bool(self._dark_var.get())
        self._apply_theme(self._dark)

    def _apply_theme(self, dark):
        _set_theme_colors(dark)

        # Regenerate logo so its background matches the new banner colour
        if self._logo_lbl is not None:
            try:
                self._logo_img = _make_logo_image(40, bg_color=CLR_BG)
                self._logo_lbl.configure(image=self._logo_img, bg=CLR_BG)
            except Exception:
                pass

        # Regenerate moon image for button
        try:
            self._moon_img = _make_moon_image(28, '#BE2B20', CLR_BG)
            if self._btn_dark is not None and self._moon_img:
                self._btn_dark.configure(image=self._moon_img)
        except Exception:
            pass

        if dark:
            bg_map = {
                '#ffffff': '#1c1c1c', '#f5f5f5': '#252525',
                '#f9f9f9': '#141414', '#000000': '#0a0a0a',
                '#d8d8d8': '#3c3c3c', '#f5e6e5': '#3a1a1a',
            }
            fg_map = {
                '#000000': '#d4d4d4', '#575757': '#8a8a8a',
                '#d8d8d8': '#606060', '#b8640a': '#cc8833',
                '#2e7d32': '#4caf50', '#d8a5a2': '#6a4040',
            }
            sel_bg = {'#ffffff': '#2a2a2a', '#f5e6e5': '#7a1a14'}
            sel_fg = {'#be2b20': '#e8e8e8'}  # red -> near-white when selected
            act_bg = {'#ffffff': '#1c1c1c', '#f5f5f5': '#252525',
                      '#f9f9f9': '#141414'}
            act_fg = {'#000000': '#d4d4d4', '#575757': '#8a8a8a'}
            hl_bg      = {'#d8d8d8': '#3c3c3c'}
            dis_fg = {'#d8a5a2': '#6a4040'}
        else:
            bg_map = {
                '#1c1c1c': '#ffffff', '#252525': '#f5f5f5',
                '#141414': '#f9f9f9', '#0a0a0a': '#000000',
                '#3c3c3c': '#d8d8d8', '#3a1a1a': '#f5e6e5',
                '#2a2a2a': '#ffffff',
            }
            fg_map = {
                '#d4d4d4': '#000000', '#8a8a8a': '#575757',
                '#606060': '#d8d8d8', '#cc8833': '#b8640a',
                '#4caf50': '#2e7d32', '#6a4040': '#d8a5a2',
            }
            sel_bg = {'#2a2a2a': '#ffffff', '#7a1a14': '#f5e6e5'}
            sel_fg = {'#e8e8e8': '#be2b20'}  # near-white -> red when deselected
            act_bg = {'#1c1c1c': '#ffffff', '#252525': '#f5f5f5',
                      '#141414': '#f9f9f9'}
            act_fg = {'#d4d4d4': '#000000', '#8a8a8a': '#575757'}
            hl_bg      = {'#3c3c3c': '#d8d8d8'}
            dis_fg = {'#6a4040': '#d8a5a2'}

        self._theme_walk(self, bg_map, fg_map, sel_bg, sel_fg, act_bg, act_fg,
                         hl_bg, dis_fg)
        # Explicitly refresh live listbox selectforeground (widget-level)
        for lb in (self._cat_lb, self._verb_lb, self._hist_lb):
            try:
                lb.configure(selectforeground=CLR_SEL_FG)
            except Exception:
                pass

        style = ttk.Style(self)
        style.configure('TScrollbar', background=CLR_BORDER,
                        troughcolor=CLR_PANEL, arrowcolor=CLR_FG_DIM)
        style.map('TScrollbar', background=[('active', CLR_ACCENT)])
        style.configure('TNotebook', background=CLR_BG, borderwidth=0)
        style.configure('TNotebook.Tab', background=CLR_PANEL,
                        foreground=CLR_BTN_FG, padding=[12, 5])
        style.map('TNotebook.Tab',
                  background=[('selected', CLR_BG)],
                  foreground=[('selected', CLR_ACCENT)],
                  font=[('selected', (_SANS, 10, 'bold'))])
        style.configure('TPanedwindow', background=CLR_BORDER)
        style.configure('Sash', sashthickness=5, sashpad=0,
                        background=CLR_BORDER)

        try:
            ok_clr = '#4CAF50' if dark else '#2E7D32'
            self._txt_output.tag_configure('ok',   foreground=ok_clr)
            self._txt_output.tag_configure('warn', foreground=CLR_YELLOW)
            self._txt_output.tag_configure('name', foreground=CLR_FG)
            self._txt_output.tag_configure('val',  foreground=CLR_FG)
            self._txt_output.tag_configure('dim',  foreground=CLR_FG)
            self._txt_output.tag_configure('mono', foreground=CLR_FG,
                                           font=FONT_MONO)
        except Exception:
            pass

        if self._btn_dark is not None:
            if dark:
                self._btn_dark.configure(
                    bg='#2A2A2A', fg=CLR_ACCENT,
                    selectcolor='#3C3C3C',
                    activebackground='#3C3C3C',
                    activeforeground=CLR_ACCENT,
                )
            else:
                self._btn_dark.configure(
                    bg=CLR_BG, fg=CLR_ACCENT,
                    selectcolor=CLR_PANEL,
                    activebackground=CLR_PANEL,
                    activeforeground=CLR_ACCENT,
                )

        self.configure(bg=CLR_BG)

        # Refresh all Frame-border wrappers
        for f in self._border_frames:
            try:
                f.configure(bg=CLR_INPUT_BORDER)
            except Exception:
                pass

    def _theme_walk(self, widget, bg_map, fg_map, sel_bg, sel_fg,
                    act_bg, act_fg, hl_bg, dis_fg):
        if self._btn_dark is not None and widget is self._btn_dark:
            return
        # Skip border-frame wrappers: their bg is CLR_INPUT_BORDER,
        # managed exclusively in _apply_theme.
        if widget in self._border_frames:
            for child in widget.winfo_children():
                self._theme_walk(child, bg_map, fg_map, sel_bg, sel_fg,
                                 act_bg, act_fg, hl_bg, dis_fg)
            return

        def _r(prop, mapping):
            try:
                val = str(widget.cget(prop)).lower()
                if val in mapping:
                    widget.configure(**{prop: mapping[val]})
            except Exception:
                pass

        _r('bg',                 bg_map)
        _r('background',         bg_map)
        _r('fg',                 fg_map)
        _r('foreground',         fg_map)
        _r('selectbackground',   sel_bg)
        _r('selectforeground',   sel_fg)
        _r('selectcolor',        sel_bg)
        _r('activebackground',   act_bg)
        _r('activeforeground',   act_fg)
        _r('highlightbackground',hl_bg)
        _r('insertbackground',   fg_map)
        _r('disabledforeground', dis_fg)

        # For button-type and entry widgets: unconditionally set border
        # colour and button text rather than trying to map from current
        # values (which may be Windows system defaults not in any map).
        import tkinter as _tk
        if isinstance(widget, (_tk.Button, _tk.Checkbutton, _tk.Radiobutton)):
            try:
                # Buttons on the accent-red background (Execute) keep white text
                cur_bg = str(widget.cget('bg')).lower()
                if cur_bg != '#be2b20':
                    widget.configure(fg=CLR_BTN_FG)
                widget.configure(
                    highlightbackground=CLR_INPUT_BORDER,
                    highlightcolor=CLR_INPUT_BORDER,
                    highlightthickness=1,
                )
            except Exception:
                pass
        elif isinstance(widget, _tk.Entry):
            try:
                # Only override if not currently showing a validation error
                cur = str(widget.cget('highlightbackground')).lower()
                if cur != '#be2b20':  # leave red error border untouched
                    widget.configure(highlightbackground=CLR_INPUT_BORDER)
            except Exception:
                pass

        for child in widget.winfo_children():
            self._theme_walk(child, bg_map, fg_map, sel_bg, sel_fg,
                             act_bg, act_fg, hl_bg, dis_fg)

    # -----------------------------------------------------------------------
    # List event handlers
    # -----------------------------------------------------------------------
    def _on_category_select(self, _event):
        sel = self._cat_lb.curselection()
        if not sel:
            return
        cat   = CATEGORIES[sel[0]]
        verbs = VERB_DATA[cat]
        self._verb_lb.delete(0, 'end')
        for v in verbs:
            self._verb_lb.insert('end', f'  {v["key"]:<12}  {v["desc"]}')
        self._clear_params()
        self._verb_title.configure(text='Select a verb')
        self._selected_verb = None
        self._btn_ibm_help.configure(state='disabled')

    def _on_verb_select(self, _event):
        sel_cat = self._cat_lb.curselection()
        sel_vrb = self._verb_lb.curselection()
        if not sel_cat or not sel_vrb:
            return
        cat   = CATEGORIES[sel_cat[0]]
        entry = VERB_DATA[cat][sel_vrb[0]]

        self._selected_verb = entry['key']
        self._verb_title.configure(
            text=f'{entry["key"]}  --  {entry["desc"].upper()}',
            fg=CLR_FG)
        self._status(f'Introspecting {entry["key"]}...')
        self._btn_execute.configure(state='disabled')
        self._btn_introspect.configure(state='disabled')
        self._clear_params()
        self._lbl_params_hint.configure(
            text=f'Loading parameters for {entry["key"]}...', fg=CLR_FG_DIM)

        self._notebook.select(0)   # switch to Parameters tab
        self._btn_ibm_help.configure(
            state='normal' if _ibm_help_url(entry['key']) else 'disabled')
        holder = _SocketHolder()
        popup  = ProgressPopup(self, holder,
                               title=f'Loading {entry["key"]}...')
        threading.Thread(target=self._introspect_worker,
                         args=(entry['key'], holder, popup), daemon=True).start()

    def _reload_params(self):
        if self._selected_verb:
            self._remove_draft(self._selected_verb)
            self._on_verb_select(None)

    def _open_ibm_help(self):
        if self._selected_verb:
            url = _ibm_help_url(self._selected_verb)
            if url:
                webbrowser.open(url)

    # -----------------------------------------------------------------------
    # Introspection
    # -----------------------------------------------------------------------
    def _introspect_worker(self, verb: str,
                           holder: '_SocketHolder | None' = None,
                           popup:  'ProgressPopup | None'  = None):
        try:
            host = self._host.get().strip()
            port = int(self._port.get().strip())
            elements, raw = zcc_call(host, port, [f'cv={verb}?'],
                                     holder=holder, tls=self._tls.get(),
                                     verify=not self._tls_noverify.get())

            def _on_done():
                if popup:
                    popup.dismiss()
                self._build_param_form(verb, elements)

            self.after(0, _on_done)
        except Exception as exc:
            cancelled = holder is not None and holder.cancelled
            msg = 'Cancelled by user' if cancelled else str(exc)

            def _on_error(m=msg):
                if popup:
                    popup.dismiss()
                self._introspect_error(m)

            self.after(0, _on_error)

    def _introspect_error(self, msg: str):
        self._lbl_params_hint.configure(
            text=f'Error loading parameters: {msg}', fg=CLR_RED)
        self._btn_introspect.configure(state='normal')
        self._status(f'Error: {msg}')

    # -----------------------------------------------------------------------
    # Build parameter form  (wire order preserved)
    # -----------------------------------------------------------------------
    def _build_param_form(self, verb: str, elements: list[zcc.BsonEl]):
        self._clear_params()
        params = parse_param_meta(elements)   # wire order, no sort

        if not params:
            self._lbl_params_hint.configure(
                text='No parameters returned by introspection.', fg=CLR_YELLOW)
            self._btn_execute.configure(state='normal', text='▶  Execute   ⇧↵')

        # Synthetic output-only rows always shown at the top
        RC_META  = {'name': 'return_code', 'sname': 'rc',  'dir': 'out',
                    'type': 'integer', 'opt': 'Y'}
        RSN_META = {'name': 'reason_code', 'sname': 'rsn', 'dir': 'out',
                    'type': 'integer', 'opt': 'Y'}
        all_params = [RC_META, RSN_META] + params

        n_req = sum(1 for p in all_params
                    if p['dir'] in ('in', 'both') and p['opt'] == 'N')
        n_opt = sum(1 for p in all_params
                    if p['dir'] in ('in', 'both') and p['opt'] == 'Y')
        n_out = sum(1 for p in all_params if p['dir'] == 'out')
        self._lbl_params_hint.configure(
            text=(f'{len(all_params)} parameters (wire order):  '
                  f'{n_req} required input,  {n_opt} optional input,  '
                  f'{n_out} output-only'),
            fg=CLR_FG_DIM)

        container = self._params_sf.inner

        # Column headers
        hdr = tk.Frame(container, bg=CLR_BG)
        hdr.pack(fill='x', padx=4, pady=(4, 0))
        for text, w in [('Dir', 6), ('Name (* = required)', 28),
                        ('Type', 18), ('Value', 48)]:
            tk.Label(hdr, text=text, bg=CLR_BG, fg=CLR_FG_DIM,
                     font=FONT_SMALL, width=w, anchor='w').pack(side='left',
                                                                padx=4)
        tk.Frame(container, bg=CLR_BORDER, height=1).pack(
            fill='x', padx=4, pady=2)

        self._param_rows = []
        for i, meta in enumerate(all_params):
            row_bg = CLR_BG if i % 2 == 0 else CLR_PANEL
            if meta['name'] == 'rule_array' and meta['dir'] in ('in', 'both'):
                row = RuleArrayRow(container, meta, self._params_sf, bg=row_bg)
            else:
                row = ParamRow(container, meta, self._params_sf, bg=row_bg)
            row.pack(fill='x', padx=4, pady=1)
            self._param_rows.append(row)

        self._btn_execute.configure(state='normal', text='▶  Execute   ⇧↵')
        self._btn_introspect.configure(state='normal')
        self._status(f'Ready  ({verb})')

        # Attach draft-update traces to every input row
        self._attach_draft_traces(verb)

        # Bind Enter / Shift+Enter navigation keys on all input entries
        self._bind_param_keys()

    def _bind_param_keys(self):
        """Bind Enter / Shift+Enter on every input entry in self._param_rows.

        Called from both _build_param_form (fresh introspection) and
        _replay_history (history / draft reload) so the bindings are
        always in place regardless of how the form was populated.

        Enter        -> move focus to first entry of the next row
        Shift+Enter  -> trigger Execute (if the button is enabled)
        Tab          -> default tkinter focus chain (unchanged)
        """
        # Build a per-row list of input widgets in logical order.
        _row_entry_lists = []
        for row in self._param_rows:
            if isinstance(row, RuleArrayRow) and row._cells:
                _row_entry_lists.append(list(row._cells))
            elif isinstance(row, ParamRow) and hasattr(row, 'entry'):
                _row_entry_lists.append([row.entry])
            else:
                _row_entry_lists.append([])

        # Map each widget -> first entry of the *next* non-empty row.
        _row_first = {}
        for i, lst in enumerate(_row_entry_lists):
            next_first = None
            for j in range(i + 1, len(_row_entry_lists)):
                if _row_entry_lists[j]:
                    next_first = _row_entry_lists[j][0]
                    break
            for w in lst:
                _row_first[id(w)] = next_first

        def _on_shift_enter(event):
            if str(self._btn_execute.cget('state')) == 'normal':
                self._on_execute()
            return 'break'

        def _on_enter(event):
            nxt = _row_first.get(id(event.widget))
            if nxt is not None:
                nxt.focus_set()
            return 'break'

        for lst in _row_entry_lists:
            for w in lst:
                w.bind('<Shift-Return>', _on_shift_enter, add=False)
                w.bind('<Return>',       _on_enter,       add=False)

    def _attach_draft_traces(self, verb: str):
        """Add write-traces to every input row so edits keep the draft current."""
        def _cb(*_):
            self._update_draft(verb)
        for row in self._param_rows:
            if hasattr(row, 'var'):
                row.var.trace_add('write', _cb)
            if isinstance(row, ParamRow) and row._sob_var is not None:
                row._sob_var.trace_add('write', _cb)

    def _update_draft(self, verb: str):
        """Upsert a draft HistoryEntry for *verb* reflecting current form state."""
        import uuid, datetime
        param_metas = [r.meta for r in self._param_rows]
        param_vals  = [r.var.get() if hasattr(r, 'var') else ''
                       for r in self._param_rows]
        param_sobs  = [
            (r._sob_var.get() if r._sob_var is not None else None)
            if isinstance(r, ParamRow) else None
            for r in self._param_rows
        ]

        # Build a lightweight preview of filled args (no connection needed)
        mode = self._name_mode.get() if self._name_mode else 'long'
        args = []
        for row, meta in zip(self._param_rows, param_metas):
            if meta['dir'] == 'out':
                continue
            val = row.var.get().strip() if hasattr(row, 'var') else ''
            if not val:
                continue
            fname = (meta.get('sname', meta['name'])
                     if mode == 'short' else meta['name'])
            if meta['type'].startswith('integer'):
                prefix = 'i'
            elif meta['type'] == 'string_or_binary':
                sob = row._sob_var.get() if (isinstance(row, ParamRow)
                      and row._sob_var) else 'c'
                prefix = sob
            elif 'binary' in meta['type']:
                prefix = 'x'
            elif meta['type'] == 'rule_array':
                packed = ' '.join(val.split())   # just preview as-is
                args.append(f'c{fname}={packed}')
                continue
            else:
                prefix = 'c'
            args.append(f'{prefix}{fname}={val}')

        ts = datetime.datetime.now().strftime('%H:%M:%S')

        existing_id = self._drafts.get(verb)
        if existing_id is not None:
            # Find and update the existing draft entry in-place
            for i, entry in enumerate(self._history):
                if entry.draft_id == existing_id:
                    entry.param_vals  = param_vals
                    entry.param_sobs  = param_sobs
                    entry.args        = args
                    # Update listbox label
                    self._hist_lb.delete(i)
                    self._hist_lb.insert(i,
                        f'  {ts}  ✎  DRAFT  {verb:<12}  '
                        + ' '.join(args))
                    self._hist_lb.itemconfig(i,
                        fg=CLR_ACCENT, selectforeground=CLR_SEL_FG)
                    self._hist_lb.see(i)   # keep draft row visible
                    return
            # Entry was deleted (e.g. CLEAR); fall through to create new
            del self._drafts[verb]

        # Create new draft
        draft_id = str(uuid.uuid4())
        entry = HistoryEntry(
            verb=verb, args=args, cmd_str='',
            param_metas=param_metas,
            param_vals=param_vals,
            param_sobs=param_sobs,
            output_segs=[],
            cca_rc=0, cca_rsn=0,
            draft_id=draft_id,
        )
        self._history.append(entry)
        self._drafts[verb] = draft_id
        self._hist_lb.insert('end',
            f'  {ts}  ✎  DRAFT  {verb:<12}  '
            + ' '.join(args))
        self._hist_lb.itemconfig('end',
            fg=CLR_ACCENT, selectforeground=CLR_SEL_FG)
        self._hist_lb.see('end')   # scroll to newly created draft

    def _remove_draft(self, verb: str):
        """Delete any existing draft entry for *verb* (called after execute)."""
        draft_id = self._drafts.pop(verb, None)
        if draft_id is None:
            return
        for i, entry in enumerate(self._history):
            if entry.draft_id == draft_id:
                self._history.pop(i)
                self._hist_lb.delete(i)
                return

    def _clear_params(self):
        for w in self._params_sf.inner.winfo_children():
            w.destroy()
        self._param_rows = []

    # -----------------------------------------------------------------------
    # Execute
    # -----------------------------------------------------------------------
    def _on_execute(self):
        if not self._selected_verb:
            return
        invalid = [r for r in self._param_rows if not r.is_valid()]
        if invalid:
            def _reason(r) -> str:
                val  = r.var.get().strip() if hasattr(r, 'var') else ''
                pt   = r.meta.get('type', '')
                mode = (r._sob_var.get() if isinstance(r, ParamRow)
                        and r._sob_var else None)
                if val and 'integer' in pt and not ParamRow._is_valid_int(val):
                    return f"{r.meta['name']}  (invalid integer)"
                if val and ('binary' in pt or mode == 'x') and not ParamRow._is_valid_hex(val):
                    v = val.replace(' ', '')
                    if len(v) % 2 != 0:
                        return f"{r.meta['name']}  (odd number of hex digits)"
                    return f"{r.meta['name']}  (invalid hex)"
                return f"{r.meta['name']}  (required)"
            messagebox.showerror(
                'Invalid or missing fields',
                'Please fix the following field(s):\n\n' +
                '\n'.join(_reason(r) for r in invalid))
            return

        mode = self._name_mode.get() if self._name_mode else 'long'
        verb_arg = f'cv={self._selected_verb}' if mode == 'short' else f'cverb={self._selected_verb}'
        args = [verb_arg]
        for row in self._param_rows:
            arg = row.to_arg()
            if arg:
                args.append(arg)

        self._btn_execute.configure(state='disabled', text='⏳ Sending...')
        self._status(
            f'Sending to {self._host.get()}:{self._port.get()}...')
        holder = _SocketHolder()
        popup  = ProgressPopup(self, holder,
                               title=f'Executing {self._selected_verb}...')
        threading.Thread(target=self._execute_worker,
                         args=(self._selected_verb, args, holder, popup),
                         daemon=True).start()

    def _execute_worker(self, verb: str, args: list[str],
                        holder: '_SocketHolder | None' = None,
                        popup:  'ProgressPopup | None'  = None):
        try:
            host = self._host.get().strip()
            port = int(self._port.get().strip())
            req_buf, _ = zcc.build_request(args)
            tls    = self._tls.get()
            verify = not self._tls_noverify.get()
            elements, resp = zcc_call(host, port, args, holder=holder, tls=tls, verify=verify)

            # Collect rc / rsn for error lookup
            cca_rc = cca_rsn = 0
            for el in elements:
                if el.name in ('rc', 'return_code') and el.type == 0x10:
                    cca_rc  = zcc.unpack_int32_le(el.value)
                if el.name in ('rsn', 'reason_code') and el.type == 0x10:
                    cca_rsn = zcc.unpack_int32_le(el.value)

            # Fetch error text if needed (in worker thread - blocks ok here)
            err_lines: list[str] = []
            if cca_rc != 0 or cca_rsn != 0:
                err_lines = fetch_error_text(host, port, cca_rc, cca_rsn,
                                             holder=holder, tls=tls, verify=verify)

            def _on_done():
                if popup:
                    popup.dismiss()
                self._show_response(verb, args, req_buf, resp, elements,
                                    cca_rc, cca_rsn, err_lines)

            self.after(0, _on_done)
        except Exception as exc:
            cancelled = holder is not None and holder.cancelled
            msg = 'Cancelled by user' if cancelled else str(exc)

            def _on_error(m=msg):
                if popup:
                    popup.dismiss()
                self._execute_error(m)

            self.after(0, _on_error)

    def _execute_error(self, msg: str):
        self._btn_execute.configure(state='normal', text='▶  Execute   ⇧↵')
        self._status(f'Error: {msg}')
        self._output_append(f'ERROR: {msg}\n', 'err')
        self._notebook.select(1)

    # -----------------------------------------------------------------------
    # Display response
    # -----------------------------------------------------------------------
    def _render_output(self, verb: str, cmd: str,
                       req_buf: bytes, resp_buf: bytes,
                       elements: list, cca_rc: int, cca_rsn: int,
                       err_lines: list[str]):
        """Write all output-pane content (text + copy buttons) for one response."""
        out = self._output_append

        out('═' * 72 + '\n', 'hdr')
        out(f'  Verb:  {verb}\n', 'hdr')
        out(f'  Command:  {cmd}\n', 'dim')
        out('═' * 72 + '\n', 'hdr')

        out('\nSending request:', 'hdr')
        self._output_hex_copy_btn(req_buf)
        out('\n', 'hdr')
        out(' ' * 54 +
            '|---- ASCII -----|  |---- EBCDIC ----|\n', 'dim')
        out(capture_dump(req_buf), 'mono')

        out('\nReceived reply:', 'hdr')
        self._output_hex_copy_btn(resp_buf)
        out('\n', 'hdr')
        out(' ' * 54 +
            '|---- ASCII -----|  |---- EBCDIC ----|\n', 'dim')
        out(capture_dump(resp_buf), 'mono')

        out('\nDecoded response fields:\n', 'hdr')
        out('─' * 72 + '\n', 'dim')

        for el in elements:
            val_str = el_to_display(el)
            tag = 'val'
            if el.name in ('rc', 'return_code'):
                tag = 'ok' if (cca_rc == 0 and cca_rsn == 0) else 'rc_err'
            elif el.name in ('rsn', 'reason_code'):
                tag = 'ok' if (cca_rc == 0 and cca_rsn == 0) else 'rc_err'
            elif el.name == 'zcc_time':
                tag = 'dim'
            out(f'  {el.name:>{zcc.LONGEST_NAME}}: ', 'name')
            self._output_copy_btn(val_str)
            out(val_str, tag)
            out('\n', tag)

        out('─' * 72 + '\n', 'dim')

        if cca_rc != 0 or cca_rsn != 0:
            out(f'\n  ✗  rc={cca_rc}  rsn={cca_rsn}\n', 'err')
            if err_lines:
                out('\nError description (cv=ERROR):\n', 'hdr')
                out('─' * 72 + '\n', 'dim')
                for line in err_lines:
                    out(f'  {line}\n', 'errtxt')
                out('─' * 72 + '\n', 'dim')
            else:
                out('  (No error description available from cv=ERROR)\n', 'dim')
        else:
            out(f'\n  ✓  rc={cca_rc}  rsn={cca_rsn}  -- success\n', 'ok')

        out('═' * 72 + '\n\n', 'hdr')

    def _show_response(self, verb: str, args: list[str],
                       req_buf: bytes, resp: bytes,
                       elements: list[zcc.BsonEl],
                       cca_rc: int, cca_rsn: int,
                       err_lines: list[str]):
        self._btn_execute.configure(state='normal', text='▶  Execute   ⇧↵')
        self._clear_output()

        host = self._host.get().strip()
        port = self._port.get().strip()
        def _quote(a: str) -> str:
            eq = a.find('=')
            if eq != -1 and ' ' in a[eq+1:]:
                return a[:eq+1] + '"' + a[eq+1:] + '"'
            return a
        quoted_args = [_quote(a) for a in args]
        tls_flags = ''
        if self._tls.get():
            tls_flags += ' -t'
            if self._tls_noverify.get():
                tls_flags += ' -k'
        cmd  = f'python zcclient.py{tls_flags} {host} {port} {" ".join(quoted_args)}'
        self._last_cmd_str = cmd
        self._btn_copy_cmd.configure(state='normal')
        short_cmd = cmd if len(cmd) <= 80 else cmd[:77] + '...'
        self._lbl_cmd_display.configure(text=short_cmd)

        self._render_output(verb, cmd, req_buf, resp,
                            elements, cca_rc, cca_rsn, err_lines)

        if cca_rc != 0 or cca_rsn != 0:
            self._status(f'{verb}  FAILED  rc={cca_rc}  rsn={cca_rsn}')
            self._conn_indicator.configure(fg=CLR_RED)
        else:
            self._status(f'{verb}  completed  rc={cca_rc}  rsn={cca_rsn}')
            self._conn_indicator.configure(fg=CLR_ACCENT2)

        # -- Remove any draft for this verb, then record executed entry ----
        self._remove_draft(verb)
        segs = list(self._last_output_segs)

        param_metas = [r.meta for r in self._param_rows]
        param_vals  = [r.var.get() if hasattr(r, 'var') else '' for r in self._param_rows]
        param_sobs  = [
            (r._sob_var.get() if r._sob_var is not None else None)
            if isinstance(r, ParamRow) else None
            for r in self._param_rows
        ]

        entry = HistoryEntry(
            verb=verb, args=args, cmd_str=cmd,
            param_metas=param_metas,
            param_vals=param_vals,
            param_sobs=param_sobs,
            output_segs=segs,
            cca_rc=cca_rc, cca_rsn=cca_rsn,
            req_buf=req_buf, resp_buf=resp,
            elements=elements, err_lines=err_lines,
        )
        self._history.append(entry)
        rc_marker = '✓' if cca_rc == 0 else '✗'
        import datetime
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        entry.ts = ts   # stored for history serialisation
        self._hist_lb.insert('end',
            f'  {ts}  {rc_marker}  rc={cca_rc:>3}  rsn={cca_rsn:>6}  {verb:<12}  '
            + ' '.join(args[1:]))  # skip cverb=VERB
        self._hist_lb.see('end')

        self._notebook.select(1)

    # -----------------------------------------------------------------------
    # Copy-command helper
    # -----------------------------------------------------------------------
    def _copy_command(self):
        if self._last_cmd_str:
            self.clipboard_clear()
            self.clipboard_append(self._last_cmd_str)
            self._btn_copy_cmd.configure(text='✓ Copied!')
            self.after(2000, lambda: self._btn_copy_cmd.configure(
                text='⧉ Copy command'))

    # -----------------------------------------------------------------------
    # History pane handlers
    # -----------------------------------------------------------------------
    def _on_history_select(self, _event):
        sel = self._hist_lb.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._history):
            return
        entry = self._history[idx]
        self._replay_history(entry)

    def _replay_history(self, entry: HistoryEntry):
        """Restore parameters pane and output pane from a history entry."""
        is_draft = entry.draft_id is not None
        # -- Rebuild param form from stored metas + values ----------------
        self._clear_params()
        self._selected_verb = entry.verb
        self._btn_ibm_help.configure(
            state='normal' if _ibm_help_url(entry.verb) else 'disabled')
        if is_draft:
            self._verb_title.configure(
                text=f'{entry.verb}  --  DRAFT (in progress)',
                fg=CLR_ACCENT2)
            self._lbl_params_hint.configure(
                text=f'Draft: {entry.verb}  --  edit fields and execute when ready',
                fg=CLR_ACCENT2)
        else:
            self._verb_title.configure(
                text=f'{entry.verb}  --  HISTORY REPLAY',
                fg=CLR_FG_DIM)
            self._lbl_params_hint.configure(
                text=f'History replay: {entry.verb}', fg=CLR_FG_DIM)

        container = self._params_sf.inner

        # Column headers
        hdr = tk.Frame(container, bg=CLR_BG)
        hdr.pack(fill='x', padx=4, pady=(4, 0))
        for text, w in [('Dir', 6), ('Name (* = required)', 28),
                        ('Type', 18), ('Value', 48)]:
            tk.Label(hdr, text=text, bg=CLR_BG, fg=CLR_FG_DIM,
                     font=FONT_SMALL, width=w, anchor='w').pack(side='left', padx=4)
        tk.Frame(container, bg=CLR_BORDER, height=1).pack(
            fill='x', padx=4, pady=2)

        self._param_rows = []
        for i, (meta, val, sob) in enumerate(zip(
                entry.param_metas, entry.param_vals, entry.param_sobs)):
            row_bg = CLR_BG if i % 2 == 0 else CLR_PANEL
            if meta['name'] == 'rule_array' and meta['dir'] in ('in', 'both'):
                row = RuleArrayRow(container, meta, self._params_sf, bg=row_bg)
            else:
                row = ParamRow(container, meta, self._params_sf, bg=row_bg)
            if hasattr(row, 'var'):
                row.var.set(val)
            if isinstance(row, ParamRow) and row._sob_var is not None:
                if sob is not None:
                    row._sob_var.set(sob)
                elif is_draft:
                    row._sob_var.set('x')   # draft default: Binary (hex)
            row.pack(fill='x', padx=4, pady=1)
            self._param_rows.append(row)

        self._btn_execute.configure(state='normal', text='▶  Execute   ⇧↵')
        self._btn_introspect.configure(state='normal')

        # Re-attach draft traces so further edits keep the draft live.
        # For a completed-entry replay we still attach traces so the user
        # can modify the form and get a new draft for this verb.
        self._attach_draft_traces(entry.verb)
        # Reapply Enter / Shift+Enter bindings to all input entries.
        self._bind_param_keys()

        # -- Restore output pane ------------------------------------------
        self._clear_output()
        if is_draft:
            # Draft has no output yet -- show a placeholder
            self._txt_output.configure(state='normal')
            self._txt_output.insert('end',
                '  (no output yet -- fill in parameters and execute)\n', 'dim')
            self._txt_output.configure(state='disabled')
        elif entry.req_buf:
            # Re-render using stored data so copy buttons are recreated
            self._render_output(entry.verb, entry.cmd_str,
                                entry.req_buf, entry.resp_buf,
                                entry.elements, entry.cca_rc, entry.cca_rsn,
                                entry.err_lines)
            self._txt_output.see('1.0')
        elif entry.output_segs:
            # Fallback for entries created before req_buf was stored
            for text, tag in entry.output_segs:
                self._txt_output.configure(state='normal')
                self._txt_output.insert('end', text, tag)
                self._txt_output.configure(state='disabled')
            self._txt_output.see('1.0')

        # -- Restore copy-command state -----------------------------------
        self._last_cmd_str = entry.cmd_str
        if entry.cmd_str:
            self._btn_copy_cmd.configure(state='normal')
            short_cmd = (entry.cmd_str if len(entry.cmd_str) <= 80
                         else entry.cmd_str[:77] + '...')
            self._lbl_cmd_display.configure(text=short_cmd)
        else:
            self._btn_copy_cmd.configure(state='disabled')
            self._lbl_cmd_display.configure(text='')

        rc = entry.cca_rc
        rsn = entry.cca_rsn
        if is_draft:
            self._status(f'{entry.verb}  (draft -- not yet executed)')
            self._conn_indicator.configure(fg=CLR_ACCENT2)
        elif rc == 0:
            self._status(f'{entry.verb}  (history)  rc={rc}  rsn={rsn}')
            self._conn_indicator.configure(fg=CLR_ACCENT2)
        else:
            self._status(f'{entry.verb}  (history)  FAILED  rc={rc}  rsn={rsn}')
            self._conn_indicator.configure(fg=CLR_RED)

        if is_draft:
            self._notebook.select(0)   # show Parameters so user can edit
        else:
            self._notebook.select(1)   # show Output for completed entries

    def _clear_history(self):
        self._history.clear()
        self._hist_lb.delete(0, 'end')
        self._drafts.clear()

    def _save_history_as(self):
        """Prompt for a .zcchist file path and write the current history to it."""
        completed = [e for e in self._history if e.draft_id is None]
        if not completed:
            messagebox.showinfo('Save History', 'No completed entries to save.',
                                parent=self)
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title='Save History',
            defaultextension='.zcchist',
            filetypes=[('ZCC History', '*.zcchist'), ('All files', '*.*')],
        )
        if not path:
            return
        try:
            _save_history(self._history, path=path)
            self._status(f'History saved to {pathlib.Path(path).name}'
                         f'  ({len(completed)} entries)')
        except Exception as exc:
            messagebox.showerror('Save History',
                                 f'Could not save history:\n{exc}', parent=self)

    def _load_history_from(self):
        """Prompt for a .zcchist file and append its entries to the current history."""
        path = filedialog.askopenfilename(
            parent=self,
            title='Load History',
            defaultextension='.zcchist',
            filetypes=[('ZCC History', '*.zcchist'), ('All files', '*.*')],
        )
        if not path:
            return
        try:
            restored = _load_history(path=path)
        except Exception as exc:
            messagebox.showerror('Load History',
                                 f'Could not load history:\n{exc}', parent=self)
            return
        if not restored:
            messagebox.showinfo('Load History',
                                'File contained no valid history entries.',
                                parent=self)
            return
        for entry, lb_text, lb_clr in restored:
            self._history.append(entry)
            self._hist_lb.insert('end', lb_text)
            if lb_clr:
                self._hist_lb.itemconfig('end', fg=lb_clr,
                                         selectforeground=lb_clr)
        self._hist_lb.see('end')
        self._status(f'Loaded {len(restored)} entries from'
                     f' {pathlib.Path(path).name}')

    # -----------------------------------------------------------------------
    # Output helpers
    # -----------------------------------------------------------------------
    def _output_append(self, text: str, tag: str = 'val'):
        self._txt_output.configure(state='normal')
        self._txt_output.insert('end', text, tag)
        self._txt_output.see('end')
        self._txt_output.configure(state='disabled')
        self._last_output_segs.append((text, tag))

    def _output_copy_btn(self, value: str, large: bool = False):
        """Embed a ⎘ copy button at the current end of the output text.
        On click, copies *value* to clipboard and shows a brief flyover popup."""

        def _show_copied(lbl):
            lbl.configure(fg=CLR_ACCENT)
            # Flyover "Copied!" popup
            tw = tk.Toplevel(lbl)
            tw.wm_overrideredirect(True)
            x = lbl.winfo_rootx() + lbl.winfo_width() + 2
            y = lbl.winfo_rooty() - 4
            tw.wm_geometry(f'+{x}+{y}')
            tk.Label(tw, text=' Copied! ', bg=CLR_ACCENT, fg='#FFFFFF',
                     font=(_SANS, 8, 'bold'), relief='flat',
                     padx=4, pady=2).pack()
            lbl.after(1200, tw.destroy)
            lbl.after(1200, lambda: lbl.configure(fg=CLR_FG_DIM))

        def _do_copy(event, lbl):
            self.clipboard_clear()
            self.clipboard_append(value)
            _show_copied(lbl)

        font  = (_SANS, 9)  if large else (_SANS, 8)
        text  = ' ⎘ Copy ' if large else ' ⎘ '
        lbl = tk.Label(self._txt_output, text=text, font=font,
                       fg=CLR_FG_DIM, bg=CLR_MONO_BG, cursor='hand2',
                       relief='flat', padx=0, pady=0)
        lbl.bind('<Button-1>', lambda e, l=lbl: _do_copy(e, l))
        lbl.bind('<Enter>',    lambda e: lbl.configure(fg=CLR_ACCENT))
        lbl.bind('<Leave>',    lambda e: lbl.configure(fg=CLR_FG_DIM))

        self._txt_output.configure(state='normal')
        self._txt_output.window_create('end', window=lbl)
        self._txt_output.configure(state='disabled')

    def _output_hex_copy_btn(self, buf: bytes):
        """Embed a larger ⎘ copy button that copies *buf* as a hex string."""
        self._output_copy_btn(buf.hex(), large=True)

    def _clear_output(self):
        self._txt_output.configure(state='normal')
        self._txt_output.delete('1.0', 'end')
        self._txt_output.configure(state='disabled')
        self._last_output_segs = []

    def _status(self, msg: str):
        self._statusbar.configure(text=msg)


# ===========================================================================
def main():
    # Load config first so cached host/port act as defaults when the
    # user doesn't supply command-line arguments.
    _cfg = _load_config()
    cached_host = _cfg.get('host', '127.0.0.1')
    cached_port = _cfg.get('port', '8080')

    parser = argparse.ArgumentParser(
        description='ZCC GUI Client',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('host', nargs='?', default=cached_host,
                        help='ZCC server host name or IP address')
    parser.add_argument('port', nargs='?', default=cached_port,
                        help='ZCC server port number')
    args = parser.parse_args()
    app = ZccGui(host=args.host, port=str(args.port))
    app.mainloop()


if __name__ == '__main__':
    main()
