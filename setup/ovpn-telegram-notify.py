#!/usr/bin/env python3
"""Telegram notification for a new ban of the ovpn-admin ban engine (called by ovpn-ban.sh, installed by configure.sh as
/usr/local/sbin/ovpn-telegram-notify).

    ovpn-telegram-notify IP FAILURES REASON EXPIRES_AT_UNIX
    ovpn-telegram-notify --check-api-base URL      validate OVPN_TELEGRAM_API_BASE (and OVPN_TELEGRAM_ALLOW_HTTP) only: exit 0 valid,
                                                   2 invalid + reason on stderr

Configuration comes from the environment only, never from argv, a file or the output:
    OVPN_TELEGRAM_BOT_TOKEN   bot token (secret: never printed, never part of an error message)
    OVPN_TELEGRAM_CHAT_ID     chat id (integer, or @channelname)
    OVPN_TELEGRAM_THREAD_ID   optional forum topic id (integer)
    OVPN_TELEGRAM_API_BASE    default https://api.telegram.org; https:// always; http:// only with OVPN_TELEGRAM_ALLOW_HTTP=true
                              (see api_base for the rules on host, port, user info, query and fragment)
    OVPN_TELEGRAM_ALLOW_HTTP  default false; exactly "true" allows an http:// API base (local mock tests only)

The message is plain text (no parse_mode), at most 4000 characters:
    🚫 ovpn-admin: banned <ip>
    Reason: <reason>
    Attempts: <failures>
    Until: <YYYY-MM-DD HH:MM UTC>
    Server: <hostname>

Exit status: 0 sent, 1 delivery failed, 2 invalid input or configuration. On failure exactly one line starting with
"ovpn-telegram-notify: WARNING" goes to stderr. It names the IP and the kind of failure (HTTP status, error class); the
response body is never printed because Telegram can echo the request, and the token is part of the request URL.
"""

import datetime
import ipaddress
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request

PROG = "ovpn-telegram-notify"
DEFAULT_API_BASE = "https://api.telegram.org"
MAX_TEXT = 4000
TIMEOUT_SECONDS = 10
# the reasons ovpn-ban.sh (reason_for) can produce, nothing else is accepted
REASONS = {
    "fail2ban",
    "revoked-certificate",
    "auth-failed",
    "revoked-certificate+auth-failed",
    "auth-failed+revoked-certificate",
}
TOKEN_RE = re.compile(r"^[0-9]{1,20}:[A-Za-z0-9_-]{1,128}$")
CHAT_ID_RE = re.compile(r"^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,63})$")
THREAD_ID_RE = re.compile(r"^[1-9][0-9]{0,15}$")
FAILURES_RE = re.compile(r"^[1-9][0-9]{0,9}$")
EXPIRES_RE = re.compile(r"^[1-9][0-9]{0,11}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
BRACKET_RE = re.compile(r"^\[[0-9A-Fa-f:.]+\](:[0-9]+)?$")


class Invalid(Exception):
    """Invalid input or configuration; the message never contains the token."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would forward the request (and with it the token in the URL path) to another place."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def warn(msg):
    print(f"{PROG}: WARNING: {msg}", file=sys.stderr)


def api_base(raw, allow_http=False):
    """The one validator for OVPN_TELEGRAM_API_BASE: used by the send path and, through "--check-api-base", by configure.sh.

    Accepted: https://, or http:// only when allow_http (OVPN_TELEGRAM_ALLOW_HTTP is exactly "true"); a host name, an IPv4
    address or a bracketed IPv6 address; an optional :port (digits, 1-65535); an optional path.
    Rejected: other schemes, a missing host, user info, an empty/non-numeric/out-of-range port, a malformed bracket,
    a query, a fragment, whitespace, control characters, a backslash. Returns the base without a trailing slash.
    The error text never echoes the value.
    """
    base = raw or DEFAULT_API_BASE
    if not base.isascii() or "\\" in base or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base):
        raise Invalid("OVPN_TELEGRAM_API_BASE must be plain ASCII without spaces, control characters or backslashes")
    try:
        parts = urllib.parse.urlsplit(base)
        port = parts.port  # ValueError: not a number or outside 0-65535
        host = parts.hostname
    except ValueError:
        raise Invalid("OVPN_TELEGRAM_API_BASE has a malformed host, bracket or port") from None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise Invalid("OVPN_TELEGRAM_API_BASE must be an https:// URL (http:// only with OVPN_TELEGRAM_ALLOW_HTTP=true)")
    if parts.scheme == "http" and not allow_http:
        raise Invalid("OVPN_TELEGRAM_API_BASE uses http://: refused unless OVPN_TELEGRAM_ALLOW_HTTP=true (local mock tests only)")
    if "?" in base or "#" in base or parts.query or parts.fragment:
        raise Invalid("OVPN_TELEGRAM_API_BASE must not carry a query or a fragment")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise Invalid("OVPN_TELEGRAM_API_BASE must not carry user info (credentials)")
    if not host:
        raise Invalid("OVPN_TELEGRAM_API_BASE needs a host name")
    if "[" in parts.netloc or "]" in parts.netloc:
        if not BRACKET_RE.match(parts.netloc):
            raise Invalid("OVPN_TELEGRAM_API_BASE has a malformed bracket")
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise Invalid("OVPN_TELEGRAM_API_BASE has a malformed bracket (not an IPv6 address)") from None
    elif not HOST_RE.match(host) or len(host) > 253:
        raise Invalid("OVPN_TELEGRAM_API_BASE needs a valid host name or IPv4 address")
    if parts.netloc.endswith(":"):
        raise Invalid("OVPN_TELEGRAM_API_BASE has an empty port (write host:PORT or leave the colon out)")
    # the port text itself must be plain digits (older Python versions accept "+80" in .port)
    port_text = parts.netloc[parts.netloc.rfind("]") + 1:].partition(":")[2]
    if (port_text and not port_text.isdigit()) or (port is not None and not 1 <= port <= 65535):
        raise Invalid("OVPN_TELEGRAM_API_BASE port must be a number from 1 to 65535")
    return base.rstrip("/")


def build_message(ip, failures, reason, expires_at):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise Invalid("IP is not an IPv4 or IPv6 address") from None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not FAILURES_RE.match(failures):
        raise Invalid("FAILURES must be a positive integer")
    if reason not in REASONS:
        raise Invalid("REASON is not a known ban reason")
    if not EXPIRES_RE.match(expires_at):
        raise Invalid("EXPIRES_AT must be a unix time in seconds")
    try:
        until = datetime.datetime.fromtimestamp(int(expires_at), datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise Invalid("EXPIRES_AT is out of range") from None
    host = socket.gethostname()
    text = (
        f"\U0001F6AB ovpn-admin: banned {addr}\n"
        f"Reason: {reason}\n"
        f"Attempts: {int(failures)}\n"
        f"Until: {until:%Y-%m-%d %H:%M} UTC\n"
        f"Server: {host}"
    )
    return str(addr), text[:MAX_TEXT]


def send(env, text):
    token = env.get("OVPN_TELEGRAM_BOT_TOKEN", "")
    chat_id = env.get("OVPN_TELEGRAM_CHAT_ID", "")
    thread_id = env.get("OVPN_TELEGRAM_THREAD_ID", "")
    if not TOKEN_RE.match(token):
        raise Invalid("OVPN_TELEGRAM_BOT_TOKEN is missing or malformed")
    if not CHAT_ID_RE.match(chat_id):
        raise Invalid("OVPN_TELEGRAM_CHAT_ID is missing or malformed")
    if thread_id and not THREAD_ID_RE.match(thread_id):
        raise Invalid("OVPN_TELEGRAM_THREAD_ID must be a positive integer")
    base = api_base(env.get("OVPN_TELEGRAM_API_BASE", ""), env.get("OVPN_TELEGRAM_ALLOW_HTTP", "") == "true")

    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if thread_id:
        payload["message_thread_id"] = int(thread_id)
    request = urllib.request.Request(
        f"{base}/bot{token}/sendMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read(65536)
            status = resp.status
    except urllib.error.HTTPError as exc:  # also a redirect: no handler follows it
        raise RuntimeError(f"Telegram answered HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        reason = exc.reason
        detail = type(reason).__name__
        if isinstance(reason, OSError) and reason.errno:
            detail += f" errno {reason.errno}"
        raise RuntimeError(f"cannot reach the Telegram API ({detail})") from None
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"request failed ({type(exc).__name__})") from None
    if status != 200:
        raise RuntimeError(f"Telegram answered HTTP {status}")
    try:
        ok = json.loads(body.decode("utf-8")).get("ok") is True
    except (ValueError, AttributeError):
        ok = False
    if not ok:
        raise RuntimeError("Telegram answered without ok=true")


def main(argv):
    if len(argv) == 3 and argv[1] == "--check-api-base":
        # startup check of configure.sh: the same validator as the send path; no token involved, nothing is sent
        try:
            api_base(argv[2], os.environ.get("OVPN_TELEGRAM_ALLOW_HTTP", "") == "true")
        except Invalid as exc:
            print(exc, file=sys.stderr)
            return 2
        return 0
    if len(argv) != 5:
        print(f"usage: {PROG} IP FAILURES REASON EXPIRES_AT_UNIX", file=sys.stderr)
        return 2
    ip = argv[1][:45]  # only used in log lines until build_message has validated it
    try:
        ip, text = build_message(*argv[1:5])
        send(os.environ, text)
    except Invalid as exc:
        warn(f"notification for {ip!r} not sent: {exc}")
        return 2
    except RuntimeError as exc:
        warn(f"notification for {ip} failed: {exc}")
        return 1
    except Exception as exc:  # never let an unexpected error carry details (or a traceback with the URL) to the log
        warn(f"notification for {ip!r} failed ({type(exc).__name__})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
