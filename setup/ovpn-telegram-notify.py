#!/usr/bin/env python3
"""Telegram notification for a new ban of the ovpn-admin ban engine (called by ovpn-ban.sh, installed by configure.sh as
/usr/local/sbin/ovpn-telegram-notify).

    ovpn-telegram-notify IP FAILURES REASON EXPIRES_AT_UNIX

Configuration comes from the environment only, never from argv, a file or the output:
    OVPN_TELEGRAM_BOT_TOKEN   bot token (secret: never printed, never part of an error message)
    OVPN_TELEGRAM_CHAT_ID     chat id (integer, or @channelname)
    OVPN_TELEGRAM_THREAD_ID   optional forum topic id (integer)
    OVPN_TELEGRAM_API_BASE    default https://api.telegram.org; only http:// or https:// is accepted

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


class Invalid(Exception):
    """Invalid input or configuration; the message never contains the token."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would forward the request (and with it the token in the URL path) to another place."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def warn(msg):
    print(f"{PROG}: WARNING: {msg}", file=sys.stderr)


def api_base(raw):
    base = (raw or DEFAULT_API_BASE).strip()
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise Invalid("OVPN_TELEGRAM_API_BASE must be an http:// or https:// URL")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise Invalid("OVPN_TELEGRAM_API_BASE must not carry credentials, a query or a fragment")
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
    base = api_base(env.get("OVPN_TELEGRAM_API_BASE", ""))

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
