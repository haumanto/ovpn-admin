#!/usr/bin/env python3
"""Telegram notification for a new ban and the lifting of a ban of the ovpn-admin ban engine (called by ovpn-ban.sh, installed by
configure.sh as /usr/local/sbin/ovpn-telegram-notify).

    ovpn-telegram-notify ban ADDRESS REASON OFFENCE BAN_SECONDS [USER]
    ovpn-telegram-notify unban ADDRESS
    ovpn-telegram-notify --check-api-base URL      validate OVPN_TELEGRAM_API_BASE (and OVPN_TELEGRAM_ALLOW_HTTP) only: exit 0 valid,
                                                   2 invalid + reason on stderr

ADDRESS is an address, a network or "-" (none). USER is optional: the user name that the OpenVPN audit log knows for the address (ovpn-ban.sh
looks it up), "-" = none. It must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} (so no space, no newline, at most 64 characters): anything else is
exit 2 with one line on stderr and nothing is sent (ovpn-ban.sh drops an invalid name itself, so the alert still goes out without it).
ADDRESS and USER only reach the message with OVPN_TELEGRAM_INCLUDE_ADDRESS=true (the default); with false the message names neither.

Configuration comes from the environment only, never from argv, a file or the output:
    OVPN_TELEGRAM_BOT_TOKEN    bot token (secret: never printed, never part of an error message)
    OVPN_TELEGRAM_CHAT_ID      chat id (integer, or @channelname)
    OVPN_TELEGRAM_THREAD_ID    optional forum topic id (integer)
    OVPN_TELEGRAM_API_BASE     default https://api.telegram.org; https:// always; http:// only with OVPN_TELEGRAM_ALLOW_HTTP=true
                               (see api_base for the rules on host, port, user info, query and fragment)
    OVPN_TELEGRAM_ALLOW_HTTP   default false; exactly "true" allows an http:// API base (local mock tests only)
    OVPN_TELEGRAM_INCLUDE_ADDRESS  default true (unset or empty = true); "true" adds the address and the user name to the message, "false"
                               leaves both out. Any other value is treated like "false" here (ovpn-ban.sh and configure.sh refuse it at start)

The message is plain text (no parse_mode) and at most 4000 characters. Since v0.1.12 it carries the address and, when known, the user name
(v0.1.11 left both out as a privacy measure; the owner reversed that, OVPN_TELEGRAM_INCLUDE_ADDRESS=false restores the address-free text):
    🚫 ovpn-admin: banned <address>   (address only with OVPN_TELEGRAM_INCLUDE_ADDRESS=true; the network for an IPv6 ban)
    Reason: <reason>                 (a manual ban: "manual", its note is never sent)
    User: <name>                     (only with an address-including message and a USER argument other than "-")
    Offence: <n>                     (left out when 0: a manual ban of an address without offences)
    Duration: <10 minutes | 1 hour | 24 hours | permanent | ...>
    Until: <YYYY-MM-DD HH:MM UTC | permanent>
    Server: <hostname>

    ✅ ovpn-admin: ban lifted for <address>   (no address with OVPN_TELEGRAM_INCLUDE_ADDRESS=false; never a user name)
    Server: <hostname>
The user name is what the client typed at the login that failed: it is not verified, anybody can type any name. Treat it as a hint.

Exit status: 0 sent, 1 delivery failed, 2 invalid input or configuration. On failure exactly one line starting with
"ovpn-telegram-notify: WARNING" goes to stderr. It names the kind of message and of failure (HTTP status, error class), never the
address or the user name; the response body is never printed because Telegram can echo the request, and the token is part of the request URL.
"""

import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROG = "ovpn-telegram-notify"
DEFAULT_API_BASE = "https://api.telegram.org"
MAX_TEXT = 4000
TIMEOUT_SECONDS = 10
# the reasons ovpn-ban.sh (reason_for) can produce, plus "manual" and "manual: <note>" (ban-manual); nothing else is accepted
REASONS = {
    "manual",
    "fail2ban",
    "revoked-certificate",
    "auth-failed",
    "revoked-certificate+auth-failed",
    "auth-failed+revoked-certificate",
}
TOKEN_RE = re.compile(r"^[0-9]{1,20}:[A-Za-z0-9_-]{1,128}$")
CHAT_ID_RE = re.compile(r"^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,63})$")
THREAD_ID_RE = re.compile(r"^[1-9][0-9]{0,15}$")
MANUAL_REASON_RE = re.compile(r"^manual: [A-Za-z0-9._:-]([A-Za-z0-9 ._:-]{0,118}[A-Za-z0-9._:-])?$")
FAILURES_RE = re.compile(r"^(0|[1-9][0-9]{0,9})$")
EXPIRES_RE = re.compile(r"^(0|[1-9][0-9]{0,11})$")
USER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # used with fullmatch: "$" would also match before a trailing newline
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


def human_duration(seconds):
    if seconds == 0:
        return "permanent"
    if seconds % 86400 == 0 and seconds >= 172800:
        return f"{seconds // 86400} days"
    if seconds % 3600 == 0:
        n = seconds // 3600
        return f"{n} hour" + ("" if n == 1 else "s")
    if seconds % 60 == 0:
        n = seconds // 60
        return f"{n} minute" + ("" if n == 1 else "s")
    return f"{seconds} seconds"


def until_text(seconds, now=None):
    """The end of the ban in UTC (now + seconds: the message is sent right after the ban), or "permanent"."""
    if seconds == 0:
        return "permanent"
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(time.time() if now is None else now) + seconds))
    except (OverflowError, ValueError, OSError):
        return "beyond year 9999"


def include_address(env):
    """OVPN_TELEGRAM_INCLUDE_ADDRESS: unset or empty = the default (true), exactly "true" = true; "false" and anything else = no address."""
    return env.get("OVPN_TELEGRAM_INCLUDE_ADDRESS", "") in ("", "true")


def checked_user(value):
    """The optional USER argument: None for "-", the name when it matches USER_RE, otherwise Invalid (the caller exits 2 and sends nothing)."""
    if value == "-":
        return None
    if not USER_RE.fullmatch(value):
        raise Invalid("USER is not a valid user name (1 to 64 characters of A-Za-z0-9._-, starting with a letter or digit), or \"-\"")
    return value


def shown_address(address, env):
    """The address as it may appear in the message: None when OVPN_TELEGRAM_INCLUDE_ADDRESS says no; "-" means "none given"."""
    if address == "-":
        return None
    try:
        net = ipaddress.ip_network(address, strict=False)
    except ValueError:
        raise Invalid("ADDRESS is not an IPv4 or IPv6 address or network, or \"-\"") from None
    if not include_address(env):
        return None
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def build_message(kind, args, env, now=None):
    """The text of a "ban" (ADDRESS REASON OFFENCE BAN_SECONDS [USER]) or "unban" (ADDRESS) message: the fixed vocabulary of the ban engine,
    numbers, the host name and, unless OVPN_TELEGRAM_INCLUDE_ADDRESS is false, the address and the validated user name. The free text of a
    manual ban (its note) is never part of it."""
    host = socket.gethostname()
    if kind == "unban":
        if len(args) != 1:
            raise Invalid("unban needs ADDRESS")
        addr = shown_address(args[0], env)
        head = "\u2705 ovpn-admin: ban lifted" + (f" for {addr}" if addr else "")
        return "\n".join([head, f"Server: {host}"])[:MAX_TEXT]
    if len(args) not in (4, 5):
        raise Invalid("ban needs ADDRESS REASON OFFENCE BAN_SECONDS [USER]")
    address, reason, offence, seconds = args[:4]
    name = checked_user(args[4]) if len(args) == 5 else None
    addr = shown_address(address, env)
    if reason not in REASONS and not MANUAL_REASON_RE.fullmatch(reason):
        raise Invalid("REASON is not a known ban reason")
    if reason.startswith("manual"):
        reason = "manual"  # the note of a manual ban is free text of the operator: never part of the message
    if not FAILURES_RE.match(offence):
        raise Invalid("OFFENCE must be a non-negative integer")
    if not EXPIRES_RE.match(seconds):
        raise Invalid("BAN_SECONDS must be a number of seconds, or 0 for a permanent ban")
    lines = ["\U0001F6AB ovpn-admin: banned" + (f" {addr}" if addr else ""), f"Reason: {reason}"]
    if name and include_address(env):  # with the address left out, the name is left out too
        lines.append(f"User: {name}")
    if int(offence) > 0:
        lines.append(f"Offence: {int(offence)}")
    lines += [f"Duration: {human_duration(int(seconds))}", f"Until: {until_text(int(seconds), now)}", f"Server: {host}"]
    return "\n".join(lines)[:MAX_TEXT]


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
    if len(argv) < 2 or argv[1] not in ("ban", "unban"):
        print(f"usage: {PROG} ban ADDRESS REASON OFFENCE BAN_SECONDS [USER] | unban ADDRESS | --check-api-base URL", file=sys.stderr)
        return 2
    kind = argv[1]
    try:
        text = build_message(kind, argv[2:], os.environ)
        send(os.environ, text)
    except Invalid as exc:
        warn(f"notification ({kind}) not sent: {exc}")
        return 2
    except RuntimeError as exc:
        warn(f"notification ({kind}) failed: {exc}")
        return 1
    except Exception as exc:  # never let an unexpected error carry details (or a traceback with the URL) to the log
        warn(f"notification ({kind}) failed ({type(exc).__name__})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
