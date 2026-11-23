#!/usr/bin/env python3
"""Manual ban control queue of the ovpn-admin ban engine (started in the background by configure.sh, installed as
/usr/local/sbin/ovpn-ban-control).

    ovpn-ban-control [CONTROL_DIR]      default: $OVPN_BAN_CONTROL_DIR

The control directory is shared with the ovpn-admin container (a subdirectory "control" of the root-only state directory /var/lib/ovpn-admin). It is owned by
the user that runs this watcher (root) with mode 0700; the watcher refuses to start otherwise. A caller writes a request:

    <id>.req     {"id":"<id>","action":"ban"|"unban","ip":"<address>","reason":"<note>","force":true|false,"minutes":<1..525600>}

("reason", "force" and "minutes" are optional: force defaults to false, minutes to absent = permanent; "minutes" and "force" apply to "ban"
only; an unban may name the network a ban list row shows, "2001:db8:1:2::/64", as well as an address)
(a temporary file first, then a rename to <id>.req, so that a half written request is never read) and waits for

    <id>.result  {"ok":true|false,"message":"..."}

<id> is 1 to 64 characters of [A-Za-z0-9_-] and equals the "id" of the request. The result name comes from the file name, never
from the content. The watcher polls every 0.5 s and handles one request per poll:

  1. the request is claimed by renaming it to <id>.proc (a request is processed at most once: an interrupted one found at the next
     start gets an error result, it is never run again; a request whose id already has a result is dropped and logged),
  2. it is validated (size, JSON, keys, id, action, address pattern, reason pattern [A-Za-z0-9 ._:-]{0,120}, force, minutes),
  3. "ban" runs   ovpn-ban.sh ban-manual [--force] [--minutes N] IP [REASON]      "unban" runs   ovpn-ban.sh unban IP --force
     (ovpn-ban.sh refuses a loopback, ignore-listed, VPN network and private address unless "force" is true; the refusal reason is the
     result message and the ban is not applied)
     through subprocess with a fixed argument vector (no shell; IP and REASON are only ever arguments, never part of a command line),
  4. the result is written atomically (temporary file, rename), then <id>.proc is removed.

A malformed request gets {"ok":false,...}. Nothing a request contains can stop the watcher: every failure is one log line on stderr,
then the loop goes on. Result files older than 10 minutes are removed. All file access goes through the directory descriptor opened at
start (no symlink is followed, only regular files of the owner are read), so replacing the path later cannot redirect the watcher.

Between requests the watcher runs "ovpn-ban.sh expire" every OVPN_BAN_SWEEP_SECONDS (default 30) seconds: that is what lifts a temporary ban
whose time has passed (the escalation lengths are longer than the bantime of the fail2ban jail, which only schedules its own unban).

Environment: OVPN_BAN_TOOL (default /usr/local/sbin/ovpn-ban.sh) and everything ovpn-ban.sh reads (OVPN_BAN_STATE, OVPN_BAN_PORT, ...,
and the OVPN_TELEGRAM_* settings for the notification of a new ban); OVPN_BAN_CONTROL_POLL (seconds, default 0.5, tests only).
"""

import json
import os
import re
import signal
import stat
import subprocess
import sys
import time

PROG = "ovpn-ban-control"
DEFAULT_TOOL = "/usr/local/sbin/ovpn-ban.sh"
POLL_SECONDS = 0.5
RESULT_MAX_AGE = 600
MAX_REQUEST_BYTES = 4096
TOOL_TIMEOUT = 60
SWEEP_SECONDS = 30
SWEEP_TIMEOUT = 30
MIN_MINUTES = 1
MAX_MINUTES = 525600
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
REQ_RE = re.compile(r"^([A-Za-z0-9_-]{1,64})\.req$")
IP_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
NET_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}(/[0-9]{1,3})?$")  # an unban may name the network of a ban list row
REASON_RE = re.compile(r"^[A-Za-z0-9 ._:-]{0,120}$")
KEYS = {"id", "action", "ip", "reason", "force", "minutes"}

running = True


def log(msg):
    print(f"{PROG}: {msg}", file=sys.stderr, flush=True)


def stop(_signum, _frame):
    global running
    running = False


class BadRequest(Exception):
    """The request is not acceptable; the message goes into the result (never contains request content)."""


def write_result(dfd, stem, ok, message):
    """Atomic: temporary file in the directory, then rename to <stem>.result (mode 0600)."""
    tmp = f".tmp-{stem}-{os.getpid()}"
    body = json.dumps({"ok": bool(ok), "message": message[:300]}).encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, f"{stem}.result", src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise


def read_request(dfd, name):
    """Read at most MAX_REQUEST_BYTES of a regular file of ours without following a link; returns bytes."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except OSError:
        raise BadRequest("request file cannot be opened") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
            raise BadRequest("request is not a regular file of the control user")
        if time.time() - st.st_mtime > RESULT_MAX_AGE:
            raise BadRequest("request expired (older than 10 minutes), not run")
        data = os.read(fd, MAX_REQUEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_REQUEST_BYTES:
        raise BadRequest("request is larger than 4096 bytes")
    return data


def parse_request(data, stem):
    try:
        req = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise BadRequest("request is not valid JSON") from None
    if not isinstance(req, dict):
        raise BadRequest("request must be a JSON object")
    if not set(req) <= KEYS or not {"id", "action", "ip"} <= set(req):
        raise BadRequest("request needs id, action and ip (reason, force and minutes are optional); no other keys")
    rid, action, ip, reason = req["id"], req["action"], req["ip"], req.get("reason", "")
    force, minutes = req.get("force", False), req.get("minutes")
    if not isinstance(rid, str) or not ID_RE.match(rid) or rid != stem:
        raise BadRequest("id must be [A-Za-z0-9_-]{1,64} and equal the request file name")
    if action not in ("ban", "unban"):
        raise BadRequest('action must be "ban" or "unban"')
    if not isinstance(ip, str) or not (IP_RE if action == "ban" else NET_RE).match(ip):
        raise BadRequest("ip is not an address")
    if reason is None:
        reason = ""
    if not isinstance(reason, str) or not REASON_RE.fullmatch(reason):
        raise BadRequest("reason must match [A-Za-z0-9 ._:-]{0,120}")
    if not isinstance(force, bool):
        raise BadRequest("force must be true or false")
    if minutes is not None and (isinstance(minutes, bool) or not isinstance(minutes, int) or not MIN_MINUTES <= minutes <= MAX_MINUTES):
        raise BadRequest(f"minutes must be a whole number from {MIN_MINUTES} to {MAX_MINUTES}")
    if action == "unban" and (force or minutes is not None):
        raise BadRequest("force and minutes apply to ban only")
    return action, ip, reason, force, minutes


def duration_text(seconds):
    if seconds == 0:
        return "permanently"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds % size == 0:
            n = seconds // size
            return f"for {n} {unit}{'' if n == 1 else 's'}"
    return f"for {seconds} seconds"


def result_fields(stdout, kind):
    """The key=value fields of the \"ovpn-ban-result KIND ...\" line the tool prints on success, or None."""
    for ln in stdout.splitlines():
        parts = ln.split()
        if len(parts) >= 2 and parts[0] == "ovpn-ban-result" and parts[1] == kind:
            fields = dict(p.split("=", 1) for p in parts[2:] if "=" in p)
            return fields
    return None


def describe_result(action, ip, minutes, stdout):
    """The reply states what the tool ENFORCED (its result line), never what was requested: the whole prefix of an IPv6 address, the step
    and the end that the history decided (a permanent ban on record overrides the minutes asked for)."""
    f = result_fields(stdout, action)
    if f is None:
        # a tool without a result line: success is all that is known, and the reply says no more than that
        return f"{action} of {ip} succeeded; the ban tool gave no summary of what is enforced"
    entry = f.get("entry", "?")
    if action == "unban":
        had = f.get("had") == "1"
        still = f.get("still", "-")
        text = f"unbanned {entry}" if had else f"nothing was banned for {entry}: no rule, row or history to remove"
        if entry != ip:
            text += f" (requested {ip})"
        if still != "-":
            text += f"; NOTE {still} overlaps it and is still banned (its rule and history are untouched)"
        return text
    try:
        seconds, expires = int(f.get("seconds", "")), int(f.get("expires", ""))
    except ValueError:
        return f"ban of {ip} succeeded; the ban tool gave no usable summary of what is enforced"
    when = "" if seconds == 0 else " until " + time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires))
    text = f"banned {entry} {duration_text(seconds)}{when}"
    if f.get("requested") and f["requested"] != entry:
        text += f" (requested {f['requested']})"
    text += f", offence {f.get('offence', '?')}"
    status = f.get("status")
    if status == "unchanged":
        text += ", already banned: nothing changed"
    elif status == "renewed":
        text += ", already banned: recorded again"
    asked = None if minutes is None else minutes * 60
    if asked is not None and asked != seconds:
        text += f"; NOT the {minutes} minutes asked for: an earlier ban on record decides the length"
    return text


def run_tool(tool, action, ip, reason, force=False, minutes=None):
    """Fixed argument vectors, no shell. Returns (ok, message)."""
    if action == "ban":
        argv = [tool, "ban-manual"] + (["--force"] if force else []) + (["--minutes", str(minutes)] if minutes is not None else [])
        argv += [ip] + ([reason] if reason.strip() else [])
    else:
        argv = [tool, "unban", ip, "--force"]
    try:
        proc = subprocess.run(argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=TOOL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return False, f"{action} timed out after {TOOL_TIMEOUT} s"
    except OSError as exc:
        return False, f"cannot run the ban tool ({type(exc).__name__})"
    if proc.returncode == 0:
        return True, describe_result(action, ip, minutes, proc.stdout.decode("utf-8", "replace"))
    err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
    # the tool's own refusals ("ovpn-ban: ...") carry no secrets; anything else is reduced to the exit status
    line = next((ln for ln in err if ln.startswith("ovpn-ban: ")), "")
    return False, (line[len("ovpn-ban: "):][:200] if line else f"ban tool failed (exit {proc.returncode})")


def sweep(tool):
    """Lift the temporary bans that ran out and reconcile the rules with the ban list (ovpn-ban.sh expire). A failure is a log line with the
    first diagnostic of the tool, never an error of the watcher."""
    try:
        proc = subprocess.run([tool, "expire"], shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                              timeout=SWEEP_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        log(f"expiry sweep timed out after {SWEEP_TIMEOUT} s")
        return
    except OSError as exc:
        log(f"expiry sweep cannot run the ban tool ({type(exc).__name__})")
        return
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        line = next((ln for ln in err if ln.startswith("ovpn-ban: ")), "")
        log(f"expiry sweep failed (exit {proc.returncode}){': ' + line[len('ovpn-ban: '):][:200] if line else ''}")


def remove_entry(dfd, name):
    """Remove a file, a link (never followed) or an empty directory; whatever else is there stays."""
    try:
        os.unlink(name, dir_fd=dfd)
    except IsADirectoryError:
        try:
            os.rmdir(name, dir_fd=dfd)
        except OSError:
            pass
    except OSError:
        pass


def handle(dfd, name, stem, tool):
    claimed = f"{stem}.proc"
    try:
        os.stat(f"{stem}.result", dir_fd=dfd, follow_symlinks=False)
        os.unlink(name, dir_fd=dfd)
        log(f"request {stem}: a result for this id exists, request dropped")
        return
    except FileNotFoundError:
        pass
    os.rename(name, claimed, src_dir_fd=dfd, dst_dir_fd=dfd)  # claimed: it can never be picked up again
    try:
        try:
            action, ip, reason, force, minutes = parse_request(read_request(dfd, claimed), stem)
            ok, message = run_tool(tool, action, ip, reason, force, minutes)
            log(f"request {stem}: {action} -> {'ok' if ok else 'failed'}")
        except BadRequest as exc:
            ok, message = False, str(exc)
            log(f"request {stem}: rejected: {exc}")
        write_result(dfd, stem, ok, message)
    finally:
        remove_entry(dfd, claimed)


def drop_unnamed(dfd, name):
    """A *.req whose name is not a safe id cannot get a result: it is dropped (a link or directory is removed, never followed)."""
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            return
        os.unlink(name, dir_fd=dfd)
    except OSError:
        pass
    log("request with an invalid file name dropped")


def recover_interrupted(dfd):
    """A .proc left behind by an earlier watcher was started and not finished: error result, never run again."""
    for name in os.listdir(dfd):
        m = re.match(r"^([A-Za-z0-9_-]{1,64})\.proc$", name)
        if not m:
            continue
        try:
            os.stat(f"{m.group(1)}.result", dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                write_result(dfd, m.group(1), False, "interrupted by a restart of the ban engine, the request was not repeated")
            except OSError as exc:
                log(f"cannot write the result of interrupted request {m.group(1)} ({type(exc).__name__})")
        remove_entry(dfd, name)


def expire_results(dfd, now):
    for name in os.listdir(dfd):
        if not (name.endswith(".result") or name.startswith(".tmp-")):
            continue
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if not stat.S_ISDIR(st.st_mode) and now - st.st_mtime > RESULT_MAX_AGE:
                os.unlink(name, dir_fd=dfd)
        except OSError:
            pass


def open_control_dir(path):
    try:
        dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise SystemExit(f"{PROG}: cannot open the control directory ({type(exc).__name__}): refusing to start")
    st = os.fstat(dfd)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise SystemExit(f"{PROG}: the control directory must be owned by the user of this process with mode 0700: refusing to start")
    return dfd


def main(argv):
    path = argv[1] if len(argv) == 2 else os.environ.get("OVPN_BAN_CONTROL_DIR", "")
    if len(argv) > 2 or not path:
        print(f"usage: {PROG} [CONTROL_DIR]  (default $OVPN_BAN_CONTROL_DIR)", file=sys.stderr)
        return 2
    tool = os.environ.get("OVPN_BAN_TOOL", DEFAULT_TOOL)
    try:
        poll = float(os.environ.get("OVPN_BAN_CONTROL_POLL", POLL_SECONDS))
    except ValueError:
        poll = POLL_SECONDS
    try:
        sweep_every = float(os.environ.get("OVPN_BAN_SWEEP_SECONDS", SWEEP_SECONDS))
    except ValueError:
        sweep_every = SWEEP_SECONDS
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    dfd = open_control_dir(path)
    try:
        recover_interrupted(dfd)
    except OSError as exc:
        log(f"startup recovery failed ({type(exc).__name__})")
    log(f"watching {path} every {poll} s")
    # one sweep right at the start: what ran out while no watcher was running is lifted at once, and a rule left by an interrupted ban is
    # adopted or removed
    sweep(tool)
    last_sweep = time.monotonic()
    while running:
        try:
            for name in sorted(n for n in os.listdir(dfd) if n.endswith(".req")):
                m = REQ_RE.match(name)
                if m:
                    handle(dfd, name, m.group(1), tool)
                    break  # one request per poll
                drop_unnamed(dfd, name)
            expire_results(dfd, time.time())
            if sweep_every > 0 and time.monotonic() - last_sweep >= sweep_every:
                last_sweep = time.monotonic()
                sweep(tool)
        except Exception as exc:  # a bad request or a full disk never stops the watcher
            log(f"error ({type(exc).__name__}), continuing")
        time.sleep(poll)
    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
