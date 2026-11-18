# ovpn-admin v0.1.6 release notes

**Status: not published.** Nothing is tagged, released, pushed or packaged yet. The v0.1.6 tag, the GitHub release, the GHCR images, the binaries and the chart release all need approval first.

- Candidate: branch `v0.1.6`, code SHA `04e0b864fb67e354c8ec92f15e584ed77844d911`. The commit that adds this file sits on top of it and changes only `RELEASE-v0.1.6.md`, `README.md` and `UPGRADING.md`.
- QA: `qa-v016/REPORT.md` (card t_5b0c4dbd), verdict **SHIP** at the candidate SHA. Items 1 to 12 PASS, plus the three fail-closed recovery paths. Real OpenVPN 2.7.7 clients. Telegram was a local mock. The UI ran in local headless Chromium.
- Static audit: `v016/audit/REPORT.md` (BLOCK, findings F1 to F3). Delta reviews `DELTA-REPORT.md` and `DELTA2-REPORT.md` (BLOCK). The final delta `DELTA3-REPORT.md` (**PASS WITH FINDINGS**) covers the candidate SHA. F1, F2 and F3 are closed for sign-off, with the qualifications under Known limitations.
- Earlier runs: `v016/p16-permanent.txt`, `v016/b16-api.txt`, `v016/b16-ui.txt` and `v016/b16-manual.txt` ran on earlier commits of this branch, not on the candidate SHA. `v016/p16c-fixes.txt` ran the candidate's `setup/ovpn-ban.sh` (sha256 `1a4d46f3…c2dd5`) on a fake firewall backend. `v016/p16c-recovery.txt` ran the script from commit `cc4a163`.

Source tags used below: `[QA n]` = QA report item n. `[audit Fn]` = audit finding n. `[DELTA3]` = `DELTA3-REPORT.md`. `[commit X]` = commit X.

## What changed since v0.1.5

- **Permanent repeat bans.** The Nth ban of the same address is permanent. N is `OVPN_BAN_REPEAT_COUNT`, default `2`. `[QA 2, 3, 4]`
- **Manual ban and unban.** A master-only **Ban IP** and **Unban** in the Banned IPs tab, and the API `POST /api/ban/manual` and `POST /api/unban`. `[QA 5, 6, 8, 10]`
- **Telegram.** A permanent ban shows `Until: permanent`. A manual ban sends a message too. `[QA 9]`
- **Ban engine fixes from the audit.** One lock covers the firewall and the ban decision. Restore failures fail readiness. A forced unban is recoverable. Unreadable state is never read as empty. `[audit F1 to F3] [DELTA3] [commits 75f7da2, cc4a163, 04e0b86]`
- **Version string** `0.1.6` in the Go binary, the chart and the frontend package. `[commit a408760]`

## Permanent repeat bans

- **Threshold.** `OVPN_BAN_REPEAT_COUNT`, a positive integer, default `2`. With `2`, the second ban of an address is permanent. `1` makes every ban permanent. Both compose files set it. A value that is not a positive integer prints an `ERROR` line at start and the container exits. `[configure.sh]`
- **Counting.** Every ban counts, including a ban that has already expired. The count is kept per address and survives restarts. `[QA 2, 3]`
- **History file.** `ban-history.tsv` in the audit directory. In the container it is `/etc/openvpn/audit/ban-history.tsv`. With the default compose file, on the host it is `./audit_master/ban-history.tsv`. It is root-owned, mode `0600`, with no header. Columns: `ip`, `ban_count`, `first_banned_unix`, `last_banned_unix`, `permanent` (0 or 1), `last_reason`, `last_failures`. It is created at the first ban, not at container start. `[QA 02] [ovpn-ban.sh header]`
- **Restart.** At start the engine restores every permanent entry: the DROP rule and a row with `expires_at` 0. In the QA run, two permanent bans came back in a fresh network namespace, with their rules and rows. `[QA 4]`
- **Temporary bans after a restart.** They are not restored from the history. A temporary ban comes back only if fail2ban re-derives it from the log lines within 120 seconds of start. It then stays temporary and is not counted again. A temporary ban with no log lines did not come back in QA. `[QA 4] [ovpn-ban.sh RESTART_GRACE=120]`
- **Permanent bans do not expire.** When the bantime ends, fail2ban's unban leaves a permanent ban in place. In QA the rule and row were still there 51 seconds after a 40-second bantime, and a valid login from that address was still dropped. `[QA 3]`

## Manual ban and unban

Master only. The slave shows the list read-only. Its control endpoints refuse requests: POST returns 400 and GET returns 405. `[QA 10]`

### In the UI

1. Open **Banned IPs**.
2. **Ban IP**: enter an IPv4 or IPv6 address, add an optional note, then press **Ban IP**. The ban is permanent at once. The reason is recorded as `manual`, or as `manual: <note>` when there is a note.
3. **Unban**: press **Unban** on the row, then **Unban** in the dialog. The dialog says that unban also clears the failure history of the address, so it starts clean.

`[QA 5, 6] [frontend/static/index.html]`

### Over the API

Basic Auth is required. The endpoints take form fields, not JSON.

| Call | Form fields | Success | Other answers |
|------|-------------|---------|---------------|
| `POST /api/ban/manual` | `ip` (required), `reason` (optional) | 200 `{"status":"ok","message":"banned <ip> permanently"}` | 400 bad address, note longer than 120 characters, refused characters, or slave. 403 cross-site request. 504 if the watcher does not answer within 6 seconds. |
| `POST /api/unban` | `ip` (required) | 200 `{"status":"ok","message":"unbanned <ip>"}` | same as above |
| `GET /api/bans` | none | a permanent ban has `"permanent": true` and an empty `expires_at` | GET on either control endpoint returns 405 with `Allow: POST` |

The note is limited to 120 characters. The watcher accepts only letters, digits, spaces and `. _ : -`, so any other character is refused. `[QA 4, 8, 10] [ban_control.go] [setup/ovpn-ban-control.py]`

```
curl -fsS -u "$BASIC_USERNAME:$BASIC_PASSWORD" -X POST http://127.0.0.1:8080/api/ban/manual \
  -d ip=203.0.113.20 -d 'reason=after bad requests'
curl -fsS -u "$BASIC_USERNAME:$BASIC_PASSWORD" -X POST http://127.0.0.1:8080/api/unban \
  -d ip=203.0.113.20
```

Repeat calls are harmless. A second ban answers 200 and the address stays permanent. A second unban answers 200. `[QA 4, 5]`

### What a manual ban and unban do

- **Ban.** It writes the DROP rule, a row with `expires_at` 0 and the history entry at once. A ban of an address that already has a temporary ban makes it permanent, and that sends a Telegram message. `[QA 4] [ovpn-ban.sh do_ban]`
- **Unban (UI and API).** It is always forced. It removes the DROP rule, the active row and the history entry, whether the ban was permanent or temporary. The address starts clean, so its next ban counts from 1. `[QA 5, 6]`
- **Pending removals.** A forced unban writes the address to `bans.tsv.removals` first. The entry stays there until the rule, the row and the history entry are all gone. While it is there, a new ban of that address fails, and the error says why. The next ban-engine operation finishes the removal. `[DELTA3] [QA 06]`
- **Expiry unban.** fail2ban calls the plain, non-forced unban at the end of the bantime. That call leaves permanent bans alone.
- **Command line.** Inside the `openvpn` container, `/usr/local/sbin/ovpn-ban.sh unban <ip> --force` runs the same forced removal. QA did not test this command on its own. `[ovpn-ban-control.py] [configure.sh]`

## Temporary bans

- The defaults are unchanged: 3 failures in 600 seconds give a 3600-second ban (`OVPN_BAN_MAXRETRY`, `OVPN_BAN_FINDTIME`, `OVPN_BAN_BANTIME`).
- A temporary ban ends on its own. fail2ban removes the rule and the row at expiry. The history keeps the count, so the next ban of the same address counts up. `[QA 2, 3]`
- Restarts do not keep temporary bans, with the 120-second exception above.
- After a restart, a re-applied temporary ban shows a later expiry in the UI than its real one. It also sends one more Telegram message. `[QA obs 2]`

## Telegram

- A permanent ban shows `Until: permanent` in the message.
- A manual ban sends one message when it is new, or when it becomes permanent.
- An unban sends nothing.
- A token scan of the QA evidence and the scanned logs found none. Two notes apply: the first container's logs were not saved (see Known limitations), and the real Telegram API was never called. `[QA 9] [ovpn-telegram-notify.py]`

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v015--v016).

- **Rebuild both images.** The `openvpn` image changed (ban engine, watcher, notifier, configure). The `ovpn-admin` image changed (API, UI, version).
- **No database migration.** The v0.1.5 to v0.1.6 diff adds no schema or SQL change. `easyrsa_master/`, `ccd_master/` and `users.db` are not changed.
- **Behavior change.** The second ban of an address is now permanent by default. Set `OVPN_BAN_REPEAT_COUNT=1` for every ban to be permanent, or a higher number to delay it. The history starts empty, so bans made before the upgrade do not count.
- **New files in the audit volume:** `ban-history.tsv` (after the first ban), `control/` (created at start, mode `0700`, owned by root), `bans.tsv.boot` (written at start) and `bans.tsv.removals` (only while a forced unban is pending).
- **Rollback.** v0.1.5 has no ban history, so a rollback does not restore permanent bans. Not tested.

## Known limitations

**Not tested at runtime** `[QA Known limitations]`

- IPv6 for permanent and manual bans.
- `OVPN_BAN_REQUIRED=true`.
- Repeat counts other than 2, including `1`.
- UDP listeners and `iptables-legacy`.
- The Helm chart. This release only bumps its version.
- A real second server as slave. QA used the candidate image with `--role=slave` in the server's network namespace.
- The real Telegram API. QA used a mock.
- Two bans at the same time, and power loss.
- A real upgrade from v0.1.5, and a rollback.

**Behavior QA observed or the audit found**

- **Unreadable history at start, with the default `OVPN_BAN_REQUIRED=false`.** The ban engine does not start. The VPN stays up with no bans. The log shows `ERROR: fail2ban did not start` and `continuing without the ban engine`. A manual ban times out with HTTP 504. Fix the file and restart the container. The code stops the container when `OVPN_BAN_REQUIRED=true`, but that was not tested. `[QA obs 1] [configure.sh]`
- **Restart display.** A re-applied temporary ban shows a later expiry than its real one, and sends one more Telegram message. `[QA obs 2]`
- **Path in error text.** A failed ban or unban shows the container path `/etc/openvpn/audit/ban-history.tsv` to Basic Auth users. `[QA obs 3]`
- **Timeouts.** A request that times out (504) may still be applied later, because the watcher does not cancel claimed work. The first audit found this and the later delta reviews did not re-check it. `[audit item 7]`
- **Private addresses.** A manual ban accepts private and unique-local addresses, such as `10.0.0.0/8` or `fd00::/8`. Only unspecified, loopback, multicast and link-local addresses are refused. The audit asked for this policy to be decided. `[audit item 2] [ban_control.go validateBanIP]`
- **Trust boundary.** The admin and the `openvpn` container share the audit directory and the `control/` queue, and both run as root. Anyone who can write there can change bans. Mounts and ACLs were not checked. `[audit items 1, 6]`
- **Audit qualifications, from DELTA3.**
  - The fallback search of the whole ruleset reads a failed `grep` as no match.
  - Rule listing accepts the `/32` and `/128` host spellings for either address family.
  - Sign-off covers ordinary engine-generated rule content. It does not cover broader prefixes or faults in the fallback search.
  `[DELTA3] [DELTA2]`
- **Relative history path.** `OVPN_BAN_HISTORY=missing-dir/history.tsv` with a missing parent directory can make first-start setup fail. It refuses readiness and never fakes it. Use an absolute path. The default path is not affected. `[DELTA3]`
- **Mobile UI.** Checked at 390 × 844 with no horizontal scroll and 44 px action targets. Tablet widths 769 to 1024 px and real devices were not checked. `[QA 7]`
- **Logs not saved.** QA did not save the first container's docker logs or `fail2ban.log` before the restart replaced it. Its audit volume and the other containers were scanned instead. `[QA item 9 gap]`
- **Harness failures.** Six failed asserts in the QA evidence are defects in the test harness, not in the product. They are listed in the QA report. `[QA Verification Notes]`

**Still needed before release:** a human decision to publish, the tag, the push, the GitHub release, the GHCR images, the binaries and the chart release. The release is not claimed as published anywhere in these notes.
