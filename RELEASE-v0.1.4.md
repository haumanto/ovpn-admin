# ovpn-admin v0.1.4 release notes

**Status: release candidate, not published.** Nothing here is tagged, pushed, or released. No `v0.1.4` tag, image, or binary exists yet. Publishing is a Conductor step, and it needs its own approval.

- Candidate: branch `v0.1.4`, code SHA `a18f961a8bb82d6bbd4c9b1144228e007b2d4b93`. The commit that adds this file sits on top of it and changes only `RELEASE-v0.1.4.md`, `README.md` and `UPGRADING.md`.
- Ban gate: QA delta report `qa-v014/DELTA-REPORT.md` (card t_40411b2d), verdict **SHIP** on `a18f961`, 81 of 81 assertions pass, real OpenVPN clients. This report replaces the earlier `qa-v014/REPORT.md` (t_d71bad3e, DO NOT SHIP on `2918962`) for the ban engine. Its UI results are still cited where the delta did not re-run them.
- Static audit: `v014/audit/REPORT.md` reviewed `8e5631f` and gave **DO NOT SHIP** pending source remediation and separate runtime QA. It has not been re-run on `a18f961`. See [Known limitations](#known-limitations).

Source tags used below:

- `[delta Dn]` / `[delta]`: `qa-v014/DELTA-REPORT.md`, check n or section.
- `[qa n]` / `[qa On]`: `qa-v014/REPORT.md`, item n or observation n. Those runs used `e3233a9` or `2918962`, as noted.
- `[p14]`: `v014/p14-ban.txt`, filter and fail-open evidence. It was built on an earlier base (`803faa9` plus the working tree).
- `[commit X]`: claim from the commit message or diff of X.

## What changed since v0.1.3

- `bef9ef2` feat(openvpn): fail2ban ban engine for auth failures and revoked certificates.
- `d3b3adc` feat(admin): `GET /api/bans` lists active bans from `bans.tsv`.
- `25ebc03` feat(ui): mobile-first admin rebuild and Banned IPs view.
- `8e5631f` style(ui): visual polish.
- `e3233a9`, `2918962`, `91a2e87`, `a18f961`: ban fixes. IPv6 bans, ban jump scoped to the OpenVPN listener port, fail-closed IPv6 check, port derived from `OVPN_SERVER_PORT`, bounded logs, a filter that matches real OpenVPN 2.7.7 lines, and one count per wrong password.
- `375ea5d` chore(release): version `0.1.4`.

Diff against the v0.1.3 range: 18 files, 2544 insertions, 445 deletions. The diff adds no `users.db` or SQL schema change. `[commit]` `[diff check]`

## Automatic banning

The `openvpn` container runs its own fail2ban 1.1.0, jail `ovpn-admin`. It reads `openvpn.log` and bans a source address when it makes too many failed attempts. `[commit bef9ef2, 91a2e87]` `[delta]`

**What counts as a failure:**

- `VERIFY ERROR: ... certificate revoked`: one line per attempt with a revoked certificate.
- `SENT CONTROL [UNDEF]: 'AUTH_FAILED'`: one line per wrong password. Each wrong password writes two `AUTH_FAILED` lines (`[UNDEF]` and `[<common name>]`). Only the `[UNDEF]` line is counted, so one wrong password is one failure.
- TLS handshake errors, expired certificates and network errors are not counted.
- The filter accepts the listener prefix (`tcp6-server:`), IPv4 sources, and IPv6 sources in brackets. `[delta]`

**Default rule:** 3 failures inside 600 seconds (10 minutes) ban the address for 3600 seconds (1 hour). These are the defaults in `docker-compose.yaml`. `[commit]`

**Measured timings:** QA measured with `MAXRETRY=3`, `FINDTIME=120`, `BANTIME=60`, not the defaults. The default 600 s and 3600 s were not waited out. `[delta]`

- The third failure gives a DROP rule 0.17 to 0.52 seconds later. `[delta]`
- The ban lifts at 59.0 to 59.5 seconds, with `BANTIME=60`. `[delta check 4]`

**Where the ban applies:**

- IPv4 rules go in the `OVPN_BAN` chain, IPv6 rules in `OVPN_BAN6`. The iptables binary is the one set by the backend variables (`OVPN_IPTABLES_BIN` for IPv4, `OVPN_IP6TABLES_BIN` for IPv6). `[commit]`
- The chains have jumps only for the OpenVPN listener port (`OVPN_SERVER_PORT`, default `1194`), over its transport (tcp or udp). The admin port 8080 is never banned. Measured: a banned client timed out on port 1194, and `:8080/ping` still returned 200. `[delta check 1]`
- IPv4 and IPv6 bans were both measured with real clients. IPv6 was measured for one client address (`fd00:172:20::61`), over TCP, with wrong passwords. `[delta extra]`

**Allowlist (never banned):** `OVPN_BAN_IGNOREIP` defaults to `127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fe80::/10`. The `172.16.0.0/12` range covers the example compose subnet `172.20.0.0/24`. The IPv6 example subnet `fd00:172:20::/64` (unique-local `fd00::/8`) is not on the default list. QA replaced the allowlist to ban test clients from those ranges. `[commit] [delta assumptions]`

**Fail-open and fail-closed:**

- `OVPN_BAN_REQUIRED=false` (default): if fail2ban cannot start, the container prints an `ERROR` line and keeps running OpenVPN without bans. `OVPN_BAN_REQUIRED=true` stops the container instead. Checked in the P14 evidence on an earlier base; not re-run on `a18f961`. `[p14] [commit]`
- `OVPN_BAN_IPV6_REQUIRED=true` (default): when IPv6 is on and the `OVPN_BAN6` chain cannot be created, the container exits, whatever `OVPN_BAN_REQUIRED` says. The only opt-out is `OVPN_BAN_IPV6_REQUIRED=false`, which keeps running and prints a loud `WARNING` that IPv6 sources are not banned. Measured on `2918962`: the failure exits 1 and names the opt-out. `[delta]` `[commit 2918962]`
- Bad values (for example `OVPN_BAN_MAXRETRY=0`, `OVPN_BAN_ENABLED=yes`) stop the container with a message. `[p14]`

**Restart behavior (measured, not "restart clears bans"):**

- At every start, `bans.tsv` and both ban chains are emptied. Then fail2ban reads the whole `openvpn.log` again and counts the failures still inside `OVPN_BAN_FINDTIME`.
- A restart within the findtime of a recent failure bans the same offender again. In QA the DROP rule and the `bans.tsv` row came back 9 seconds after the restart, with a new `banned_at`. The row's `expires_at` can show a later time than the real unban. `[qa 8]` (measured on `e3233a9`; the restart text in `docs/hardening/README.md` is platform-measured, and the restart test was not re-run on `a18f961`.)
- A restart after the findtime has passed bans nothing, and the lists are empty. `[qa 8]`

## Configuration

Set these in `docker-compose.yaml` or `docker-compose-slave.yaml`. Every value is validated at start.

| Variable | Default | Meaning |
|----------|---------|---------|
| `OVPN_BAN_ENABLED` | `true` | `false` turns the ban engine off |
| `OVPN_BAN_MAXRETRY` | `3` | failures that trigger a ban |
| `OVPN_BAN_FINDTIME` | `600` | window in seconds in which failures count |
| `OVPN_BAN_BANTIME` | `3600` | ban length in seconds |
| `OVPN_BAN_IGNOREIP` | `127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fe80::/10` | never-banned sources, space-separated IPs or CIDRs |
| `OVPN_BAN_REQUIRED` | `false` | `true` stops the container when fail2ban cannot start. `false` runs OpenVPN without bans and logs an error |
| `OVPN_BAN_IPV6_REQUIRED` | `true` | `true` stops the container when IPv6 is on and the IPv6 ban chain cannot be built. `false` is the only opt-out |
| `OVPN_SERVER_PORT` | `1194` | OpenVPN listener port. The ban jumps and the compose port mapping follow it |
| `OVPN_BAN_PORT` | unset | optional check only. If set and different from `OVPN_SERVER_PORT`, the container exits |
| `OVPN_LOG_MAX_BYTES` | `10485760` | rotate `openvpn.log` and `fail2ban.log` past this size |
| `OVPN_LOG_KEEP` | `3` | rotated copies kept per log (1 to 99) |
| `OVPN_LOG_ROTATE_INTERVAL` | `60` | seconds between size checks |

Sources for this table: `[commit]` `[qa]` `[delta]`.

## Banned IPs in the admin UI

- A read-only list, no controls. It has a count badge that matches the number of rows and the API. `[qa 11]`
- Data comes from `GET /api/bans` (only `GET` and `HEAD` are allowed; other methods return 405). It sits behind the same Basic Auth as the rest of the UI, and reads `bans.tsv`. `[commit d3b3adc]` `[qa 9]`
- Desktop table columns: IP address, Reason, Attempts, Banned since, Expires. `[qa 11]`
- Phone card: IP, reason badge, Banned time, Expires, Attempts. `[qa 11]`
- Empty state: "No IPs are banned right now." `[qa 11]`
- The list refreshes on a timer (every 30 seconds per the spec in `v014/design/SPEC.md`). The Refresh action also reloads it. `[qa 11]` `[spec]`
- The view shows what is banned right now. It does not show the reason in more detail, or the log lines behind it.

## Mobile-first UI rebuild

- Phones (up to 768 px): one column of cards. Each user is a card with its name as a heading, a primary action, a History button and a More button. Actions open in a bottom sheet. `[spec] [qa 10]`
- Tablet and desktop (769 px and up): a table. `[spec] [qa 10]`
- Dialogs are full-height sheets on phones and centered dialogs on desktop, with a sticky footer. The overflow menu is a bottom sheet on phones. `[qa 10]` `[spec]`
- Targets: the stylesheet sets `--tap` and `--control-h` to 44 px. The spec asks for 44 px on phones and tablets and 36 px on desktop with a fine pointer. Target sizes were not measured in QA. `[commit style.css] [spec]`
- Keyboard and accessibility: arrow keys move through the menu, Esc closes it, and focus returns to the opener. Icon-only buttons have labels that name the user. `[qa 10]`
- Measured layouts: 1280 px wide desktop and 390 x 844 phone, with mobile emulation and touch, no horizontal scroll at 390 px. Checks passed: 54 on desktop, 56 on phone, one failure each, both on the same item. It is the Show config dialog, which is not reachable by spec and is not a defect. `[qa 10]` `[delta check 6]`
- Not measured: tablet popover (769 to 1024 px), real phones, and screen-reader runs.

## Upgrade notes

Full steps are in [UPGRADING.md](UPGRADING.md#v013--v014).

- **Rebuild the images.** The ban engine is in the `openvpn` image (fail2ban, setup scripts). The Banned IPs API and UI are in the `ovpn-admin` image. Run `scripts/upgrade.sh` or `docker compose up -d --build`. `[commit]`
- **No database migration.** `users.db` and certificates are untouched. `[diff check]`
- **New files in the audit volume:** `openvpn.log` (the ban engine's input, mode 0600, owned by `nobody`) and `bans.tsv` (the list the UI reads, root 0600). Both sit in `audit_master/` (or `audit_slave/` on a slave). `[p14] [commit]`
- **Restarts clear the ban state, then re-derive it.** See "Restart behavior" under [Automatic banning](#automatic-banning).
- **IPv6:** bans for IPv6 sources are in `OVPN_BAN6`. The check is on the OpenVPN listener's own port, and IPv6 must have ip6tables. Only one IPv6 client was measured. `[delta]`
- **Log growth:** `openvpn.log` and `fail2ban.log` are rotated in the container (`copytruncate`). Worst case per log: `(OVPN_LOG_KEEP + 1) x OVPN_LOG_MAX_BYTES`, which is 40 MiB with the defaults, plus what is written between two checks. Rotation was measured with five rotations: three files kept and a ban one second after rotation. `audit.tsv` is not rotated. `[delta]` `[qa 22]` `[commit]`
- **Slave:** `docker-compose-slave.yaml` mounts `./audit_slave` so the slave's `bans.tsv` reaches its ovpn-admin. Not measured. `[commit]`

## Known limitations

- **Release status:** candidate only. Not tagged, pushed, or published. The approval to publish is still needed.
- **Default timings** (600 s findtime, 3600 s bantime) were not waited out. QA used 120 s and 60 s. `[delta]`
- **Restart behavior** was measured on `e3233a9`. It was not re-run on `a18f961`. `[qa 8]`
- **Static audit (`v014/audit/REPORT.md`, reviewed `8e5631f`):** verdict DO NOT SHIP pending source remediation and separate runtime QA. Its concerns, and where they stand now:
  - IPv6 not covered (C1): IPv6 bans added. Measured with one real client. `[delta extra]`
  - Source-wide INPUT scope (C2): jumps are limited to the listener port. Measured: port 8080 still answers. `[delta check 1]`
  - Log retention (C3): rotation added. Measured on `2918962`. `[qa 22]`
  - Slave ban file sharing (C4): `docker-compose-slave.yaml` mounts `./audit_slave` for ovpn-admin. Not measured.
  The audit was not re-run on `a18f961`, and its runtime questions are not closed by this release.
- **Not tested:** UDP listeners, `iptables-legacy`, the slave compose file, the Helm chart, `ALPINE_VERSION=3.23`, a client through the published port 7777, old-style log lines without a listener name, real phones, the tablet popover. `[delta]` `[qa]`
- **Filter version dependency:** the ban filter counts the `[UNDEF]` line that OpenVPN 2.7.7 writes. A different OpenVPN version may stop writing it, and then wrong passwords count 0. Check with `fail2ban-regex`, as in `docs/hardening/README.md`. `[delta]`
- **Allowlist:** default private ranges are never banned. Unique-local IPv6 (`fd00::/8`, including the example compose subnet) is not on the default list, so it is bannable by default. `[commit]`
- **Config dialog:** not reachable from any row action, by spec. The UI has "Download config" only. `[delta check 6]`
- **Compose comment:** `docker-compose.yaml` still says bans are not kept across restarts. The measured behavior is above. Not changed in this release.
- **Not verified:** UI, API and Go tests were not re-run on `a18f961`. The last full runs were on `e3233a9` (Go 195 PASS, 1 SKIP, 0 FAIL; UI 54 and 56 asserts). Since then, `setup/` changed. `[qa 1]` `[delta]`
- **Leftovers:** QA left one clean clone in its scratch area. It is pruned after 24 idle hours.
