# ovpn-admin v0.1.12 release notes

**Status: published.** Tag `v0.1.12`, GitHub release with amd64 and arm64 binaries, both multi-arch images and chart `openvpn-admin-0.1.12` are published from the `v0.1.12` tag. The code in that tag is commit `665a3ac` plus the version bump `47e6d74` and these notes; no code changed after `665a3ac`.

- Code candidate: `665a3ac97cd3a6e844a67dce7666cb6344af91f2` (tree `60b655d`), the commit the release gate passed. The release commit adds the version bump (`47e6d74`, tree `1ad4f55` after the docs commit `d83f799`) on top of it; no code changes after `665a3ac`.
- The v0.1.12 code commits after the v0.1.11 release notes: `e6bbefc` (certificate features), `ca2013f` (ban and jail race), `9afb1ec` (login hardening), `02f427f` (compose Telegram settings), `0e92aa6` (panel: expiry badge, renew, server card, disconnect request, throttle notices, timed manual ban), `47a0bd5` (F4 wait text), `0207487` (F2 lock keying, allowlist, compose and chart wiring), `5178ab9` (F3 metrics), `665a3ac` (F1 re-hash spool), `47e6d74` (version bump), `d83f799` (these notes).
- QA: `v0112/release-gate/REPORT.md`, verdict **SHIP on `665a3ac`**, eight of eight checks pass. `v0112/auth-qa/REPORT.md` found four login defects in `9afb1ec` (DO-NOT-SHIP); `v0112/auth-recheck/REPORT.md` returned **PASS on `665a3ac`** after the four fixes, 205 assertions with 0 failures.
- Owner decisions: `v0112/DECISIONS.md`, including the scope trim of 2026-11-24 14:52 and the ship-with-limits decision taken on this release.

Source tags below: `[GATE]` = `v0112/release-gate/REPORT.md`, `[RC]` = `v0112/auth-recheck/REPORT.md`, `[IQA]` = `v0112/auth-qa/REPORT.md`, `[IQA-CERT]` = `v0112/cert-qa/REPORT.md`, `[D]` = `v0112/DECISIONS.md`, `[C]` = code at `665a3ac`, file and line.

## What changed

### Certificate expiry notices, including the server certificate

The panel reads expiry dates from the easy-rsa index and notifies Telegram as a certificate crosses a threshold. It covers client certificates **and the server certificate**, which is the one that takes the whole VPN down when it expires.

- `OVPN_NOTIFY_CERT_DAYS` is a comma-separated list of days, largest first. The default is `30,14,7,3,1`; a value that cannot be read logs a warning and falls back to the default. `[C] cert_lifecycle.go:certNotifyThresholds`
- One notice per threshold crossing, so a certificate 40 days out is quiet and the same certificate at 13 days produces the `14` notice once.

### One-action safe renewal

- **Client.** The Renew action issues a new certificate and a new profile while the old certificate keeps working for a configurable grace window, so a client can download and switch without losing its tunnel. Grace is `grace_hours`, a whole number from 0 to 720; `0` revokes the old certificate at once. `[C] cert_lifecycle.go:57, userRenew:851`
- **Server.** The server certificate card shows the expiry date and a Renew action. A server renewal needs a restart of the `openvpn` container to take effect, and the panel shows a banner saying so.

### Panel controls

- An expiry badge on each client, the Renew action, the server certificate card with its restart banner, throttle notices, and a manual ban with a duration. `[C] frontend/src/main.js`, `frontend/src/style.css`, `frontend/static/index.html`, commit `0e92aa6` (629 insertions in 3 files).

### Login hardening

An independent review of the hardening commit `9afb1ec` found four defects. All four are fixed in this release.

- **F1, password upgrade could not write.** The login hook runs as `nobody` (`[C] setup/openvpn.conf:44`) and cannot write `users.db`, so a weak-hash upgrade failed. The upgrade now goes through a spool file that the panel applies, so the network-facing OpenVPN user never needs write access to the password database. `[C] rehash_spool.go`, `third_party/openvpn-user/src/rehash_spool.go`. Evidence: `rehash applied: user=u4text cost 4 -> 12`, `spool files that hold the user's secret: 0`, zero `attempt to write a readonly database` in both logs. `[RC] p61_rehash`
- **F2, one lock for everybody.** The lock is keyed on source address plus user name, and sources inside `OVPN_ADMIN_ALLOW_CIDR` are never locked. Both compose files and the chart pass the settings through. `[C] authguard.go; docker-compose.yaml:154`
- **F3, `/metrics` was a free guessing channel.** It counts failed logins like every other path and is refused for a locked source. `[C] authguard.go, main.go`; evidence `[RC] p31_lock`.
- **F4, the wait text was wrong past the hour.** It read `Try again in 3 hours 60 minutes`; it now carries 60 minutes into the hour. `[C] authguard.go:678 waitText`. Evidence: `Try again in 4 hours 0 minutes.` with retry-after 14397, and `Try again in 24 hours 0 minutes.` with 86385. `[RC] p41_f4_text`

### Table stakes carried by this line

Permanent repeat bans and manual ban and unban control, the audit trail, the hardened nginx and fail2ban guide, the TLS floor on the listener, and the alert and Telegram delivery fixes from the previous releases of this line.

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v0111--v0112).

- **Rebuild both images.** Both change: `ovpn-admin` (certificate features, panel controls, lock and metrics fixes) and `openvpn` (the re-hash side of the login hook). Restarting the `openvpn` container drops connected clients, so pick a quiet window. `[C] Dockerfile.ovpn-admin`, `build.sh`
- **The compose files pass `OVPN_ADMIN_TRUST_PROXY=true` for the panel.** Your reverse proxy must overwrite `X-Forwarded-For`, as the shipped nginx example does. If the panel port is reachable without a proxy, set it to `false`, because every client then looks like the Docker bridge gateway and the lock becomes one lock for everybody. The binary's own flag default and the chart default stay `false`. `[C] docker-compose.yaml:154; [D]`
- **Merge the four failed-login settings into your own copy of the compose file.** `OVPN_ADMIN_TRUST_PROXY` (default `true`), `OVPN_ADMIN_ALLOW_CIDR` (default empty), `OVPN_AUTH_MAX_FAILURES` (default 5), `OVPN_AUTH_FAIL_WINDOW` (default 15m). `[C] docker-compose.yaml`
- **Set the notice threshold if you want notices.** `OVPN_NOTIFY_CERT_DAYS`, for example `30,14,7,1`. Telegram delivery needs `OVPN_TELEGRAM_ENABLED=true` and the bot token and chat id as before. `[C] cert_lifecycle.go`
- **The Helm chart moves to v0.1.12** in `version` and `appVersion` only. No chart template changed. The chart is not hardened to the compose level, see `charts/openvpn-admin/README.md`. `[C] charts/openvpn-admin/Chart.yaml`
- **Back up first,** as for every release. See [UPGRADING.md](UPGRADING.md#v0111--v0112).

## Known limitations

Open items, in the order you are most likely to hit them.

- **Disconnect does not disconnect anyone in this version.** The panel action answers 200 and shows "Disconnect requested for NAME. The server did not report how many sessions it closed." No session ends. The button has been in the panel since v0.1.11; the server side is scheduled for v0.1.13. `[GATE] W2, [D]`
- **On a slave, the Telegram address switch is ignored.** `docker-compose-slave.yaml` does not hand the `OVPN_TELEGRAM_*` settings to its containers, so `OVPN_TELEGRAM_INCLUDE_ADDRESS=false` never reaches them and a slave always sends the client address and user name in a ban message. The slave panel's failed-login flood alert also logs its CRITICAL line without sending the Telegram message. `docker-compose.yaml` is not affected. Fixed in v0.1.13. `[GATE] W1, [D]`
- **A request through the published port with no `X-Forwarded-For` counts as the Docker bridge gateway.** With the compose default on, five wrong secrets lock every header-less client, including you. Anyone who reaches the panel port without a proxy can forge the header and is never locked. The port is loopback-only, so this is host-local. `[RC] F2 limits`
- **The shipped nginx example still says the panel ignores `X-Forwarded-For`** in a code comment. It does not, with the compose default. The comment is stale. `[GATE] warning`
- **A panel started without a `pki` directory logs a re-hash spool warning every five seconds** (`users.db.rehash: no such file or directory`). It does not appear on the full stack. `[RC] warning`
- **A connected VPN client still reaches the host and the LAN behind it.** Default-deny forwarding is deferred; a stolen client certificate still reaches the whole host and LAN. `[D] row 3`
- **The Helm chart is not hardened to the compose level.** `[C] charts/openvpn-admin/README.md`
- **Slave mode is unsupported and was not tested.** So were in-place upgrade of a running v0.1.11 deployment, rollback, arm64 and UDP. `[GATE]`
- **Two known vulnerabilities in build-only npm packages,** unchanged since v0.1.11. They do not ship in the panel bundle. `[GATE] W3`
- **Confirming a server renewal trusts you, not OpenVPN.** `POST /api/server/confirm-renew` answers 200 and revokes the previous server certificate even if you have not restarted the `openvpn` container yet, so the running server can be serving a certificate the CRL now rejects. Confirm only after the restart. `[C] cert_lifecycle.go:1409` (the function states it cannot see a restart), `[IQA-CERT] F4`
- **A failed server renewal can still say "could not be restored completely".** That sentence appears only when the rollback itself fails; when it succeeds the message says the previous certificate is not revoked. The wording of the first case is unchanged in this release. `[IQA-CERT] F3`
- **Server certificate renewal was verified with real containers on a scratch PKI,** including the restart, but not against a live production server whose clients stay connected during that restart. `[IQA-CERT] check 3`

## Evidence

- `v0112/release-gate/REPORT.md`: the shipping sha, eight checks, four warnings, per-check command output.
- `v0112/auth-recheck/REPORT.md`: the four F1 to F4 fixes on `665a3ac`, 205 assertions, the Go suite (`ok ovpn-admin 1262.735s`, 0 FAIL) and the vendored module (15 PASS).
- `v0112/auth-qa/REPORT.md`: the original DO-NOT-SHIP on `9afb1ec` and the four findings.
- `v0112/cert-qa/REPORT.md`: the certificate feature review on `e6bbefc`. Its F1 (Telegram settings on the wrong container) is fixed in `02f427f`, and its F2 (no panel button, no documentation) in `0e92aa6` plus these notes. F3 and F4 are the two limitations listed above.
- `v0112/DECISIONS.md`: the scope trim, the trust-proxy default, the ship-with-limits decision, and the accepted risks (CA risk, offline root deferred to v0.2.0).
- `v0112/ui/REPORT.md`, `v0112/f1-compose/REPORT.md`: the panel build path and the compose wiring checks.
