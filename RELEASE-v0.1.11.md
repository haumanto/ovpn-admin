# ovpn-admin v0.1.11 release notes

**Status: candidate, not published.** No tag, GitHub release, image, binary or chart release exists for v0.1.11. Approval for publishing is still needed.

- Code candidate: branch `v0.1.11`, SHA `61763ac83b073bfd6470ac22271b89899e0f994c` (`CA key guard: a legacy encrypted block counts only when its encryption is declared`), tree `87521f7c`, parent `ba1b3a2`. The v0.1.11 code commits after the v0.1.10 release notes (`58ee2d7`) are `70f33c9`, `123506a`, `8bf7646`, `64c72cd`, `9108599`, `93c74cf` (version bump), `9020674`, `b1cece9`, `ba1b3a2` and `61763ac`.
- QA: `qa-v0111/delta4/REPORT.md`, verdict SHIP on `61763ac`: 14 of 14 checks pass, and a red control on `ba1b3a2` fails 9 asserts. Earlier QA rounds (`qa-v0111/REPORT.md`, `delta/`, `delta2/`, `delta3/`) found problems on earlier commits. Those problems are fixed in the commits above.
- Auditor: `v0111/audit1111/ENCRYPTION-GUARD-REPORT.md`, PASS on `61763ac`. The earlier gate rows also pass on this sha (Conductor, card t_ad41821e).

Source tags below: `[QA4]` = `qa-v0111/delta4/REPORT.md`, `[QA3]` = `qa-v0111/delta3/REPORT.md`, `[AUD]` = `v0111/audit1111/`, `[C]` = code at `61763ac`, file and line.

## What changed

### The admin panel is no longer reachable from the VPN tunnel

- The panel listens on port 8080 in the network namespace shared with the `openvpn` container. VPN clients arrive on `tun+`, so they could reach it. The container now drops TCP to that port from `tun+`, for IPv4 and IPv6. `[C] setup/configure.sh:252, 261-280`
- Setup checks the rule right before OpenVPN starts. If the rule is missing, the container stops with an error. `[C] setup/configure.sh:559-573`
- QA, with a real client: `curl http://192.168.100.1:8080/ping` through the tunnel gets no answer (curl exit 28). The same ping answers 200 on loopback and on the published host port. `[QA4] check 6`

### Ban engine fails closed, and the ignore list is narrower

- `OVPN_BAN_REQUIRED` defaults to `true`. If fail2ban cannot start, the container stops. `[C] docker-compose.yaml:41; setup/configure.sh:21, 532-536`
- QA, with a broken fail2ban: the container exited with status 1 and nothing listened on the published ports. `[QA4] check 7`
- The default `OVPN_BAN_IGNOREIP` is `127.0.0.0/8 ::1 172.20.0.0/24`: loopback and the compose bridge only. The old default also had `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and `fe80::/10`. `[C] docker-compose.yaml:53; setup/configure.sh:39`
- QA, real ban cycle: three wrong passwords led to a DROP rule about 2 s later. The banned address could not connect, even with the right password. Another address still connected. After unban, the address connected again. `[QA4] check 7`

### Revoke, rotate and delete cut the live session at once

- Each one ends every session of the user on every management interface. The panel no longer waits for its 28 s client list to show the session. `[C] mgmt.go:469-472; main.go:1367-1368, 1548-1555; main.go:1576, 2057, 2090`
- QA, real clients: the session was gone 3.4 s after a revoke, 4.5 s after a rotate and 3.0 s after a delete. Other users' sessions kept the same connection and kept pinging. `[QA4] check 8`

### Real errors instead of a fake success

- Revoke, rotate and delete answer HTTP 400 for a refused request (unknown user, bad input). They answer HTTP 500 when a server-side step fails (easyrsa, CRL, management interface, password database). The body is the plain error text. `[C] main.go:1013-1022`
- QA, with the CRL file made immutable: revoke answered 500 with `Revoke of user "qa-m2" is incomplete, do not rely on it: the CRL could not be rebuilt; ...`. Delete and rotate also answered 500. After the file was writable again, a repeated revoke answered 200 and the CRL listed the serial. `[QA4] check 9`

### Unrevoke tells the truth

- Unrevoke answers 500 and says what is incomplete when the certificate, key or request is not restored, or when the serial is still in the disk CRL. A retry is checked the same way, so the answer stays 500 until the restore is complete. `[C] main.go:1390-1473, 1470`
- QA, a directory at the key path: unrevoke answered 500 with `Unrevoke of user "d1" is incomplete: the private key could not be restored. Check the admin log`. The index stayed `R` and a real client was still refused. After the directory was removed, unrevoke answered 200 and the client connected. `[QA4] check 9`
- QA, normal path: a revoked client got `certificate revoked`, unrevoke answered 200, and the client connected again. `[QA4] check 8`

### A failed rotate names the password state

These are the exact replies. Each one is checked against the password database and real clients. `[C] main.go:2031-2051`

- Nothing stored: `Failed to rotate user "<name>", the certificate and the password are as before`
- New password stored and live: `... The new password was already stored and is live: the password of the user is the one you entered, not the old one`
- New password not live, row removed: `... The new password is not live: after the rollback the user has no password row, so no password is accepted`
- New password not live, row revoked: `... The new password is not live: after the rollback the password row of the user is revoked, so no password is accepted (the stored password is the new one, it is accepted again when the user is unrevoked)`
- State unknown: `... The password of the user may be the new one or the old one, it could not be checked: set it again with change password`
- Rollback itself failed: `Failed to rotate user "<name>" and the previous state could not be restored completely, check the admin log`

QA: each of R1 to R5 matched reality. For example, the active user's reply said the new password was live, and the real login with it succeeded. `[QA4] check 9`

### Passwords: 12 characters minimum, bcrypt cost 12

- New and changed passwords (create, change-password, rotate) must be at least 12 characters. The count is in characters, not bytes. `[C] main.go:54, 1031-1032`
- The 72-byte maximum stays, because bcrypt reads at most 72 bytes. `[C] main.go:55, 1034-1038`
- New and changed hashes use bcrypt cost 12, about 250 ms by the vendored source's own note. Upstream used `bcrypt.MinCost` (4). Old hashes keep their own cost. Nothing is rehashed. `[C] third_party/openvpn-user/src/commands.go:29-32`
- QA: 11 characters refused (400), 12 accepted (200). The new hash starts with `$2a$12$`. A 72-byte password works and logs in. A 73-byte password is refused (400). `[QA4] check 10`
- The web UI also asks for 12 characters (commit `64c72cd`). The password dialog was not clicked in QA's run.

### CRL: daily check, lock against revoke, expiry metric

- A background check runs 5 minutes after start and then every 24 hours. It rebuilds the CRL when less than 30 days are left. A failed rebuild is retried after 1 hour. It logs one line for a rebuild and one for a failure. `[C] main.go:108-114, 632`
- The check holds the same lock as every PKI write (revoke, unrevoke, delete, rotate, create), so a revoke that runs while the check waits is not lost. `[C] main.go:2552-2570`
- New gauge `ovpn_crl_expire_days`: days until the CRL's `nextUpdate`, negative when the CRL has expired. `[C] main.go:149, 2518-2523; commit 8bf7646`
- QA: the gauge matched `openssl` within 0.002 days. A 10-day-old CRL was rebuilt at the first daily check. `[QA4] check 11`. The 24 hour interval itself was not waited for (see Known limitations).

### Sync: off by default, and the CA key stays out of the archive

- `OVPN_MASTER_TOKEN` is optional. Without a token, the master serves no PKI or CCD archive. `/api/data/certs/download` and `/api/data/ccd/download` answer 403 to every request, including an empty token. `[C] main.go:511-512, 542-543, 725-731; docker-compose.yaml:117-120`
- QA: 403 with no token, 403 with a 64-character token when sync is off. With sync on: 200 with the right token, 403 with a wrong token, 403 with the token minus one character, 403 with no token. `[QA4] check 12`
- **To turn sync on**, set the same token on the master and on the slave: `export OVPN_MASTER_TOKEN="$(openssl rand -hex 32)"`. `docker-compose-slave.yaml` still requires it.
- **Slave mode stays unsupported.** The slave downloads with the token in the URL (`?token=`). `[C] main.go:2160, 2177` A URL can end up in logs. Moving the token to a header would break old slaves, so it stays in the URL for now. `[AUD] DECISIONS.md, row 2`
- The export answers 500 unless the identity of the CA signing key is usable. The message is `the sync archive cannot be built: the identity of the CA signing key is not usable, see the admin log`. `[C] main.go:521, 2225-2257`
- The CA private key is not in the archive, in any form tested. That covers plain, PKCS#8, AES and DES-EDE3 legacy encryption, and renamed copies. Client keys are in the archive unchanged. `[C] main.go:2187-2200`. QA: 0 archive members with the CA key, and 3 planted copies were left out. `[QA4] checks 1 to 4`

### Change-password on a revoked user answers 400

- A revoked user is refused before the password is checked, and nothing is written. The reply is HTTP 400 with `{"status":"error","message":"user \"<name>\" is revoked, unrevoke or rotate it first"}`. `[C] main.go:1208-1214, 394-409`
- Before this release it answered 200 and changed the password. `RELEASE-v0.1.10.md`, Known limitations.
- QA: 400, and the password row was unchanged. `[QA4] check 10`

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v0110--v0111).

- **Rebuild both images.** Both change: the Go code, `setup/configure.sh` and the vendored `openvpn-user`. The Helm chart templates do not change. Only `Chart.yaml` and the chart README change.
- **The ban engine stops the stack if it cannot start.** `OVPN_BAN_REQUIRED` now defaults to `true`. If you ran without bans on purpose, set `OVPN_BAN_REQUIRED=false` explicitly.
- **Add your admin networks to the ban ignore list before you upgrade.** The default no longer has `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `fe80::/10`. A client from one of those ranges can now be banned after repeated failed logins. Set the list in the environment, for example `OVPN_BAN_IGNOREIP="127.0.0.0/8 ::1 172.20.0.0/24 10.0.0.0/8"`. Entries are IPs or CIDRs separated by single spaces. `[C] setup/configure.sh:87-88`
- **Existing short passwords keep working.** Only create, change-password and rotate check the new 12-character minimum. `[C] main.go:1031; third_party/openvpn-user/src/commands.go:289` (`AuthUser` has no length check). This was read from the code and was not tested live in QA.
- **Your own copy of `docker-compose.yaml` keeps its old values.** Diff it against the new file. The changed defaults are `OVPN_MASTER_TOKEN` (optional now), `OVPN_BAN_REQUIRED` and `OVPN_BAN_IGNOREIP`. `[C] docker-compose.yaml`
- **Sync is off unless you set a token.** If you run a slave, set `OVPN_MASTER_TOKEN` on the master and on the slave. Without it the slave cannot download.
- **Scripts that read the old answers must change.** Revoke, rotate and delete answer 500 on a server failure, not 200. Change-password on a revoked user answers 400, not 200. The rotate failure text is new.
- **A `ca.key` encrypted with another legacy cipher now stops the export.** The sync export accepts a PEM `ca.key` encrypted with AES-128, AES-192, AES-256 or DES-EDE3-CBC. Any other cipher (for example Camellia) answers 500. Convert it to PKCS#8 with `openssl pkcs8 -topk8`. `[QA4] observation O1`
- **Back up first,** as for every release. See [UPGRADING.md](UPGRADING.md#v0110--v0111).

## Known limitations

Open items, in the order you are most likely to hit them. QA did not test the items under "Not tested" or could not confirm them.

- **The slave compose file keeps the old ban defaults.** `docker-compose-slave.yaml` still has `OVPN_BAN_REQUIRED` defaulting to `false` and the old ignore list with `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and `fe80::/10`. This release does not change it, and slave mode is unsupported. If you use that file, set both variables explicitly. `[C] docker-compose-slave.yaml:40, 51`
- **A connected VPN client still reaches the host and the LAN behind it.** This is accepted for now. Default-deny forwarding (audit H2) is deferred, not fixed. A stolen client certificate still reaches the whole host and LAN. `[AUD] DECISIONS.md, row 3`
- **The Helm chart is not hardened to the compose level.** It sets `duplicate-cn` and `client-to-client`, has no password check and no ban engine, always creates the Ingress, and stores the admin password as `{PLAIN}`. See `charts/openvpn-admin/README.md`. `[AUD] REVIEW.md, H5`
- **After a failed CRL rebuild, the panel can show Active before the disk CRL allows the connection.** This is from the audit and is not fixed in this release. `[AUD] FINAL-REPORT.md:32`
- **If the rollback of a failed rotate itself fails, the password database may accept the new password while the certificate stays revoked.** The reply says so, but the state can still exist. `[QA4] observations O3, O4`
- **Kubernetes backend.** The unrevoke path for `kubernetes.secrets` is unchanged and was not run on a real cluster. QA's Kubernetes checks used a fake API server. `[QA4] known limitations`
- **Slave side of sync.** Not run in QA. The slave token stays in the URL (see above).
- **The 24 hour CRL interval and the 1 hour retry were not waited for.** Only the first daily check ran. `[QA4] known limitations`
- **The 64 MiB archive member bound has a unit test only.** No live oversize test. `[QA4] known limitations`
- **Multiple `ca.key` blocks in one file** were not tried live. The Auditor read that path. `[QA4] known limitations`
- **Legacy ciphers other than the four listed above** were tried with one cipher (Camellia). See the upgrade note.
- **Tested scope.** `linux/amd64`, TCP, Docker, the filesystem backend, real OpenVPN 2.7.7 clients, easy-rsa 3.2.3 (admin image) and 3.2.5 (openvpn image). `[QA4] reference`. arm64, UDP, the Helm chart and the slave were not tested.
- **Not tested with easy-rsa 3.0.8.** `bootstrap.sh` downloads 3.0.8 for a local build. That path was not tested in this release. `[C] bootstrap.sh:8`
- **The web UI password dialog** was not clicked in QA's run. The minimum is in commit `64c72cd`.
- **Known open audit items not addressed in this release:** the nginx example has no address allowlist and logs query strings (audit H3). See `docs/hardening/README.md`.

## Evidence

- `qa-v0111/delta4/REPORT.md`: the shipping sha, 14 checks, red control, observations, notes for the Editor.
- `qa-v0111/delta3/REPORT.md`, `delta2/REPORT.md`, `delta/REPORT.md`, `qa-v0111/REPORT.md`: earlier rounds on earlier shas.
- `v0111/audit1111/ENCRYPTION-GUARD-REPORT.md`: Auditor PASS on `61763ac`. `FINAL-REPORT.md`, `GATE-REPORT.md`, `DELTA-REPORT.md`: earlier gates.
- `audit-20261122/REVIEW.md` and `DECISIONS.md`: the findings these fixes answer, and the owner decisions on H2 and sync.
- `v0111/e1111/REPORT.md`: this release's documentation check, with each claim and its source.
