# ovpn-admin v0.1.1 release notes

**Status: release candidate, not published.** Nothing here is tagged, pushed, or released. Publishing is a Conductor step. The images and binaries below do not exist until it happens.

- Candidate: branch `v0.1.1`, code SHA `d1be1e0bbc9ab12a5810eba06bc7a36ac52c7779` (commit `fix(audit): use wall-clock event time`). The commit that adds this file sits on top of it and changes only the three documentation files.
- Release gate: delta QA report `qa-v011b/REPORT.md`, verdict CLOSED. Every checklist item (1 to 9, with sub-items 4a to 4d) is PASS, with a real OpenVPN client. The first QA run, at `1e0b860`, returned DO NOT SHIP. Its two failures (event order and disconnect time) are fixed at `d1be1e0`. Quote `d1be1e0`, not `1e0b860`.
- Other checks (Go tests, npm build, image build, auth matrix, slave config, upgrade dry run, logs) were measured at `1e0b860`. The only code change since is `setup/audit.sh`. They were not re-run at `d1be1e0`.

Source tags used below:

- `[qa-b n]`: `qa-v011b/REPORT.md`, item n, candidate `d1be1e0`.
- `[qa-a n]`: `qa-v011/REPORT.md`, item n, candidate `1e0b860`. Measured before the audit fix, so not re-run at `d1be1e0`.
- `[design]`: UI design spec `v011/design-spec.md`.
- `[sec]`: security review `v011/security-review.md`.
- `[commit X]`: claim from the commit message or diff of X.
- `[src file]` and `[cfg file]`: read from the source or config at `d1be1e0`. Not run unless a QA tag is also given.

## What is new since v0.1.0

### Exact login history per user

- The OpenVPN hooks write one tab-separated audit line for each `connect`, `disconnect`, `auth_ok` and `auth_fail` event to `audit.tsv`. ovpn-admin reads the file and shows the history per user. `[commit f9e694c]` `[commit 5be209e]` `[src audit.go]`
- Event times are wall-clock times taken when the hook runs. A `disconnect` line carries the time the session ended. `[commit d1be1e0]` Real client, 2 of 2 sessions (14 s and 20 s): the disconnect time equals the stop time, 0 s off. `[qa-b 5]`
- Newest-first order: after a login, `connect` is the newest event in 2 of 2 logins. `[qa-b 4c]` When `auth_ok` and `connect` fall in the same second, file order decides. `[qa-b observations]`
- `LastLogin` and `LastLoginIP` come from the newest `connect` event. `[qa-b 4d]` `[qa-a 6d]`
- Passwords are never written to the audit file or returned by the API: 0 hits in the file and in 4 API answers per session. `[qa-b 7]`
- A wrong password with a real client gives one `auth_fail` line, and `LastLogin` does not move. `[qa-a 6g]` (measured at `1e0b860`). After the fix, the `auth_fail` time was checked only by running `auth.sh` inside the image with a stale `time_unix`. `[qa-b 2]` `[qa-b Known Limitations]`
- The API returns 50 events by default and 500 at most. `[src audit.go]`

### Table and dialogs (UI refresh from the design spec)

- User table: a status badge (for example `Online`, `Revoked`) and a Last login column. The tooltip shows the full UTC time. `[design §2]` `[qa-b 8]`
- Login history dialog: connect, disconnect and password rows, newest first. `[design §3]` `[qa-a 7]` `[qa-b 8]`
- Confirm dialogs for Revoke and Delete. The Revoke dialog says whether the user is connected now. Cancel changes nothing. Seen in screenshots. `[qa-a 7]` `[design Change 3]`
- Rotate has a confirm dialog in the code (`openRotate` in `frontend/src/main.js`). QA did not capture a screenshot of it. `[src main.js]`
- Honest empty states: a user with no event in the audit log shows `No record`, with the text "Logins before v0.1.1 are not recorded." `[design Change 1]` `[qa-a ui-check log]`
- Success and error toasts for actions. `[design Change 6]` `[src main.js]`
- Layout checked at 1440 px and at 390 px. At 390 px the success toasts cover the top bar while they are shown. `[qa-a 7]` `[qa-a observations]`

### Security hardening

- Failed logins are logged. A request with a wrong Basic Auth password writes one warn line: `auth failed remote=<address> path=<path>`. It contains no credentials. A request without an `Authorization` header writes nothing. Behind a reverse proxy, `remote` is the proxy address. `[qa-a 8]` `[commit 31a832e]` `[src main.go]`
- Security headers on the web UI and API: `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`. `[qa-a 8]` `[src main.go]`
- API answers send `Cache-Control: no-store`. The static UI keeps `no-cache` and an ETag. `[qa-a 8]` `[src main.go]`
- The slave compose file fails closed. It refuses to start unless `BASIC_USERNAME`, `BASIC_PASSWORD`, `OVPN_MASTER_TOKEN`, `OVPN_MASTER_USER` and `OVPN_MASTER_PASSWORD` are set. The slave admin port is published as `127.0.0.1:8081:8080`. The literal sync token is gone. `[qa-a 9]` (`compose config` only, see limitations) `[cfg docker-compose-slave.yaml]` `[sec S01]`
- Hardening guide in `docs/hardening/README.md`: an nginx example, fail2ban filters for the audit log and for proxy 401 responses, and a jail example. The README links to it. `[commit 09226a6]` `[cfg docs/hardening]` These docs are not part of the QA checklist.

### Upgrade script

- One script, `scripts/upgrade.sh`, for every version. It backs up `easyrsa_master/`, `ccd_master/` and `audit_master/` before any change. `[commit ed060a2]` `[qa-a 10]`
- Ordered start: `openvpn` first, then the script waits for the management interface, then `ovpn-admin` starts. `[commit 1a590bb]` `[qa-a 10]`
- Bash 4.2 and 4.3 are supported, and so is `docker-compose` V1 from 1.25 on. The dry run was run under Bash 4.3 and 4.2 and against a compose V1 shim, with 0 unbound-variable errors. `[commit 0bfff35]` `[qa-a 10]`

## Upgrade notes

Full steps are in `UPGRADING.md`, section v0.1.0 → v0.1.1.

- **Replace the compose file once.** Use the v0.1.1 `docker-compose.yaml`. It mounts `./audit_master` at `/etc/openvpn/audit` (openvpn) and at `/mnt/audit` (ovpn-admin). Re-apply your own edits.
- **Set the credentials.** The compose file refuses to start without `BASIC_USERNAME`, `BASIC_PASSWORD` and `OVPN_MASTER_TOKEN`. A slave also needs `OVPN_MASTER_USER` and `OVPN_MASTER_PASSWORD`.
- **New audit volume.** `audit_master/` holds the login history. Deleting it erases the history. The upgrade script includes it in the backup.
- **No database migration in v0.1.1.** The diff of `setup/configure.sh` from v0.1.0 to `d1be1e0` changes no `db-init` or `db-migrate` line. `easyrsa_master/`, `ccd_master/` and `users.db` are not changed by the upgrade. `[src setup/configure.sh]`
- **Logins before v0.1.1 are not in the history.** The history starts with the first event the v0.1.1 hooks write. `[qa-a ui-check log]`
- **First start can be slow.** In QA, the first OpenVPN start took 2 min 28 s (DH generation, host under load). The upgrade script waits up to 180 s for the management interface by default (`--mgmt-timeout`). `[qa-a observations]` `[src upgrade.sh]`
- **Roll back by hand.** The script never rolls back by itself. Its rollback steps are in `UPGRADING.md`.

## Install paths

- **Compose (from source):** clone the repo, export the three variables, run `./start.sh`. See `README.md`, section 1. `[cfg start.sh]`
- **Compose (registry images):** `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.1` and `ghcr.io/haumanto/ovpn-admin/openvpn:v0.1.1`, for `linux/amd64` and `linux/arm64`. These are published only with the v0.1.1 release. Until then, build from source. `[cfg publish-tag.yaml]` `[cfg release.yaml]`
- **Binaries:** `linux-amd64` and `linux-arm64` tar.gz files on the release page, once published. `[cfg release.yaml]` Not built or tested in this candidate's QA.
- **Helm chart:** not covered by this candidate's QA. See limitations.

## Known limitations

### What the audit log can and cannot show

- The audit log records successful connections and disconnects. It records password results (`auth_ok`, `auth_fail`) only when password authentication is enabled.
- A certificate handshake failure that never reaches the connect hook is not recorded.
- The history is keyed by username. A user deleted and then recreated with the same name inherits the old history and Last login. The Delete dialog says history stays, but does not warn about the merge. `[design Known Limitations]`
- ovpn-admin reads only the last 2 MiB of the audit file. A user whose last login is older than that window shows `No record`. `[src audit.go]` `[design Known Limitations]`
- Nothing rotates the file. See `README.md`, Audit log, for retention.
- Online status lags behind a disconnect. The API still showed connected 24 s after the client stopped, and the status cleared at 32 s. `[qa-b 8 observations]` The first QA run saw a lag of up to about 40 s. `[qa-a observations]`

### Timing and tests

- Only 14 s and 20 s sessions were measured after the fix. Sessions over 3 minutes and a keepalive timeout (client lost without a clean disconnect) were not measured. `[qa-a Known Limitations]` `[qa-b Known Limitations]`
- There is no in-repo regression test for the wall-clock rule. A future change could bring back the bug without a red test. `[qa-b observations]`
- The `d1be1e0` fix was proven by running the hooks in the rebuilt image with a stale `time_unix`. `[qa-b 2]`
- Go tests (89 pass, 0 fail, 1 skip; 94 subtests pass) were measured at `1e0b860`, not at `d1be1e0`. `[qa-a 2]`
- The UI was tested on local headless Chromium 156, one browser, at 1440 px and 390 px. Browser Use cloud was not used, because the panel is loopback only. Firefox, Safari and touch devices were not tested. `[qa-b 8]`
- Not tested: UDP, IPv6 client transport, several clients at once, a real upgrade run, a real `docker-compose` V1 binary (shim only), the Helm chart.

### Slave

- `docker-compose-slave.yaml` still sets `--master.host="http://172.20.0.1:8080"`. The master publishes port 8080 on `127.0.0.1` only, so this address does not reach it. Put a TLS reverse proxy between them, as described in `docs/hardening/README.md`. `[cfg docker-compose-slave.yaml]` `[cfg docker-compose.yaml]`
- Slave compose was checked with `config` only. The slave runtime was not run. `[qa-a 9]` `[qa-a Known Limitations]`

### Security scope

- Basic Auth is one shared admin credential. There are no per-admin accounts, sessions or tokens.
- 2FA and an in-app rate limiter are deferred to v0.2 or later. Rate limiting belongs in the reverse proxy for now. `[sec Deferred]` `[sec V5]`
- Dependency audit: `npm ci` reports 2 vulnerabilities (1 moderate, 1 high). They were not assessed. `[qa-a 3]` `[qa-a observations]`

### Documentation

- `docs/hardening/fail2ban/testdata/README.md`, line 16, still says the sample `audit.tsv` was made by setting `time_unix`. The hooks no longer read it. That file is outside this release's documentation scope and needs a follow-up edit. `[qa-b observations]`
- The Rotate confirm dialog has code but no QA screenshot. `[src main.js]`
- At 390 px the success toasts cover the top bar while shown. `[qa-a observations]`
