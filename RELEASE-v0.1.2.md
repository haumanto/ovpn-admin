# ovpn-admin v0.1.2 release notes

**Status: release candidate, not published.** Nothing here is tagged, pushed, or released. Publishing is a Conductor step. The images and binaries named below do not exist until it happens.

- Candidate: branch `v0.1.2`, code SHA `341ee84bb6ac0facb47d797c1911c9daeb43e172` (commit `chore(release): bump version to 0.1.2`). The commit that adds this file sits on top of it and changes only the three documentation files: `README.md`, `UPGRADING.md`, `RELEASE-v0.1.2.md`.
- Release gate: QA report `qa-v012/REPORT.md` (card t_2fbdfe48), verdict SHIP. All 11 checklist items PASS on `341ee84`, including a real OpenVPN client login.
- Build evidence: P12 build record `v012/p12-build.txt`, taken at `7d5075c`, the commit before the version bump. The bump changes version strings only (`main.go`, frontend `package.json` and `package-lock.json`, chart `Chart.yaml` and chart `README.md`).
- Changes are measured against the `v0.1.1` tag (`04aec9d`).

Source tags used below:

- `[qa n]`: `qa-v012/REPORT.md`, checklist item n (sub-labels as in the report).
- `[qa O n]`: `qa-v012/REPORT.md`, observation n outside the checklist.
- `[p12]`: `v012/p12-build.txt`.
- `[commit X]`: claim from the commit message or diff of X.
- `[src file]`: read from the source at `341ee84`. Not run unless a QA tag is also given.

## What changed since v0.1.1

### Alpine 3.23 base images (older Docker hosts)

- Both images moved from `alpine:3.24` to `alpine:3.23`: `Dockerfile.openvpn` and the final stage of `Dockerfile.ovpn-admin`. The stated reason is older Docker hosts. `[commit 7d5075c]`
- The reason is not proven here. QA ran on Docker 29.7.2 only, so an older Docker host was not tested. `[qa Known Limitations]`
- OpenVPN package version changed. On `alpine:3.24` (v0.1.1) the package was `openvpn-2.7.7-r0` with `easy-rsa-3.2.5-r0`. On `alpine:3.23` (v0.1.2) it is `openvpn-2.6.20-r0` (OpenVPN 2.6.20, OpenSSL 3.5.9) with `easy-rsa-3.2.3-r0`. `[p12 package versions]` `[qa 2]`
- Behavior note: the server on 2.6.20 reached `Initialization Sequence Completed`. A real client on OpenVPN 2.7.7 logged in. The three audit hooks ran on 2.6.20 with 0 failures and wrote the same 9-field lines as on 2.7.7. `[qa OpenVPN 2.6.20 vs 2.7.7]`
- Server log differences only: the peer prefix in log lines differs. The 2.7.7 build prints a `--persist-key` deprecation line that 2.6.20 does not print. `[qa OpenVPN 2.6.20 vs 2.7.7]`
- The 2.6.20 build does not list the PKCS11 and DCO features that the 2.7.7 build lists. The server config (AES-128-CBC) was accepted. `[p12 risk notes]`

### Hook scripts installed with mode 0755

- `setup/auth.sh` is mode `100755` in git (was `100644`). Its content did not change. `[commit 7d5075c]`
- `setup/configure.sh` installs `audit.sh`, `client-connect.sh`, `client-disconnect.sh` and `auth.sh` with `chmod 0755` instead of `chmod +x`. `[commit 7d5075c]`
- After `configure.sh`, all four are `-rwxr-xr-x` (755), in the throwaway image and in the live container. User `nobody`, which runs the hooks, can run them. `[qa 4]`
- Why it matters: in QA, the old `cp` plus `chmod +x` under umask 077 produced `-rwx------` (700). `[qa Verification Notes, controls]`
- Limit: under umask 077 the directory `/etc/openvpn/scripts` is still created as 700, so `nobody` still cannot reach the hooks. The shipped setup runs with umask 0022, and the directory is 755. Not reachable in the shipped setup. `[qa O2]`

### Version strings

- `--version` prints `0.1.2`. `[qa 3]`
- Chart `version` and `appVersion` are `0.1.2` and `v0.1.2`. The chart was not tested. `[commit 341ee84]` `[qa Known Limitations]`

### Not covered by QA: chart release workflow

- `.github/workflows/chart-release.yml` gained `skip_existing: true`. Commit `2f0340b` also regenerated the chart README for v0.1.1. Neither is covered by the QA checklist. `[commit 2f0340b]` `[src .github/workflows/chart-release.yml]`

## Already shipped in v0.1.1 (verified in v0.1.2, not new)

These were in the v0.1.1 candidate and are not changed by v0.1.2. QA re-verified them on `341ee84`.

- **Bash 4.2 and 4.3 safe upgrade script.** `scripts/upgrade.sh` has guarded empty-array loops, and it is unchanged since the v0.1.1 tag. QA ran the old loop under Bash 4.3.48 and 4.2.53: it dies with `unbound variable`. The fixed forms pass. A `docker-compose` 1.29.2 shim dry run exited 0. `[qa 7]` `[src scripts/upgrade.sh]`
- **Explicit Dockerfile entries in both compose files.** `docker-compose.yaml` and `docker-compose-slave.yaml` each name `dockerfile: Dockerfile.openvpn` and `dockerfile: Dockerfile.ovpn-admin`. Both compose files are unchanged since the v0.1.1 tag. `docker compose config -q` exits 0 with the required variables set. `[qa 6]`
- **No `env` dump in the auth hook.** `setup/auth.sh` contains no `env` command. Its only `env` is the shebang `#!/usr/bin/env sh`. With canary variables in the environment, the three auth paths printed 0 `NAME=value` lines and 0 canary hits. `[qa 5]`

## Upgrade notes

- **No database migration.** Since the v0.1.1 tag, `setup/configure.sh` changed two lines, both `chmod`. No `db-init` or `db-migrate` line changed. `[commit 7d5075c]` `[src setup/configure.sh]`
- **Image rebuild required.** The base image changed from `alpine:3.24` to `alpine:3.23`. Rebuild with `build --pull`, or pull the registry images once they are published.
- **OpenVPN package version changed** from `openvpn-2.7.7-r0` to `openvpn-2.6.20-r0` (see above). `[p12]` `[qa 2]`
- **Compose files and volumes unchanged.** Keep your v0.1.1 `docker-compose.yaml`. No new variable and no new volume. `easyrsa_master/`, `ccd_master/` and `audit_master/` keep their paths. `[commit 7d5075c]`
- **Backup first.** `scripts/upgrade.sh` backs up the three directories before any change.
- **Script label bug.** The default `--target-version` in `scripts/upgrade.sh` is still `v0.1.1` on this branch. A default run from v0.1.2 prints `target: v0.1.1` and names the backup `pre-v0.1.1-<time>.tar.gz`. Only the labels are wrong. The images are built from the checkout, so v0.1.2 is what gets installed. Pass `--target-version v0.1.2` for correct labels. `[qa O1]` `[qa 7]`
- **Dry run only.** QA ran the upgrade script as a dry run. No real upgrade from v0.1.1 data was run. `[qa 7]` `[qa Known Limitations]`

## Known limitations

### Carried over from v0.1.1 (still apply)

- **Audit scope.** The audit log records successful connections and disconnects. It records password results (`auth_ok`, `auth_fail`) only when password authentication is enabled. A certificate handshake failure that never reaches the connect hook is not recorded. `[RELEASE-v0.1.1.md]`
- **History keyed by username.** A user deleted and recreated with the same name inherits the old history and Last login. `[RELEASE-v0.1.1.md]`
- **Shared Basic Auth.** There is one shared admin credential. There are no per-admin accounts, sessions or tokens. `[RELEASE-v0.1.1.md]`
- **2FA deferred.** Two-factor authentication and an in-app rate limiter are deferred. Rate limiting belongs in the reverse proxy for now. `[RELEASE-v0.1.1.md]`
- **Audit file not rotated.** Nothing rotates `audit.tsv`. See `README.md`, Audit log. `[RELEASE-v0.1.1.md]`
- **Status lag after disconnect.** Right after the client stopped, `/api/users/list` still showed `ConnectionStatus: Connected`. A read about 110 s after the stop showed no connection. The same lag was recorded for v0.1.1. `[qa O4]` `[qa 8]`
- **Slave.** `docker-compose-slave.yaml` was checked with `docker compose config` only. The slave runtime was not started. It still targets `http://172.20.0.1:8080`. `[qa 6]` `[qa Known Limitations]` `[src docker-compose-slave.yaml]`
- **Helm chart.** Not tested for v0.1.2. `[qa Known Limitations]`
- **Documentation.** `docs/hardening/fail2ban/testdata/README.md`, line 16, still describes the old `time_unix` setup. This release did not change that file. `[RELEASE-v0.1.1.md]`
- **Dependency audit.** The npm audit findings recorded for v0.1.1 were not re-assessed for v0.1.2. `[RELEASE-v0.1.1.md]`

### New in v0.1.2

- **Script label default.** See Upgrade notes. `scripts/upgrade.sh` labels say v0.1.1 by default. Labels only. `[qa O1]`
- **Restrictive umask.** Under umask 077, `/etc/openvpn/scripts` is 700 and the hooks cannot be run by `nobody`. Not reachable with the shipped setup. `[qa O2]`
- **Wrong-password log lines.** A wrong password writes two server log lines: `openvpn-user: error: password mismatched`, then `Authorization failed`. Neither line contains the password or environment content. `[qa O3]` `[qa 8]`
- **Not tested on this candidate:**
  - an older Docker host (QA ran Docker 29.7.2);
  - OpenVPN 2.6.x clients, UDP, and IPv6 transport (the client was OpenVPN 2.7.7, TCP);
  - the arm64 build (`README.md` lists arm64 images; QA built amd64 only);
  - the slave runtime, and the Helm chart;
  - a real upgrade run (dry run only);
  - audit persistence across restart, security headers, and narrow-screen UI. These were not repeated from v0.1.1 QA. `[qa Known Limitations]`
- **Test depth.** One session and one wrong-password attempt. No load or soak test. The UI was checked in local headless Chromium 156 only, not Browser Use cloud, because the panel is loopback only. `[qa Known Limitations]` `[qa 9]`

## Measured results (v0.1.2 candidate `341ee84`)

- Go: `go build`, `go vet` and `go test ./...` exit 0. `ok ovpn-admin 2.647s`. Verbose run: 89 PASS, 0 FAIL, 1 SKIP (`TestFakeEasyrsa`). `[qa 2]`
- Real client: OpenVPN 2.7.7 reached `Initialization Sequence Completed` in 4 s. Session stopped 8 s after connect. Disconnect time equals the stop time (0 s difference). `[qa 8]`
- Wrong password: exactly one new `auth_fail` line. No `connect` line. `LastLogin` unchanged. `[qa 8]`
- Wrong password, server log: `openvpn-user: error: password mismatched` and `Authorization failed`. `[qa O3]`
- Wrong Basic Auth password: 3 `auth failed` log lines for 3 requests. A request without an Authorization header logs nothing. `[qa 10]`
- Logs: 0 `panic`, 0 fatal, 0 `level=error`. 7 secret forms: 0 hits. `[qa 10]`
- UI: 14 of 14 asserts pass. 0 console errors. `[qa 9]`
- Teardown: no `qa12-` containers, networks, volumes, images or scratch directories left. `[qa 11]`

## Install paths

- **Compose (from source):** clone the repo at the release tag, export the required variables, run `./start.sh`. See `README.md`, section 1. `[src start.sh]`
- **Compose (registry images):** `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.2` and `ghcr.io/haumanto/ovpn-admin/openvpn:v0.1.2`. These are published only with the v0.1.2 release. Until then, build from source. `[src README.md]`
- **Binaries:** `linux-amd64` and `linux-arm64` tar.gz on the release page, once published. Not built or tested in QA. `[src README.md]`
- **Helm chart:** not covered by QA. See limitations.

## Not done

- Published: tag `v0.1.2`, GitHub release with amd64/arm64 binaries, GHCR images, chart release.
- The `v0.1.2` tag is published.
