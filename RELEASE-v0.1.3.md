# ovpn-admin v0.1.3 release notes

**Status: release candidate, not published.** Nothing here is tagged, pushed, or released. Publishing is a Conductor step. The images and binaries named below do not exist until it happens.

- Candidate: branch `v0.1.3`, code SHA `35d9181b0385e2442acf657e7549ec95e50e66ae` (commit `chore(upgrade): default target and backup labels to v0.1.3`). The commit that adds this file sits on top of it and changes only the three documentation files: `README.md`, `UPGRADING.md`, `RELEASE-v0.1.3.md`.
- Release gate: QA report `qa-v013/REPORT.md` (card t_f7d059f0), verdict SHIP.
- Tested SHA: items 1 to 10 of the QA checklist were measured on `8fe81cd3e700d3772526ed3c7a49c8b1d12b01ef`. `35d9181` adds one commit that changes two label lines in `scripts/upgrade.sh`. QA checked that delta (grep, `bash -n`, dry run). The builds, Go tests and runtime stacks were not repeated on `35d9181`.
- Changes are measured against the `v0.1.2` tag (commit `eeaf018`).

Source tags used below:

- `[qa n]`: `qa-v013/REPORT.md`, checklist item n.
- `[qa Dn]`: `qa-v013/REPORT.md`, delta check n (`8fe81cd` to `35d9181`).
- `[qa On]`: `qa-v013/REPORT.md`, observation n.
- `[commit X]`: claim from the commit message or diff of X.

## What changed since v0.1.2

Commits between the `v0.1.2` tag and `35d9181`:

- `6579fdc` feat(openvpn): configurable Alpine version, iptables-legacy, selectable IPv4 firewall backend.
- `8fe81cd` chore(release): bump version to v0.1.3 (`main.go`, frontend `package.json` and `package-lock.json`, chart `Chart.yaml` and chart `README.md`). `--version` prints `0.1.3`. `[qa 7]`
- `35d9181` chore(upgrade): default target and backup labels to v0.1.3. Before this commit a default run printed `target: v0.1.2`. `[qa O1]` `[qa D7 D8]`
- `d4923af`, `8d170e3` ci(chart): test values for chart-testing. Not covered by QA.
- `1ea80df`, `d8f3f08`: upgrade-script labels and README wording for v0.1.2.

### Configurable Alpine version for the OpenVPN image

- `Dockerfile.openvpn` takes `ARG ALPINE_VERSION=3.24`. `[commit 6579fdc]`
- Default build: `alpine:3.24`, image reports Alpine 3.24.4, OpenVPN 2.7.7 (package `openvpn-2.7.7-r0`). `[qa 2]`
- Build with `--build-arg ALPINE_VERSION=3.23`: image reports Alpine 3.23.8, OpenVPN 2.6.20. `[qa 3]`
- `ALPINE_VERSION` applies to `Dockerfile.openvpn` only. `Dockerfile.ovpn-admin` stays on `alpine:3.23`. `[qa O5]` `[commit 6579fdc]` (admin Dockerfile unchanged since the tag)

### Both iptables implementations, selectable IPv4 backend

- The OpenVPN image installs `iptables` (nf_tables), `iptables-legacy` and `ip6tables`. Versions: iptables v1.8.13 on Alpine 3.24, v1.8.11 on Alpine 3.23. `[qa 2]` `[qa 3]`
- `OVPN_IPTABLES_BIN` selects the IPv4 NAT backend. Default `iptables`. Set `iptables-legacy` for older hosts. The compose files set `OVPN_IPTABLES_BIN: "${OVPN_IPTABLES_BIN:-iptables}"` on the `openvpn` service only. `[qa 5]` `[commit 6579fdc]`
- Measured in both images, six cases each `[qa 4]`:
  - unset, `iptables`, or empty: one IPv4 MASQUERADE rule in the nf_tables table, none in the legacy table.
  - `iptables-legacy`: one rule in the legacy table, none in the nf_tables table.
  - A second run in the same container leaves exactly one rule.
  - Missing binary: exit 1, stderr `ERROR: iptables binary not found: iptables-nope`, no rule written, OpenVPN never started.
- Runtime, default backend: one MASQUERADE rule in the nf_tables table. Runtime, `iptables-legacy`: one rule in the legacy table, none in nf_tables. `[qa 8]` `[qa 9]`
- IPv6 NAT always uses `ip6tables` (nf_tables). `OVPN_IPTABLES_BIN` does not change it. `[qa Known Limitations]`

### Fixes carried from v0.1.1 and v0.1.2, re-verified in v0.1.3

These are not new in v0.1.3. The code behind them is unchanged from the `v0.1.2` tag: the `auth.sh` blob is identical, `scripts/upgrade.sh` differs only in its label lines, and the compose `dockerfile:` lines are unchanged. QA re-verified them on `8fe81cd` `[qa 6]`.

- `setup/auth.sh` is mode `100755` in git. `configure.sh` installs the hooks as `0755`. The installed `auth.sh` is `-rwxr-xr-x` after every `configure.sh` run.
- No environment dump. `setup/auth.sh` has no `env`, `printenv` or `set` command. Live server logs show 0 env-dump lines.
- Bash 4.2 and 4.3 safe upgrade script. `scripts/upgrade.sh` uses guarded empty-array loops. On real `bash:4.3` (4.3.48) and `bash:4.2` (4.2.53) the old form fails with `unbound variable`, and the new form passes. A `--dry-run` with a docker-compose V1 1.29.2 shim exits 0. `[qa 6]`
- Explicit admin Dockerfile in both compose files: `dockerfile: Dockerfile.ovpn-admin`. `[qa 6]`

## Upgrade notes

- **No database migration.** The `configure.sh` changes since `v0.1.2` are the iptables block only. No `db-init` or `db-migrate` line changed. `[commit 6579fdc]`
- **Image rebuild required.** `Dockerfile.openvpn` changed. `scripts/upgrade.sh` runs `build --pull`.
- **OpenVPN package changes back.** The default image returns from `openvpn-2.6.20-r0` (v0.1.2, Alpine 3.23) to `openvpn-2.7.7-r0` (Alpine 3.24). `[qa 2]`
- **Older hosts: build Alpine 3.23.** QA built this image on its test host. Build the OpenVPN image with `docker build --build-arg ALPINE_VERSION=3.23 -f Dockerfile.openvpn`. QA ran this command. The shipped compose files do not pass the argument, and `scripts/upgrade.sh` does not pass it either. See Known limitations.
- **Compose gains an optional variable.** `OVPN_IPTABLES_BIN` defaults to `iptables`, so no edit is needed on nf_tables hosts. A variable set in the shell reaches the container only through the compose line. An older compose file without that line ignores it. `[commit 6579fdc]` `[qa 5]`
- **Script labels fixed.** `scripts/upgrade.sh` defaults to `v0.1.3` in its messages and backup name (`pre-v0.1.3-<time>.tar.gz`). `[qa O1]` `[qa D8]`
- **Dry run only.** QA ran the upgrade script as a dry run. No real upgrade from v0.1.2 data was run. `[qa 7]`
- **First start.** On this host the server was ready after 57 s on the default stack and after 2 min 22 s on the `iptables-legacy` stack. Both runs generated the PKI on first start. `[qa O6]`

## Known limitations

### Specific to v0.1.3

- **Not published.** No `v0.1.3` tag, no images, no binaries. `[qa Known Limitations]`
- **Tested SHA.** Items 1 to 10 were measured on `8fe81cd`. The builds, Go tests, runtime stacks and UI check were not repeated on `35d9181`. `[qa D1-D12]`
- **Bash 4.2 and 4.3 runs not repeated** on the `35d9181` script. The host has bash 5.3.9 only. `[qa Known Limitations]`
- **Compose and upgrade script do not pass `ALPINE_VERSION`.** The `3.23` build was tested with `docker build` only. No compose stack or `upgrade.sh` run used the 3.23 image. `[qa 3]` `[qa Known Limitations]` (the shipped compose files declare no `build.args`)
- **Older Docker host not tested.** QA ran Docker Compose v5.4.0 on one Linux host (kernel 7.0.0-43-generic). Whether older hosts need the 3.23 image is not measured. `[qa Known Limitations]`
- **Missing-binary error is late.** The check runs after PKI generation. In the QA run the error appeared 3 min 58 s after container start. OpenVPN never started. `[qa O2]`
- **Legacy backend proven on one host.** That host loads both the legacy and nf_tables kernel modules. `[qa Known Limitations]`
- **Status lag.** Right after a client disconnected, `/api/users/list` still showed one connection. A read 86 s later showed none. `[qa O3]`
- **Harmless log line.** On first start `iptables -t nat -D ...` may print `iptables: Bad rule`. It comes from the idempotence step (`|| true`). `[qa O4]`
- **Not tested:** arm64 build, Helm chart (including its version bump and the `d4923af` and `8d170e3` CI changes), slave runtime (`docker compose config -q` only), a real upgrade run, UDP, OpenVPN 2.6.x clients, IPv6 traffic, UI on the `iptables-legacy` stack. `[qa Known Limitations]`
- **Alpine 3.23 OpenVPN image** was built and checked for all six backend cases. No compose stack and no client session ran on it. `[qa Known Limitations]`

### Carried from earlier releases (not re-measured in v0.1.3)

- **Audit scope.** The audit log records successful connections and disconnects. It records password results only when password authentication is enabled. A certificate handshake failure that never reaches the connect hook is not recorded. `[RELEASE-v0.1.1.md]`
- **History keyed by username.** A user deleted and recreated with the same name inherits the old history. `[RELEASE-v0.1.1.md]`
- **Shared Basic Auth.** There is one shared admin credential. There are no per-admin accounts, sessions or tokens. `[RELEASE-v0.1.1.md]`
- **2FA deferred.** Two-factor authentication and an in-app rate limiter are deferred. Rate limiting belongs in the reverse proxy for now. `[RELEASE-v0.1.1.md]`
- **Audit file not rotated.** Nothing rotates `audit.tsv`. `[RELEASE-v0.1.1.md]`
- **Slave compose file.** It still targets `http://172.20.0.1:8080`, which the loopback binding of the master does not serve. `[RELEASE-v0.1.2.md]`
- **Dependency audit.** npm audit findings were not assessed. `[RELEASE-v0.1.1.md]` `[qa Known Limitations]`

## Measured results (v0.1.3 candidate `35d9181`, measured on `8fe81cd`)

- Go: `go build`, `go vet` and `go test ./...` exit 0 in `golang:1.26-alpine`. 89 PASS, 0 FAIL, 1 SKIP (`TestFakeEasyrsa`). `[qa 7]`
- Frontend: `npm run build` in the admin image build: `webpack 5.111.1 compiled successfully`. `[qa 7]`
- `ovpn-admin --version` prints `0.1.3`. `[qa 7]`
- Real client, default stack: OpenVPN 2.7.7 reached `Initialization Sequence Completed` 2 s after start. Ping of the gateway 3/3. `[qa 8]`
- Real client, `iptables-legacy` stack: initialised 3 s after start. Ping of the gateway 3/3. `[qa 9]`
- Audit log: `connect` and `LastLogin` share one epoch. The `disconnect` line equals the stop time. A wrong password writes one `auth_fail` line and leaves `LastLogin` unchanged. `[qa 8]`
- NAT: traffic outside the VPN pool answered 3/3 on both stacks. The MASQUERADE counter went from 0 to 1. `[qa 8]` `[qa 9]`
- Restart: the server initialised again and the rule count stayed at 1. `[qa 8]`
- UI (headless Chrome 156, default stack): 4 login-history rows, times equal to the audit log. 0 console errors. `[qa 10]`
- Logs: default stack 0 `level=error`, 0 panic, 0 iptables error lines; `iptables-legacy` stack 0 errors. Secret values: 0 hits in the audit TSV and API answers (default stack). `[qa 8]` `[qa 9]`

## Install paths

- **Compose (from source):** clone the repo (branch `v0.1.3` until the tag exists), export the required variables, run `./start.sh`. See `README.md`, section 1. `[src start.sh]`
- **Compose (registry images):** not published for v0.1.3 yet. Build from source. `[src README.md]`
- **Binaries:** not published for v0.1.3 yet. Not built or tested in QA. `[src README.md]`
- **Helm chart:** not covered by QA. See limitations.

## Not done

- Tag `v0.1.3`.
- GitHub release with amd64 and arm64 binaries.
- GHCR images.
- Chart release.
- Real upgrade run from v0.1.2 data.
