# ovpn-admin v0.1.0 release notes

**Status: release candidate, not published.** Nothing here is tagged, pushed, or released. Publishing is a Conductor step.

- Candidate: branch `v0.1.0`, commit `ce9ea994018e8ad8ac0f99e342bb128fc773fd90`
- Release gate: delta QA of this SHA, verdict SHIP on the fixed checklist, no failing items. One step is not verified: removing an old QA clone (a QA-environment step, not a product check).
- Binary version: `0.1.0` (`/app/ovpn-admin --version` prints `0.1.0`).

Source tags used below:

- `[QA2 n]`: delta QA report, `ovpn-admin-evidence/qa2/REPORT.md`, item n (candidate `ce9ea99`)
- `[QA1 n]`: first QA report, `ovpn-admin-evidence/qa/REPORT.md`, item n (candidate `eda1956`, before fixes)
- `[AUD Fnn]`: static security review, `ovpn-admin-evidence/audit/REPORT.md`, finding nn (candidate `eda1956`, static only)
- `[H2]`, `[H2b]`: supply-chain and deployment-default evidence files (`h2-build.txt`, `h2b-defaults.txt`)
- `[commit X]`: claim taken from the commit message of X. Not separately tested unless a QA tag is also given.
- `[src]`, `[cfg]`: read from the source or workflow config at `ce9ea99`. Not run.

## What this fork is

ovpn-admin is a web UI to manage OpenVPN users, their certificates, and their routes on Linux. The backend is Go. The frontend is Vue.js. `[README]`

This repository is a fork of palark/ovpn-admin. The fork point is base commit `34c78fd`. `v0.1.0` is 18 commits on top of it, from `b9e2455` to `ce9ea99`. The project history goes back to Flant (2021), then Palark (November 2024). `[README]` The images and the Helm chart point to `ghcr.io/haumanto/ovpn-admin/*`. `[src]`

## Highlights

### Security

- **No shell.** Commands run with argument lists. The CCD static address and the openvpn-user password no longer go through a shell. `[commit b9e2455]`
- **Input checks.** Usernames are checked wherever they become file paths. A slave rejects unsafe names when it extracts master archives. `[commit b9e2455]` In QA, usernames and CCD values with shell metacharacters or `../` returned 422 and created no file. `[QA1 8a, 8b, 8c]` (eda1956; not re-run at ce9ea99)
- **Basic Auth.** HTTP Basic Auth covers the web UI, the API, and `/metrics`. `/ping` stays open. `[commit 55bd04e]` `[QA2 5]` `[QA1 6a, 6b, 6d]`
- **Sync token.** The example values and the old built-in default are refused at startup. A sync request with a wrong token gets 403. `[commit 4f47051]` `[QA2 13a]`
- **No secrets in the request log.** The log writes the path only, not the query string. `[commit b208419]` `[QA2 7]` (0 hits for the test passwords in the logs)
- **Cross-site writes refused.** Mutation routes accept POST only (405 otherwise). A request with a foreign `Origin` or `Referer` gets 403. `[commit 4f47051]` `[QA2 13b, 13c]` This is not a token-based CSRF defense. See K1.
- **Loopback admin in compose.** The compose file publishes the admin port on `127.0.0.1` only. Compose and the Helm chart refuse to start without credentials. `[QA2 12a, 12b, 12c]`
- **Server certificates hidden.** The OpenVPN server certificate is not listed as a user and cannot be revoked, rotated, or deleted from the UI or API. `[commit d9de299]` (not tested by QA)
- **Server address protected.** Tun/tap addresses that the OpenVPN server reports are reserved for CCD. `[commit c4ff352]` (not tested by QA)

### Lifecycle fixes

- **Revoke before delete and rotate.** Rotate and delete revoke an active certificate first. Deleting a user also removes its CCD file. `[commit 33c9add]` `[commit da98909]`
- Verified for delete on the candidate. The revoked serial is in the CRL, `openssl verify` fails with error 23, the CCD file is gone, and the same name can be created again with a dynamic address. `[QA2 6b, 6c, 6d, 6e]` These are the three delete defects from the first QA run (`[QA1 F1, F2, F3]`), now fixed.
- Rotate is not measured by QA at ce9ea99. See K9.

### Features

- **IPv6.** Dual-stack UI listener, an IPv6 pool for VPN clients, static IPv6 addresses and routes in CCD, and IPv6 status from the management interface. `[commit b9e2455]` `[commit 0fe0f85]` `[README]` IPv6 CCD runtime behavior was not exercised by QA. See K15.
- **Vue 3 UI.** The frontend moved to Vue 3.5 with webpack 5. `[commit a70a63d]` `[src frontend/package.json: vue ^3.5.44]` The build passes and the UI smoke test passes. `[QA2 3, 10]`
- **Upstream PR 433.** A configured OpenVPN host list takes priority over LoadBalancer discovery. `[commits 3246209, 9353ffc]` (the test covers the `len(hosts) == 0` condition; not tested by QA)
- **Slave sync.** A slave syncs its PKI and CCD from the master before the management check. `[commit 0789d1d]` A slave refuses user changes with 423. `[QA2 8]`

### Toolchain and dependencies

- **Go 1.26.** `go.mod` says `go 1.26.0`, and the Dockerfiles use `golang:1.26-alpine`. `[src]` QA ran go1.26.11. `[QA2 2]`
- **Node 24.** The frontend image uses `node:24-alpine`. `[src]` QA ran node v24.22.3. `[QA2 3]`
- **openvpn-user 1.0.9.** The tarball is checked against a pinned SHA256 for amd64 and arm64 in both Dockerfiles. `[commit f13b2d3]` `[QA2 9]` The pinned value is trust-on-first-use. See K12.
- **Dependency bumps.** follow-redirects 1.16.3 `[commit f13b2d3]`. logrus v1.10.2, client_golang v1.25.0, and k8s.io v0.37.1 `[commit b9e2455]`. Remaining npm findings: K13.
- **64-bit only.** Images and release binaries are amd64 and arm64. There is no 32-bit build. `[commit 0fe0f85]` `[README]`

## Upgrade notes

Read `UPGRADING-v0.1.0.md` first. It has the full steps and the rollback. The upgrade script takes a backup before it changes anything. `[UPGRADING-v0.1.0.md]` The script's backup path was run on a disposable copy. A full upgrade was not run. `[t_ffe94643 upgrade-script evidence]`

- **Credentials are required.** Set `BASIC_USERNAME`, `BASIC_PASSWORD`, and `OVPN_MASTER_TOKEN`. Compose refuses to start without them. `[QA2 12a]`
- **users.db from openvpn-user 1.0.4.** On start, `db-init` and `db-migrate` run, and `NULL` in the `secret` column becomes an empty string. Without this, password users created by 1.0.4 cannot log in. `[README]` `[commit b9e2455]` Not exercised by QA.
- **Back up first.** The users.db migration cannot be undone. The backup archive holds the CA private key. The script writes it with mode 600 in a mode 700 directory. `[UPGRADING-v0.1.0.md]` `[t_ffe94643 upgrade-script evidence]`
- **64-bit only.** Images are `linux/amd64` and `linux/arm64`. Release binaries are `linux-amd64` and `linux-arm64`. `[README]` `[cfg release.yaml]` Only the amd64 build ran in QA. `[QA2 9, limitations]`
- **Listen address.** `--listen.host` defaults to empty, which means all interfaces, IPv4 and IPv6. `[README]` `[commit b9e2455]` The compose file publishes the admin on `127.0.0.1` only. `[QA2 12b]`
- **CCD API status codes.** `GET api/user/ccd` returns 400 for an invalid name and 404 for an unknown user. It used to return 200 with an empty CCD. An invalid JSON body to `POST api/user/ccd/apply` returns 422. `[README]` `[src main.go:408-411, 438]` QA measured 422 for an address outside the pool and 422 for an invalid username. `[QA1 7c, 8a]` The 400 and 404 codes were not measured.
- **Certificate operations fail loudly.** `api/user/create` fails if the certificate cannot be issued, and `api/user/revoke` fails if `easyrsa revoke` fails. Both used to report success. `[README]` Not measured by QA.
- **Metrics.** `ovpn_client_bytes_sent` and `ovpn_client_bytes_received` sum over all sessions of a common name. `ovpn_client_connection_info` has one series per virtual address. Metric names are unchanged. `[README]`
- **Helm chart.** `ingress.basicAuth.user` and `ingress.basicAuth.password` are required. The old `admin`/`changeme` defaults are refused. Image tags default to the chart `appVersion`, and `master` is refused. `[QA2 12c]` `[H2b]`
- **Helm RBAC.** The Role is narrowed to `secrets` (get, list, create, update) and `services` (get) in the release namespace. `[src charts/openvpn-admin/templates/rbac.yaml]`
- **Web UI caching.** The UI is served with `Cache-Control: no-cache` and an `ETag`, so browsers load the new UI after an upgrade. `[README]`

## Install

### 1. Docker Compose (build from source, the `start.sh` flow)

```bash
git clone https://github.com/haumanto/ovpn-admin.git
cd ovpn-admin
git checkout v0.1.0            # the tag is created at release time; today the branch is v0.1.0
export BASIC_USERNAME=admin
export BASIC_PASSWORD='<long random password>'
export OVPN_MASTER_TOKEN="$(openssl rand -hex 32)"
./start.sh
```

`start.sh` runs `docker compose -p openvpn-master up -d --build`. `[src start.sh]` QA built both images from the clean clone and ran the compose file with an override. `[QA2 4, 5]` The `start.sh` path itself was not run.

### 2. Release binaries

`release.yaml` builds `ovpn-admin-linux-amd64` and `ovpn-admin-linux-arm64` when a GitHub release is created. `[cfg .github/workflows/release.yaml]` Not run. No release exists yet.

### 3. Container images

- `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.0`
- `ghcr.io/haumanto/ovpn-admin/openvpn:v0.1.0`

`publish-tag.yaml` pushes them when a `v*` tag is pushed. `[cfg]` **These images are not published yet.** The Helm chart points at these names. `[QA2 12c]` Pulls were not tested.

### 4. Helm

```bash
helm install openvpn-admin charts/openvpn-admin \
  --set ingress.basicAuth.user='<user>' \
  --set ingress.basicAuth.password='<password>'
```

Keep the credentials out of git, for example in a values file that is not committed. `[charts/openvpn-admin/README.md]` QA ran `helm template` and `helm lint` only. Nothing was installed on a cluster. `[QA2 12c, limitations]`

## Secure deployment

Read the **Secure deployment** section of `README.md` before you expose the service. In short: Basic Auth is required, a TLS-terminating reverse proxy must sit in front of the admin UI, and direct access to the backend port must be blocked. Cross-host master/slave sync must use HTTPS.

## Known issues

Each item names its source. Items marked `unverified` have no test result.

- **K1. CSRF is mitigated, not defended by a token.** Mutation routes accept POST only, and a foreign `Origin` or `Referer` gets 403. Requests with neither header are accepted by design, so curl and the CLI work. Script running on the same origin (for example through XSS) is not covered by this check. `[AUD F02, residual]` `[QA2 13b, 13c]` Browser cross-site behavior was not tested with a browser.
- **K2. The container runs as root, and base images and Actions are not pinned.** The Dockerfiles have no `USER` and no `HEALTHCHECK`. Base images use tags, not digests. Actions use version tags, not commit SHAs. `[AUD F06, F07]` `[src Dockerfile.ovpn-admin, Dockerfile.openvpn]`
- **K3. Chart RBAC is narrowed, but not tested in a cluster.** The Role covers only the objects the app uses. Cluster admission, other-namespace reachability, and service-account token mounting were not exercised. `[AUD F08]` `[QA2 12c, limitations]`
- **K4. Archive handling is unverified.** Archive handling still follows pre-existing symlinks. Key files and the fixed `/tmp` archive use default creation modes. No untrusted symlink writer was shown. `[AUD F09]` `unverified`
- **K5. No real VPN client was connected.** CRL enforcement at connect time is not shown. QA checked the CRL content and `openssl verify` only. `[QA1 limitations]` `[QA2 limitations]` `[AUD F04]`
- **K6. `/api/server/settings` has no version field.** QA check 6c failed at `eda1956`: the response is `status`, `serverRole`, and `modules`. `[QA1 6c]` The source at `ce9ea99` has the same body. `[src main.go:459]` The delta QA did not re-run this check. The README does not promise a version field. Conductor must either add the field or drop the expectation. `--version` reports `0.1.0`. `[QA2 4]`
- **K7. Basic Auth is off when both flags are empty.** `--basic.username` and `--basic.password` both empty disables auth in the binary itself. Compose and the Helm chart refuse to start without credentials, but a bare binary run does not. `[AUD F01]` `[src main.go:642]` `[README flags]`
- **K8. Trace logs and the auth hook still expose secrets.** At trace level, the log writes the rendered client config. The audit reports that it includes the private key and the TLS auth key. `[AUD F03]` `[src main.go:912]` The auth hook `setup/auth.sh` runs `env`. `[src]` The request-log part of F03 is fixed (see Highlights). `[QA2 7]`
- **K9. Rotate and the Kubernetes backend are not measured.** Delete is verified at `ce9ea99` (`[QA2 6b–6e]`). Rotate revocation is described in `[commit 33c9add]`, tested by its author with easy-rsa 3.2.7 and a fake easyrsa. The delta QA did not measure it. The `kubernetes.secrets` backend was not measured. `[AUD F04]` `unverified`
- **K10. docker-compose-slave.yaml cannot start as shipped.** It has the literal `--master.sync-token="TOKEN"`, which the binary refuses. It has no Basic Auth. Its `master.host` is `http://172.20.0.1:8080`, which the loopback admin binding does not serve. `[QA2 13a, limitations]` `[t_ffe94643]` Fix or document it before or right after release. The README mentions the URL problem.
- **K11. Images and binaries are not published.** No `ghcr.io` pull was tested, and no release binary was built. `[QA2 limitations]` `[cfg]`
- **K12. The openvpn-user checksum is trust-on-first-use.** The upstream release publishes only `.md5` files and no signature. The SHA256 values were computed from the live asset. `[H2]` `[commit f13b2d3]`
- **K13. npm reports two vulnerabilities.** `npm ci` reported 2 vulnerabilities (1 moderate, 1 high) at `ce9ea99`. They are listed as dev dependencies and were not analyzed. `[QA2 3, verification notes]` `[H2]`
- **K14. Minor API observations from the first QA run.** At `eda1956`, `/api/users/list` returned `null` instead of `[]` when empty. `POST /api/user/config/show` returned 200 with a not-found body for an unknown user. JSON endpoints answered `text/plain`. A successful unrevoke logged one error line. Not re-run at `ce9ea99`. `[QA1 minor observations]`
- **K15. Not covered by QA.** IPv6 CCD runtime (QA covered only IPv6 "dynamic" on a re-created user, `[QA2 6e]`). The `kubernetes.secrets` backend. The change-password and rotate APIs. The full openvpn-user 1.0.4 migration. A full `scripts/upgrade.sh` run. The arm64 build. `[QA1 not covered]` `[QA2 limitations]` `unverified`

### Audit findings at `ce9ea99`

These statuses are the release-note view of `audit/REPORT.md`. The audit's own headline is not the release status. The release gate is the delta QA verdict above.

| ID | Topic | Status at `ce9ea99` | Source |
|---|---|---|---|
| F01 | Default credentials, example sync token | Fixed for compose and chart. The binary can still run with auth off (K7). | `[QA2 12a, 12c, 13a]` |
| F02 | CSRF | Mitigated by POST-only and Origin/Referer. No token (K1). | `[QA2 13b, 13c]` |
| F03 | Secrets in logs | Query strings fixed. Trace and env sinks remain (K8). | `[QA2 7]`, `[src]` |
| F04 | Revocation and CCD on delete and rotate | Delete fixed and verified. Rotate and Kubernetes not measured (K9). | `[QA2 6b–6e]` |
| F05 | openvpn-user artifact checksum | Pinned SHA256 for amd64 and arm64. Checked at build for amd64 in QA; the arm64 build was not run. Trust-on-first-use (K12). | `[QA2 9]`, `[H2]` |
| F06 | Mutable build and Action refs | Not fixed (K2). | `[AUD F06]` |
| F07 | Container hardening | Not fixed: root, no healthcheck (K2). | `[AUD F07]` |
| F08 | Chart RBAC scope | Narrowed. Not tested in a cluster (K3). | `[src rbac.yaml]` |
| F09 | Symlinks and file modes | Not fixed. Unverified (K4). | `[AUD F09]` |
| F10 | Transport documentation | README "Secure deployment" section added. Text only. | `[src README.md]` |

## Verification summary

Numbers below come from the QA reports only.

- Delta QA on `ce9ea99`: items 1 to 13 pass, except item 1 delete step (not verified, QA environment). `[QA2 summary]`
- Go: `go vet` and `go test -count=1 -v ./...` in `golang:1.26-alpine`. 72 top-level tests run, 71 pass, 1 skipped (`TestFakeEasyrsa`, a helper process). `[QA2 2]`
- Frontend: `npm ci` and `npm run build` in `node:24-alpine`. Webpack compiled, `bundle.min.js` is 372955 bytes. `[QA2 3]`
- Images: both built with `--no-cache`. `--version` prints `0.1.0`. `[QA2 4]`
- Compose: `/ping` returns 200. `/api/server/settings` returns 401 without auth, 401 with a wrong password, and 200 with auth. `[QA2 5]`
- Delete: revoked in index, CRL, and `openssl verify`. CCD removed. Name reusable. `[QA2 6b–6e]`
- Deployment defaults: compose and Helm refuse missing credentials. Explicit credentials render. Images are tagged `v0.1.0`. `[QA2 12a–12c]`
- Logs: 0 panic lines, 0 `level=error` or `level=fatal` lines, and 0 hits for the test passwords and the sync token. `[QA2 11]`
- UI: a headless Chromium 156 run (local, not Browser Use cloud) shows the user table with 0 uncaught errors and 0 console errors. `[QA2 10]`
- Slave: writes return 423 on the slave, and its state does not change. `[QA2 8]`
