# ovpn-admin v0.1.8 release notes

**Status: published.** Tag `v0.1.8`, GitHub release with amd64/arm64 binaries, GHCR images, chart release.

- Candidate: branch `v0.1.8`, code SHA `e94a24b4c7a02bf40c24be4074efab9c2d824e76` (`chore(release): bump version to v0.1.8`). It is two commits on top of v0.1.7 (`a66404b`): `9da577c` (component inventory, scan workflow, Dependabot) and `e94a24b` (version bump). The commit that adds this file sits on top of `e94a24b` and changes only `RELEASE-v0.1.8.md`, `README.md` and `UPGRADING.md`.
- QA: `qa-v018/REPORT.md` (card `t_1b00509a`), verdict **SHIP** at `e94a24b`. Items 1 to 12 PASS. Items 4 and 5 (workflow and Dependabot on GitHub) are checked only statically, see [Known limitations](#known-limitations).
- Developer evidence: `v018/p18-tracking.txt` (builds, inventory, scanner dry runs, card numbers).

Source tags below: `[QA n]` = QA report item n. `[P18]` = developer evidence file `v018/p18-tracking.txt`.

## What was added

- **`COMPONENTS.md`** (new, repository root). Lists every component of the `ovpn-admin` and `openvpn` images: Alpine and its apk packages (40 in `ovpn-admin`, 59 in `openvpn`), OpenVPN, OpenSSL, easy-rsa, sqlite, Go toolchain 1.26.11 and its 56 Go modules, the six npm runtime dependencies of the web UI. Each row says where it comes from and how to bump it. It also has the commands to refresh it. QA re-measured 56 components from the built images and manifests: 56 match, 0 mismatch. `[QA 2, 3]`
- **Security scan workflow** (`.github/workflows/security-scan.yaml`, "Security scan"). Four independent jobs:
  - `sbom`: builds both images for `linux/amd64` locally (nothing is pushed) and writes an SPDX JSON SBOM per image with Syft (via `anchore/sbom-action` v0.24.3). The SBOMs are kept as workflow artifacts for 90 days and, on a tag build, attached to the GitHub release if it exists. `[QA 6]`
  - `scan`: Trivy 0.70.0 (via `aquasecurity/trivy-action` v0.36.0) on both images, `CRITICAL,HIGH`, unfixed findings included. SARIF goes to code scanning from master and the weekly run only.
  - `go-vuln`: `govulncheck` v1.10.0 on `./...`, in the same Go image the Dockerfile builds with. `[QA 7]`
  - `npm-audit`: `npm audit --omit=dev --audit-level=high` in `frontend/`, Node 24. `[QA 8]`
  - Triggers: push to `master`, tags `v*`, pull requests to `master`, and a weekly run on Mondays at 03:17 UTC.
- **Dependabot** (`.github/dependabot.yml`). Weekly update pull requests for Go modules (`/`), npm packages (`/frontend`), Docker base images named in the Dockerfiles (`/`), GitHub Actions (`/`) and Helm chart dependencies (`/charts/openvpn-admin`). Minor and patch updates are grouped into one pull request per ecosystem, major updates come separately, at most 5 open pull requests per ecosystem. The Helm block is idle today: the chart has no dependencies. `[QA 5]`
- **`docs/components.md`** (new). How to read a Trivy finding, which file to change for each component class, the bump procedure and the known limits of Dependabot.
- **README and UPGRADING**: a "Keeping dependencies current" section in `README.md`, and a v0.1.7 to v0.1.8 section in `UPGRADING.md`.
- **Version string `0.1.8`** in `main.go`, `frontend/package.json`, `frontend/package-lock.json`, and the chart (`Chart.yaml`: `version` 0.1.8, `appVersion` v0.1.8; chart README badge). `[P18 section 3]`

No Dockerfile, compose file, Go logic, frontend source, template or chart template changed since v0.1.7. `[QA 10]`

## How to read the results

- Open the **Actions** tab and the "Security scan" workflow. Job names: `SBOM (ovpn-admin)`, `SBOM (openvpn)`, `Trivy (ovpn-admin)`, `Trivy (openvpn)`, `govulncheck`, `npm audit (frontend)`.
- The SBOMs are in the run's artifacts: `sbom-ovpn-admin.spdx.json` and `sbom-openvpn.spdx.json`. Code scanning alerts are in the **Security** tab (from master and the weekly run).
- **Pull requests stay green.** Findings are printed as warnings, and no job fails on a finding. Master, tags and the weekly run fail on a finding at the gated level.
- Trivy's target line tells you the layer. `alpine 3.23.8` or `alpine 3.24.4` is an apk package. `(gobinary)` is a Go module or the Go standard library compiled into a binary. `stdlib` is the Go toolchain that built that binary, not a module.
- A Trivy match means the vulnerable version is present. It does not mean the code path is reachable. For this repository's Go code, `govulncheck` tells you whether a vulnerable function is called.
- An empty "Fixed Version" means no fix exists yet.
- Find the component in `COMPONENTS.md`, then follow the "How to bump" cell or the table in `docs/components.md`.
- To run the scanners yourself, use the commands in `COMPONENTS.md`, "How to refresh this file".

## Bump procedure

The full procedure is in `docs/components.md`. In short:

1. Find the component and its "How to bump" cell in `COMPONENTS.md`.
2. Change the file named in that cell, on a branch.
3. Build both images and run the scanners locally. The finding should be gone and nothing new should appear.
4. Run `go test ./...` for Go changes, and `npm ci && npm run build` in `frontend/` for UI changes.
5. Update the versions and the "measured on" line in `COMPONENTS.md` in the same pull request.
6. Open the pull request. The scan runs in report-only mode. After the merge it runs on master with the gate on.
7. Release as usual. The tag build attaches fresh SBOMs to the release.

Dependabot does not update the Alpine tag of `Dockerfile.openvpn` (it sits behind `ARG ALPINE_VERSION`), apk package versions, the pinned `openvpn-user` download, or `GOVULNCHECK_VERSION` in the workflow. Those are bumped by hand.

## Scanner findings recorded at release time

Measured on 2026-11-21 by QA `[QA 6, 7, 8]`, on images built from `e94a24b` for `linux/amd64`. Trivy 0.70.0, all severities, unfixed included. Full list of all 130 rows: `qa-v018/06-findings.md`.

| Image | Target | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Total |
|---|---|---|---|---|---|---|---|
| `ovpn-admin` | alpine 3.23.8 | 0 | 0 | 1 | 0 | 0 | 1 |
| `ovpn-admin` | `app/ovpn-admin` (Go binary) | 0 | 0 | 0 | 0 | 0 | 0 |
| `ovpn-admin` | `usr/local/bin/openvpn-user` | 4 | 54 | 66 | 4 | 1 | 129 |
| `openvpn` | alpine 3.24.4 | 0 | 0 | 1 | 0 | 0 | 1 |
| `openvpn` | `usr/local/bin/openvpn-user` | 4 | 54 | 66 | 4 | 1 | 129 |

Both images report the same 130 distinct findings.

**Gate findings (CRITICAL and HIGH): 58 per image.** The `scan` job fails on these. All 58 are in the prebuilt `usr/local/bin/openvpn-user` v1.0.9 binary (built with Go 1.19.3, `golang.org/x/crypto` v0.2.0), in both images. All 58 have a fixed version upstream. 45 are in the Go standard library (`stdlib` v1.19.3) and 13 in `golang.org/x/crypto` v0.2.0. `[QA 6, 06-findings.md] [P18 section 5]`

CRITICAL (4):

| CVE | Component | Installed | Fixed in |
|---|---|---|---|
| CVE-2023-24538 | Go standard library | v1.19.3 | 1.19.8, 1.20.3 |
| CVE-2023-24540 | Go standard library | v1.19.3 | 1.19.9, 1.20.4 |
| CVE-2024-24790 | Go standard library | v1.19.3 | 1.21.11, 1.22.4 |
| CVE-2025-68121 | Go standard library | v1.19.3 | 1.24.13, 1.25.7, 1.26.0-rc.3 |

HIGH (54): 41 in the Go standard library and 13 in `golang.org/x/crypto`. The IDs and fixed versions are in the table of `qa-v018/REPORT.md` and in `06-findings.md`.

**Below the gate (reported only, never fails a job):**

| Severity | Count | Where | Note |
|---|---|---|---|
| MEDIUM | 1 | Alpine package `zlib` 1.3.2-r1, both images | CVE-2026-4738, fixed in 1.4-r0. The only finding in an Alpine package |
| MEDIUM | 66 | `openvpn-user` binary, both images | Listed in `06-findings.md` |
| LOW | 4 | `openvpn-user` binary, both images | Listed in `06-findings.md` |
| UNKNOWN | 1 | `openvpn-user` binary, both images | GO-2026-5932 |

**Other scanners:**

| Scanner | Scope | Result |
|---|---|---|
| govulncheck v1.10.0 | Go code of this repository, `./...` | No vulnerabilities found, exit 0 |
| npm audit, production (`--omit=dev`) | 62 packages that feed the UI bundle | 0 at every severity |
| npm audit, dev tooling (not gated, not shipped) | 408 dev packages | `body-parser` 2.0.0 to 2.3.0, HIGH (GHSA-27r3-jxmh-p828); `fast-uri` 3.0.0 to 3.1.8, MODERATE (4 advisories) |

These counts were true on the day they were measured. New advisories appear without a commit, and the weekly run will report them.

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v017--v018).

- **Rebuild the `ovpn-admin` image only.** The `openvpn` image has no source change since v0.1.7 (`Dockerfile.openvpn` and `setup/` are unchanged). `[QA 10]`
- **No runtime or config change.** Nothing to configure. The compose files are unchanged. The only change a running `ovpn-admin` sees is the version string.
- **No database migration.** The Go code is unchanged apart from the version line. `easyrsa_master/`, `ccd_master/`, `users.db` and `audit_master/` are not changed by this release. `[QA 10]`
- **Weekly scans start with this release.** The security scan runs every Monday at 03:17 UTC on master. It runs on GitHub runners, not on your server, so it does not change a deployment.
- **Helm.** The chart moves to version 0.1.8 with `appVersion` v0.1.8. Its default image tags follow `appVersion`, so the chart asks for `v0.1.8` for both images. Helm was not re-run in QA; the chart change is the version fields only. `[QA Known limitations] [P18 section 3]`
- **An openvpn image built today is not the same as the v0.1.7 one.** A fresh build pulls newer Alpine packages (for example `openssl` 3.5.9-r1; the v0.1.7 image had 3.5.9-r0). That comes from Alpine, not from this release. You do not need to rebuild the `openvpn` image for v0.1.8. `[P18 section 3]`

## Known limitations

- **Not published.** No tag, GitHub release, image, binary or chart release exists. Approval for publishing is still needed.
- **The `Trivy` jobs will be red** on the first master run, on the `v0.1.8` tag build, and on every weekly run, until the prebuilt `openvpn-user` binary is rebuilt with a current Go and `golang.org/x/crypto`. Pull requests stay green. The fix is a change to the pinned download and SHA-256 in both Dockerfiles. It is not in this release and is proposed as separate work. Whether to tag before that fix is a release-owner decision.
- **The workflow and Dependabot were never run on GitHub.** Not verified: that GitHub accepts the workflow, the real behavior of the Trivy `exit-code` expression (checked by reading it and by Trivy's own exit codes, not by a run on GitHub), SARIF upload to code scanning, artifact upload, the release attachment on a tag, and that Dependabot accepts the five blocks. `[QA 4, 5]`
- **Reachability of the 58 gate findings was not assessed.** Whether any is reachable through `openvpn-user` is an open question for a security review.
- **Only amd64 was scanned.** arm64 images were not built or scanned. The workflow scans amd64 only.
- **Alpine package `zlib`** (CVE-2026-4738, MEDIUM) is below the gate and is reported only.
- **Dependabot cannot see** the Alpine tag of `Dockerfile.openvpn`, apk versions, the `openvpn-user` pin or `GOVULNCHECK_VERSION`. Those are bumped by hand.
- **`COMPONENTS.md` versions are for a build made on 2026-11-21.** A build on another day can carry newer patch versions.
- **In-place upgrade not run.** QA used a fresh stack, not an existing v0.1.7 install with data. The stack ran from the resolved compose configuration with `docker run`, not `docker compose up`. `[QA Assumptions]`
- **Helm chart tests were not re-run.** `helm-docs` regenerated the chart README in the developer's check. `[P18 section 3]`
- **Go unit tests.** `go test ./...` passes in a writable copy (`ok ovpn-admin`). In a read-only mount, `TestDeleteActiveUserRevokesTheCertificate` fails, because the test removes a file in the working directory instead of a temp directory. This is a test issue, not a product regression. It is recorded for follow-up. `[QA 10, 10d-10f]`
- **Other workflows** (`chart-test.yaml`, `publish-tag.yaml`) have actionlint and shellcheck notes. They are not changed by v0.1.8. `[QA observation 7]`
- **UI coverage is a short regression pass.** QA ran 22 of 22 UI asserts (Users and Banned IPs, the theme menu, Light, Dark and System, reload) at 1280 and 390 px, in Chromium 158 only. Dialogs, Ban IP and Unban, History and contrast were not repeated in this release. The UI source has not changed since v0.1.7. `[QA 10]`
