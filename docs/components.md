# Components, SBOM and CVE tracking

The versions that ship in the `ovpn-admin` and `openvpn` images are listed in [COMPONENTS.md](../COMPONENTS.md). This page explains how to read a vulnerability finding and what to change to fix it.

## What runs automatically

| What | Where | When | Result |
|---|---|---|---|
| SBOM (SPDX JSON) of each image | Job `sbom` in [security-scan.yaml](../.github/workflows/security-scan.yaml) | push to master, tags `v*`, pull requests, weekly | Workflow artifacts `sbom-ovpn-admin.spdx.json` and `sbom-openvpn.spdx.json` (90 days). On tag builds also attached to the GitHub release when the release exists. |
| Trivy scan of each image (`CRITICAL,HIGH`, unfixed included) | Job `scan` | same | Table in the job log. Pull requests never fail on findings. Master, tags and the weekly run fail the job. SARIF goes to the Security tab (code scanning) from master and the weekly run. |
| `govulncheck ./...` | Job `go-vuln` | same | Reports only vulnerabilities in code the binary can actually reach. |
| `npm audit --omit=dev --audit-level=high` | Job `npm-audit` | same | Production npm dependencies only. |
| Update pull requests | [dependabot.yml](../.github/dependabot.yml) | weekly | Go modules, npm (`/frontend`), Dockerfile base images, GitHub Actions, Helm chart dependencies. Minor and patch updates are grouped, majors come separately, 5 open PRs at most per ecosystem. |

The four jobs are independent, so one red job does not hide the others.

## Reading a Trivy finding

A finding looks like this:

```
usr/local/bin/openvpn-user (gobinary)
Library              Vulnerability   Severity  Status  Installed Version  Fixed Version  Title
golang.org/x/crypto  CVE-2024-45337  HIGH      fixed   v0.2.0             0.31.0         ...
```

1. **Target line** (`alpine 3.24.4`, `app/ovpn-admin (gobinary)`, `usr/local/bin/openvpn-user (gobinary)`): which layer owns the package. `alpine` means an apk package. `gobinary` means a Go module or the Go standard library compiled into that binary. This tells you which row of COMPONENTS.md and which file below applies.
2. **Library** and **Installed Version**: look the name up in [COMPONENTS.md](../COMPONENTS.md). `stdlib` means the Go toolchain that built the binary, not a module.
3. **Fixed Version**: the version that contains the fix. Empty with Status `affected` or `will_not_fix` means no fix exists yet.
4. **Is it reachable?** A Trivy match only says the vulnerable version is present. For Go code in this repository, `govulncheck ./...` says whether the vulnerable function is called. Alpine findings in tools that are only used for PKI work in the `ovpn-admin` image (OpenVPN, easy-rsa, sqlite) are lower risk than the same finding in the running `openvpn` server image; judge it from the "not the running server" note in COMPONENTS.md.
5. Decide: bump (below), or if there is no fix and the risk is accepted, record the decision in the pull request. Do not silence a finding without writing down why.

Open an SBOM to answer "do we ship package X at all?": `jq '.packages[] | select(.name=="openssl") | .versionInfo' sbom-openvpn.spdx.json`.

## Which file to change

| Component class | Example finding target | File to change | Command or edit |
|---|---|---|---|
| Alpine package (OpenSSL, OpenVPN, musl, busybox, bash, easy-rsa, sqlite, fail2ban, Python, iptables) | `alpine 3.24.4` | `Dockerfile.openvpn` (`ARG ALPINE_VERSION`) or `Dockerfile.ovpn-admin` (`FROM alpine:3.23`) | Rebuild with `--pull` first: Alpine usually has the fix in the same branch. If the fix only exists in a newer branch, change the tag. Add `apk upgrade` or a package version pin only if the fix is published but the base image is not rebuilt yet. |
| Go standard library (`stdlib`) in `ovpn-admin` | `app/ovpn-admin (gobinary)` | `Dockerfile.ovpn-admin` (`golang:1.26-alpine`) and `go` in `go.mod` | Rebuild with `--pull` for a patch release; change the tag and `go.mod` for a new minor. |
| Go module in `ovpn-admin` | `app/ovpn-admin (gobinary)` | `go.mod`, `go.sum` | `go get <module>@<fixed-version> && go mod tidy`, run `go test ./...`. |
| npm package (production) | `npm audit` output | `frontend/package.json`, `frontend/package-lock.json` | `cd frontend && npm install <package>@<fixed-version>` or `npm audit fix --omit=dev`, then rebuild the UI. |
| openvpn-user binary | `usr/local/bin/openvpn-user (gobinary)` | `Dockerfile.ovpn-admin` **and** `Dockerfile.openvpn` (URL and both SHA-256 values) | Needs a new upstream release or a rebuilt binary of `pashcovich/openvpn-user`. See COMPONENTS.md, "Known findings". |
| GitHub Action used by CI | n/a | `.github/workflows/*.yaml` | Dependabot opens the PR. Actions pinned to a commit SHA keep the `# vX.Y.Z` comment next to it. |
| Helm chart dependency | n/a | `charts/openvpn-admin/Chart.yaml` | Dependabot opens the PR (none today). |

## Bump procedure

1. Find the component and its "How to bump" cell in [COMPONENTS.md](../COMPONENTS.md).
2. Make the change in the file from the table above, on a branch.
3. Build both images and run the scanners locally with the commands in COMPONENTS.md, "How to refresh this file". The finding should be gone and nothing new should appear.
4. Run the Go tests (`go test ./...`) for Go changes and `cd frontend && npm ci && npm run build` for frontend changes.
5. Update the version numbers and the "measured on" line in COMPONENTS.md in the same pull request.
6. Open the pull request. The `Security scan` workflow runs on it (report only). After the merge the same workflow runs on master with the gate on.
7. Release as usual. The tag build attaches fresh SBOMs to the release.

## Known limits

* Dependabot cannot update the Alpine tag in `Dockerfile.openvpn` (it is behind `ARG ALPINE_VERSION`), apk package versions, the pinned `openvpn-user` download, or `GOVULNCHECK_VERSION` in the workflow. Bump those by hand.
* Trivy and Syft scan the `linux/amd64` images. The arm64 images use the same Dockerfiles and package names but are not scanned separately.
* Uploading SARIF to code scanning needs code scanning to be available for the repository (public repositories, or GitHub Advanced Security for private ones).
