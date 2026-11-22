# Components

What ships in the two container images, where each component comes from and how to bump it. Use it to answer "are we affected by CVE-X?" and "which file do I change?".

Measured on `linux/amd64` builds of the v0.1.9 branch, 2026-11-21 (the openvpn-user rows and "Known findings" are from the build that replaced the prebuilt openvpn-user binary; the Alpine and apk rows were measured the same day on the v0.1.8 build and the Trivy scan of the rebuilt images reports the same Alpine 3.23.8 and 3.24.4). Versions in the tables are what the built images report, not what the Dockerfiles ask for: `alpine:3.23` and `golang:1.26-alpine` are floating tags and `apk add` takes the newest package of the Alpine branch, so a rebuild on another day can ship newer patch versions. Refresh the file with the commands at the end whenever a base image, an apk package or a dependency is bumped, and at every release.

Neither image contains PHP or nginx (nginx only appears as an example reverse proxy in [docs/hardening](docs/hardening/README.md)).

How these tables are tracked automatically: [.github/workflows/security-scan.yaml](.github/workflows/security-scan.yaml) builds both images, writes an SPDX SBOM per image, scans them with Trivy, and runs `govulncheck` and `npm audit`. [.github/dependabot.yml](.github/dependabot.yml) opens weekly update pull requests. How to read a finding and what to change: [docs/components.md](docs/components.md).

## Image `ovpn-admin` (`Dockerfile.ovpn-admin`)

Web UI and API. The running server process is the Go binary `/app/ovpn-admin`. The final stage is `alpine:3.23` plus the packages below.

OpenVPN, easy-rsa and sqlite in this image are **not the running VPN server**. They are only PKI and user-database tooling that `ovpn-admin` shells out to (`easyrsa` for certificates, `openvpn-user` and `sqlite3` for the password database, `openssl` for certificate handling). The VPN server runs in the `openvpn` image. A CVE in `openvpn` itself therefore matters for the `openvpn` image; in this image it matters only if someone runs `openvpn` here by hand.

### Distro and system packages

| Component | Version | Where it comes from | How to bump |
|---|---|---|---|
| Alpine Linux | 3.23.8 | Base image `alpine:3.23` (final stage) | Rebuild with `--pull` for patch releases of 3.23. Change the tag in `Dockerfile.ovpn-admin` for a new Alpine branch. |
| musl libc | 1.2.5 (apk `musl-1.2.5-r24`) | apk, part of the Alpine base | Follows the base image (rebuild with `--pull`). |
| busybox | 1.37.0 (apk `busybox-1.37.0-r30`) | apk, part of the Alpine base | Follows the base image. |
| OpenSSL | 3.5.9 (apk `openssl`, `libssl3`, `libcrypto3`, all `3.5.9-r0`) | apk `openssl` (explicit) | Rebuild with `--pull`. A fix that exists only in a newer Alpine branch needs a base image tag bump. |
| OpenVPN | 2.6.20 (apk `openvpn-2.6.20-r0`) | apk `openvpn` (explicit). PKI tooling only, see above. | Rebuild with `--pull`. The version is whatever the Alpine branch carries. |
| easy-rsa | 3.2.3 (apk `easy-rsa-3.2.3-r0`) | apk `easy-rsa` (explicit). Symlinked to `/usr/local/bin/easyrsa`. | Rebuild with `--pull`. |
| sqlite | 3.53.4 (apk `sqlite-3.53.4-r0`) | apk `sqlite` (explicit). CLI used to repair `users.db`. | Rebuild with `--pull`. |
| bash | 5.3.3 (apk `bash-5.3.3-r1`) | apk `bash` (explicit) | Rebuild with `--pull`. |
| coreutils | 9.8 (apk `coreutils-9.8-r1`) | apk `coreutils` (explicit) | Rebuild with `--pull`. |
| openvpn-user | v1.0.9, upstream commit `5eefd1b` | Vendored upstream source in `third_party/openvpn-user/` (Go files unmodified except a 72-byte password guard and bcrypt cost 12, see its README), compiled by the stage `openvpn-user-builder` of `Dockerfile.ovpn-admin` (`golang:1.26-alpine` on the build host plus `gcc musl-dev`, `CGO_ENABLED=1`, static, Go 1.26.11; native gcc with up to 3 attempts when target and build architecture match, `zig cc` cross build for the other architecture, see the vendored README) and copied to `/usr/local/bin/openvpn-user`. Modules: `github.com/mattn/go-sqlite3` v1.14.53, `golang.org/x/crypto` v0.59.0 (details in the table below). Nothing is downloaded as a binary. | Modules: `cd third_party/openvpn-user && go get <module>@<version> && go mod tidy`. Standard library: rebuild with `--pull`. Edit `Dockerfile.ovpn-admin` **and** `Dockerfile.openvpn` only to change the build stage. Rules and checks: [third_party/openvpn-user/README.md](third_party/openvpn-user/README.md). |
| apk packages, total | 40 | `apk info` in the final image | n/a |

### Go build and Go modules (compiled into `/app/ovpn-admin`)

| Component | Version | Where it comes from | How to bump |
|---|---|---|---|
| Go toolchain (and its standard library, linked into the binary) | 1.26.11 | Build stage image `golang:1.26-alpine`; `go 1.26.0` in `go.mod` | Rebuild with `--pull` for patch releases (the standard library is what `govulncheck` and Trivy report as `stdlib`). Change the tag in `Dockerfile.ovpn-admin` and `go` in `go.mod` for a new Go minor. |
| `github.com/alecthomas/kingpin/v2` | v2.4.0 | Go module (direct) | `go get github.com/alecthomas/kingpin/v2@<version> && go mod tidy` |
| `github.com/google/uuid` | v1.6.0 | Go module (direct) | `go get github.com/google/uuid@<version> && go mod tidy` |
| `github.com/prometheus/client_golang` | v1.25.0 | Go module (direct) | `go get github.com/prometheus/client_golang@<version> && go mod tidy` |
| `github.com/sirupsen/logrus` | v1.10.2 | Go module (direct) | `go get github.com/sirupsen/logrus@<version> && go mod tidy` |
| `k8s.io/api` | v0.37.2 | Go module (direct) | `go get k8s.io/api@<version> k8s.io/apimachinery@<version> k8s.io/client-go@<version> && go mod tidy` (bump the three together) |
| `k8s.io/apimachinery` | v0.37.2 | Go module (direct) | same as above |
| `k8s.io/client-go` | v0.37.2 | Go module (direct) | same as above |
| `golang.org/x/net`, `golang.org/x/sys` (transitive, examples) | v0.62.0, v0.49.0 | Go modules (indirect) | `go get golang.org/x/net@<version> && go mod tidy` |
| Go modules in the binary, total | 56 | `go version -m /app/ovpn-admin` | n/a |

### Go modules compiled into `/usr/local/bin/openvpn-user` (both images)

Separate Go module `third_party/openvpn-user` (vendored upstream source plus our `go.mod` and `go.sum`), built by the stage `openvpn-user-builder` with Go 1.26.11 (`golang:1.26-alpine`). Versions from `go version -m` of the built binary. Upstream v1.0.9 pinned `go-sqlite3` v1.14.16 and `golang.org/x/crypto` v0.2.0 and was built with Go 1.19.3.

| Component | Version | Where it comes from | How to bump |
|---|---|---|---|
| Go toolchain (standard library, linked in) | 1.26.11 | Build stage image `golang:1.26-alpine` | Rebuild with `--pull`. |
| `golang.org/x/crypto` (bcrypt) | v0.59.0 | `third_party/openvpn-user/go.mod` (direct) | `cd third_party/openvpn-user && go get golang.org/x/crypto@<version> && go mod tidy` |
| `github.com/mattn/go-sqlite3` (cgo, bundles SQLite) | v1.14.53 | same (direct) | `go get github.com/mattn/go-sqlite3@<version> && go mod tidy` |
| `github.com/dgryski/dgoogauth` | v0.0.0-20190221195224-5a805980a5f3 | same (direct, unchanged from upstream) | `go get github.com/dgryski/dgoogauth@<version> && go mod tidy` |
| `gopkg.in/alecthomas/kingpin.v2` | v2.2.6 | same (direct, unchanged from upstream) | `go get gopkg.in/alecthomas/kingpin.v2@<version> && go mod tidy` |
| `github.com/alecthomas/template`, `github.com/alecthomas/units` (transitive) | v0.0.0-20190718012654-fb15b899a751, v0.0.0-20201120081800-1786d5ef83d4 | same (indirect) | follow kingpin |
| Go modules in the binary, total | 6 | `go version -m /usr/local/bin/openvpn-user` | n/a |

### Web UI (webpack bundle served by the Go binary, built in a `node:24-alpine` stage)

The UI is compiled at build time and embedded in the binary. There is no Node.js or npm in the final image. Node 24.22.3 and npm 11.19.1 (from `node:24-alpine` at measurement time) exist only in the build stage.

| Component | Version | Where it comes from | How to bump |
|---|---|---|---|
| Vue | 3.5.44 | npm package `vue` (runtime dependency) | `cd frontend && npm install vue@<version>` (updates `package.json` and `package-lock.json`) |
| axios | 1.20.0 | npm package `axios` (runtime dependency) | `cd frontend && npm install axios@<version>` |
| bootstrap | 5.3.8 | npm package `bootstrap` (runtime dependency) | `cd frontend && npm install bootstrap@<version>` |
| vue-good-table-next | 0.2.2 | npm package (runtime dependency) | `cd frontend && npm install vue-good-table-next@<version>` |
| @kyvg/vue3-notification | 3.4.2 | npm package (runtime dependency) | `cd frontend && npm install @kyvg/vue3-notification@<version>` |
| normalize.css | 8.0.1 | npm package (runtime dependency) | `cd frontend && npm install normalize.css@<version>` |
| Build toolchain (webpack 5.111.1, babel, loaders) | see `frontend/package.json` | npm devDependencies, not shipped in the image | `cd frontend && npm update` (or Dependabot) |
| npm packages at build time | 470 in `package-lock.json` (62 production, 408 dev) | `npm ci` in the build stage | `cd frontend && npm update`, commit `package-lock.json` |

## Image `openvpn` (`Dockerfile.openvpn`)

The VPN server (`openvpn`), PKI tooling, the firewall and the fail2ban ban engine. The final stage is `alpine:${ALPINE_VERSION}` with the build argument default `3.24`.

### Distro and system packages

| Component | Version | Where it comes from | How to bump |
|---|---|---|---|
| Alpine Linux | 3.24.4 | Base image `alpine:${ALPINE_VERSION}`, `ARG ALPINE_VERSION=3.24` in `Dockerfile.openvpn` | Rebuild with `--pull` for patch releases. Change the `ARG` default for a new Alpine branch (or pass `--build-arg ALPINE_VERSION=...`). Dependabot cannot see this tag (it sits behind an `ARG`). |
| musl libc | 1.2.6 (apk `musl-1.2.6-r3`) | apk, part of the Alpine base | Follows the base image. |
| busybox | 1.37.0 (apk `busybox-1.37.0-r31`) | apk, part of the Alpine base | Follows the base image. |
| OpenVPN | 2.7.7 (apk `openvpn-2.7.7-r0`) | apk `openvpn` (explicit). This is the running VPN server. | Rebuild with `--pull`. The version is whatever the Alpine branch carries. |
| OpenSSL | 3.5.9 (apk `openssl`, `libssl3`, `libcrypto3`, all `3.5.9-r1`) | apk `openssl` (dependency of `openvpn`, `easy-rsa`, `python3`) | Rebuild with `--pull`. A fix that exists only in a newer Alpine branch needs the `ARG ALPINE_VERSION` bump. |
| fail2ban | 1.1.0 (apk `fail2ban-1.1.0-r3`) | apk `fail2ban` (explicit) | Rebuild with `--pull`. |
| Python | 3.14.10 (apk `python3-3.14.10-r1`) | apk, dependency of `fail2ban` (not named in the Dockerfile) | Rebuild with `--pull`. |
| iptables | 1.8.13, nf_tables backend (apk `iptables-1.8.13-r0`) | apk `iptables` (explicit; also provides `ip6tables`) | Rebuild with `--pull`. |
| iptables-legacy | 1.8.13 (apk `iptables-legacy-1.8.13-r0`) | apk `iptables-legacy` (explicit) | Rebuild with `--pull`. |
| easy-rsa | 3.2.5 (apk `easy-rsa-3.2.5-r0`) | apk `easy-rsa` (explicit). Symlinked to `/usr/local/bin/easyrsa`. | Rebuild with `--pull`. |
| sqlite | 3.53.4 (apk `sqlite-3.53.4-r0`, `sqlite-libs-3.53.4-r0`) | apk `sqlite` (explicit) | Rebuild with `--pull`. |
| bash | 5.3.9 (apk `bash-5.3.9-r1`) | apk `bash` (explicit) | Rebuild with `--pull`. |
| openvpn-user | v1.0.9, upstream commit `5eefd1b` | The same vendored source as in the `ovpn-admin` image (`third_party/openvpn-user/`), built by the stage `openvpn-user-builder` of `Dockerfile.openvpn` with the same stage text (same flags, same gcc or zig selection). Go 1.26.11, `golang.org/x/crypto` v0.59.0, `go-sqlite3` v1.14.53. | See the `ovpn-admin` table. |
| apk packages, total | 59 | `apk info` in the final image | n/a |

## Known findings at measurement time

Trivy 0.70.0 (`--severity CRITICAL,HIGH --ignore-unfixed=false`) on both rebuilt `linux/amd64` images: **0 findings in the Alpine packages, 0 in `/app/ovpn-admin` and 0 in `usr/local/bin/openvpn-user`** (gate run exit code 0 for both images). Before openvpn-user was built from source, the prebuilt v1.0.9 release binary (Go 1.19.3, `golang.org/x/crypto v0.2.0`) carried 129 findings in each image (4 CRITICAL, 54 HIGH, 66 MEDIUM, 4 LOW, 1 UNKNOWN); the 58 CRITICAL and HIGH ones failed the `scan` job on master, tags and the weekly run. With all severities, the only finding of the v0.1.9 images was one MEDIUM, CVE-2026-4738 in the Alpine package `zlib` 1.3.2-r1 (fixed in 1.4-r0), because `apk add` does not upgrade a package the base image already carries. Both Dockerfiles now run `apk upgrade zlib` after the `apk add` (only that package changes: the package count stays 40 and 59, `zlib` becomes 1.4-r0), and Trivy reports 0 findings of any severity in both rebuilt `linux/amd64` images. `govulncheck ./...` (v1.10.0) reports no vulnerabilities in this repository, and none in the vendored module `third_party/openvpn-user` (source mode and on the built binary). `npm audit --omit=dev --audit-level=high` reported 0 at the v0.1.8 measurement; the frontend is unchanged.

## How to refresh this file

Run from the repository root. Needs Docker; nothing is pushed.

```bash
# 1. Build both images for amd64 (local only)
docker build --platform linux/amd64 -f Dockerfile.ovpn-admin -t ovpn-admin:scan .
docker build --platform linux/amd64 -f Dockerfile.openvpn    -t openvpn:scan .

# 2. Distro and tool versions, and the full apk list (40 and 59 packages)
for img in ovpn-admin openvpn; do
  echo "== $img"
  docker run --rm --entrypoint sh "$img:scan" -c '
    cat /etc/alpine-release; openvpn --version | head -1; openssl version; sqlite3 --version
    bash --version | head -1; busybox | head -1; apk info | wc -l
    apk info -v | sort'
done
docker run --rm --entrypoint sh openvpn:scan -c \
  'python3 --version; fail2ban-client --version | head -1; iptables --version; iptables-legacy --version'

# 3. Go modules of the Go binaries (ovpn-admin and the openvpn-user built from third_party/openvpn-user)
mkdir -p /tmp/bins
c=$(docker create ovpn-admin:scan)
docker cp "$c:/app/ovpn-admin" /tmp/bins/ovpn-admin
docker cp "$c:/usr/local/bin/openvpn-user" /tmp/bins/openvpn-user
docker rm "$c"
docker run --rm -v /tmp/bins:/bins:ro golang:1.26-alpine sh -c \
  'go version -m /bins/ovpn-admin; go version -m /bins/openvpn-user'

# 4. Frontend versions and package count from the lockfile (what npm ci installs)
cd frontend
for p in vue axios bootstrap vue-good-table-next @kyvg/vue3-notification normalize.css; do
  node -p "'$p ' + require('./package-lock.json').packages['node_modules/$p'].version"
done
node -p "'packages: ' + (Object.keys(require('./package-lock.json').packages).length - 1)"
cd ..

# 5. Vulnerabilities and SBOMs, same tools and flags as CI
for img in ovpn-admin openvpn; do
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.70.0 \
    image --severity CRITICAL,HIGH --ignore-unfixed=false "$img:scan"
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock anchore/syft:latest \
    "docker:$img:scan" -o spdx-json > "sbom-$img.spdx.json"
done
docker run --rm -v "$PWD:/src:ro" -w /src golang:1.26-alpine sh -c \
  'go install golang.org/x/vuln/cmd/govulncheck@v1.10.0 && /go/bin/govulncheck ./...'
(cd frontend && npm audit --omit=dev --audit-level=high)
```

Then update the tables above, the "measured on" line and the "Known findings" section.
