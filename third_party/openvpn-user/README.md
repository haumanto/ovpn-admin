# openvpn-user (vendored)

Command line tool that keeps the password database (`users.db`, SQLite) of the OpenVPN password authentication. `ovpn-admin` runs it for user create, delete, revoke, restore and change-password, and `setup/auth.sh` and `setup/configure.sh` of the `openvpn` image run it for `auth`, `db-init` and `db-migrate`.

| | |
|---|---|
| Upstream | https://github.com/pashcovich/openvpn-user |
| Version | v1.0.9 (the `version` constant in `openvpn-user.go`) |
| Commit | `5eefd1b4d304810718246d352912c0667232fbb3` (`5eefd1b`, tag `v1.0.9`) |
| License | Apache-2.0, see [LICENSE](LICENSE) (unchanged copy of the upstream file) |

## What is vendored and what is changed

Vendored: `openvpn-user.go`, `src/`, `go.mod`, `go.sum`, `LICENSE`. Everything else of the upstream repository (scripts, upstream Dockerfile, CI workflows, README) is not needed to build and is not copied.

The Go source (`openvpn-user.go`, `src/*.go`) is **unmodified**. The only change against upstream is the dependency versions in `go.mod` and `go.sum`, because upstream pins versions from 2022 with known vulnerabilities:

| Module | Upstream v1.0.9 | Here |
|---|---|---|
| `github.com/mattn/go-sqlite3` | v1.14.16 | v1.14.53 |
| `golang.org/x/crypto` | v0.2.0 | v0.59.0 |
| `go` directive | 1.14 | 1.26.0 (required by `golang.org/x/crypto` v0.59.0) |
| `github.com/dgryski/dgoogauth`, `gopkg.in/alecthomas/kingpin.v2` | unchanged | unchanged |

`go.mod` and `go.sum` were produced with `go get github.com/mattn/go-sqlite3@<version> golang.org/x/crypto@<version> && go mod tidy`. The `go.mod` file keeps the upstream module path `github.com/pashcovich/openvpn-user`, which the source imports (`github.com/pashcovich/openvpn-user/src`).

## How it is built

`Dockerfile.ovpn-admin` and `Dockerfile.openvpn` have a stage `openvpn-user-builder` (`FROM --platform=$BUILDPLATFORM golang:1.26-alpine`, plus `gcc musl-dev`; CGO is required by `go-sqlite3`) that runs, in this directory:

```sh
CGO_ENABLED=1 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags "-linkmode external -extldflags -static -s -w" -o /out/openvpn-user .
```

The stage runs on the build host, never under emulation. Which C compiler it uses depends on the target:

- Target architecture equals build architecture (for example amd64 on amd64, or a native arm64 builder): native `gcc`. The build is retried up to 3 times (5 s apart, every attempt is logged). If all 3 fail, the stage falls back to the zig path.
- Target differs from the build architecture (for example `linux/arm64` on an amd64 host): `CC="zig cc -target aarch64-linux-musl"` (zig from the Alpine package `zig`, installed only on this path; `x86_64-linux-musl` for amd64 targets). Reason: `gcc` segfaults intermittently when run under qemu, which broke multi-arch builds on amd64 runners. Only the C toolchain changes; the Go source and the module versions stay the same. The zig path adds `-s` to the external linker flags (zig's linker does not strip on its own: without it the arm64 binary is 14 MB instead of 6 MB) and `CGO_CFLAGS='-O2 -fno-sanitize=undefined'` (zig cc turns on UBSan traps by default, gcc does not).

The final stages copy `/out/openvpn-user` to `/usr/local/bin/openvpn-user`. The result is a static binary for the target platform. Nothing is downloaded as a prebuilt binary.

The module `third_party/openvpn-user` is a separate Go module. It is not part of the module in the repository root, so `go build ./...`, `go test ./...` and `govulncheck ./...` in the root do not touch it. [Dependabot](../../.github/dependabot.yml) tracks it with its own `gomod` entry.

## How to update

Dependency bump (the usual case):

```sh
cd third_party/openvpn-user
go get golang.org/x/crypto@<version> github.com/mattn/go-sqlite3@<version>
go mod tidy
go vet ./...
```

Then run the old-versus-new command comparison and `govulncheck ./...` as in the P19 evidence, rebuild both images, and update the row in [COMPONENTS.md](../../COMPONENTS.md). Dependabot pull requests need the same checks.

New upstream release (none exists after v1.0.9 at the time of writing):

1. Check out the upstream tag, note the full commit id.
2. Replace `openvpn-user.go`, `src/` and `LICENSE` with the upstream files. Keep (and re-bump) our `go.mod` and `go.sum`.
3. Update the version and commit id in this file and in COMPONENTS.md.
4. Re-run the checks above. Review the diff to upstream; do not carry local code changes silently.
