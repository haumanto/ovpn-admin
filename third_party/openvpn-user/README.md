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

The Go source (`openvpn-user.go`, `src/*.go`) is **unmodified, except for one local patch** (next section). The other change against upstream is the dependency versions in `go.mod` and `go.sum`, because upstream pins versions from 2022 with known vulnerabilities:

| Module | Upstream v1.0.9 | Here |
|---|---|---|
| `github.com/mattn/go-sqlite3` | v1.14.16 | v1.14.53 |
| `golang.org/x/crypto` | v0.2.0 | v0.59.0 |
| `go` directive | 1.14 | 1.26.0 (required by `golang.org/x/crypto` v0.59.0) |
| `github.com/dgryski/dgoogauth`, `gopkg.in/alecthomas/kingpin.v2` | unchanged | unchanged |

`go.mod` and `go.sum` were produced with `go get github.com/mattn/go-sqlite3@<version> golang.org/x/crypto@<version> && go mod tidy`. The `go.mod` file keeps the upstream module path `github.com/pashcovich/openvpn-user`, which the source imports (`github.com/pashcovich/openvpn-user/src`).

## Local patch (carry it forward)

There are **four local modifications to the upstream Go source**: a 72-byte password guard and bcrypt cost 12 instead of `bcrypt.MinCost` (both in `src/commands.go`, the second one is described after the table), the re-hash at login, and its spool (described after the second). Upstream base: commit `5eefd1b4d304810718246d352912c0667232fbb3` (tag `v1.0.9`). Every other `.go` file and `LICENSE` is byte-identical to that commit.

| | |
|---|---|
| File | `src/commands.go` only (the 72-byte guard added `+12` lines and removed nothing; the cost change adds `+5` lines and changes the two `GenerateFromPassword` calls) |
| Change | New `var errPasswordTooLong`, and `if len(password) > 72 { return "", errPasswordTooLong }` at the top of `CreateUser` and `ChangeUserPassword`. Both sites carry the marker `LOCAL PATCH (ovpn-admin)`; `grep -rn "LOCAL PATCH" src/` finds all of them. |
| Why | bcrypt hashes at most 72 bytes. `golang.org/x/crypto/bcrypt` returns `ErrPasswordTooLong` for a longer password, and upstream drops that error (`hash, _ := bcrypt.GenerateFromPassword(...)`), so a direct `openvpn-user create --password=<73+ bytes>` reported "User created" with an empty hash stored, and `change-password` reported "Password changed" and replaced the existing hash with NULL (measured on the unpatched binary, exit code 0 both times). Now the command exits 1 with `openvpn-user: error: password is longer than 72 bytes (bcrypt limit)` and writes nothing. |
| Behaviour for 72 bytes or less | Unchanged. |
| Also enforced by | `ovpn-admin` itself (HTTP 400 for a password under 12 characters or over 72 bytes, `password_test.go`; the minimum of 12 characters lives in ovpn-admin only, the `openvpn-user` command line itself enforces the 72-byte maximum and no minimum); the patch closes the direct command line path. |

**Second modification: bcrypt cost 12.** Upstream hashes every password with `bcrypt.MinCost` (cost 4, a few milliseconds per guess, which makes a copied `users.db` cheap to brute force). `CreateUser` and `ChangeUserPassword` now use the constant `bcryptCost = 12` (about 250 ms per hash; each login check costs the same). A bcrypt hash carries its own cost, so existing cost-4 hashes keep verifying and stay valid until that user's password is changed; nothing is rehashed or reset. The marker `LOCAL PATCH (ovpn-admin), second modification` sits at the constant. Check after an import: create a user against a throwaway database and read the hash, it must start with `$2a$12$`.

**Third modification: re-hash at login** (`rehashAfterLogin` in `src/commands.go`). After a successful bcrypt comparison `AuthUser` reads the cost of the stored hash. Below cost 12 it makes a cost 12 hash of the password just verified and stores it with `UPDATE users SET password = <new> WHERE username = ? AND CAST(password AS TEXT) = <old hash>`, so a password changed in the meantime is never overwritten. After a stored re-hash it prints `openvpn-user: rehash cost <old> -> 12` on stderr. The password is never printed.

**Fourth modification: the re-hash spool** (`src/rehash_spool.go`, the `rehash-apply` command in `openvpn-user.go`, the `SpoolDir` field in `src/models.go`, marker `LOCAL PATCH (ovpn-admin), fourth modification`). The login hook runs as `nobody` and `users.db` belongs to root, so the update of the third modification fails with `attempt to write a readonly database`. When it fails, the new hash goes to a spool file instead: `<db.path>.rehash/<sha256 of the user name>.json` holds the user name, the old hash, the new hash and the time (never the password), written to a temporary name and renamed. A second login of the same user finds the entry and writes nothing. The directory is created by the panel (mode 0700, owned by the hook user), not by this tool. If it cannot be written, the login still succeeds and one warning per process is printed. The command `openvpn-user rehash-apply --db.path=<db>` (run as root by the panel at start and every few seconds while the spool is not empty) stores each entry with the same `WHERE CAST(password AS TEXT) = <old hash>` guard and deletes it; an entry whose row no longer matches is dropped. It refuses any entry that is not a regular file (no symlink), is larger than 4 KiB, does not carry bcrypt hashes of the right shape (old below cost 12, new exactly 12), or whose file name does not belong to the user name. It prints `openvpn-user: rehash applied user="<name>" cost <old> -> 12` or `rehash dropped user="<name>": <reason>`, never a hash. Tests: `src/rehash_spool_test.go` (cgo: gcc and musl-dev in `golang:1.26-alpine`). After an upstream import re-apply both modifications; `grep -rn "LOCAL PATCH" src/ openvpn-user.go` must also find the markers of the third and fourth.

If upstream fixes this itself, drop the patch. Until then, **a new upstream import must re-apply it**: after step 2 of "How to update", check that `grep -rn "LOCAL PATCH" src/` still finds the four markers (the comment above the guard, the comment at `bcryptCost`, and the two guards), and run the guard check (73 bytes must exit non-zero and leave `users.db` unchanged, 72 bytes must succeed) and the cost check above. To list the whole difference against upstream, diff this directory against a fresh clone of the base commit: expected are `src/commands.go` (the patch), `go.mod`, `go.sum`, and this README; the upstream files that are not vendored (scripts, Dockerfile, CI) do not exist here.

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
2. Replace `openvpn-user.go`, `src/` and `LICENSE` with the upstream files, then re-apply the "Local patch" above (the replacement removes it). Keep (and re-bump) our `go.mod` and `go.sum`.
3. Update the version and commit id in this file and in COMPONENTS.md.
4. Re-run the checks above. Review the diff to upstream; the only local code change is the "Local patch" above, do not carry any other silently.
