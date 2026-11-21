# ovpn-admin v0.1.9 release notes

**Status: candidate, not published.** No tag, GitHub release, image, binary or chart release exists for v0.1.9. Approval for publishing is still needed.

- Code candidate: branch `v0.1.9`, SHA `d9c3fce75546cb0ff3fd6e52b5f6d792d46aa2bf` (`fix(password): reject passwords over 72 bytes`). It sits on `29a35ae` (`docs: mark v0.1.8 published`) through four commits: `f0c8f2f` (vendored openvpn-user), `1b5acb5` (bounded build retry and zig cross-compile), `911ff94` (version bump to 0.1.9), `d9c3fce` (72-byte password limit).
- QA: `qa-v019/REPORT.md` (candidate `911ff94`, verdict DO NOT SHIP: finding F1, passwords over 72 bytes silently dropped). `qa-v019/DELTA-REPORT.md` (candidate `d9c3fce`, verdict SHIP: F1 closed). The DELTA report covers the code in this release. The full report covers the CVE and parity tables, measured on `911ff94`.

Source tags below: `[QA]` = `qa-v019/REPORT.md`, `[QA-D]` = `qa-v019/DELTA-REPORT.md`, `[P19]` = `v019/p19-vendor.txt` (developer evidence).

## Why the prebuilt binary was replaced

- Both images shipped a prebuilt `openvpn-user` v1.0.9 release binary, pinned by SHA-256 in the Dockerfiles. That binary was built with Go 1.19.3 and `golang.org/x/crypto` v0.2.0. `[QA]`
- Trivy 0.70.0 (vulnerability DB of 2026-11-21) found 58 HIGH or CRITICAL findings in it: 4 CRITICAL and 54 HIGH. 45 come from the Go standard library v1.19.3 and 13 from `golang.org/x/crypto` v0.2.0. `[QA]`
- Those findings failed the Trivy jobs on master, on tags and in the weekly run in v0.1.8 (see [RELEASE-v0.1.8.md](RELEASE-v0.1.8.md#known-limitations)).
- Upstream is dormant. The newest upstream tag is v1.0.9 (commit `5eefd1b`, dated 2022-12-02). No upstream commit exists after it on the default branch, as checked on 2026-11-21. No upstream fix could be taken. `[P19]` `[QA]`

## What changed

- **Vendored source.** `third_party/openvpn-user/` holds the upstream v1.0.9 source at commit `5eefd1b4d304810718246d352912c0667232fbb3`, under Apache-2.0. The five `.go` files and `LICENSE` are byte-identical to upstream (SHA-256 compared). `[P19]`
- **Module versions.** Only `go.mod` and `go.sum` changed: `github.com/mattn/go-sqlite3` v1.14.16 to v1.14.53, `golang.org/x/crypto` v0.2.0 to v0.59.0, and the `go` directive 1.14 to 1.26.0. `[P19]`
- **Build.** Both `Dockerfile.ovpn-admin` and `Dockerfile.openvpn` build the binary in a stage `openvpn-user-builder` with `golang:1.26-alpine` (Go 1.26.11). It is a static binary built on the build host. A native `gcc` build is tried up to 3 times. If the target architecture differs from the host, `zig cc` cross-compiles instead. Nothing is downloaded as a binary any more. `[P19]` `[QA]`
- **Password limit (one behaviour change).** Passwords over 72 bytes are now refused with the message `Password too long, the hash accepts at most 72 bytes`. The check is in `validatePassword` in `main.go`. It applies to create, change-password and rotate in ovpn-admin. Nothing is written when a password is refused, and the old password keeps working. Exactly 72 bytes is accepted. The limit counts bytes, so a non-ASCII character takes 2 to 4 bytes. The 6-character minimum is unchanged. The UI hint now says "72 bytes maximum". `[QA-D]`
- **Behaviour is not identical.** The new `x/crypto` and Go toolchain changed how long passwords are handled. See [Behaviour parity](#behaviour-parity). This release does not claim identical behaviour.

## Measured CVE counts

Trivy 0.70.0, all severities, DB of 2026-11-21. Before = published v0.1.8 images (`linux/amd64`). After = images built from the candidate with `--no-cache` (`linux/amd64`, and `linux/arm64` where marked). `[QA]`

| Image | Target | Before (v0.1.8, amd64) | After (v0.1.9, amd64) | After (v0.1.9, arm64) |
|---|---|---|---|---|
| ovpn-admin | `usr/local/bin/openvpn-user` | 4 CRITICAL, 54 HIGH, 66 MEDIUM, 4 LOW, 1 UNKNOWN | 0 | 0 |
| ovpn-admin | whole image | 130 (4 CRITICAL, 54 HIGH, 67 MEDIUM, 4 LOW, 1 UNKNOWN) | 1 (1 MEDIUM) | 1 (1 MEDIUM) |
| openvpn | `usr/local/bin/openvpn-user` | 4 CRITICAL, 54 HIGH, 66 MEDIUM, 4 LOW, 1 UNKNOWN | 0 | 0 |
| openvpn | whole image | 145 (4 CRITICAL, 54 HIGH, 82 MEDIUM, 4 LOW, 1 UNKNOWN) | 1 (1 MEDIUM) | 1 (1 MEDIUM) |

- HIGH and CRITICAL in `openvpn-user`: 58 before, 0 after, in both images.
- The one left in each image is MEDIUM CVE-2026-4738 in the Alpine package `zlib` 1.3.2-r1 (fixed in 1.4-r0). It was there before too. It is not in `openvpn-user`.
- The `openvpn` image had 16 MEDIUM Alpine findings before and 1 after. That drop comes from a rebuild with newer `openssl`, `libssl3` and `libcrypto3` packages, not from this change.
- The "after" counts were measured on the `911ff94` build. The fix in `d9c3fce` changes only ovpn-admin Go code and two frontend files. `openvpn-user` and the Dockerfiles did not change, but no Trivy rescan was run at `d9c3fce`. `[QA-D]`
- `govulncheck` on the vendored module reports no vulnerabilities. `[QA]` `[P19]`

## Behaviour parity

Method: the same command line was run with the v0.1.8 binary and the v0.1.9 binary, each on a fresh database, and stdout, stderr, exit code and database content were compared. `[QA]`

- Subcommands covered: `db-init`, `db-migrate`, `create`, `list`, `list --all`, `check`, `auth`, `revoke`, `restore`, `delete`, `delete --force`, `change-password`, `update-secret`, `get-secret`, `register-app`, `check-app`, `reset-app`, and `--help`, no arguments, unknown command and missing flags.
- Result on amd64, 120 steps in three phases:

| Phase | Steps | Same | Different |
|---|---|---|---|
| main (lifecycle) | 80 | 69 | 11 |
| totp (fixed secret and time) | 26 | 25 | 1 |
| cross (old binary on new database, and the reverse) | 14 | 10 | 4 |
| **Total** | **120** | **104** | **16** |

- The 16 differences fall in two classes:
  - **Class A, 3 steps (main 006, 010, 080):** `list` on a database that was never initialised. Both binaries exit with code 2 and print the same stdout. Only the Go panic trace text differs. Acceptable.
  - **Class B, 13 steps:** a password longer than 72 bytes. In v0.1.8 it was accepted and only its first 72 bytes were used. In the unfixed `911ff94` build the write reported success and stored an empty or NULL hash. In `d9c3fce` ovpn-admin refuses it with an error. This is the intended change.
- The same parity run on the arm64 binary under emulation: 80 of 80 main steps gave the same verdicts, and stdout and exit codes matched amd64 in 80 of 80 steps. This was emulated, not run on arm64 hardware. `[QA]`
- Earlier developer check `[P19]`: 107 cases, exit codes and stdout equal in 107 of 107. The one stderr difference is the same class A panic trace. That check had no password over 72 bytes.
- Real client, `d9c3fce`: an OpenVPN 2.7.7 client with a 40-byte password connected and passed traffic. A wrong 40-byte password gave `AUTH_FAILED`. `[QA-D]`

**Direct `openvpn-user` calls are not guarded.** The 72-byte check is in ovpn-admin. The vendored Go source is unchanged, so a direct call such as `openvpn-user create` or `openvpn-user change-password` with more than 72 bytes still reports success and stores no usable hash. This was measured on `911ff94`, which has the same vendored source as `d9c3fce`. Scripts that call `openvpn-user` directly must keep passwords to 72 bytes.

**TOTP.** 25 of 26 TOTP steps match. The one difference is the 72-byte class (totp 018). TOTP codes were checked against an independent RFC 6238 script at one fixed secret and time. Secrets made by `update-secret` are random, so only their format was compared. `[QA]`

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v018--v019).

- **Rebuild both images.** Unlike v0.1.8, the `openvpn` image changed in this release because it now carries the new `openvpn-user` binary. Rebuild `ovpn-admin` and `openvpn`.
- **No data migration.** This release adds no migration and no schema change. A v0.1.9 binary and a v0.1.8 binary read each other's `users.db` without error. `[QA]` The start-up steps `db-init` and `db-migrate` still run as before, so `users.db` is not byte-for-byte untouched. Back it up before you upgrade.
- **Existing passwords.** Users whose password was set under v0.1.8 keep working after the upgrade. Login still reads only the first 72 bytes, as in v0.1.8. `[QA-D]`
- **New long passwords are refused.** Any password over 72 bytes is refused with a clear message on create, change-password and rotate in ovpn-admin. Tell admins the limit is 72 bytes.
- **Image size.** The `openvpn-user` binary grew: amd64 from 5,926,752 to 6,451,696 bytes (+524,944), arm64 from 5,410,208 to 6,238,776 bytes (+828,568). `[P19]` `[QA]` The root filesystem grew by about 0.5 MB in each image: `ovpn-admin` +516 kB, `openvpn` +520 kB. These numbers come from the `911ff94` build. Compressed image sizes are not comparable with the published images, because the local build has a different layer layout.
- **Helm.** Only the chart version fields change (`charts/openvpn-admin/Chart.yaml`). No chart template changed. The chart was not deployed in QA.

## Known limitations

- **Rotate is broken for valid passwords (not new in v0.1.9).** A rotate with a valid 40-byte password returns HTTP 400 `Failed to issue certificate`. The admin log shows easy-rsa `Request file already exists. Aborting build`. It fails the same way on v0.1.8, on `911ff94` and on `d9c3fce`. After a failed rotate of an Active user, the certificate is revoked and the password row is deleted, so that user cannot connect and shows as Revoked. Until this is fixed, do not rotate an Active user. Not fixed in this release. `[QA]` `[QA-D]`
- **Refusal status codes.** The 72-byte refusal returns HTTP 422 on create, 500 on change-password and 400 on rotate. The 500 on change-password is an input error reported as a server error. These are the codes v0.1.8 uses for a too-short password. They were not changed in this release. `[QA-D]`
- **The 72-byte limit is not in `openvpn-user`.** See [Behaviour parity](#behaviour-parity). A direct call to the CLI is still unguarded.
- **Upstream is dormant.** No upstream release or commit exists after `5eefd1b` (2022-12-02). The vendored copy is ours to maintain: security fixes come from us, not upstream. `[P19]`
- **Updating the vendored source.** See [third_party/openvpn-user/README.md](third_party/openvpn-user/README.md). For a dependency bump: `cd third_party/openvpn-user && go get <module>@<version> && go mod tidy && go vet ./...`, then run `govulncheck ./...`, rebuild both images and update [COMPONENTS.md](COMPONENTS.md). For a new upstream release: replace `openvpn-user.go`, `src/` and `LICENSE` from the upstream tag, keep our `go.mod` and `go.sum`, update the version and commit in the README and COMPONENTS.md, and re-run the checks. Do not carry local code changes into the vendored `.go` files.
- **Measurement scope.** QA's delta re-run was amd64 only. arm64 was tested only on the `911ff94` build, under qemu, not on arm64 hardware. The browser UI was not driven. Only the served strings were checked. The `kubernetes.secrets` storage backend and the Helm chart were not run. No Trivy rescan was run at `d9c3fce`. `[QA-D]`
- **Live stack.** The head live stack ran once, on `911ff94`. The delta run repeated only the parent and v0.1.8 controls. `[QA-D]`
- **Remaining MEDIUM.** CVE-2026-4738 in Alpine `zlib` is still open in both images, at MEDIUM. It is below the Trivy gate.
