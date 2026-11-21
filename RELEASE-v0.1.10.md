# ovpn-admin v0.1.10 release notes

**Status: candidate, not published.** No tag, GitHub release, image, binary or chart release exists for v0.1.10. Approval for publishing is still needed.

- Code candidate: branch `v0.1.10`, SHA `3a475b27a998b991c732d01088e31636505d5116` (`fix(change-password): a user that does not exist is HTTP 400, not 500`). It sits on `700cdedc8d87e5eb433233c39612ecdac1e4b070` (`chore(release): bump to v0.1.10`) and the commits `e932150` (zlib and 72-byte guard) and `5991c39` (rotate fix), all after the v0.1.9 release notes commit `7bd918f`.
- QA: `qa-v0110/REPORT.md` (candidate `700cded`, verdict DO NOT SHIP: finding F1, change-password with an unknown user name answered HTTP 500). `qa-v0110/DELTA-REPORT.md` (candidate `3a475b2`, verdict SHIP: F1 closed, 242 assertions PASS, 0 FAIL). The delta covers the code in this release. The full report covers the rest.

Source tags below: `[QA]` = `qa-v0110/REPORT.md`, `[QA-D]` = `qa-v0110/DELTA-REPORT.md`, `[B]` = builder evidence in `v0110/work/` (`f-images.txt`, `f-rotate.txt`).

## Rotate is fixed

### What was broken (v0.1.9 and earlier)

- A rotate with a valid password could fail. Easy-rsa stopped with `Request file already exists`, and the API answered HTTP 400 `Failed to issue certificate`. `RELEASE-v0.1.9.md`
- The failed rotate had already revoked the certificate and deleted the password row. The user was left Revoked and could not connect. `RELEASE-v0.1.9.md` `5991c39` commit message.
- Rotating an expired user also failed, because its files were still in `issued/`, `private/` and `reqs/`. `5991c39` commit message.

### What a user can expect now

- Rotate works for an **active**, **revoked** or **expired** user. The API answers HTTP 200 with `{"msg":"User <name> successfully rotated"}`. `[QA]` check 2 and 4.
- After a successful rotate:
  - The old certificate is revoked. Its serial stays in the CRL.
  - There is exactly one valid entry for the user, with a new serial.
  - The account is Active.
  - The new password works. The old password is rejected.
  - A real client with the new configuration and new password connects and passes traffic. `[QA]` check 2 and 4.
- Rotating twice in a row works. Each rotate gives a new serial. `[QA]` check 3.

### Already revoked and expired certificates

| Starting state | Rotate | Result |
|---|---|---|
| Active | HTTP 200 | Old serial revoked, new valid certificate, Active. |
| Revoked through the API | HTTP 200 | Old serial stays revoked. One new valid certificate, Active. The password is replaced. |
| Expired (really expired certificate, index flag `V`) | HTTP 200 | Old serial revoked, new valid certificate, Active. |
| Expired (really expired certificate, index flag `E`) | HTTP 200 | Same as above. |

- Old configuration files stay refused after a rotate. Tested for a revoked user and an expired user. `[QA]` check 4.
- Rotate on a revoked or expired user is not refused. It issues a new certificate and makes the account Active again.

### What happens on failure (no half-rotated users)

- A rotate is all or nothing on the filesystem backend. If a step fails, the old certificate, index entry, files, CRL and password come back.
- Tested with two forced failures (immutable files, so easy-rsa fails at the sign step, and at the archive step):
  - The API answers HTTP 400 `Failed to rotate user "<name>", the certificate and the password are as before`.
  - `index.txt` and `users.db` are byte-identical before and after.
  - The old certificate still verifies against the CA and CRL.
  - The old password still works.
  - A new real client with the old configuration connects.
  - A client that was connected before the attempt was disconnected during it and reconnected by itself with its old certificate and password (one case, 3 of 3 pings). `[QA]` check 5.
- If the rollback itself fails, the API answers `... the previous state could not be restored completely, check the admin log`. **Not tested.** `[QA]` did not force this case.
- A failed rotate answers HTTP 400 even when the failure is on the server. This is known and not changed (see Known limitations).

## Error codes: bad input answers 400

- Create, change-password and rotate now answer HTTP 400 for bad input. Before, some refusals answered 422 (create) or 500 (change-password). Rotate already answered 400 for the 72-byte case. `[QA-D]` `5991c39` commit message.
- Checked on `3a475b2`, 12 refusal cells: a 5-byte password, a 73-byte password, and an invalid user name (`bad name!`, `a/b`) on each of the three endpoints. All 12 answer 400. A valid request answers 200. `[QA-D]` check 2.
- Change-password with an unknown user name answers 400 `User "<name>" not found`. Before this release it answered 500. Nothing is created or changed by a refused request. `[QA-D]` check 1 (20 refused requests in total, all 400).
- The message text did not change. Only the status code changed.
- Exception: creating a user whose name was deleted earlier answers 422. This is a pre-existing problem and is not part of this release (see Known limitations).

## zlib upgraded (CVE-2026-4738)

- Both images now ship `zlib-1.4-r0`. Before, they shipped `zlib-1.3.2-r1`. Both Dockerfiles run `apk upgrade zlib` after `apk add`, because `apk add` does not upgrade a package that the base image already has. The package count stays at 40 (`ovpn-admin`) and 59 (`openvpn`). `[B]` `e932150` commit message.
- Trivy 0.70.0, all severities, `--ignore-unfixed=false`:

| Image | Before (unmodified `5991c39`, built locally) | After (`700cded`, rebuilt) |
|---|---|---|
| `ovpn-admin`, whole image | 1 (MEDIUM, CVE-2026-4738, zlib) | 0 |
| `openvpn`, whole image | 1 (MEDIUM, CVE-2026-4738, zlib) | 0 |

- "Before" images were built locally from `5991c39`. The published v0.1.9 images were not scanned. `[B]` The published v0.1.9 tags could not be saved locally (incomplete multi-arch index), so they were not used.
- "After" counts were measured on the `700cded` images. The delta changed only `main.go` and a test, so the Alpine layers are the same. Trivy was not re-run on `3a475b2`. `[QA]` check 7, `[QA-D]`.

## 72-byte password limit now enforced in the tool

- ovpn-admin already refused passwords over 72 bytes in v0.1.9. From this release the `openvpn-user` tool refuses them too. Before, a direct `openvpn-user create` or `change-password` with 73 bytes exited 0 and stored an empty or NULL hash. `[B]` section 4.
- Now `openvpn-user create` and `change-password` with 73 bytes exit 1, print `openvpn-user: error: password is longer than 72 bytes (bcrypt limit)`, and write nothing. 72 bytes works. 74 bytes as 37 two-byte characters is refused. `[QA]` check 8 (both images, 18 of 18 assertions each).
- **Local patch.** `third_party/openvpn-user/src/commands.go` gets 12 added lines and nothing removed, with the marker `LOCAL PATCH (ovpn-admin)`. It is the only change to the upstream Go source (upstream v1.0.9, commit `5eefd1b`). Details: [third_party/openvpn-user/README.md](third_party/openvpn-user/README.md). `[QA]` check 9.

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v019--v0110).

- **Rebuild both images.** `ovpn-admin` changed (zlib and Go code) and `openvpn` changed (zlib and the `openvpn-user` binary).
- **No data migration.** The diff adds no schema change and no migration. `users.db` keeps its schema. The start-up steps `db-init` and `db-migrate` run as before.
- **Nothing to configure.** The diff adds no flag and no environment variable.
- **Existing users keep their passwords and certificates.** Nothing needs to be re-issued.
- **Chart.** Only the version fields of `charts/openvpn-admin/Chart.yaml` change. No chart template changed.
- **Back up before you upgrade**, as for every release.

## Known limitations

Open items, in the order a user is most likely to hit them:

- **Kubernetes backend is not verified for rotate.** `storage.backend=kubernetes.secrets` was not run. Read from the code (`main.go` 1381 to 1387): the certificate step error is logged and the rotate continues, so a rotate on this backend may answer success after revoking the old certificate, without a new one. The rollback covers the filesystem backend only. Do not rely on rotate with this backend until it is tested.
- **A failed rotate answers HTTP 400**, although the failure is on the server (`[QA]` N1). A 5xx would be more correct. Not changed.
- **Sessions can stay connected briefly after a rotate.** The panel cuts a session only if it knows the session. The panel reads the client list every 28 s. A session that started less than about 28 s before the rotate was not cut and stayed connected until another connection of the same user displaced it (14 s later in one run). A revoked certificate cannot reconnect. The same applies to Revoke (`[QA]` N2). Not changed.
- **Create of a deleted user's name answers 422** (pre-existing, also v0.1.9, not changed in v0.1.10). The old certificate request and key stay on disk after a delete, and easy-rsa stops with `Request file already exists`. Reproduced 3 of 3 times on `3a475b2` `[QA-D]` DN1. Not fixed in this release.
- **Upstream is dormant.** The newest upstream tag is `openvpn-user` v1.0.9 (commit `5eefd1b`, 2022-12-02). QA's fresh clone of upstream had 0 commits after it on 2026-11-21. Security fixes for the vendored copy come from us, not upstream. `[QA]` check 9.
- **Wrong number in the vendored README.** `third_party/openvpn-user/README.md` says ovpn-admin refuses a password under 8 bytes. The code enforces 6 (`Password too short, password length must be greater or equal 6`). Not changed in this release. `[QA]` N3.
- **Tested scope.** Only `linux/amd64`, Docker, and the filesystem backend. Rotate was tested through the API and with real OpenVPN 2.7.7 clients. The web UI was checked for views, theme and layout (22 of 22 assertions). The rotate dialog was not clicked.
- **Not tested on v0.1.10:**
  - arm64 images (not built, not scanned, not run).
  - Slave mode (only `docker compose config -q` was run).
  - Concurrent rotates of the same user.
  - A rotate of a user that v0.1.9 left Revoked.
  - Rollback to v0.1.9 with data written by v0.1.10.
  - An upgrade of a running v0.1.9 deployment with live data (fresh stacks were used).
  - Compose refusing to start without credentials.
  - The rollback-failed message (see above).
- **Image scan.** Trivy was not re-run on `3a475b2` (see zlib above).
- **Information only.** Change-password on a revoked user answers 200 and the password is changed (`[QA-D]` DN2). This is unchanged from v0.1.9.
- No item is marked NOT VERIFIED by QA. The open items above are the ones QA did not test or could not confirm.
