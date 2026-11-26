# ovpn-admin v0.1.13 release notes

**Status: ready to publish.** Code candidate `2c21f89`, release gate **SHIP**. The tag, the GitHub release, the binaries, both images and the chart are cut from the code candidate plus the version bump and these notes. No code changes after `2c21f89`.

- Code candidate: `2c21f8948717f84b6a554228644a0077bfc6741f` (tree `4f252677c1f0ca5011c132a50daf645b3684a45e`), the commit the release gate passed.
- The nine commits after the v0.1.12 release notes: `0a195f6` (docs baseline, the slave Telegram limit stated precisely), `7c018d1` (drop AES-128-CBC), `421c9b0` (the config comment must not name the dropped cipher), `aaf3b2e` (upgrade notes), `3d4abbb` (sync token in a header, plain-HTTP sync refused, real Disconnect, user-name rule, cert lifetime, password on stdin), `1330d77` (test-only: log the easy-rsa argv), `4eddf03` (`--selftest`, `GET /api/selftest`, daily scheduled self-test, 11 checks), `7373dc4` (self-test audit-line wording), `2c21f89` (test-only: stop the CRL refresh test flaking).
- QA: `v0113/release-gate-r2/REPORT.md`, verdict **SHIP on `2c21f89`**, nine of nine checks pass. The first gate (`t_e069bce6`) returned DO-NOT-SHIP because of a defect in the gate card itself: its leftovers check matched `docs/hardening/fail2ban/testdata/nginx-access.log`, a documented fixture tracked since before v0.1.12 and byte-identical at both revisions. The corrected gate isolates new files only.
- Independent confirmation: the conductor re-ran the full suite on a disposable export of `2c21f89` and got the same numbers as the gate, **462 PASS / 0 FAIL / 5 SKIP** top level and **872 / 0 / 6** with subtests.
- Owner decisions: `v0112/DECISIONS.md`, including "Dropping AES-128-CBC … Removed in v0.1.13" (lines 48-49).

Source tags below: `[GATE]` = `v0113/release-gate-r2/REPORT.md`, `[CD]` = `v0113/cipher-drop/REPORT.md`, `[TR]` = `v0113/truth/REPORT.md`, `[ST]` = `v0112/selftest/REPORT.md`, `[D]` = `v0112/DECISIONS.md`, `[C]` = code at `2c21f89`, file and line.

## What changed

### The server no longer accepts AES-128-CBC. **This breaks old clients.**

The AEAD data channel ciphers are now the only ones offered: `AES-256-GCM`, `AES-128-GCM`, `CHACHA20-POLY1305`. `AES-128-CBC` is removed from `setup/openvpn.conf`, and the `cipher` and `data-ciphers-fallback` lines are deleted, in the server config and in the Helm chart. `[C] setup/openvpn.conf:20`, `[CD]`

- A client that pinned CBC stops connecting, with `AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)`. **Read `UPGRADING.md` step 1 before you upgrade the server.**
- **Who breaks:** a config whose `data-ciphers` list holds no AEAD cipher, or one relying on `data-ciphers-fallback AES-128-CBC`, or a client too old to negotiate a cipher.
- **Who does not:** an OpenVPN 2.5 or newer client with a v0.1.12 config still connects and negotiates `AES-256-GCM`, because 2.5 and newer ignore the `cipher` line for negotiation. Tested on a 2.7.9 client. Clients older than 2.5 were not tested.
- Fix for a client: download a fresh `.ovpn` from the panel, or delete the `cipher AES-128-CBC` and `data-ciphers-fallback` lines from the file you already handed out.

### Disconnect now really ends the session

The panel action used to answer 200 and disconnect nobody; v0.1.12 listed that as a known limitation. It now calls the management interface and reports how many sessions it closed: `disconnected NAME (N sessions)`. `[C] main.go:712`, `truthfixes.go:135-163`, `mgmt.go:460,496ff`; evidence `[TR]` lines 89-132: the panel showed one client, then none, and the client received `SIGTERM`.

### The sync token is no longer in the URL

The slave sync accepts the token from `Authorization: Bearer`, then `X-OVPN-Token`, and only then the old `?token=` query. The query form still works but logs a rate-limited deprecation warning. A non-loopback plain-HTTP sync request is refused with **426**, unless the operator explicitly allows insecure HTTP. `[C] syncauth.go:29,45-55,69-88,110-111,129-138`; evidence `[TR]`

### `--selftest`, an endpoint, and a daily run

`ovpn-admin --selftest` runs 11 checks against the running box and exits 0 (no check failed, warnings allowed), 1 (a check failed) or 2 (internal error). `GET /api/selftest` returns the same report. A daily scheduled run writes the same result to the log and to Telegram when it is configured.

- The 11 checks: `admin_fence`, `ban_jail`, `crl_age`, `cert_expiry`, `key_modes`, `credentials`, `control_channel`, `audit_chain`, `sync`, `versions`, `pki_readable`. `[C] selftest.go:245-258`
- Failure paths are real, not cosmetic: removing a firewall rule turns `ban_jail` to FAIL and the command exits 1; a broken audit chain and an expiring certificate do the same. `[ST]`
- The panel image now carries `iptables` and `ip6tables` so the firewall checks can run. `[C] Dockerfile.ovpn-admin`, `4eddf03`

### Smaller fixes carried in this line

- **A password can be read from stdin**, so it need not appear in the process list. `[C]` `3d4abbb`
- **The user-name rule and the certificate lifetime** are stated and enforced the same way in the panel and the self-test.
- **The config comment no longer names the dropped cipher**, so a reader cannot copy it back in. `[C] setup/openvpn.conf`, `421c9b0`
- **The slave compose file now carries all eight `OVPN_TELEGRAM_*` keys under both its `openvpn` and `ovpn-admin` services.** That closes the v0.1.12 limitation that a slave panel sent no Telegram at all and a slave ban message always carried the client address. `[C] docker-compose-slave.yaml:69-79,137-146`; `[TR]`; `[D]`

## Upgrade notes

Full steps: [UPGRADING.md](UPGRADING.md#v0112--v0113).

- **Re-issue client configs before you upgrade the server.** This is the one step that matters. See above and `UPGRADING.md` step 1.
- **Rebuild both images.** `openvpn` changes (`setup/openvpn.conf`) and `ovpn-admin` changes (embedded client template, `iptables`, the self-test). Restarting the `openvpn` container drops connected clients, so pick a quiet window. `[C] Dockerfile.ovpn-admin`, `build.sh`
- **Merge the slave compose change** if you run a slave: copy the eight `OVPN_TELEGRAM_*` keys onto both services in your own `docker-compose-slave.yaml`. `[C] docker-compose-slave.yaml`
- **If a Telegram ban message must not carry the client address**, set `OVPN_TELEGRAM_INCLUDE_ADDRESS=false` on the `openvpn` service. On a slave this setting now reaches the notifier; it did not before.
- **Run the self-test after the upgrade** to confirm the protections are in place on your box: `docker compose exec ovpn-admin /ovpn-admin --selftest`, then `echo $?`. Exit 0 means no check failed. WARN is allowed and named.
- **The Helm chart moves to v0.1.13** in `version` and `appVersion` only. No chart template changed. The chart is not hardened to the compose level, see `charts/openvpn-admin/README.md`.
- **Back up first,** as for every release. See [UPGRADING.md](UPGRADING.md#v0112--v0113).

## Known limitations

Open items, in the order you are most likely to hit them.

- **Old clients stop connecting.** That is the point of this release, and there is no compatibility fallback. Re-issue the configs. Clients on OpenVPN older than 2.5 were not tested at all.
- **A connected VPN client still reaches the host and the LAN behind it.** Default-deny forwarding is deferred; a stolen client certificate still reaches the whole host and LAN. The certificate-touching release is v0.2.0 and carries nothing else. `[D] row 3`
- **The self-test needs extra privilege to read the firewall rules.** In a container the `ban_jail` and related checks need `NET_ADMIN`; without it they report WARN, not PASS. The self-test is honest about that and does not fail the run. Widening the shipped container privileges is a separate decision, deliberately not taken in this release.
- **The self-test's `key_modes` check warns on a stock install** because `users.db` is world-readable. Pre-existing, not introduced here, and left as a WARN rather than a failure so the release was not blocked on a product change.
- **A request through the published port with no `X-Forwarded-For` counts as the Docker bridge gateway.** With the compose default on, five wrong secrets lock every header-less client, including you. Anyone who reaches the panel port without a proxy can forge the header and is never locked. The port is loopback-only, so this is host-local. Unchanged from v0.1.12. `[D]`
- **The base64-signed CRL is not verified against a hash chain** and the CA key is still online on the server. Offline root is v0.4.0. `[D]`
- **The Helm chart is not hardened to the compose level.** `[C] charts/openvpn-admin/README.md`
- **Slave mode is unsupported and was not tested end to end.** So were in-place upgrade of a running v0.1.12 deployment, rollback, arm64 and UDP beyond what the release workflow builds. `[GATE]`
- **Two npm advisories remain in build-only packages** (`body-parser` via `webpack-dev-server`, `fast-uri`). Neither ships in the panel bundle: a production-only audit found zero, and the bundle contains no reference to either. A dependency refresh is recommended before the next build. Confirming this did not change the gate verdict. `[GATE]`, `t_a6fab31f`
- **Ten CRL test passes show no observed flake,** not the impossibility of one.
- **The secret scan is heuristic and offline.** It proves no obvious secret, not the absence of every secret.

## Evidence

- `v0113/release-gate-r2/REPORT.md`: the shipping sha, nine checks, per-check command output, start and finish HEAD, export hash, and the six skip events with their reasons.
- `v0113/release-gate/REPORT.md`: the first gate, DO-NOT-SHIP, and the proof that its single finding was the documented fixture rather than a new file.
- `v0113/cipher-drop/REPORT.md`: the cipher removal, the rendered chart, and the client that was refused versus the client that renegotiated.
- `v0113/truth/REPORT.md`: the sync header, the 426 refusal, the Disconnect proof (one client, then none, `SIGTERM`), the slave compose keys, and the test counts.
- `v0112/selftest/REPORT.md`: the 11 checks, the FAIL paths, and the exit codes.
- `v0113/PLAN.md`: the release plan, the four cards, and the start of this release.
- `v0112/DECISIONS.md`: the owner decisions, the accepted risks, and the scope trim.
