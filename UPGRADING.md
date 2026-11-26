# Upgrading ovpn-admin (docker compose)

One script covers every version: `scripts/upgrade.sh`. It backs up the bind-mounted data, builds or pulls the images, starts `openvpn`, waits for its management interface, then starts `ovpn-admin` and waits for `/ping`. The version you upgrade to comes from the compose file and the checkout you are on; `--target-version` (default `v0.1.3`) only changes the text of the messages, the name of the backup archive and the rollback text.

Pick your section:

* [v0.1.12 → v0.1.13](#v0112--v0113) (in development, not tagged)
* [v0.1.0 → v0.1.1](#v010--v011)
* [v0.1.1 → v0.1.2](#v011--v012)
* [v0.1.2 → v0.1.3](#v012--v013)
* [v0.1.3 → v0.1.4](#v013--v014)
* [v0.1.4 → v0.1.5](#v014--v015)
* [v0.1.5 → v0.1.6](#v015--v016)
* [v0.1.6 → v0.1.7](#v016--v017)
* [v0.1.7 → v0.1.8](#v017--v018)
* [v0.1.8 → v0.1.9](#v018--v019)
* [v0.1.9 → v0.1.10](#v019--v0110)
* [v0.1.10 → v0.1.11](#v0110--v0111)
* [v0.1.11 → v0.1.12](#v0111--v0112)
* [upstream → v0.1.x](#upstream--v01x)

Kubernetes/Helm deployments: see `charts/openvpn-admin/README.md`. The historical notes of the first release stay in `UPGRADING-v0.1.0.md`.

## v0.1.12 → v0.1.13

Status: in development, not tagged yet. This section is the first one in the file on purpose: the first change in this release breaks old clients, and step 1 is the one to read before you upgrade.

1. **Re-issue the client configs before you upgrade the server.** The server now accepts the AEAD data channel ciphers `AES-256-GCM`, `AES-128-GCM` and `CHACHA20-POLY1305` and nothing else. `AES-128-CBC` is gone from `setup/openvpn.conf` (it was in `data-ciphers`, and the `cipher` and `data-ciphers-fallback` lines are deleted), and from the Helm chart. A client that pinned CBC stops connecting: a config whose `data-ciphers` list has no AEAD cipher, or one that relies on `data-ciphers-fallback AES-128-CBC` or on a client too old to negotiate a cipher. The server answers it with `AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)` and logs `PUSH: No common cipher between server and client. Server data-ciphers: 'DEFAULT' (AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305), client supported ciphers 'AES-128-CBC'`. Download a new `.ovpn` for each user from the panel (the new template writes the AEAD list and no `cipher` line), or delete the `cipher AES-128-CBC` line and any `data-ciphers-fallback` line from the file you already gave out. What was tested: a client on OpenVPN 2.7.9 that offers only `AES-128-CBC` is refused, while a 2.7.9 client with a v0.1.12 config (`data-ciphers` with the AEAD list plus `cipher AES-128-CBC`) still connects and negotiates `AES-256-GCM`, because OpenVPN 2.5 and newer ignore `cipher` for negotiation. Clients older than 2.5 were not tested.
2. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
3. **Update the checkout** once the `v0.1.13` tag exists: `git fetch --tags && git checkout v0.1.13`. If you build the `openvpn` image from your own edited `setup/openvpn.conf`, apply the same change to it by hand: `data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305` and no `cipher` or `data-ciphers-fallback` line.
4. **Back up before you upgrade:**
   ```bash
   mkdir -p -m 700 backups
   tar -czf backups/pre-v0.1.13-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
   sha256sum backups/pre-v0.1.13-*.tar.gz
   ```
5. **Rebuild both images.** `openvpn` changes (`setup/openvpn.conf`) and `ovpn-admin` changes (the embedded client template):
   ```bash
   docker compose -p openvpn-master build --pull ovpn-admin openvpn
   docker compose -p openvpn-master up -d --no-deps ovpn-admin openvpn
   curl -fsS http://127.0.0.1:8080/ping
   ```
   Restarting the `openvpn` container drops connected VPN clients. Do this in a quiet window.
6. **Custom client template.** If you run your own `client.conf.tpl` (`--templates.clientconf.path`), remove `cipher AES-128-CBC` from it and make sure it has `data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305`. Your template is not changed by the upgrade.
7. **Verify the data channel cipher.** Connect one client and read the negotiated cipher from the server log, about a second after the connect: `docker compose -p openvpn-master logs openvpn | grep "Data Channel: cipher"`. The line ends in `Data Channel: cipher 'AES-256-GCM', peer-id: 0`. The management interface shows the same: `docker compose -p openvpn-master exec openvpn sh -c 'printf "status 3\n" | nc -w 2 127.0.0.1 8989'`, last column of the `CLIENT_LIST` line.
8. **Helm.** The chart's ConfigMap now sets `cipher AES-256-GCM` instead of `AES-128-CBC`, so a chart deployment also stops accepting CBC-only clients; with no `data-ciphers` line OpenVPN uses its default list, which is the same three AEAD ciphers. The chart's other gaps are unchanged, see `charts/openvpn-admin/README.md`.
9. **Rollback.** Check out your previous tag, rebuild both images with the command in step 5 and start them again. v0.1.12 accepts `AES-128-CBC` again, so the old configs work again. No data format changes in this item.

## What the script does and never does

* Preflight: docker compose, the compose file, required variables, bind-mount sources, a warning when there is no audit mount.
* Requirements: Bash 4.2 or newer; both `docker compose` (V2 plugin, tried first) and `docker-compose` (V1, at least 1.25, refused when older) are supported, and the manual commands below work with either (write `docker-compose` for V1).
* Backup (tar.gz, mode 600, in a mode 700 directory) of `easyrsa_master/`, `ccd_master/` and, when the compose file mounts it, `audit_master/`. It prints path, size, entries and sha256.
* `build --pull` (compose file with `build:`) or `pull` (registry images), then the ordered start (next paragraph), then `GET /ping`.
* It never runs `down`, `down -v`, a volume removal or a delete, and it never rolls back by itself. On a failure it prints the rollback steps with your paths filled in.

Options:

```
--project-dir DIR       compose file and data directories (required)
--compose-file NAME     default docker-compose.yaml
--project-name NAME     default openvpn-master, as in start.sh; it must match your running stack
--target-version VER    default v0.1.3; messages, backup file name and rollback text only
--backup-dir DIR        default <project-dir>/backups
--health-url URL        default http://127.0.0.1:8080/ping
--health-timeout SECS   default 180
--mgmt-timeout SECS     default 180; how long to wait for the OpenVPN management interface
--previous-ref REF      tag or commit you are leaving; fills in the rollback steps
--backup-only           preflight and backup, then stop (nothing is built or started)
--dry-run               print the plan and every command, change nothing
--yes                   no confirmation prompt
```

**Ordered start.** The script runs `up -d --no-deps openvpn`, waits until the management interface answers inside the container (`nc` to `127.0.0.1:8989`, up to `--mgmt-timeout` seconds), and only then runs `up -d --no-deps ovpn-admin`. (The probe holds the connection open for a second: BusyBox `nc` exits on end of input and would otherwise drop the reply.) ovpn-admin connects to that management interface, and on a first start OpenVPN can take ~20s to generate DH parameters before it listens; a single `up -d` starts both at once and the admin retries against a port that is not open yet. If the interface does not answer in time, the script does not start or recreate ovpn-admin, prints the last 40 openvpn log lines and the rollback steps, and exits non-zero.

The data of a running stack is often root-owned (the openvpn container hands `audit_master/` to the `nobody` user, mode 700). If the backup fails with a permission error, re-run with `sudo`.

## The audit volume (`audit_master/`)

v0.1.1 adds a shared directory, `audit_master/` next to the compose file, mounted at `/etc/openvpn/audit` in the `openvpn` service and at `/mnt/audit` in `ovpn-admin`. The OpenVPN hooks write the connection audit log (`audit.tsv`) there and ovpn-admin reads it to show the exact login history per user.

* `audit_master/` **holds the login history. Deleting it erases the history**, and nothing else rebuilds it.
* The backup includes it, together with `easyrsa_master/` and `ccd_master/`.
* If it is missing, the script creates it with mode 0755 before the backup, so the first start does not leave a surprise root-owned directory. The openvpn container sets its own owner and mode (700) on start.
* The script never edits your compose file. If the compose file has no audit mount (`/etc/openvpn/audit` or `OVPN_AUDIT_PATH`) it prints a warning, and the upgrade goes on: login history will not persist until the v0.1.1 `docker-compose.yaml` is used.
* Nothing rotates the file. See the README section on the audit log for retention.

## v0.1.0 → v0.1.1

No database migration. `easyrsa_master/`, `ccd_master/` and `users.db` are untouched; the new data is the new `audit_master/` directory.

1. **Note your current version**: `git describe --tags --always` (or write down the image tags). You need it for a rollback.
2. **Replace the compose file** with the v0.1.1 `docker-compose.yaml`: `git fetch --tags && git checkout v0.1.1` in the existing checkout, or copy the v0.1.1 file next to your data. Registry users: change the two `image:` lines to `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.1` and `ghcr.io/haumanto/ovpn-admin/openvpn:v0.1.1` (once the release images are published). Re-apply your own edits (network, ports, `OVPN_*` settings). Check that it contains `./audit_master:/etc/openvpn/audit` and `./audit_master:/mnt/audit`.
3. **Set `BASIC_USERNAME`, `BASIC_PASSWORD` and `OVPN_MASTER_TOKEN`** in `.env` next to the compose file (`chmod 600 .env`) or in the environment, if v0.1.0 did not already have them. The compose file refuses to start without them:
   ```
   BASIC_USERNAME=admin
   BASIC_PASSWORD=<a long random password>
   OVPN_MASTER_TOKEN=<output of: openssl rand -hex 32>
   ```
   If you run a slave (`docker-compose-slave.yaml`), it needs the same `OVPN_MASTER_TOKEN`, its own `BASIC_USERNAME` and `BASIC_PASSWORD`, and `OVPN_MASTER_USER` and `OVPN_MASTER_PASSWORD` (the master's Basic Auth user and password). The slave compose file refuses to start unless all five are set.
4. **Preview, then upgrade**:
   ```bash
   scripts/upgrade.sh --project-dir . --dry-run
   scripts/upgrade.sh --project-dir . --previous-ref <your old tag or commit>
   ```
   The dry run prints the plan, the backup file list, any warning, and starts nothing. `--target-version v0.1.1` gives the correct labels for this upgrade. The script's default label is now `v0.1.3`.
5. **Verify**: `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and connect one VPN client. Its `connect` line then shows up in the user's login history. `ls -l audit_master/` should list `audit.tsv`.

Manual equivalent, no script:
```bash
mkdir -p -m 700 backups
mkdir -p audit_master && chmod 0755 audit_master   # only if it does not exist yet
tar -czf backups/pre-v0.1.2-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
sha256sum backups/pre-v0.1.2-*.tar.gz
docker compose -p openvpn-master build --pull   # registry images: docker compose -p openvpn-master pull
docker compose -p openvpn-master up -d --no-deps openvpn
until docker compose -p openvpn-master exec -T openvpn sh -c "(printf 'version\n'; sleep 1; printf 'quit\n') | nc -w 2 127.0.0.1 8989" | grep -q 'OpenVPN Version'; do sleep 2; done   # wait for the management interface
docker compose -p openvpn-master up -d --no-deps ovpn-admin
curl -fsS http://127.0.0.1:8080/ping
```

## v0.1.1 → v0.1.2

Image rebuild, no database migration. The compose files and the volumes do not change. The base image moves from Alpine 3.24 to 3.23, so the OpenVPN package in the images changes from `openvpn-2.7.7-r0` to `openvpn-2.6.20-r0`. Release notes: `RELEASE-v0.1.2.md`. The v0.1.2 tag is published; the steps below apply now.

1. **Note your current version**: `git describe --tags --always` (or write down the image tags). You need it for a rollback.
2. **Keep your compose file.** `docker-compose.yaml` and `docker-compose-slave.yaml` are the same as in v0.1.1. Registry users: change the two `image:` lines to `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.2` and `ghcr.io/haumanto/ovpn-admin/openvpn:v0.1.2`.
3. **Get the v0.1.2 code**: `git fetch --tags && git checkout v0.1.2` in the existing checkout.
4. **Preview, then upgrade**. The script's default label is `v0.1.3`. For correct labels in this step, pass `--target-version v0.1.2`.
   ```bash
   scripts/upgrade.sh --project-dir . --dry-run
   scripts/upgrade.sh --project-dir . --previous-ref <your v0.1.1 tag or commit>
   ```
   The script runs `build --pull` (or `pull` for registry images), so the Alpine 3.23 base image is fetched. The dry run prints the plan and starts nothing.
5. **Verify**: `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and connect one VPN client. Its `connect` line then shows in the user's login history. `ls -l audit_master/` should list `audit.tsv`.

Manual equivalent, no script (the wait for the management interface is the loop in the v0.1.0 → v0.1.1 section):
```bash
mkdir -p -m 700 backups
tar -czf backups/pre-v0.1.2-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
sha256sum backups/pre-v0.1.2-*.tar.gz
docker compose -p openvpn-master build --pull   # registry images: docker compose -p openvpn-master pull
docker compose -p openvpn-master up -d --no-deps openvpn
# wait for the management interface (loop from the v0.1.0 → v0.1.1 section)
docker compose -p openvpn-master up -d --no-deps ovpn-admin
curl -fsS http://127.0.0.1:8080/ping
```

Not tested for v0.1.2: a real upgrade run (QA used the dry run only), older Docker hosts, and the arm64 build. See `RELEASE-v0.1.2.md`, Known limitations.

## v0.1.2 → v0.1.3

Image rebuild, no database migration. The volumes do not change. The compose files gain one optional variable, `OVPN_IPTABLES_BIN` (default `iptables`). The default OpenVPN image goes back to Alpine 3.24, so the OpenVPN package changes from `openvpn-2.6.20-r0` (v0.1.2) to `openvpn-2.7.7-r0`. Older Docker hosts can build the image on Alpine 3.23 instead. Release notes: `RELEASE-v0.1.3.md`. v0.1.3 is a release candidate. These steps apply once it is published.

1. **Note your current version**: `git describe --tags --always` (or write down the image tags). You need it for a rollback.
2. **Compose files.** `docker-compose.yaml` and `docker-compose-slave.yaml` in v0.1.3 add `OVPN_IPTABLES_BIN: "${OVPN_IPTABLES_BIN:-iptables}"` to the `openvpn` service. Hosts on nf_tables need no change. If you keep a v0.1.2 compose file and need `iptables-legacy`, add that line to the `openvpn` service's `environment`. Registry users: change the two `image:` lines to `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.3` and `ghcr.io/haumanto/ovpn-admin/openvpn:v0.1.3`.
3. **Get the v0.1.3 code**: `git fetch --tags && git checkout v0.1.3` in the existing checkout.
4. **Older Docker hosts: Alpine 3.23 image.** Build the OpenVPN image on Alpine 3.23 (OpenVPN 2.6.20):
   ```bash
   docker build --build-arg ALPINE_VERSION=3.23 -f Dockerfile.openvpn .
   ```
   QA ran this command on its test host. The compose build and `scripts/upgrade.sh` do not pass the build argument, and the way to make compose use this image on an older host is not tested. On such a host, do not run the `build --pull` steps below until that is settled. See `RELEASE-v0.1.3.md`, Known limitations.
5. **Preview, then upgrade.** For a legacy host, export the backend before the script runs (QA tested this export with `docker compose up`, not through `upgrade.sh`). The script's default label is `v0.1.3`. Pass `--previous-ref` with your v0.1.2 tag or commit.
   ```bash
   export OVPN_IPTABLES_BIN=iptables-legacy   # older hosts only; leave unset otherwise
   scripts/upgrade.sh --project-dir . --dry-run
   scripts/upgrade.sh --project-dir . --previous-ref <your v0.1.2 tag or commit>
   ```
   The dry run prints the plan and starts nothing. The backup is `backups/pre-v0.1.3-<time>.tar.gz`.
6. **Verify**: `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and connect one VPN client. Its `connect` line then shows up in the user's login history. `ls -l audit_master/` should list `audit.tsv`. On a legacy host, check the NAT rule in the legacy table: `docker compose -p openvpn-master exec -T openvpn iptables-legacy -t nat -S POSTROUTING`.

Manual equivalent, no script (the wait for the management interface is the loop in the v0.1.0 → v0.1.1 section):
```bash
mkdir -p -m 700 backups
tar -czf backups/pre-v0.1.3-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
sha256sum backups/pre-v0.1.3-*.tar.gz
docker compose -p openvpn-master build --pull   # registry images: docker compose -p openvpn-master pull
docker compose -p openvpn-master up -d --no-deps openvpn
# wait for the management interface (loop from the v0.1.0 → v0.1.1 section)
docker compose -p openvpn-master up -d --no-deps ovpn-admin
curl -fsS http://127.0.0.1:8080/ping
```

Known limits of this upgrade: a real upgrade run was not done (QA used the dry run only). Older Docker hosts were not tested, and the Alpine 3.23 path is not tested through compose. The arm64 build was not tested. See `RELEASE-v0.1.3.md`, Known limitations.

## v0.1.3 → v0.1.4

Status: release candidate. v0.1.4 is not tagged or published yet. The steps below apply once the images are built from the v0.1.4 checkout. Details: [RELEASE-v0.1.4.md](RELEASE-v0.1.4.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout and the compose file.** Use the v0.1.4 `docker-compose.yaml` (or `docker-compose-slave.yaml` on a slave). It carries the ban and log variables with their defaults. Re-apply your own edits (network, ports, `OVPN_*`, `BASIC_*`, `OVPN_MASTER_TOKEN`).
3. **Rebuild both images.** The ban engine (fail2ban and setup scripts) is in the `openvpn` image. The Banned IPs API and UI are in the `ovpn-admin` image. Use `scripts/upgrade.sh --target-version v0.1.4 --previous-ref <old ref> --project-dir <dir>` (it backs up first and builds with `--pull`), or run `docker compose up -d --build` by hand.
4. **No database migration.** `easyrsa_master/`, `ccd_master/` and `users.db` are not changed. The new state lives in files in the audit volume.
5. **Audit volume gets two new files:**
   * `openvpn.log` (`audit_master/openvpn.log`, or `audit_slave/` on a slave): the connection log the ban engine reads. It is mode 0600, owned by `nobody`. Rotated in the container; see step 8.
   * `bans.tsv`: the list of active bans that the UI shows. Root, mode 0600. It is emptied at every start.
   The backup from `scripts/upgrade.sh` already includes `audit_master/`.
6. **Optional ban settings** (all have defaults; no setting is required): `OVPN_BAN_ENABLED` (`true`), `OVPN_BAN_MAXRETRY` (`3`), `OVPN_BAN_FINDTIME` (`600`), `OVPN_BAN_BANTIME` (`3600`), `OVPN_BAN_IGNOREIP`, `OVPN_BAN_REQUIRED` (`false`), `OVPN_BAN_IPV6_REQUIRED` (`true`), `OVPN_SERVER_PORT` (`1194`). The full table is in [RELEASE-v0.1.4.md](RELEASE-v0.1.4.md#configuration). `OVPN_BAN_IPV6_REQUIRED=false` is the only way to run IPv6 without IPv6 bans, and it prints a warning on every start.
7. **Restarts clear the bans but re-derive recent ones.** At start, the ban rules, the ban chains and `bans.tsv` are emptied. Then the engine re-reads `openvpn.log` and bans again any source that still has `OVPN_BAN_MAXRETRY` failures inside `OVPN_BAN_FINDTIME`. Measured in QA: a restart within the findtime banned the same address again 9 seconds later. After the findtime has passed, nothing is banned.
8. **Log growth:** `openvpn.log` and `fail2ban.log` are rotated past `OVPN_LOG_MAX_BYTES` (10 MiB) and keep `OVPN_LOG_KEEP` (3) copies, checked every `OVPN_LOG_ROTATE_INTERVAL` (60 s). Worst case per log with the defaults: 40 MiB plus one minute of log. `audit.tsv` is not rotated; manage it as before (see the README audit log section).
9. **Check the ban engine after the start:**
   ```bash
   docker compose -p openvpn-master exec -T openvpn fail2ban-client status ovpn-admin
   docker compose -p openvpn-master exec -T openvpn fail2ban-regex /etc/openvpn/audit/openvpn.log /etc/fail2ban/filter.d/ovpn-admin.conf
   ```
   The jail should be running. `fail2ban-regex` should match lines on a log that holds failed logins. `Failregex: 0 total` on such a log means the filter does not fit your OpenVPN version.
10. **IPv4 and IPv6 are both banned, but IPv6 was measured for one client only.** Check your IPv6 setup with `ip6tables` before you rely on it. Use `OVPN_IP6TABLES_BIN` and `OVPN_IPTABLES_BIN` together for legacy backends.
11. **Default allowlist:** `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fe80::/10`. Unique-local IPv6 (`fd00::/8`, including the example compose subnet `fd00:172:20::/64`) is not on the list, so those sources can be banned. `OVPN_BAN_IGNOREIP` replaces the whole default list, so copy the entries you want to keep.

Rollback: as in the Rollback section below, with `--previous-ref` set to the old tag, and keep the audit volume so the login history is kept. A downgrade with the new `openvpn.log` and `bans.tsv` files in place was not tested.

## v0.1.4 → v0.1.5

Status: release candidate. v0.1.5 is not tagged or published yet. The steps below apply once the images are built from the v0.1.5 checkout. Details: [RELEASE-v0.1.5.md](RELEASE-v0.1.5.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout and the compose file.** Use the v0.1.5 `docker-compose.yaml` (or `docker-compose-slave.yaml` on a slave). It adds the seven `OVPN_TELEGRAM_*` variables with their defaults. Re-apply your own edits (network, ports, `OVPN_*`, `BASIC_*`, `OVPN_MASTER_TOKEN`).
3. **Rebuild the images.** The Telegram notifier is in the `openvpn` image, so rebuild it. The `ovpn-admin` image changed only in its version string; rebuild it from the same checkout. Use `scripts/upgrade.sh --target-version v0.1.5 --previous-ref <old ref> --project-dir <dir>` (it backs up first and builds with `--pull`), or run `docker compose up -d --build` by hand.
4. **No database migration.** `easyrsa_master/`, `ccd_master/` and `users.db` are not changed. The v0.1.4 to v0.1.5 diff has no schema or SQL change. No new files appear in the audit volume.
5. **Notifications are off by default.** Nothing is sent after the upgrade until you set `OVPN_TELEGRAM_ENABLED=true`. The variables, all optional until you enable notifications:
   * `OVPN_TELEGRAM_ENABLED` (`false`): `true` turns notifications on. It needs a token and a chat id.
   * `OVPN_TELEGRAM_BOT_TOKEN` (empty): the bot token from BotFather.
   * `OVPN_TELEGRAM_BOT_TOKEN_FILE` (empty): a file whose first line is the token. It wins over `OVPN_TELEGRAM_BOT_TOKEN`. Prefer it: mount it read-only and keep it out of the repository.
   * `OVPN_TELEGRAM_CHAT_ID` (empty): the chat id, or `@channelname`.
   * `OVPN_TELEGRAM_THREAD_ID` (empty): an optional forum topic id.
   * `OVPN_TELEGRAM_API_BASE` (`https://api.telegram.org`): keep it on `https://`.
   * `OVPN_TELEGRAM_ALLOW_HTTP` (`false`): accepts an `http://` base. For local mock tests only.

   Setup steps and the message format are in the README section [Telegram notifications](README.md#telegram-notifications).
6. **Verify.** Check the start log: `docker compose -p openvpn-master logs openvpn | grep -i telegram` should print `telegram notifications: disabled` (the default) or `telegram notifications: enabled`. A bad setting prints one `ERROR` line and the VPN still starts. Then run `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and check the ban engine as in the v0.1.4 section.

Known limits of this upgrade: a real upgrade run was not done (QA used a fresh stack with a local mock). The real Telegram API was not called. A downgrade was not tested. Restarts can send messages again for addresses still inside the find time. See `RELEASE-v0.1.5.md`, Known limitations.

## v0.1.5 → v0.1.6

Status: published. v0.1.6 is tagged and released. Details: [RELEASE-v0.1.6.md](RELEASE-v0.1.6.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout and the compose file.** Use the v0.1.6 `docker-compose.yaml` (or `docker-compose-slave.yaml` on a slave). It adds `OVPN_BAN_REPEAT_COUNT` (default `2`). Re-apply your own edits (network, ports, `OVPN_*`, `BASIC_*`, `OVPN_MASTER_TOKEN`, Telegram settings). If you keep your own compose file, you can skip the new variable: the default is the same in the script.
3. **Rebuild both images.** Both changed: the `openvpn` image (ban engine, manual ban watcher, notifier, start script) and the `ovpn-admin` image (API, UI, version). Run `docker compose -p openvpn-master build --pull`, then `up -d --no-deps openvpn`, then `up -d --no-deps ovpn-admin`, as in the manual steps of the upstream section. Or run `docker compose up -d --build`. `scripts/upgrade.sh` takes the same `--target-version`, `--previous-ref` and `--project-dir` options as in v0.1.5. It has not been run for this release.
4. **No database migration.** `easyrsa_master/`, `ccd_master/` and `users.db` are not changed. The v0.1.5 to v0.1.6 diff adds no schema or SQL change. Back up before you upgrade anyway, as always.
5. **Behavior change: repeat bans are on by default.** From v0.1.6 the second ban of an address is permanent. A permanent ban stays until someone unbans it in the UI or the API. Set `OVPN_BAN_REPEAT_COUNT` to change this:
   * `2` (default): the second ban is permanent.
   * a higher number delays permanence; `1` makes every ban permanent (not tested).
   * The history starts empty after the upgrade, so bans made before the upgrade do not count.
6. **Audit volume.** The upgrade adds files to `audit_master/` (`/etc/openvpn/audit` in the container):
   * `ban-history.tsv`: appears at the first ban, not at start. Root-owned, mode `0600`. It keeps the ban counts and the permanent bans. Do not delete it: deleting it forgets the permanent bans and resets the counts.
   * `control/`: created at start, owned by root, mode `0700`. It carries manual ban requests and their results. Old results are removed after 10 minutes.
   * `bans.tsv.boot`: written at start.
   * `bans.tsv.removals`: exists only while a forced unban is pending. A new ban of that address waits until it is gone.
7. **Verify.** Check the start log: `docker compose -p openvpn-master logs openvpn | grep -E "ban control|fail2ban: jail"`. It should print `ban control: watching /etc/openvpn/audit/control` and `fail2ban: jail ovpn-admin running (... repeat-count=2)`. Then run `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and check that the **Banned IPs** tab shows **Ban IP** (master only).

Known limits of this upgrade: no real upgrade run was done. QA used a fresh stack. The real Telegram API was not called. A rollback was not tested. v0.1.5 has no ban history, so after a rollback the permanent bans are not restored. If history is unreadable at start, the ban engine does not start with the default `OVPN_BAN_REQUIRED=false`: the VPN runs without bans. Fix the file and restart. See `RELEASE-v0.1.6.md`, Known limitations.

## v0.1.6 → v0.1.7

Status: published. v0.1.7 is tagged and released. The steps below apply now. Details: [RELEASE-v0.1.7.md](RELEASE-v0.1.7.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout.** Use `git fetch --tags && git checkout v0.1.7`. The compose files (`docker-compose.yaml`, `docker-compose-slave.yaml`) do not change in v0.1.7. Keep your own edits (network, ports, `OVPN_*`, `BASIC_*`, `OVPN_MASTER_TOKEN`, Telegram settings).
3. **Rebuild the `ovpn-admin` image only.** The `openvpn` image has no source change since v0.1.6, so it does not need a rebuild.
   ```bash
   docker compose -p openvpn-master build --pull ovpn-admin
   docker compose -p openvpn-master up -d --no-deps ovpn-admin
   curl -fsS http://127.0.0.1:8080/ping
   ```
   Registry users: once the v0.1.7 images are published, change the `ovpn-admin` `image:` line to `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.7` and run `docker compose -p openvpn-master pull ovpn-admin` instead of `build`. `scripts/upgrade.sh` can also be used, but it builds both images and was not run for this release.
4. **No database migration.** `easyrsa_master/`, `ccd_master/`, `users.db` and `audit_master/` are not changed by v0.1.7. Back up before you upgrade anyway, as always:
   ```bash
   mkdir -p -m 700 backups
   tar -czf backups/pre-v0.1.7-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
   sha256sum backups/pre-v0.1.7-*.tar.gz
   ```
5. **The theme defaults to System.** Themes are a browser setting, not a server setting. v0.1.6 had no theme setting, so existing browsers have no stored choice and show System. Each user picks Light or Dark from the theme button in the top bar, and that choice is kept in that browser only.
6. **Verify.** Run `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and check the theme button in the top bar. Hover over it or focus it: its tooltip reads `Theme: System (Light)` or `Theme: System (Dark)`, depending on the device setting.

Known limits of this upgrade: no in-place upgrade from a running v0.1.6 with data was run. QA used a fresh stack. The Helm chart was not re-run; it has only its version changed. Firefox and Safari were not tested. A rollback was not tested. v0.1.6 does not read the browser's theme choice, so a rollback leaves that choice unused. See `RELEASE-v0.1.7.md`, Known limitations.

## v0.1.7 → v0.1.8

Status: published. v0.1.8 is tagged and released. The steps below apply now. Details: [RELEASE-v0.1.8.md](RELEASE-v0.1.8.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout.** Use `git fetch --tags && git checkout v0.1.8`. The compose files (`docker-compose.yaml`, `docker-compose-slave.yaml`) do not change in v0.1.8. Keep your own edits (network, ports, `OVPN_*`, `BASIC_*`, `OVPN_MASTER_TOKEN`, Telegram settings).
3. **Rebuild the `ovpn-admin` image only.** The `openvpn` image has no source change since v0.1.7, so it does not need a rebuild.
   ```bash
   docker compose -p openvpn-master build --pull ovpn-admin
   docker compose -p openvpn-master up -d --no-deps ovpn-admin
   curl -fsS http://127.0.0.1:8080/ping
   ```
   Registry users: once the v0.1.8 images are published, change the `ovpn-admin` `image:` line to `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.8` and run `docker compose -p openvpn-master pull ovpn-admin` instead of `build`.
4. **Nothing to configure.** There is no runtime or config change in v0.1.8. **No database migration.** `easyrsa_master/`, `ccd_master/`, `users.db` and `audit_master/` are not changed by v0.1.8. Back up before you upgrade anyway, as always:
   ```bash
   mkdir -p -m 700 backups
   tar -czf backups/pre-v0.1.8-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
   sha256sum backups/pre-v0.1.8-*.tar.gz
   ```
5. **Scans run weekly from now on.** The security scan workflow runs every Monday at 03:17 UTC on master, and on every tag and pull request. It runs on GitHub, not on your server, so it does not change a running deployment. Its results are in the repository's Actions and Security tabs. How to read them: [docs/components.md](docs/components.md).
6. **Verify.** Run `curl -fsS http://127.0.0.1:8080/ping`, then log in to the UI with the Basic Auth user.

Helm: the chart moves to version 0.1.8 with `appVersion` v0.1.8, and its default image tags follow `appVersion`. Helm was not re-run for this release. See `charts/openvpn-admin/README.md`.

Known limits of this upgrade: no in-place upgrade from a running v0.1.7 with data was run. QA used a fresh stack. A rollback was not tested. The scan jobs of the security workflow are red on master, on tags and in the weekly run until the prebuilt `openvpn-user` binary is rebuilt. That does not affect the running deployment. See `RELEASE-v0.1.8.md`, Known limitations.

## v0.1.8 → v0.1.9

Status: candidate, not published. The steps below apply once v0.1.9 is tagged and released. Details: [RELEASE-v0.1.9.md](RELEASE-v0.1.9.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout.** Use `git fetch --tags && git checkout v0.1.9`. The compose files (`docker-compose.yaml`, `docker-compose-slave.yaml`) and `setup/` do not change in v0.1.9. Keep your own edits.
3. **Rebuild both images.** Unlike v0.1.8, the `openvpn` image changes in this release: it now carries the `openvpn-user` binary built from vendored source. Rebuild `ovpn-admin` and `openvpn`:
   ```bash
   docker compose -p openvpn-master build --pull ovpn-admin openvpn
   docker compose -p openvpn-master up -d --no-deps ovpn-admin openvpn
   curl -fsS http://127.0.0.1:8080/ping
   ```
   Restarting the `openvpn` container drops connected VPN clients. Do this in a quiet window.
   Registry users: once the v0.1.9 images are published, change the `image:` lines to the `:v0.1.9` tags and run `docker compose -p openvpn-master pull` instead of `build`.
4. **No config change, no data migration.** `users.db` has no schema change in v0.1.9 and no migration is added. The start-up steps `db-init` and `db-migrate` still run as before, so the file is not byte-for-byte untouched. Back up before you upgrade:
   ```bash
   mkdir -p -m 700 backups
   tar -czf backups/pre-v0.1.9-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
   sha256sum backups/pre-v0.1.9-*.tar.gz
   ```
5. **Passwords.** A password over 72 bytes is now refused with a clear message on create, change-password and rotate in ovpn-admin. Passwords set under v0.1.8 keep working after the upgrade. Login still reads only the first 72 bytes of a password.
6. **Do not rotate an Active user.** A valid rotate fails in v0.1.9 (and in v0.1.8). The certificate is revoked and the password row is deleted, so the user cannot connect and shows as Revoked. This is not fixed in v0.1.9. See `RELEASE-v0.1.9.md`, Known limitations.
7. **Helm.** The chart's version fields move to 0.1.9 (`charts/openvpn-admin/Chart.yaml`). No chart template changed in this release. The chart was not deployed in QA.
8. **Verify.** Run `curl -fsS http://127.0.0.1:8080/ping`, then log in to the UI with the Basic Auth user.

Known limits of this upgrade: no in-place upgrade of a running v0.1.8 deployment with live data was run. QA used fresh stacks and databases written by each binary. A rollback was not part of QA. The refusal status codes are 422 (create), 500 (change-password) and 400 (rotate). See `RELEASE-v0.1.9.md`, Known limitations.

## v0.1.9 → v0.1.10

Status: candidate, not published. The steps below apply once v0.1.10 is tagged and released. Details: [RELEASE-v0.1.10.md](RELEASE-v0.1.10.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout** once the `v0.1.10` tag exists: `git fetch --tags && git checkout v0.1.10`. The compose files (`docker-compose.yaml`, `docker-compose-slave.yaml`) and `setup/` do not change in v0.1.10. Keep your own edits.
3. **Rebuild both images.** Both images change: `ovpn-admin` (zlib 1.4-r0 and the Go code) and `openvpn` (zlib 1.4-r0 and the `openvpn-user` binary, which now refuses passwords over 72 bytes):
   ```bash
   docker compose -p openvpn-master build --pull ovpn-admin openvpn
   docker compose -p openvpn-master up -d --no-deps ovpn-admin openvpn
   curl -fsS http://127.0.0.1:8080/ping
   ```
   Restarting the `openvpn` container drops connected VPN clients. Do this in a quiet window.
   Registry users: once the v0.1.10 images are published, change the `image:` lines to the `:v0.1.10` tags and run `docker compose -p openvpn-master pull` instead of `build`.
4. **No config change, no data migration.** The release adds no flag, no environment variable and no schema change. The start-up steps `db-init` and `db-migrate` still run as before. Back up before you upgrade:
   ```bash
   mkdir -p -m 700 backups
   tar -czf backups/pre-v0.1.10-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
   sha256sum backups/pre-v0.1.10-*.tar.gz
   ```
5. **Rotate works for active, revoked and expired users.** A rotate answers HTTP 200, revokes the old certificate and gives a new valid certificate with the new password you enter. A failed rotate keeps the old certificate and password. The warning "do not rotate an Active user" from v0.1.9 no longer applies after this upgrade, but see the next step.
6. **Check users that v0.1.9 left Revoked.** A failed rotate under v0.1.9 could leave a user Revoked and locked out. This was not tested on v0.1.10. After the upgrade, check these users in the UI before you rely on them.
7. **Passwords.** A password over 72 bytes is refused on create, change-password and rotate, with HTTP 400 and a clear message. A direct `openvpn-user create` or `change-password` with more than 72 bytes exits 1 and writes nothing. Passwords set under v0.1.9 keep working.
8. **Helm.** The chart's `version` and `appVersion` move to v0.1.10 (`charts/openvpn-admin/Chart.yaml`). No chart template changed in this release.
9. **Verify.** Run `curl -fsS http://127.0.0.1:8080/ping`, then log in to the UI with the Basic Auth user.

Known limits of this upgrade: no in-place upgrade of a running v0.1.9 deployment with live data was run. QA used fresh stacks. A rollback was not tested. arm64 images were not tested. Do not rotate a user on the `kubernetes.secrets` backend until it is tested. See `RELEASE-v0.1.10.md`, Known limitations.

## v0.1.10 → v0.1.11

Status: published. v0.1.11 was tagged and released on 2026-11-22. Details: [RELEASE-v0.1.11.md](RELEASE-v0.1.11.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Set the ban ignore list before you upgrade.** The default no longer has `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `fe80::/10`. Add the networks your admins use, for example in your environment or compose file:
   ```bash
   export OVPN_BAN_IGNOREIP="127.0.0.0/8 ::1 172.20.0.0/24 10.0.0.0/8"
   ```
   Entries are IPs or CIDRs separated by single spaces.
3. **Decide about the ban engine.** `OVPN_BAN_REQUIRED` now defaults to `true`: if fail2ban cannot start, the container stops with `ERROR: OVPN_BAN_REQUIRED=true, stopping the container`. If you ran without bans on purpose, set `OVPN_BAN_REQUIRED=false` explicitly.
4. **Update the checkout** once the `v0.1.11` tag exists: `git fetch --tags && git checkout v0.1.11`. `docker-compose.yaml` changes in this release (the sync token is optional, and the ban defaults change). `docker-compose-slave.yaml` does not change. If you keep your own copy of the compose file, merge the changed defaults by hand. Keep your own edits.
5. **Back up before you upgrade:**
   ```bash
   mkdir -p -m 700 backups
   tar -czf backups/pre-v0.1.11-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
   sha256sum backups/pre-v0.1.11-*.tar.gz
   ```
6. **Rebuild both images.** Both change: `ovpn-admin` (Go code, the 12-character minimum and cost-12 hashes) and `openvpn` (`setup/configure.sh`, the tunnel fence and the ban engine start-up, and `openvpn-user`):
   ```bash
   docker compose -p openvpn-master build --pull ovpn-admin openvpn
   docker compose -p openvpn-master up -d --no-deps ovpn-admin openvpn
   curl -fsS http://127.0.0.1:8080/ping
   ```
   Restarting the `openvpn` container drops connected VPN clients. Do this in a quiet window. If the container stops at start with `ERROR: fail2ban did not start`, fix fail2ban in the container or set `OVPN_BAN_REQUIRED=false` explicitly, then start again.
7. **Sync is off unless you set a token.** If you run a slave, set `OVPN_MASTER_TOKEN` (`openssl rand -hex 32`) on the master and on the slave. Without it the download endpoints answer 403.
8. **Convert a hand-encrypted `ca.key` if it uses another cipher.** The sync export accepts AES-128, AES-192, AES-256 and DES-EDE3-CBC legacy PEM keys, and PKCS#8. Any other cipher (for example Camellia) answers 500. Convert the key with `openssl pkcs8 -topk8` first.
9. **Update scripts that read the old answers.** Revoke, rotate and delete answer 500 on a server failure, not 200. Change-password on a revoked user answers 400. The rotate failure text is new.
10. **Passwords.** Existing short passwords keep working. New and changed passwords must be at least 12 characters, and at most 72 bytes.
11. **Verify.** Run `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and check the CRL gauge with `curl -s -u <user>:<password> http://127.0.0.1:8080/metrics | grep ovpn_crl_expire_days`.
12. **Helm.** The chart's `version` and `appVersion` move to v0.1.11 (`charts/openvpn-admin/Chart.yaml`). No chart template changed. The chart is not hardened to the compose level, see `charts/openvpn-admin/README.md`.

Known limits of this upgrade: QA used fresh stacks, so no in-place upgrade of a running v0.1.10 deployment with live data was run. A rollback was not tested. arm64 images were not tested. The slave was not tested. See `RELEASE-v0.1.11.md`, Known limitations.

## v0.1.11 → v0.1.12

Status: published. v0.1.12 was tagged and released on 2026-11-24. Details: [RELEASE-v0.1.12.md](RELEASE-v0.1.12.md).

1. **Note your current version** (`git describe --tags --always`, or the image tags). You need it for a rollback.
2. **Update the checkout** once the `v0.1.12` tag exists: `git fetch --tags && git checkout v0.1.12`. `docker-compose.yaml` changes in this release (the four failed-login settings below). `docker-compose-slave.yaml` changes too (the same four settings). If you keep your own copy of either file, merge the changed defaults by hand and keep your own edits.
3. **Back up before you upgrade:**
   ```bash
   mkdir -p -m 700 backups
   tar -czf backups/pre-v0.1.12-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
   sha256sum backups/pre-v0.1.12-*.tar.gz
   ```
4. **Rebuild both images.** Both change: `ovpn-admin` (the certificate features, the panel controls, the lock and metrics fixes) and `openvpn` (the re-hash side of the login hook):
   ```bash
   docker compose -p openvpn-master build --pull ovpn-admin openvpn
   docker compose -p openvpn-master up -d --no-deps ovpn-admin openvpn
   curl -fsS http://127.0.0.1:8080/ping
   ```
   Restarting the `openvpn` container drops connected VPN clients. Do this in a quiet window.
5. **Set the certificate notice threshold if you want notices.** `OVPN_NOTIFY_CERT_DAYS` takes a comma-separated list of days, largest first (for example `30,14,7,1`), and the panel notifies Telegram when a client or the server certificate crosses one. Telegram delivery needs `OVPN_TELEGRAM_ENABLED=true` and the bot token and chat id, as before.
6. **Panel controls are new.** Each client now has an expiry badge and a Renew action, and there is a server certificate card with a restart banner. `RELEASE-v0.1.12.md` states plainly that **Disconnect does not end a session in this version**: it sends the request and shows a notice. Do not rely on it.
7. **Helm.** The chart's `version` and `appVersion` move to v0.1.12 (`charts/openvpn-admin/Chart.yaml`). No chart template changed. The chart is not hardened to the compose level, see `charts/openvpn-admin/README.md`.

### Login lock and password re-hash (new in v0.1.12)

1. **Login lock (new in this release).** Five wrong secrets for one account from one address lock that account from that address (429, 15 min, then 1 h, 4 h, 24 h). Both compose files now pass four settings through to the panel: `OVPN_ADMIN_TRUST_PROXY` (default `true`), `OVPN_ADMIN_ALLOW_CIDR` (default empty), `OVPN_AUTH_MAX_FAILURES` (default 5), `OVPN_AUTH_FAIL_WINDOW` (default 15m). Merge them into your own copy of the compose file.
    * **Put the panel behind the TLS reverse proxy and make the proxy overwrite `X-Forwarded-For`** with the address it saw (nginx: `proxy_set_header X-Forwarded-For $remote_addr;`). The panel port is published to `127.0.0.1`, so without `OVPN_ADMIN_TRUST_PROXY=true` every client is the Docker bridge gateway and the lock is one lock for everybody. Set it to `false` only when the panel is exposed without a proxy.
    * **`OVPN_ADMIN_ALLOW_CIDR`** limits who may reach the panel (CIDR list, comma separated, `/32` for one host); other sources get 403. Sources on the list are never locked, so with a list set the lock does not engage.
    * **`/metrics` is counted like every other path** (it was exempt in the earlier candidate). A scraper with the right secret never fails; a source that is locked gets 429 there too, even with the right secret. A scraper inside `OVPN_ADMIN_ALLOW_CIDR` is exempt.
    * **Lift a lock by hand:** `docker compose -p openvpn-master stop ovpn-admin`, delete the entries whose key starts with the address from `state_master/auth-throttle.json` (or delete the file to lift every lock), `docker compose -p openvpn-master start ovpn-admin`. A restart alone does not lift it. Entries of the lock of the earlier candidate (keyed on the address alone) are ignored at start.
    * **Helm:** `ovpnAdmin.trustProxy` (default `false`), `ovpnAdmin.allowCidr`, `ovpnAdmin.authMaxFailures`, `ovpnAdmin.authFailWindow`.
    * Details: README, section "Login lock and source allowlist".
2. **Password re-hash at login.** A VPN login with a hash below bcrypt cost 12 leaves a small spool file (user name, old hash, new hash, never the password) in `users.db.rehash/` next to `users.db`, because the login hook runs as `nobody` and cannot write `users.db`. The panel creates that directory at start (mode 0700, owned by `nobody`) and applies the entries within a few seconds, with a compare-and-set on the old hash (an entry whose row changed meanwhile is dropped), then deletes them; each applied entry is one info line in the panel log (`rehash applied: user=<name> cost 4 -> 12`) and one `auth.rehash` line in the admin audit trail. `users.db` itself stays root-owned. Rebuild **both** images: the hook side is in the `openvpn` image, the applier in the `ovpn-admin` image. A spool entry that is left behind (panel stopped) is applied at the next panel start; deleting the directory loses only the pending re-hashes, the next login of the user makes a new one.

Known limits of this upgrade: no in-place upgrade of a running v0.1.11 deployment with live data was run. A rollback was not tested. arm64 images were not tested. The slave was not tested. The panel's Disconnect button does not end a session. In `docker-compose-slave.yaml` the `openvpn` service does not get `OVPN_TELEGRAM_INCLUDE_ADDRESS`, so a slave always sends the client address and user name in a ban message, and the slave's `ovpn-admin` service gets none of the `OVPN_TELEGRAM_*` settings, so its flood alert sends no Telegram message. Both are fixed in v0.1.13. See `RELEASE-v0.1.12.md`, Limits you need to know.

## upstream → v0.1.x

For deployments started with upstream `./start.sh` (images built locally with `docker compose up -d --build`) or with the upstream registry images.

### Why `docker compose pull` alone is not enough

* Upstream compose files use `ghcr.io/palark/...` images. This fork publishes `ghcr.io/haumanto/ovpn-admin/ovpn-admin` and `ghcr.io/haumanto/ovpn-admin/openvpn`. Pulling the old names gives you the old code; the script refuses to go on while the compose file still names them.
* Local-build compose files (the `start.sh` flow) have `build:` and no registry image: `pull` does nothing, you need `build --pull`. The script picks the right one.
* The compose file requires `BASIC_USERNAME`, `BASIC_PASSWORD` and `OVPN_MASTER_TOKEN` and refuses to start without them.

### Steps

1. **Note your current version**: `git describe --tags --always` (or write down the image tags).
2. **Get the new release next to your data**: `git fetch --tags && git checkout v0.1.1` in the existing checkout, or clone the repo and copy `easyrsa_master/` and `ccd_master/` next to its `docker-compose.yaml`. Registry users: change the two `image:` lines as in the section above. Re-apply your own edits to the new `docker-compose.yaml`. It mounts `./audit_master` (see [the audit volume](#the-audit-volume-audit_master)); keep those two lines.
3. **Set the credentials** `BASIC_USERNAME`, `BASIC_PASSWORD`, `OVPN_MASTER_TOKEN` as in the section above.
4. **Preview, then upgrade**:
   ```bash
   scripts/upgrade.sh --project-dir . --dry-run
   scripts/upgrade.sh --project-dir . --previous-ref <your old tag or commit>
   ```
   `audit_master/` does not exist on an upstream install: the script creates it (mode 0755) before the backup.
5. **Verify**: `curl -fsS http://127.0.0.1:8080/ping`, then log in to the UI with the Basic Auth user.

Manual equivalent, no script:
```bash
mkdir -p -m 700 backups
mkdir -p audit_master && chmod 0755 audit_master
tar -czf backups/pre-v0.1.2-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
sha256sum backups/pre-v0.1.2-*.tar.gz
docker compose -p openvpn-master build --pull   # registry images: docker compose -p openvpn-master pull
docker compose -p openvpn-master up -d --no-deps openvpn
until docker compose -p openvpn-master exec -T openvpn sh -c "(printf 'version\n'; sleep 1; printf 'quit\n') | nc -w 2 127.0.0.1 8989" | grep -q 'OpenVPN Version'; do sleep 2; done   # wait for the management interface
docker compose -p openvpn-master up -d --no-deps ovpn-admin
curl -fsS http://127.0.0.1:8080/ping
```
Never use `down -v` and never delete `easyrsa_master/` (it holds your CA) or `audit_master/` (it holds the login history).

### Data migration

`easyrsa_master/` and `ccd_master/` are bind mounts and are not touched by the upgrade. On start the openvpn image (`setup/configure.sh`) and ovpn-admin run `openvpn-user db-init`, `db-migrate` and replace `NULL` in the `secret` column of `users.db` with an empty string, so password users created by old versions keep working. Backups are still mandatory: the `users.db` migration is not reversible, a rollback restores the archive.

### Behavior changes that can surprise

* 64-bit only: images are `linux/amd64` and `linux/arm64`, no 32-bit ARM.
* `GET api/user/ccd` answers `400` (invalid name) and `404` (unknown user) instead of `200` with an empty CCD; an invalid body of `POST api/user/ccd/apply` answers `422`.
* Rotate and delete revoke the certificate first. Deleting a user also removes its ccd file.
* The admin port is published as `127.0.0.1:8080`, no longer on all interfaces. Put a TLS reverse proxy in front for remote access. A slave that reaches the master on `172.20.0.1:8080` (`docker-compose-slave.yaml`) cannot use that path any more: put a TLS reverse proxy between them and give the slave the master token.
* The web UI and API need Basic Auth (`/ping` stays open).

## Rollback

`scripts/upgrade.sh` never rolls back by itself. On a failure after the backup it prints these steps with your paths filled in (the `audit_master` line appears when the compose file mounts it):
```bash
docker compose -p openvpn-master stop
mv easyrsa_master easyrsa_master.failed-upgrade && mv ccd_master ccd_master.failed-upgrade && mv audit_master audit_master.failed-upgrade
tar -xzf backups/pre-v0.1.3-<timestamp>.tar.gz -C .
git checkout <previous tag or commit>
docker compose -p openvpn-master up -d --build   # registry images: pull, then up -d
curl -fsS http://127.0.0.1:8080/ping
```
Keep the `*.failed-upgrade` directories until the old version runs, then remove them by hand. `audit_master.failed-upgrade` has the login history written after the backup; keep it if you want that history.
