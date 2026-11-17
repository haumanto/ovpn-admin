# Upgrading ovpn-admin (docker compose)

One script covers every version: `scripts/upgrade.sh`. It backs up the bind-mounted data, builds or pulls the images, runs `up -d` and waits for `/ping`. The version you upgrade to comes from the compose file and the checkout you are on; `--target-version` (default `v0.1.1`) only changes the text of the messages, the name of the backup archive and the rollback text.

Pick your section:

* [v0.1.0 → v0.1.1](#v010--v011)
* [upstream → v0.1.x](#upstream--v01x)

Kubernetes/Helm deployments: see `charts/openvpn-admin/README.md`. The historical notes of the first release stay in `UPGRADING-v0.1.0.md`.

## What the script does and never does

* Preflight: docker compose, the compose file, required variables, bind-mount sources, a warning when there is no audit mount.
* Backup (tar.gz, mode 600, in a mode 700 directory) of `easyrsa_master/`, `ccd_master/` and, when the compose file mounts it, `audit_master/`. It prints path, size, entries and sha256.
* `build --pull` (compose file with `build:`) or `pull` (registry images), then `up -d`, then `GET /ping`.
* It never runs `down`, `down -v`, a volume removal or a delete, and it never rolls back by itself. On a failure it prints the rollback steps with your paths filled in.

Options:

```
--project-dir DIR       compose file and data directories (required)
--compose-file NAME     default docker-compose.yaml
--project-name NAME     default openvpn-master, as in start.sh; it must match your running stack
--target-version VER    default v0.1.1; messages, backup file name and rollback text only
--backup-dir DIR        default <project-dir>/backups
--health-url URL        default http://127.0.0.1:8080/ping
--health-timeout SECS   default 180
--previous-ref REF      tag or commit you are leaving; fills in the rollback steps
--backup-only           preflight and backup, then stop (nothing is built or started)
--dry-run               print the plan and every command, change nothing
--yes                   no confirmation prompt
```

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
   If you run a slave (`docker-compose-slave.yaml`), it needs the same `OVPN_MASTER_TOKEN`, and it needs `BASIC_*` too.
4. **Preview, then upgrade**:
   ```bash
   scripts/upgrade.sh --project-dir . --dry-run
   scripts/upgrade.sh --project-dir . --previous-ref <your old tag or commit>
   ```
   The dry run prints the plan, the backup file list, any warning, and starts nothing. `--target-version v0.1.1` is the default and can be left out.
5. **Verify**: `curl -fsS http://127.0.0.1:8080/ping`, log in to the UI with the Basic Auth user, and connect one VPN client. Its `connect` line then shows up in the user's login history. `ls -l audit_master/` should list `audit.tsv`.

Manual equivalent, no script:
```bash
mkdir -p -m 700 backups
mkdir -p audit_master && chmod 0755 audit_master   # only if it does not exist yet
tar -czf backups/pre-v0.1.1-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
sha256sum backups/pre-v0.1.1-*.tar.gz
docker compose -p openvpn-master build --pull   # registry images: docker compose -p openvpn-master pull
docker compose -p openvpn-master up -d
curl -fsS http://127.0.0.1:8080/ping
```

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
tar -czf backups/pre-v0.1.1-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master audit_master
sha256sum backups/pre-v0.1.1-*.tar.gz
docker compose -p openvpn-master build --pull   # registry images: docker compose -p openvpn-master pull
docker compose -p openvpn-master up -d
curl -fsS http://127.0.0.1:8080/ping
```
Never use `down -v` and never delete `easyrsa_master/` (it holds your CA) or `audit_master/` (it holds the login history).

### Data migration

`easyrsa_master/` and `ccd_master/` are bind mounts and are not touched by the upgrade. On start the openvpn image (`setup/configure.sh`) and ovpn-admin run `openvpn-user db-init`, `db-migrate` and replace `NULL` in the `secret` column of `users.db` with an empty string, so password users created by old versions keep working. Backups are still mandatory: the `users.db` migration is not reversible, a rollback restores the archive.

### Behavior changes that can surprise

* 64-bit only: images are `linux/amd64` and `linux/arm64`, no 32-bit ARM.
* `GET api/user/ccd` answers `400` (invalid name) and `404` (unknown user) instead of `200` with an empty CCD; an invalid body of `POST api/user/ccd/apply` answers `422`.
* Rotate and delete revoke the certificate first. Deleting a user also removes its ccd file.
* The admin port is published as `127.0.0.1:8080`, no longer on all interfaces. Put a TLS reverse proxy in front for remote access. A slave that reaches the master on `172.20.0.1:8080` (`docker-compose-slave.yaml`) cannot use that path any more and needs the master token.
* The web UI and API need Basic Auth (`/ping` stays open).

## Rollback

`scripts/upgrade.sh` never rolls back by itself. On a failure after the backup it prints these steps with your paths filled in (the `audit_master` line appears when the compose file mounts it):
```bash
docker compose -p openvpn-master stop
mv easyrsa_master easyrsa_master.failed-upgrade && mv ccd_master ccd_master.failed-upgrade && mv audit_master audit_master.failed-upgrade
tar -xzf backups/pre-v0.1.1-<timestamp>.tar.gz -C .
git checkout <previous tag or commit>
docker compose -p openvpn-master up -d --build   # registry images: pull, then up -d
curl -fsS http://127.0.0.1:8080/ping
```
Keep the `*.failed-upgrade` directories until the old version runs, then remove them by hand. `audit_master.failed-upgrade` has the login history written after the backup; keep it if you want that history.
