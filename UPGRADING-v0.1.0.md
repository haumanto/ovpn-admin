# Upgrading to v0.1.0

For deployments run with docker compose, started with upstream `./start.sh` (images built locally with `docker compose up -d --build`) or with registry images. Kubernetes/Helm deployments: see `charts/openvpn-admin/README.md`.

## Why `docker compose pull` alone is not enough

* Upstream compose files use `ghcr.io/palark/...` images. This fork publishes `ghcr.io/haumanto/ovpn-admin/ovpn-admin` and `ghcr.io/haumanto/ovpn-admin/openvpn`. Pulling the old names gives you the old code.
* Local-build compose files (the `start.sh` flow) have `build:` and no registry image: `pull` does nothing, you need `build --pull`.
* The v0.1.0 compose file requires `BASIC_USERNAME`, `BASIC_PASSWORD` and `OVPN_MASTER_TOKEN` and refuses to start without them.

## Steps

1. **Note your current version**: `git describe --tags --always` (or write down the image tags). You need it for a rollback.
2. **Get v0.1.0 next to your data**: `git fetch --tags && git checkout v0.1.0` in the existing checkout, or clone the repo and copy `easyrsa_master/` and `ccd_master/` next to its `docker-compose.yaml`. Registry users: change the two `image:` lines of your compose file to `ghcr.io/haumanto/ovpn-admin/ovpn-admin:v0.1.0` and `ghcr.io/haumanto/ovpn-admin/openvpn:v0.1.0` (once the release images are published). Re-apply your own edits (network, ports, `OVPN_*` settings) to the new `docker-compose.yaml`.
3. **Set the credentials** in `.env` next to the compose file (`chmod 600 .env`) or in the environment:
   ```
   BASIC_USERNAME=admin
   BASIC_PASSWORD=<a long random password>
   OVPN_MASTER_TOKEN=<output of: openssl rand -hex 32>
   ```
4. **Preview, then upgrade** (the script backs up first, then builds or pulls, then `up -d`):
   ```bash
   scripts/upgrade.sh --project-dir . --dry-run
   scripts/upgrade.sh --project-dir . --previous-ref <your old tag or commit>
   ```
   Options: `--compose-file NAME` (default `docker-compose.yaml`), `--project-name NAME` (default `openvpn-master`, as in `start.sh`; it must match your running stack), `--backup-dir DIR` (default `<project-dir>/backups`), `--health-url URL`, `--health-timeout SECS`, `--backup-only` (stop after the backup), `--yes` (no prompt). The data of a running stack is often root-owned: if the backup fails, re-run with `sudo`.
5. **Verify**: `curl -fsS http://127.0.0.1:8080/ping`, then log in to the UI with the Basic Auth user.

Manual equivalent, no script:
```bash
mkdir -p -m 700 backups
tar -czf backups/pre-v0.1.0-$(date -u +%Y%m%dT%H%M%SZ).tar.gz easyrsa_master ccd_master
sha256sum backups/pre-v0.1.0-*.tar.gz
docker compose -p openvpn-master build --pull   # registry images: docker compose -p openvpn-master pull
docker compose -p openvpn-master up -d
curl -fsS http://127.0.0.1:8080/ping
```
Never use `down -v` and never delete `easyrsa_master/`: it holds your CA.

## Data migration

`easyrsa_master/` and `ccd_master/` are bind mounts and are not touched by the upgrade. On start the new openvpn image (`setup/configure.sh`) and ovpn-admin run `openvpn-user db-init`, `db-migrate` and replace `NULL` in the `secret` column of `users.db` with an empty string, so password users created by old versions keep working. Backups are still mandatory: the `users.db` migration is not reversible, a rollback restores the archive.

## Behavior changes that can surprise

* 64-bit only: images are `linux/amd64` and `linux/arm64`, no 32-bit ARM.
* `GET api/user/ccd` answers `400` (invalid name) and `404` (unknown user) instead of `200` with an empty CCD; an invalid body of `POST api/user/ccd/apply` answers `422`.
* Rotate and delete revoke the certificate first. Deleting a user also removes its ccd file.
* The admin port is published as `127.0.0.1:8080`, no longer on all interfaces. Put a TLS reverse proxy in front for remote access. A slave that reaches the master on `172.20.0.1:8080` (`docker-compose-slave.yaml`) cannot use that path any more and needs the master token.
* The web UI and API need Basic Auth (`/ping` stays open).

## Rollback

`scripts/upgrade.sh` never rolls back by itself. On a failure it prints these steps with your paths filled in:
```bash
docker compose -p openvpn-master stop
mv easyrsa_master easyrsa_master.failed-upgrade && mv ccd_master ccd_master.failed-upgrade
tar -xzf backups/pre-v0.1.0-<timestamp>.tar.gz -C .
git checkout <previous tag or commit>
docker compose -p openvpn-master up -d --build   # registry images: pull, then up -d
curl -fsS http://127.0.0.1:8080/ping
```
Keep the `*.failed-upgrade` directories until the old version runs, then remove them by hand.
