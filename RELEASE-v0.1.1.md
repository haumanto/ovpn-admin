# ovpn-admin v0.1.1 release notes

**Status: in preparation, not published.** Nothing here is tagged, pushed, or released.

## Upgrade notes

- **Slave compose now requires credentials and binds the admin port to loopback.** `docker-compose-slave.yaml` refuses to start unless `BASIC_USERNAME`, `BASIC_PASSWORD`, `OVPN_MASTER_TOKEN`, `OVPN_MASTER_USER` and `OVPN_MASTER_PASSWORD` are set. The admin port is published as `127.0.0.1:8081:8080` (the VPN port `7778` is unchanged). Put a TLS reverse proxy in front of the slave panel, and generate the token with `openssl rand -hex 32` (same value as the master). `[S01]`
