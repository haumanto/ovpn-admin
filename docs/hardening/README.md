# Hardening guide for an internet-exposed ovpn-admin

This guide is for the operator of a Docker Compose deployment of ovpn-admin v0.1.1 that is reachable from the internet. It tells you what the application already protects, what you must put around it, and the exact steps to do that. Everything referenced here is in this directory:

| File | Purpose |
|---|---|
| [nginx-ovpn-admin.conf.example](nginx-ovpn-admin.conf.example) | TLS, HSTS, rate limit and access log for the admin panel |
| [fail2ban/filter.d/ovpn-admin-audit.conf](fail2ban/filter.d/ovpn-admin-audit.conf) | detects wrong VPN passwords in the audit log |
| [fail2ban/filter.d/ovpn-admin-http-401.conf](fail2ban/filter.d/ovpn-admin-http-401.conf) | detects wrong admin-panel credentials in the nginx log |
| [fail2ban/jail.d/ovpn-admin.local.example](fail2ban/jail.d/ovpn-admin.local.example) | two jails (5 failures in 10 minutes, ban for 1 hour) |
| [fail2ban/testdata/](fail2ban/testdata/README.md) | log samples to test the filters with `fail2ban-regex` |

## Threat model

Two things face the internet:

1. **The OpenVPN port** (7777 in `docker-compose.yaml`). A client needs a valid certificate from your CA to get past the TLS handshake (`verify-client-cert require`). With `OVPN_PASSWD_AUTH=true` it also needs the right user name and password.
2. **The admin panel** (HTTP on 8080, which controls certificates, users and routes). Whoever logs in can issue VPN access and read who connected from where.

What an attacker can try:

| Attack | Where it hits | Who stops it |
|---|---|---|
| Guess the admin password | admin panel | Basic Auth in ovpn-admin; nginx rate limit slows it; fail2ban bans the source address |
| Sniff the admin password | network path to the panel | TLS in nginx (the app speaks plain HTTP and is bound to loopback) |
| Reach the panel without the proxy | port 8080 | compose publishes it on `127.0.0.1` only; keep it closed in your firewall |
| Guess a VPN password with a stolen or leaked client certificate | OpenVPN | `auth_fail` lines in the audit log; fail2ban bans the source address |
| Scan the VPN port, connect without a certificate | OpenVPN | the TLS handshake fails; OpenVPN logs it, the audit log does **not** (see Limits) |
| Flood the panel with requests | nginx, ovpn-admin | nginx `limit_req` answers 429 per client address |
| Click-jack or content-sniff the panel | browser | security headers set by ovpn-admin; HSTS set by nginx |

### What the application does itself

* Refuses to start without `BASIC_USERNAME`, `BASIC_PASSWORD` and `OVPN_MASTER_TOKEN` (compose) and compares credentials in constant time.
* Binds the admin panel to `127.0.0.1:8080`.
* Writes `auth failed remote=<address> path=<path>` (warn level) when a request carries wrong credentials. Behind a proxy `remote` is the proxy address, so this line is for detection, not for banning.
* Sets `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, and `Cache-Control: no-store` on `/api/` answers.
* Writes one audit line per connect, disconnect and password check (`auth_ok`, `auth_fail`), with the real client address. Passwords are never written.

### What is delegated

| To nginx | To fail2ban |
|---|---|
| TLS and certificates | Banning addresses that fail logins repeatedly |
| HSTS | Firewall rules (`iptables`) for the ban |
| Per-client rate limit (HTTP 429) | |
| The access log that records failed logins with the real client address | |

ovpn-admin does not ban anyone and does not rate-limit. Without nginx and fail2ban an attacker can guess passwords at full speed.

## Install

Assumptions: a Linux host with Docker Compose, the repository checked out at `/opt/ovpn-admin` (change the paths if yours differs), nginx and fail2ban installed from your distribution (fail2ban 1.x; the files were tested with fail2ban 1.1.0 and nginx 1.30), a DNS name for the panel and a TLS certificate for it.

### 1. Start ovpn-admin

```bash
cd /opt/ovpn-admin
export BASIC_USERNAME=admin
export BASIC_PASSWORD="$(openssl rand -base64 24)"   # store it in your password manager
export OVPN_MASTER_TOKEN="$(openssl rand -hex 32)"
./start.sh
```

Check: `ss -ltn | grep -E ':(8080|7777)\b'` shows `127.0.0.1:8080` and the VPN port on all interfaces, and `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/` prints `401`.

### 2. Put nginx in front

```bash
sudo cp /opt/ovpn-admin/docs/hardening/nginx-ovpn-admin.conf.example /etc/nginx/conf.d/ovpn-admin.conf
sudoedit /etc/nginx/conf.d/ovpn-admin.conf   # server_name (twice), ssl_certificate, ssl_certificate_key
sudo nginx -t && sudo systemctl reload nginx
```

Check from another machine:

```bash
curl -sI https://admin.example.com/ | grep -i -E '^(HTTP|strict-transport)'   # 401 and the HSTS header
curl -sI http://admin.example.com/ | head -1                                   # 301 to https
```

The access log `/var/log/nginx/ovpn-admin.access.log` now has lines like

```
203.0.113.50 - - [17/Nov/2026:09:19:06 +0000] "GET / HTTP/2.0" 401 179 "-" "Mozilla/5.0" auth=0
198.51.100.23 - - [17/Nov/2026:09:19:06 +0000] "GET /api/users HTTP/2.0" 401 179 "-" "curl/8.23.0" auth=1
```

`auth=0` is the normal browser challenge before the login prompt; `auth=1` means credentials were sent and were wrong. Only `auth=1` counts for fail2ban.

Notes on the nginx file:

* The rate limit is 10 requests per second per address with a burst of 30. The web UI loads a handful of files per page, so normal use stays far below it; lower `rate` if you want it tighter.
* If nginx itself is behind another proxy or CDN, `$remote_addr` is that proxy. Restore the client address first (`set_real_ip_from` plus `real_ip_header`) or fail2ban will ban your proxy.
* The upstream is `127.0.0.1:8080`. If nginx runs in a container, point it at an address that container can reach and keep 8080 closed to everything else.

### 3. Install the fail2ban filters and jails

```bash
sudo cp /opt/ovpn-admin/docs/hardening/fail2ban/filter.d/ovpn-admin-*.conf /etc/fail2ban/filter.d/
sudo cp /opt/ovpn-admin/docs/hardening/fail2ban/jail.d/ovpn-admin.local.example /etc/fail2ban/jail.d/ovpn-admin.local
sudoedit /etc/fail2ban/jail.d/ovpn-admin.local   # the two logpath lines, ignoreip, and the VPN port
```

Test the filters against your real logs before enabling anything:

```bash
sudo fail2ban-regex /opt/ovpn-admin/audit_master/audit.tsv ovpn-admin-audit
sudo fail2ban-regex /var/log/nginx/ovpn-admin.access.log ovpn-admin-http-401
```

`Lines: N lines, 0 ignored, M matched` must show M equal to the number of failed logins in the file (zero is fine on a fresh install). Then:

```bash
sudo fail2ban-client -t                      # configuration test, prints "OK: configuration test is successful"
sudo systemctl restart fail2ban              # or: sudo fail2ban-client reload
sudo fail2ban-client status ovpn-admin-audit
sudo fail2ban-client status ovpn-admin-http-401
```

To lift a ban: `sudo fail2ban-client set ovpn-admin-audit unbanip 198.51.100.23`.

### Why the VPN jail uses `DOCKER-USER`

Docker publishes the VPN port with NAT rules that take the traffic before the host's `INPUT` chain, so fail2ban's default action (a rule in `INPUT`) would have no effect. The jail bans in the `DOCKER-USER` chain, which Docker evaluates first for published ports. There the packet already has its container address, so the rule matches the container port (`1194`), not the published port `7777`. The jail file explains this next to the setting. If you use UDP, set `protocol = udp`.

### 4. Check that the audit log shows real addresses

Before relying on the VPN jail, make one failed login from outside and read the log:

```bash
sudo tail -n 3 /opt/ovpn-admin/audit_master/audit.tsv
```

The fourth column must be the client's public address. If it shows a Docker address (for example `172.20.0.1`), the container does not see real addresses (this can happen with IPv6 through Docker's userland proxy); banning would then block the gateway for everyone. Add the Docker subnet to `ignoreip` and fix the address path first, or leave the VPN jail disabled.

### 5. Keep the logs from growing

Nothing rotates the audit file. A `copytruncate` rule keeps it small; fail2ban follows truncation:

```
/opt/ovpn-admin/audit_master/audit.tsv {
    weekly
    rotate 8
    copytruncate
    missingok
    notifempty
    compress
}
```

(save as `/etc/logrotate.d/ovpn-admin-audit`). Debian and Ubuntu already rotate `/var/log/nginx/*.log`.

## Limits you should know

* **The audit log only sees password failures.** A client without a valid certificate fails the TLS handshake and writes no `auth_fail` line, so the VPN jail does not react to port scans or to certificate-less connection attempts. That traffic is rejected by OpenVPN itself. If you need to react to it, add OpenVPN's own log as a third source.
* **The admin jail also bans a mistyped saved password.** A browser that keeps sending an old password produces `auth=1` failures. Put your own address in `ignoreip`.
* **Bans are per address.** Many attackers behind one NAT share a fate, and an attacker with many addresses is slowed down, not stopped. Use long, random passwords.
* **The jail and filter files were tested** with `fail2ban-regex` and a real fail2ban 1.1.0 server in a container, including real iptables rules in a stand-in `DOCKER-USER` chain. They were not tested against a Docker host with live NAT traffic. Do step 4 on your host.
* **Fixtures are partly synthetic.** See [fail2ban/testdata/README.md](fail2ban/testdata/README.md).
* **Kubernetes (Helm chart):** the chart's Ingress does TLS and Basic Auth for the panel; the audit volume is an `emptyDir` by default, which fail2ban on a node cannot read. This guide covers Docker Compose.
