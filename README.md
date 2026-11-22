# ovpn-admin

Simple web UI to manage OpenVPN users, their certificates & routes in Linux. While backend is written in Go, frontend is based on Vue.js.

***DISCLAIMER!** This project was created for experienced users (system administrators) and private (e.g., protected by network policies) environments only. Thus, it is not implemented with security in mind (e.g., it doesn't strictly check all parameters passed by users, etc.). It also relies heavily on files and fails if required files aren't available.*

## Features

* Adding, deleting OpenVPN users (generating certificates for them);
* Revoking/restoring/rotating users certificates (from v0.1.10, rotate works for active, revoked and expired users: the old certificate is revoked, a new one is issued with a new password, and a failed rotate leaves the user as it was; see [RELEASE-v0.1.10.md](RELEASE-v0.1.10.md));
* Generating ready-to-user config files;
* Providing metrics for Prometheus, including certificates expiration date, number of (connected/total) users, information about connected users;
* (optionally) Specifying CCD (`client-config-dir`) for each user;
* (optionally) Operating in a master/slave mode (syncing certs & CCD with other server);
* (optionally) Specifying/changing password for additional authorization in OpenVPN;
* (optionally) Specifying the Kubernetes LoadBalancer if it's used in front of the OpenVPN server (to get an automatically defined `remote` in the `client.conf.tpl` template).
* (optionally) Storing certificates and other files in Kubernetes Secrets (**Attention, this feature is experimental!**).
* (optionally) IPv6: dual-stack web UI listener, IPv6 pool for VPN clients, static IPv6 addresses and IPv6 routes in CCD (see [IPv6](#ipv6)).
* Automatic banning of sources that make repeated failed logins or present revoked certificates, run by fail2ban inside the OpenVPN container, IPv4 and IPv6 (see [Ban engine](#ban-engine)). New in v0.1.4.
* **Banned IPs** view in the admin UI, read-only on a slave (see [Banned IPs](#banned-ips)).
* Mobile-first web UI: phone cards, a table on tablet and desktop, sheet dialogs (see [Mobile support](#mobile-support)). New in v0.1.4.
* (optionally) A Telegram message for every new ban, off by default (see [Telegram notifications](#telegram-notifications)). New in v0.1.5.
* Permanent bans for repeat offenders (the Nth ban of an address, `OVPN_BAN_REPEAT_COUNT`, default 2) and manual ban/unban on the master (see [Permanent bans and manual control](#permanent-bans-and-manual-control)). New in v0.1.6.
* Light, Dark and System themes, chosen with the theme button in the top bar and saved per browser (see [Theme](#theme)). New in v0.1.7.

### Screenshots

Managing users in ovpn-admin:
![ovpn-admin UI](https://raw.githubusercontent.com/haumanto/ovpn-admin/master/img/ovpn-admin-users.png)

An example of dashboard made using ovpn-admin metrics:
![ovpn-admin metrics](https://raw.githubusercontent.com/haumanto/ovpn-admin/master/img/ovpn-admin-metrics.png)

## Installation

Release notes for this version: [RELEASE-v0.1.11.md](RELEASE-v0.1.11.md) (v0.1.11 candidate, not yet tagged or published). Previous release: [RELEASE-v0.1.10.md](RELEASE-v0.1.10.md), then [RELEASE-v0.1.9.md](RELEASE-v0.1.9.md). Earlier releases: [RELEASE-v0.1.8.md](RELEASE-v0.1.8.md) (published with the v0.1.8 release), [RELEASE-v0.1.7.md](RELEASE-v0.1.7.md) (published with the v0.1.7 release), [RELEASE-v0.1.6.md](RELEASE-v0.1.6.md) (published with the v0.1.6 release), [RELEASE-v0.1.5.md](RELEASE-v0.1.5.md), [RELEASE-v0.1.4.md](RELEASE-v0.1.4.md), [RELEASE-v0.1.3.md](RELEASE-v0.1.3.md), [RELEASE-v0.1.2.md](RELEASE-v0.1.2.md), [RELEASE-v0.1.1.md](RELEASE-v0.1.1.md), [RELEASE-v0.1.0.md](RELEASE-v0.1.0.md). Upgrading from v0.1.0 to v0.1.4: [UPGRADING.md](UPGRADING.md). Upgrading from v0.1.4 to v0.1.5: [UPGRADING.md](UPGRADING.md#v014--v015). Upgrading from v0.1.5 to v0.1.6: [UPGRADING.md](UPGRADING.md#v015--v016). Upgrading from v0.1.6 to v0.1.7: [UPGRADING.md](UPGRADING.md#v016--v017). Upgrading from v0.1.7 to v0.1.8: [UPGRADING.md](UPGRADING.md#v017--v018). Upgrading from v0.1.8 to v0.1.9: [UPGRADING.md](UPGRADING.md#v018--v019). Upgrading from v0.1.9 to v0.1.10: [UPGRADING.md](UPGRADING.md#v019--v0110). Upgrading from v0.1.10 to v0.1.11: [UPGRADING.md](UPGRADING.md#v0110--v0111).

### 1. Docker

There is a ready-to-use [docker-compose.yaml](https://github.com/haumanto/ovpn-admin/blob/master/docker-compose.yaml), so you can just change/add values you need and start it with [start.sh](https://github.com/haumanto/ovpn-admin/blob/master/start.sh).

Requirements:
You need [Docker](https://docs.docker.com/get-docker/) and [Docker Compose v2](https://docs.docker.com/compose/install/) (`docker compose`) installed.
The example enables IPv6 for the containers, which needs a Docker Engine with IPv6 support (27.0+ recommended) and IPv6 enabled in the host kernel (see [IPv6 with Docker Compose](#docker-compose) to turn it off).

Compose refuses to start unless `BASIC_USERNAME` and `BASIC_PASSWORD` are set (see [Secure deployment](#secure-deployment)). `OVPN_MASTER_TOKEN` is optional: it enables the master/slave sync, and without it the master serves no PKI archive at all.

Commands to execute:

```bash
git clone https://github.com/haumanto/ovpn-admin.git
cd ovpn-admin
export BASIC_USERNAME=admin
export BASIC_PASSWORD='<a long random password>'
# optional, only to run a slave: setting a token turns the master/slave sync on
# export OVPN_MASTER_TOKEN="$(openssl rand -hex 32)"
./start.sh
```
#### 1.1
Ready docker images are published to the GitHub Container Registry: [`ghcr.io/haumanto/ovpn-admin/ovpn-admin`](https://github.com/haumanto/ovpn-admin/pkgs/container/ovpn-admin%2Fovpn-admin) for ovpn-admin and [`ghcr.io/haumanto/ovpn-admin/openvpn`](https://github.com/haumanto/ovpn-admin/pkgs/container/ovpn-admin%2Fopenvpn) for openvpn-server. Tags are the release tags (`$VERSION`, e.g. `v0.1.2`) and `master` (the latest build of the master branch). Images are built for `linux/amd64` and `linux/arm64`. The v0.1.2 images are published with the v0.1.2 release. The v0.1.3 images are published with the v0.1.3 release. The v0.1.4 images are published with the v0.1.4 release. The v0.1.5 images are published with the v0.1.5 release.

### 2. Building from source

Requirements. You need Linux with the following components installed:
- [golang](https://golang.org/doc/install) 1.26 or newer
- [nodejs/npm](https://nodejs.org/en/download/package-manager/) 22.18+ or 24.11+ (LTS)

The frontend and templates are embedded into the binary with `go:embed`, no C toolchain is needed (`build.sh` builds with `CGO_ENABLED=0`; set `GOARCH`, e.g. `GOARCH=arm64 ./build.sh`, to cross-compile). Only 64-bit platforms (`amd64`, `arm64`) are supported.

Commands to execute:

```bash
git clone https://github.com/haumanto/ovpn-admin.git
cd ovpn-admin
./bootstrap.sh
./build.sh
./ovpn-admin 
```

(Please don't forget to configure all needed params in advance.)

### 3. Prebuilt binary

You can also download and use prebuilt binaries from the [releases](https://github.com/haumanto/ovpn-admin/releases/latest) page — just choose a relevant tar.gz file (`linux-amd64` or `linux-arm64`). The v0.1.2 binaries are attached to the v0.1.2 release. The v0.1.3 binaries are attached to the v0.1.3 release.


## Secure deployment

Step-by-step guide with a ready nginx config and fail2ban jails: [docs/hardening/README.md](docs/hardening/README.md). fail2ban can watch both the OpenVPN audit log (`audit_master/audit.tsv`) and the reverse proxy's access log.

* **Basic Auth is mandatory.** `docker-compose.yaml` and the Helm chart refuse to start without credentials: compose needs `BASIC_USERNAME` and `BASIC_PASSWORD`, `start.sh` passes your environment through; the chart fails to render until `ingress.basicAuth.user` and `ingress.basicAuth.password` are set (the old `admin`/`changeme` defaults are rejected).
* **Scope of Basic Auth.** It covers the web UI, the API and `/metrics`. `/ping` stays open without credentials; the Helm chart's readiness and liveness probes use it.
* **Failed logins are logged.** A request with wrong credentials writes one warn line, `auth failed remote=<address> path=<path>` (no credentials, no `X-Forwarded-For`); a request without an `Authorization` header writes nothing. Behind a reverse proxy `remote` is the proxy address: use the line for detection, not for banning.
* **Terminate TLS in a reverse proxy** in front of the admin UI. Basic Auth over plain HTTP exposes the credentials.
* **Block direct access to the backend** (port 8080 / 8000) with a firewall or NetworkPolicy, only the proxy may reach it.
* **Compose binds the admin port to loopback** (`127.0.0.1:8080`); the VPN port 7777 stays on all interfaces. Publish the admin UI only through the proxy.
* **Cross-host master/slave sync only over HTTPS** (`--master.host=https://...`, plus `--master.basic-auth.user/password`).
* **Sync is off by default.** `OVPN_MASTER_TOKEN` is optional and enabling: with no token (unset or empty) the master serves no PKI or CCD archive, `/api/data/certs/download` and `/api/data/ccd/download` answer `403` to every request, and no token value is accepted, the empty one included. Set a token only when you run a slave (`docker-compose-slave.yaml` still requires it, with the same value).
* **Sync token.** Only needed to enable the sync. Generate it with `openssl rand -hex 32`. The example values `TOKEN` and `VerySecureToken` and the former built-in default are refused at startup.
* **Slave compose file (known issue).** `docker-compose-slave.yaml` refuses to start unless Basic Auth, the sync token and the master credentials are set in the environment, and it publishes its admin port on `127.0.0.1:8081`. It still targets `http://172.20.0.1:8080`, which the loopback binding of the master no longer serves: put a TLS reverse proxy in between. The slave runtime is not verified yet. See `RELEASE-v0.1.2.md` and `RELEASE-v0.1.1.md`.
* **Chart upgrade notes:** `ovpnAdmin.tag` and `openvpn.tag` are new and default to the chart `appVersion` (the images were `:master`); no value was renamed. The Role is narrowed to `secrets` (get, list, create, update) and `services` (get) in the release namespace.

## Keeping dependencies current

[COMPONENTS.md](COMPONENTS.md) lists every component that ships in the `ovpn-admin` and `openvpn` images (Alpine packages, OpenVPN, OpenSSL, easy-rsa, Go modules, npm packages), where each one comes from and how to bump it. How to read a scan finding and what to change: [docs/components.md](docs/components.md).

The `Security scan` workflow (`.github/workflows/security-scan.yaml`) builds both images, writes an SBOM for each, and runs Trivy, `govulncheck` and `npm audit`. It runs every Monday at 03:17 UTC, on every push to master, on every tag, and on every pull request. A pull request only reports findings. On master, on tags and in the weekly run, a critical or high Trivy finding fails the Trivy jobs.

[Dependabot](.github/dependabot.yml) opens update pull requests every week for Go modules, npm packages in `frontend/`, Docker base images, GitHub Actions and the Helm chart.

`openvpn-user` is built from vendored source ([third_party/openvpn-user](third_party/openvpn-user/README.md)) with a current Go toolchain and current modules. The prebuilt v1.0.9 binary it replaced carried 58 critical and high findings that made the Trivy jobs fail on master, tags and weekly runs in v0.1.8 (see [RELEASE-v0.1.8.md](RELEASE-v0.1.8.md#known-limitations)). On the rebuilt `linux/amd64` images Trivy reports no critical or high finding, see [COMPONENTS.md](COMPONENTS.md#known-findings-at-measurement-time).

## Notes
* This tool uses external calls for `bash`, `coreutils` and `easy-rsa`, thus **Linux systems only are supported** at the moment.
* To enable additional password authentication, provide `--auth.password` and `--auth.db="/etc/easyrsa/pki/users.db"` flags and install [openvpn-user](https://github.com/pashcovich/openvpn-user/releases/tag/v1.0.9) v1.0.9 and `sqlite3` (needed to upgrade a `users.db` created by openvpn-user v1.0.4 or older, see [Upgrade notes](#upgrade-notes)). Both should be available in your `$PATH` and be executable (`+x`). Two-factor authentication (TOTP) of openvpn-user is not supported by ovpn-admin.
* OpenVPN server certificates are not listed and cannot be managed (revoked, deleted, rotated, downloaded) as users: a certificate with the extended key usage `serverAuth` and without `clientAuth`, as `easyrsa build-server-full` issues it, whatever its common name is (e.g. the host name), and the CN `server`. A new user cannot take the CN of a server certificate either.
* If you use `--ccd` and `--ccd.path="/etc/openvpn/ccd"` and plan to use static address setup for users, do not forget to provide `--ovpn.network="172.16.100.0/24"` (and `--ovpn.network.ipv6="fd00:16:100::/64"` for IPv6) with valid openvpn-server network.
* The Docker images ship [openvpn-user](https://github.com/pashcovich/openvpn-user) v1.0.9 and `sqlite3`. openvpn-user is compiled from the vendored upstream source in `third_party/openvpn-user` (upstream commit `5eefd1b`, one local 72-byte guard in `src/commands.go` since v0.1.10, see its README) by the stage `openvpn-user-builder` of `Dockerfile.ovpn-admin` and `Dockerfile.openvpn`; no prebuilt binary is downloaded. An existing `users.db` of openvpn-user v1.0.4 is migrated automatically on start, see [Upgrade notes](#upgrade-notes).
* If you want to pass all the traffic generated by the user, you need to edit `ovpn-admin/templates/client.conf.tpl` and uncomment `redirect-gateway def1`.
* The images ship OpenVPN 2.7.7 (the `openvpn` image on `alpine:3.24`, the default of `ALPINE_VERSION` in `Dockerfile.openvpn`) and 2.6.20 on `alpine:3.23` (see [COMPONENTS.md](COMPONENTS.md)). v0.1.11 was tested with an OpenVPN 2.7.7 server and 2.7.7 clients over `tls-auth` (`setup/openvpn.conf`). Other server versions, including 2.4 and 2.5, were not tested in this release ([RELEASE-v0.1.11.md](RELEASE-v0.1.11.md#known-limitations)).
* The images ship easy-rsa 3.2.3 (`ovpn-admin` image) and 3.2.5 (`openvpn` image). v0.1.11 was tested with those versions. Other easy-rsa versions were not tested: `bootstrap.sh` downloads 3.0.8 for a local build, and that path was not tested in this release ([RELEASE-v0.1.11.md](RELEASE-v0.1.11.md#known-limitations)).
* Status of user connections update every 28 seconds.
* Master-replica synchronization and additional password authentication do not work with `--storage.backend=kubernetes.secrets` - **WIP**

## IPv6

IPv6 is optional and disabled by default (except the web UI listener). An IPv4 pool is always required, IPv6 is added on top of it.

### ovpn-admin

* `--listen.host` defaults to an empty value: ovpn-admin listens on all interfaces, IPv4 and IPv6. Use `0.0.0.0` (IPv4 only), `::` or e.g. `::1` to restrict it.
* `--ovpn.network.ipv6` (`OVPN_NETWORK_IPV6`) sets the IPv6 pool of the OpenVPN server, i.e. the same value as `server-ipv6` in the OpenVPN config, e.g. `fd00:16:100::/64` (prefix length 64-124). An empty value (default) disables IPv6 support. When it is set, the `ipv6` module is enabled (`/api/server/settings`) and the UI offers IPv6 fields.
* `--ovpn.network` (`OVPN_NETWORK`) accepts `172.16.100.0/24` as well as `172.16.100.0/255.255.255.0`. Both networks are validated at startup, ovpn-admin exits on an invalid value.
* IPv6 literals in addresses must be written in brackets:
  * `--ovpn.server="[2001:db8::1]:1194:udp"` (becomes `remote 2001:db8::1 1194 udp` in client configs). Hostnames and IPv4 addresses work as before. Supported protocols: `udp`, `udp4`, `udp6`, `tcp`, `tcp4`, `tcp6`, `tcp-client`, `tcp4-client`, `tcp6-client`;
  * `--mgmt="main=[::1]:8989"`;
  * `--master.host="http://[fd00::1]:8080"`.
* The status of connected clients is read with `status 3` from the management interface, the statistics include the IPv6 virtual address of a client (`VirtualAddressIPv6`).

### Static addresses and routes (CCD)

With `--ccd` every user can get a static IPv4 address (inside `--ovpn.network`, except the network, broadcast and server addresses) and, when IPv6 is enabled, a static IPv6 address (inside `--ovpn.network.ipv6`, except the network and server addresses). The server addresses are read from the running OpenVPN servers (the `state` command of their management interfaces, i.e. the addresses of `server`/`ifconfig` and `server-ipv6`/`ifconfig-ipv6` in their configs), so a server with its own address, e.g. a `dev tap` server with `ifconfig 172.29.11.10 255.255.255.0`, is protected as well; while a server has not reported an address of a family, network+1 (the address OpenVPN takes with `server`/`server-ipv6`) is reserved instead. Static addresses must be unique across users. Routes are IPv4 (address + dotted netmask, `10.1.0.0` / `255.255.0.0`) or IPv6 (address + prefix length, `fd00:1::` / `64`, the CIDR form `fd00:1::/64` is accepted too). A generated CCD file looks like:

```
ifconfig-push 172.16.100.10 255.255.255.0
ifconfig-ipv6-push fd00:16:100::10/64
push "route 10.1.0.0 255.255.0.0" # lan
push "route-ipv6 fd00:1::/64" # lan6
```

Custom CCD templates (`--templates.ccd-path`) using `.ClientAddress` and `.CustomRoutes` keep working. Templates also get `.ClientAddressIPv6` (`dynamic` or an address), `.Netmask` (the dotted netmask of `--ovpn.network`), `.IPv6PrefixLen` (the prefix length of `--ovpn.network.ipv6`) and the `.IsIPv6` method of a route (`Mask` of an IPv6 route is the prefix length), see [templates/ccd.tpl](templates/ccd.tpl).

The CCD API (`GET api/user/ccd?username=...`, `POST api/user/ccd/apply`) is backward compatible and has one new field, `ClientAddressIPv6` (missing or empty means `dynamic`):

```json
{"User":"alice","ClientAddress":"172.16.100.10","ClientAddressIPv6":"fd00:16:100::10","CustomRoutes":[{"Address":"10.1.0.0","Mask":"255.255.0.0","Description":"lan"},{"Address":"fd00:1::","Mask":"64","Description":"lan6"}]}
```

### OpenVPN server container

The `openvpn` image (`Dockerfile.openvpn`, [setup/configure.sh](setup/configure.sh)) is configured with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OVPN_SERVER_NET`, `OVPN_SERVER_MASK` | `172.16.100.0`, `255.255.255.0` | IPv4 pool for VPN clients (`--server`) |
| `OVPN_SERVER_NET6` | empty (IPv6 disabled) | IPv6 pool for VPN clients in CIDR format (`--server-ipv6`), e.g. `fd00:16:100::/64`. Adds an `ip6tables` MASQUERADE rule for the pool and enables IPv6 forwarding |
| `OVPN_PROTO` | `tcp` | Transport of the listener (`--proto`): `tcp` listens on IPv4 only, `tcp6` is dual-stack and accepts clients over IPv4 and IPv6. Independent of `OVPN_SERVER_NET6` |
| `OVPN_PASSWD_AUTH` | `false` | Enable the additional password authentication |
| `OVPN_ROLE` | `master` | `slave` waits for the first successful sync of its ovpn-admin with the master instead of generating new certificates |
| `OVPN_AUDIT_LOG` | `/etc/openvpn/audit/audit.tsv` | Connection audit log written by the OpenVPN hooks, see [Audit log](#audit-log) |
| `OVPN_IPTABLES_BIN` | `iptables` | IPv4 NAT backend. `iptables` uses nf_tables. Set `iptables-legacy` on older Docker hosts. The container exits with `ERROR: iptables binary not found: <name>` if the binary is missing. IPv6 NAT always uses `ip6tables` |

Build argument `ALPINE_VERSION` (`Dockerfile.openvpn`, default `3.24`, OpenVPN 2.7.7). On an older Docker host, build the image on Alpine 3.23 (OpenVPN 2.6.20):

```bash
docker build --build-arg ALPINE_VERSION=3.23 -f Dockerfile.openvpn .
```

The compose files do not pass this build argument. See [RELEASE-v0.1.3.md](RELEASE-v0.1.3.md) for what was tested.

IPv6 forwarding (`net.ipv6.conf.all.forwarding=1`) has to be enabled in the network namespace of the container. `configure.sh` tries to set it, but `/proc/sys` is usually read-only in containers, so set it from the outside (e.g. `sysctls` in Docker Compose), otherwise only a warning is printed and IPv6 traffic of the clients is not routed. Use the same pool for `OVPN_SERVER_NET6` and ovpn-admin's `OVPN_NETWORK_IPV6`.

### Docker Compose

[docker-compose.yaml](docker-compose.yaml) runs the example with IPv6 enabled:

* the user-defined network `ovpn` has `enable_ipv6: true` with the subnets `172.20.0.0/24` and `fd00:172:20::/64` ([docker-compose-slave.yaml](docker-compose-slave.yaml) uses `172.21.0.0/24` and `fd00:172:21::/64` and reaches the master via `http://172.20.0.1:8080`);
* the `openvpn` service gets the `net.ipv6.conf.all.disable_ipv6=0` and `net.ipv6.conf.all.forwarding=1` sysctls, `OVPN_SERVER_NET6="fd00:192:168:100::/64"` and `OVPN_PROTO="tcp6"`;
* the `ovpn-admin` service gets `OVPN_NETWORK_IPV6="fd00:192:168:100::/64"`.

To run it without IPv6, remove `enable_ipv6` and the IPv6 subnet of the network, the `sysctls`, `OVPN_SERVER_NET6` and `OVPN_NETWORK_IPV6`, and set `OVPN_PROTO` to `tcp` (or remove it).

### Kubernetes (Helm chart)

The [Helm chart](charts/openvpn-admin) has the following IPv6-related values:

* `openvpn.subnetIPv6` - IPv6 pool for VPN clients (`server-ipv6`), passed to ovpn-admin as `--ovpn.network.ipv6`;
* `openvpn.dualStack` - `tcp6-server` listener and `ipFamilyPolicy: PreferDualStack` for the Services (`openvpn.ipFamilies` optionally sets `ipFamilies`);
* `openvpn.externalIPs` - list of IPv4 and/or IPv6 addresses for `inlet: ExternalIP` (the legacy `openvpn.externalIP` still works), they are also used as `remote` addresses of the client configs;
* `podSecurityContext` - IPv6 forwarding in the pod is an unsafe sysctl in Kubernetes: allow `net.ipv6.conf.all.forwarding` on the kubelets and set it with `podSecurityContext.sysctls`.

```bash
helm install openvpn-admin charts/openvpn-admin \
  --set openvpn.subnetIPv6=fd00:16:200::/64 \
  --set openvpn.dualStack=true \
  --set openvpn.inlet=ExternalIP \
  --set 'openvpn.externalIPs={203.0.113.10,2001:db8::10}'
```

### Audit log

The `openvpn` image installs the hooks [client-connect.sh](setup/client-connect.sh) and [client-disconnect.sh](setup/client-disconnect.sh) and the password check [auth.sh](setup/auth.sh) (with `OVPN_PASSWD_AUTH=true`); all three append to one audit log through [audit.sh](setup/audit.sh):

* **Path:** `/etc/openvpn/audit/audit.tsv` in the OpenVPN container (`OVPN_AUDIT_LOG`). ovpn-admin reads the same file through `OVPN_AUDIT_PATH` (`/mnt/audit/audit.tsv`); Docker Compose shares it as the host directory `./audit_master`, the Helm chart as an `emptyDir` volume `audit` (it is lost when the pod is recreated: mount a persistent volume there to keep it).
* **Format:** append-only, one tab-separated line per event, a missing value is `-`, tabs and line breaks inside a value are replaced by a space and every value is cut to 128 characters:

  ```
  event  time_unix  username  real_ip  real_port  virtual_ip4  virtual_ip6  bytes_received  bytes_sent
  ```

  `event` is `connect` (client connected), `disconnect` (client left, with the byte counters of the session), `auth_ok` or `auth_fail` (password authentication result; the address of a client that is not yet connected is the one it connects from).
* **One line per connection:** each connection writes a `connect` and later a `disconnect` line, plus an `auth_ok` or `auth_fail` line for each password check.
* **Passwords are never logged**, only the username, address and port. The directory is `700` and the file `600`, owned by the `nobody` user that the hooks run as.
* **Retention is operator-managed:** nothing rotates or truncates `audit.tsv`. Rotate it with `copytruncate` (or move it and restart the container), and keep its size in mind: ovpn-admin only reads the tail. The container does rotate its own `openvpn.log` and `fail2ban.log` from v0.1.4 (see [Ban engine](#ban-engine)).
* A failed write never blocks a client: the hooks print a warning to the container log and exit `0`.
* The hooks need `script-security 2`, which `configure.sh` now always sets. The Helm chart's `openvpn.conf` loads the hooks from `/etc/openvpn/setup/` of the image, so use an image that contains them (the chart `appVersion` has to be the release that ships them).

### Ban engine

The `openvpn` container runs fail2ban 1.1.0 (jail `ovpn-admin`). It reads `openvpn.log` and bans a source address after repeated failures:

* **What counts:** a revoked certificate (`VERIFY ERROR: ... certificate revoked`, one line per attempt) and a wrong password (`SENT CONTROL [UNDEF]: 'AUTH_FAILED'`, one per wrong password; the second `AUTH_FAILED` line of the same attempt is not counted). Nothing else counts.
* **Default rule:** 3 failures in 600 seconds ban the address for 3600 seconds. Measured with 120 s and 60 s timers, real clients, IPv4 and IPv6: the ban starts within about half a second of the third failure and lifts at 59 to 60 seconds.
* **Enforcement:** DROP rules in the `OVPN_BAN` (IPv4) and `OVPN_BAN6` (IPv6) chains, only for the OpenVPN listener port `OVPN_SERVER_PORT`. The admin port is never affected.
* **Repeat bans:** the Nth ban of the same address is permanent (`OVPN_BAN_REPEAT_COUNT`, default 2). See [Permanent bans and manual control](#permanent-bans-and-manual-control).
* **Restarts:** temporary bans are not kept. Permanent bans are restored from `ban-history.tsv` (v0.1.6). A source still inside the findtime is banned again within seconds, and that re-applied ban is not counted again. See [UPGRADING.md](UPGRADING.md#v013--v014).
* **Allowlist:** `OVPN_BAN_IGNOREIP` (default: `127.0.0.0/8`, `::1` and the compose bridge subnet `172.20.0.0/24`; private ranges are not on it, so a client that arrives with a `10.x`, `172.16.x` or `192.168.x` address is banned). A client whose connection reaches OpenVPN through Docker's proxy shows up with the bridge gateway `172.20.0.1`, which is on the list and is never banned. Unique-local `fd00::/8` (including `fd00:172:20::1`) is not on the default list.
* **Logs:** `openvpn.log`, `bans.tsv` and `ban-history.tsv` (from v0.1.6) live in the audit volume. `openvpn.log` and `fail2ban.log` are rotated in the container (`OVPN_LOG_MAX_BYTES`, `OVPN_LOG_KEEP`, `OVPN_LOG_ROTATE_INTERVAL`).

| Variable | Default | Meaning |
|----------|---------|---------|
| `OVPN_BAN_ENABLED` | `true` | turn the ban engine on or off |
| `OVPN_BAN_MAXRETRY` | `3` | failures that trigger a ban |
| `OVPN_BAN_FINDTIME` | `600` | window in seconds for counting failures |
| `OVPN_BAN_BANTIME` | `3600` | ban length in seconds |
| `OVPN_BAN_REPEAT_COUNT` | `2` | the Nth ban of an address is permanent; `1` makes every ban permanent (v0.1.6) |
| `OVPN_BAN_IGNOREIP` | `127.0.0.0/8 ::1 172.20.0.0/24` | never banned (replaces the default list) |
| `OVPN_BAN_REQUIRED` | `true` | `true` stops the container if fail2ban cannot start; `false` runs without bans and logs an error |
| `OVPN_BAN_IPV6_REQUIRED` | `true` | `true` stops the container if IPv6 is on and the IPv6 ban chain cannot be built; `false` runs without IPv6 bans and prints a warning |

Full list, measured behavior and limits: [RELEASE-v0.1.4.md](RELEASE-v0.1.4.md). Check the filter against your own log with `fail2ban-regex`, as described in [docs/hardening/README.md](docs/hardening/README.md).

### Permanent bans and manual control

From v0.1.6, a repeat offender stays banned. The Nth ban of the same address is permanent, where N is `OVPN_BAN_REPEAT_COUNT` (default `2`; set `1` to make every ban permanent). The ban counts are kept in `ban-history.tsv` in the audit directory, so permanent bans survive a container restart. Set the variable in the compose file or in the environment file you pass to `docker compose`, then run `docker compose up -d --build`.

The master's **Banned IPs** tab has two controls:

1. **Ban IP:** enter an IPv4 or IPv6 address, optionally add a note (up to 120 characters: letters, digits, spaces, `. _ : -`), then press **Ban IP**. The ban is permanent until you unban it.
2. **Unban:** press **Unban** on the row and confirm. This also clears the address's failure count, so its next ban counts from 1.

The slave shows the list read-only. The API (`POST /api/ban/manual`, `POST /api/unban`), the Telegram messages, and the known limits are in [RELEASE-v0.1.6.md](RELEASE-v0.1.6.md).

### Telegram notifications

Off by default. With it on, every new ban sends one plain-text message to a Telegram chat or forum topic. A manual ban sends one too. Unban sends nothing. A failed send logs one warning and never undoes the ban. Details, limits and token notes: [RELEASE-v0.1.5.md](RELEASE-v0.1.5.md).

Setup (not tested against the real Telegram API in QA):

1. **Create a bot.** In Telegram, send `/newbot` to `@BotFather` and copy the token. Save it in a file outside the repo, mode 0600.
2. **Get the chat id.** Add the bot to the chat and send a message there. Open `https://api.telegram.org/bot<BOT_TOKEN>/getUpdates` and read `chat.id` (groups and channels are negative, starting with `-100`). The URL contains the token: do not share it. Optional: the thread id of a forum topic is the second number in its message link.
3. **Set the variables and start.** Uncomment the read-only token mount in `docker-compose.yaml` (`- /path/on/host/telegram-bot-token:/run/secrets/telegram-bot-token:ro`), then set `OVPN_TELEGRAM_ENABLED=true`, `OVPN_TELEGRAM_BOT_TOKEN_FILE=/run/secrets/telegram-bot-token` and `OVPN_TELEGRAM_CHAT_ID=<chat id>`, and run `docker compose up -d --build`. The start log should print `telegram notifications: enabled`.

| Variable | Default | Meaning |
|----------|---------|---------|
| `OVPN_TELEGRAM_ENABLED` | `false` | `true` turns notifications on (needs a token and a chat id) |
| `OVPN_TELEGRAM_BOT_TOKEN` | empty | token from BotFather. Prefer the file below |
| `OVPN_TELEGRAM_BOT_TOKEN_FILE` | empty | path inside the container to a file whose first line is the token; wins over the variable |
| `OVPN_TELEGRAM_CHAT_ID` | empty | chat id (`-100...` for groups) or `@channelname` |
| `OVPN_TELEGRAM_THREAD_ID` | empty | optional forum topic id |
| `OVPN_TELEGRAM_API_BASE` | `https://api.telegram.org` | Bot API base; keep it on `https://` |
| `OVPN_TELEGRAM_ALLOW_HTTP` | `false` | accepts an `http://` base; local mock tests only |

Message example:

```
🚫 ovpn-admin: banned 203.0.113.10
Reason: auth-failed
Attempts: 3
Until: 2026-11-18 03:51 UTC
Server: <container hostname>
```

A bad setting logs one `ERROR` line at start, notifications stay off, and the VPN still starts. Restarts can send again for addresses still inside the find time.

### Banned IPs

The **Banned IPs** tab of the admin UI is a list: IP address, reason, attempts, banned since, expires (or **Permanent**), and a count badge that matches the number of rows. It refreshes on a timer. On the master it also has **Ban IP** and **Unban** (see [Permanent bans and manual control](#permanent-bans-and-manual-control)); the slave stays read-only. Data comes from `GET /api/bans`, which reads `bans.tsv`. It sits behind the same Basic Auth as the rest of the UI.

### Mobile support

The admin UI is mobile-first from v0.1.4. Up to 768 px each user is a card with its actions; from 769 px up it is a table. Dialogs are sheets on phones and centered dialogs on desktop. Touch targets are 44 px on phones and tablets (per the design spec; target sizes were not measured). Tested in QA on the candidate UI (frontend unchanged since `e3233a9`) at 390 × 844 (phone emulation) and 1280 px (desktop). Tablet widths 769 to 1024 px and real devices were not tested. Details: [RELEASE-v0.1.4.md](RELEASE-v0.1.4.md).

## Theme

ovpn-admin has three themes: **Light**, **Dark** and **System**. **System** is the default. It follows the light or dark setting of your device, and it updates while the page is open.

To change the theme, press the theme button in the top bar. It is the button just left of **Refresh**, with a sun, moon or monitor icon. Pick **Light**, **Dark** or **System**.

The choice is saved in your browser only. The server does not store it, so each browser and device keeps its own choice. Details and limits: [RELEASE-v0.1.7.md](RELEASE-v0.1.7.md).

## Upgrade notes

Upgrading a docker compose deployment (upstream, v0.1.0, v0.1.1, v0.1.2, v0.1.3): follow [UPGRADING.md](UPGRADING.md); `scripts/upgrade.sh` backs up first and covers the audit volume. v0.1.4 steps: [UPGRADING.md](UPGRADING.md#v013--v014). v0.1.5 steps: [UPGRADING.md](UPGRADING.md#v014--v015). v0.1.6 steps: [UPGRADING.md](UPGRADING.md#v015--v016). v0.1.7 steps: [UPGRADING.md](UPGRADING.md#v016--v017). v0.1.8 steps: [UPGRADING.md](UPGRADING.md#v017--v018). v0.1.9 steps: [UPGRADING.md](UPGRADING.md#v018--v019). v0.1.10 steps: [UPGRADING.md](UPGRADING.md#v019--v0110). v0.1.11 steps: [UPGRADING.md](UPGRADING.md#v0110--v0111).

* **openvpn-user v1.0.4 → v1.0.9** (only relevant with password authentication, `--auth.password` / `OVPN_PASSWD_AUTH=true`). openvpn-user v1.0.9 adds the columns `secret` and `app_configured` to `users.db`. The column `secret` is added without a default value, so for every user whose password was saved by openvpn-user v1.0.4 or older it is `NULL`, and `openvpn-user auth` of v1.0.9 rejects these users (`converting NULL to string is unsupported`) — they cannot connect to the VPN any more. Users created by v1.0.9 are not affected. Additionally `openvpn-user db-migrate` does nothing on a database created by v1.0.4 until `openvpn-user db-init` has created the `migrations` table, and until the database is migrated `openvpn-user create` reports success without saving the user.
  * The Docker images handle this: `setup/configure.sh` of the openvpn image and ovpn-admin itself (when started with `--auth.password` or `--auth.db-init`) run `db-init` and `db-migrate` on start and then replace `NULL` in `secret` with an empty string (the value v1.0.9 stores for new users). All steps are idempotent.
  * If you install openvpn-user yourself, back up `users.db` and run once after the upgrade, before VPN clients connect:
    ```bash
    openvpn-user db-init --db.path=/etc/easyrsa/pki/users.db
    openvpn-user db-migrate --db.path=/etc/easyrsa/pki/users.db
    sqlite3 /etc/easyrsa/pki/users.db "UPDATE users SET secret = '' WHERE secret IS NULL;"
    ```
  * ovpn-admin checks whether a user has a password record with `openvpn-user list --all` (`openvpn-user check` of v1.0.9 prints nothing).
* **32-bit platforms are not supported any more**: Docker images are built for `linux/amd64` and `linux/arm64` only (no `linux/arm/v7`, `linux/arm/v8`), release binaries for `linux-amd64` and `linux-arm64` only (no `linux-386`, `linux-arm`).
* `GET api/user/ccd` answers `400` for an invalid username and `404` for an unknown user (it used to answer `200` with an empty CCD). An invalid JSON body of `POST api/user/ccd/apply` is rejected with `422`, like the other CCD validation errors (plain text message).
* `api/user/create` fails if the certificate cannot be issued (with `--auth.password` also if the password cannot be saved; the password is removed again if the certificate fails), `api/user/revoke` fails if `easyrsa revoke` fails. Both used to report success.
* Rotating or deleting a user whose certificate is not revoked (active or expired; the UI offers it for expired users, the API for any) revokes the certificate first: it used to stay valid after a delete (the user could still connect), and rotating an expired user failed because its files were still in `issued/`, `private/` and `reqs/`. Unrevoke restores `certs_by_serial/<serial>.pem` as well.
* `api/user/change-password` always answers valid JSON: `{"status": "ok"|"error", "message": "..."}`.
* `ovpn_client_bytes_sent` and `ovpn_client_bytes_received` are the sums over all sessions of a common name (`duplicate-cn`), `ovpn_client_connection_info` has a series for each virtual address (IPv4 and IPv6) of a session. Metric names and labels are unchanged.
* `ConnectedSince` and `LastRef` (`api/user/statistic`) are formatted as `yyyy-MM-dd HH:mm:ss` in the local time zone of ovpn-admin for all OpenVPN versions.
* With `--storage.backend=kubernetes.secrets` clearing the static address and routes of a user also clears the CCD file of OpenVPN, and the address can be assigned to another user right away.
* The web UI is served with `Cache-Control: no-cache` and an `ETag` (it used to be cached for 30 days), so browsers load the new UI right after an upgrade.

## Usage

```
usage: ovpn-admin [<flags>]


Flags:
  --[no-]help                   Show context-sensitive help (also try
                                --help-long and --help-man).
  --listen.host=""              host for ovpn-admin; empty means all
                                interfaces (IPv4 and IPv6), e.g. 0.0.0.0, ::,
                                ::1 ($OVPN_LISTEN_HOST)
  --listen.port="8080"          port for ovpn-admin ($OVPN_LISTEN_PORT)
  --listen.base-url="/"         base url for ovpn-admin ($OVPN_LISTEN_BASE_URL)
  --role="master"               server role, master or slave ($OVPN_ROLE)
  --master.host="http://127.0.0.1"  
                                URL for the master server, IPv6 hosts
                                in brackets: http://[fd00::1]:8080
                                ($OVPN_MASTER_HOST)
  --basic.username=""           username for HTTP Basic Auth on the web UI, API
                                and metrics (except /ping); requires
                                --basic.password, both empty disables it
                                ($BASIC_USERNAME)
  --basic.password=""           password for HTTP Basic Auth on the web UI, API
                                and metrics (except /ping); requires
                                --basic.username, both empty disables it
                                ($BASIC_PASSWORD)
  --master.basic-auth.user=""   user for master server's Basic Auth
                                ($OVPN_MASTER_USER)
  --master.basic-auth.password=""  
                                password for master server's Basic Auth
                                ($OVPN_MASTER_PASSWORD)
  --master.sync-frequency=600   master host data sync frequency in seconds
                                ($OVPN_MASTER_SYNC_FREQUENCY)
  --master.sync-token=TOKEN     master host data sync security token
                                ($OVPN_MASTER_TOKEN)
  --ovpn.network="172.16.100.0/24"  
                                IPv4 NETWORK/MASK_PREFIX (or NETWORK/NETMASK)
                                for OpenVPN server ($OVPN_NETWORK)
  --ovpn.network.ipv6=""        IPv6 NETWORK/PREFIX for OpenVPN server
                                (server-ipv6), e.g. fd00:16:100::/64; empty
                                disables IPv6 ($OVPN_NETWORK_IPV6)
  --ovpn.server=HOST:PORT:PROTOCOL ...  
                                HOST:PORT:PROTOCOL for OpenVPN server,
                                IPv6 hosts in brackets: [2001:db8::1]:1194:udp;
                                can have multiple values ($OVPN_SERVER)
  --[no-]ovpn.server.behindLB   enable if your OpenVPN server is behind
                                Kubernetes Service having the LoadBalancer type
                                ($OVPN_LB)
  --ovpn.service=openvpn-external ...  
                                the name of Kubernetes Service having the
                                LoadBalancer type if your OpenVPN server is
                                behind it ($OVPN_LB_SERVICE)
  --mgmt=main=127.0.0.1:8989 ...  
                                ALIAS=HOST:PORT for OpenVPN server
                                mgmt interface, IPv6 hosts in brackets:
                                main=[::1]:8989; can have multiple values
                                ($OVPN_MGMT)
  --metrics.path="/metrics"     URL path for exposing collected metrics
                                ($OVPN_METRICS_PATH)
  --easyrsa.path="./easyrsa"    path to easyrsa dir ($EASYRSA_PATH)
  --easyrsa.index-path=""       path to easyrsa index file; empty means
                                <easyrsa.path>/pki/index.txt ($OVPN_INDEX_PATH)
  --easyrsa.bin-path="easyrsa"  path to easyrsa script ($EASYRSA_BIN_PATH)
  --[no-]ccd                    enable client-config-dir ($OVPN_CCD)
  --ccd.path="./ccd"            path to client-config-dir ($OVPN_CCD_PATH)
  --templates.clientconfig-path=""  
                                path to custom client.conf.tpl
                                ($OVPN_TEMPLATES_CC_PATH)
  --templates.ccd-path=""       path to custom ccd.tpl
                                ($OVPN_TEMPLATES_CCD_PATH)
  --[no-]auth.password          enable additional password authentication
                                ($OVPN_AUTH)
  --auth.db="./easyrsa/pki/users.db"  
                                database path for password authentication
                                ($OVPN_AUTH_DB_PATH)
  --[no-]auth.db-init           enable database initialization if db user not
                                exists or size is 0 ($OVPN_AUTH_DB_INIT)
  --log.level="info"            set log level: trace, debug, info, warn,
                                error (default info) ($LOG_LEVEL)
  --log.format="text"           set log format: text, json (default text)
                                ($LOG_FORMAT)
  --storage.backend="filesystem"  
                                storage backend: filesystem, kubernetes.secrets
                                (default filesystem) ($STORAGE_BACKEND)
  --client-cert.expiration-days="3650"  
                                Expiration period of OpenVPN client
                                certificates in days, the period will shrink
                                automatically to the CA expiration period
                                ($CLIENT_CERT_EXPIRATION_DAYS)
  --[no-]version                Show application version.
```

## Authors

ovpn-admin was originally created in [Flant](https://github.com/flant/) and used internally for years.

In March 2021, it [went public](https://medium.com/flant-com/introducing-ovpn-admin-a-web-interface-to-manage-openvpn-users-d81705ad8f23) and was still developed in Flant.
Namely, [@vitaliy-sn](https://github.com/vitaliy-sn) created its first version in Python, and [@pashcovich](https://github.com/pashcovich) rewrote it in Go.

In November 2024, this project was moved to Palark, which maintained it. This fork (v0.1.0) is maintained by [haumanto](https://github.com/haumanto/ovpn-admin).
