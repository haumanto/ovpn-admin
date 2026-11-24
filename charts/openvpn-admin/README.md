# openvpn-admin

![Version: 0.1.12](https://img.shields.io/badge/Version-0.1.12-informational?style=flat-square) ![AppVersion: v0.1.12](https://img.shields.io/badge/AppVersion-v0.1.12-informational?style=flat-square)

Simple web UI to manage OpenVPN users, their certificates & routes in Linux. While backend is written in Go, frontend is based on Vue.js.

> **Not hardened to the Docker Compose level.** Missing: `duplicate-cn` and `client-to-client` are on (`templates/configmap.yaml`), no password authentication, no ban engine (the container runs `/entrypoint.sh`, not `configure.sh`), the cipher is `AES-128-CBC`, the Ingress is always created even with `ingress.enabled: false`, the admin password is stored as `{PLAIN}` in the Secret, and the Role can get, list, create and update every Secret in the namespace. Do not use it for an internet-facing VPN until these are fixed. Templates are unchanged in this release.

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| nabokihms | <max.nabokih@gmail.com> | <github.com/nabokihms> |

## Source Code

* <https://github.com/haumanto/ovpn-admin>

## Requirements

Kubernetes: `>=1.14.0-0`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| ovpnAdmin.repo | string | `"ghcr.io/haumanto/ovpn-admin/ovpn-admin"` |  |
| ovpnAdmin.tag | string | `""` | Image tag, defaults to the `appVersion` of the chart. Never use `master`. |
| ovpnAdmin.trustProxy | bool | `false` | Take the source address of the login lock and the allowlist from the last `X-Forwarded-For` value (`OVPN_ADMIN_TRUST_PROXY`). Set `true` when the ingress overwrites that header with the address it saw. Behind an ingress with `false` every client is the ingress pod and the lock is one lock for everybody; with no proxy in front, leave `false` (a client could name its own address). |
| ovpnAdmin.allowCidr | string | `""` | Source networks that may reach the panel, comma separated CIDRs (`OVPN_ADMIN_ALLOW_CIDR`); other sources get 403. Sources on the list are never locked. Empty = no restriction. |
| ovpnAdmin.authMaxFailures | int | `5` | Wrong secrets for one account from one address within `authFailWindow` that lock it (`OVPN_AUTH_MAX_FAILURES`). |
| ovpnAdmin.authFailWindow | string | `"15m"` | Window of the failure count (`OVPN_AUTH_FAIL_WINDOW`), e.g. `15m`. |
| openvpn.repo | string | `"ghcr.io/haumanto/ovpn-admin/openvpn"` |  |
| openvpn.tag | string | `""` | Image tag, defaults to the `appVersion` of the chart. Never use `master`. |
| openvpn.subnet | string | `"172.16.200.0/255.255.255.0"` | IPv4 pool for VPN clients in the `address/netmask` format (OpenVPN `server`). |
| openvpn.subnetIPv6 | string | `""` | IPv6 pool for VPN clients in the CIDR format (OpenVPN `server-ipv6`), e.g. `fd00:16:200::/64`. Empty disables IPv6 inside the tunnel. The pod needs IPv6 forwarding, see `podSecurityContext`. |
| openvpn.dualStack | bool | `false` | Accept OpenVPN clients over IPv4 and IPv6: `tcp6-server` listener and `ipFamilyPolicy: PreferDualStack` for the Services (IPv6 Service addresses require a dual-stack cluster). |
| openvpn.ipFamilies | list | `[]` | `ipFamilies` of the Services when `dualStack` is enabled, e.g. `[IPv4, IPv6]`. Every listed family must be enabled in the cluster. Empty lets `PreferDualStack` use the families of the cluster. |
| openvpn.inlet | string | `"HostPort"` |  |
| openvpn.externalIPs | list | `[]` | External IPv4 and/or IPv6 addresses of the `openvpn-external` Service if `inlet: ExternalIP`, they are also used as `remote` in client configs. The legacy single `externalIP` value is still supported. IPv6 addresses require `dualStack: true`. |
| openvpn.hostPort | int | `1194` |  |
| nodeSelector | object | `{}` | [Node selector](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#nodeselector) configuration. |
| tolerations | list | `[]` | [Tolerations](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) for node taints. See the [API reference](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#scheduling) for details. |
| podSecurityContext | object | `{}` | Pod [security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/). IPv6 inside the tunnel (`openvpn.subnetIPv6`) requires IPv6 forwarding in the pod: allow the unsafe sysctl `net.ipv6.conf.all.forwarding` on the kubelets ([docs](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/)) and set it here. |
| ingress.enabled | bool | `false` | Enable [ingress](https://kubernetes.io/docs/concepts/services-networking/ingress/). |
| ingress.className | string | `""` | Ingress [class name](https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-class). |
| ingress.annotations | object | `{}` | Annotations to be added to the ingress. |
| ingress.domain | string | `"changeme"` |  |
| ingress.basicAuth | object | `{"password":"","user":""}` | Credentials of the admin UI (ingress Basic Auth and the Basic Auth of ovpn-admin itself). Required: rendering fails if they are empty or the old defaults `admin`/`changeme`. |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
