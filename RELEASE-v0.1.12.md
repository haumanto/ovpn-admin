# v0.1.12

Certificate expiry notices and safe renewal, plus a hardened login path.

This release adds the two certificate features that were waiting on this
version, fixes four login-path defects an independent review found in the
hardening commit, and adds the renewal controls to the panel.

**Two limits are stated plainly at the end of this file. Read them before you
rely on a slave setup or on the Disconnect button.**

## What is new since v0.1.11

### Certificate expiry and safe renewal

- **Expiry notices to Telegram.** The panel scans the certificates on a
  schedule and notifies you before a client or the **server** certificate runs
  out. The threshold is configurable (`OVPN_NOTIFY_CERT_DAYS`).
- **One-action safe renewal.** Renew a client certificate from the panel. The
  old certificate keeps working during a grace window, so a client can fetch
  the new profile without losing its tunnel first. The server certificate can
  be renewed the same way, and the panel tells you if the server needs a
  restart afterwards.
- **Panel controls.** An expiry badge on each client, a Renew action, a server
  certificate card with the restart banner, and a Disconnect action.

### Login hardening

- The panel refuses to start without credentials unless you ask it not to
  (`OVPN_INSECURE_NO_AUTH`).
- Repeated failed logins from one source are locked out for a growing window,
  and the message now reads correctly past the hour ("4 hours 0 minutes", not
  "3 hours 60 minutes").
- The lock is keyed on **source address plus user name**, so one noisy client
  cannot lock you out from somewhere else. Sources inside
  `OVPN_ADMIN_ALLOW_CIDR` are never locked.
- `/metrics` counts failed logins like every other path and is refused for a
  locked source.
- Weak password hashes are upgraded to the current cost at login. The upgrade
  goes through a spool file the panel applies, so the network-facing OpenVPN
  user never needs write access to the password database.

### Everywhere else

- Permanent repeat bans and manual ban and unban control.
- An audit trail of panel actions, and a hardened nginx and fail2ban
  deployment guide.
- A TLS floor on the panel listener, and the alert and Telegram delivery fixes
  from the previous releases of this line.

## Upgrading

Both compose files now set `OVPN_ADMIN_TRUST_PROXY=true` for the panel, and
name the failed-login settings (`OVPN_AUTH_MAX_FAILURES`,
`OVPN_AUTH_FAIL_WINDOW`, `OVPN_ADMIN_ALLOW_CIDR`). The binary's own flag and
the Helm chart default stay `false`.

`OVPN_ADMIN_TRUST_PROXY=true` means the panel believes `X-Forwarded-For`.
**Your reverse proxy must overwrite that header**, as the shipped nginx
example does. If the panel port is reachable without a proxy, set it to
`false`: then every client looks like the Docker bridge gateway and the lock
becomes one lock for everybody.

## Limits you need to know

1. **The Disconnect button does not disconnect anyone yet.** It sends the
   request and shows "Disconnect requested for NAME. The server did not report
   how many sessions it closed." The session keeps running. The button has been
   in the panel since v0.1.11 and the server-side implementation is scheduled
   for v0.1.13. Treat it as a request only.
2. **On a slave setup the Telegram address switch is ignored.**
   `docker-compose-slave.yaml` does not hand the `OVPN_TELEGRAM_*` settings to
   its containers, so `OVPN_TELEGRAM_INCLUDE_ADDRESS=false` never reaches them
   and a slave always sends the client address and user name in a ban message.
   The slave panel's failed-login flood alert also logs its CRITICAL line
   without sending the Telegram message. The main `docker-compose.yaml` is not
   affected. Fixed in v0.1.13.

Two smaller notes: the shipped nginx example still carries an old comment
saying the panel ignores `X-Forwarded-For` (it does not, with the compose
default), and a panel started without a `pki` directory logs a re-hash spool
warning every five seconds. Neither blocks a deployment.

## Verification

- Independent review of the login path found four defects in the hardening
  commit. All four were fixed and re-checked by the reviewer that found them:
  205 assertions, 0 failures, plus the full suite.
- The release gate ran on one commit with all eight checks passing: clean
  tree, the release build path (`build.sh`, with both panel bundles inside the
  binary), the suite at 403 pass and 0 fail, all 51 feature symbols present,
  the Telegram settings reaching the panel container, no secrets, no stray
  files, and the version strings correct before the bump.
- Full details are in the release-gate report shipped beside this file.

## Assets

- `ovpn-admin-linux-amd64.tar.gz`, `ovpn-admin-linux-arm64.tar.gz` and their
  `.md5` files.
- Multi-arch panel and OpenVPN images on GHCR.
- The Helm chart as `openvpn-admin-0.1.12`.
- SBOMs.
