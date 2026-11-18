# ovpn-admin v0.1.5 release notes

**Status: release candidate, not published.** Nothing here is tagged, pushed, or released. No `v0.1.5` tag, image, or binary exists yet. Publishing is a Conductor step and needs its own approval.

- Candidate: branch `v0.1.5`, code SHA `d6dcd4073dbb3a7218931564f23d29046a8435ae`. The commit that adds this file sits on top of it and changes only `RELEASE-v0.1.5.md`, `README.md` and `UPGRADING.md`.
- QA: `qa-v015/REPORT.md` (card t_d8ec88a4), verdict **SHIP** at the candidate SHA, items 1 to 12 PASS. Real OpenVPN 2.7.7 clients. Telegram was a local mock. The real Telegram API was never called.
- Static audit: `v015/audit/REPORT.md` (PASS WITH FINDINGS, reviewed `d66fa47`). Delta review: `v015/audit/DELTA-REPORT.md` (PASS-WITH-FINDINGS, reviewed `d6dcd40`). Findings F1, F2 and F4 are closed in the candidate. F3 is partly closed. F5 is open.

Source tags used below: `[QA n]` = QA report item n. `[P15]` = `v015/p15-telegram.txt`. `[audit Fn]` / `[delta Fn]` = auditor finding n. `[commit X]` = commit message or diff of X.

## What changed since v0.1.4

- **Telegram message for every new ban.** Off by default. A new ban sends one plain-text message after the DROP rule and the `bans.tsv` row are written. Unban sends nothing. `[commit 0add172]` `[QA 3]`
- **Token from a file.** `OVPN_TELEGRAM_BOT_TOKEN_FILE` names a readable file whose first line is the token. When set, the file wins over `OVPN_TELEGRAM_BOT_TOKEN`. `[commit d6dcd40]` `[QA 6]`
- **HTTPS by default for the API base.** `http://` is refused unless `OVPN_TELEGRAM_ALLOW_HTTP=true`, which is for local mock tests only. `[delta F2]` `[QA 10]`
- **One URL check.** The API base must have a host, a numeric port from 1 to 65535, no user info, no query and no fragment. The same check runs at start and before each send. `[delta F4]` `[QA 10]`
- **Env files kept out of Git and the build context.** `.env`, `.env.*` and `*.env` are ignored (`.env.example` stays allowed). `[delta F1]`
- **Compose files.** Both `docker-compose.yaml` and `docker-compose-slave.yaml` pass the seven Telegram variables with safe defaults. The token file mount is a commented example, not a default. `[commit d6dcd40]`
- **Version string** `0.1.5` in the Go binary, the chart and the frontend package. No other code change in the UI: QA saw the UI unchanged apart from the version. `[QA 11]` `[commit d66fa47]`

The Helm chart does not carry the Telegram settings in this release. `[grep of charts/]`

## Telegram setup

The steps below use Telegram's public Bot API. QA did not run them against the real Telegram API. Treat them as untested in this release.

1. **Create the bot.** In Telegram, open `@BotFather`, send `/newbot`, and follow the prompts. BotFather returns a token that looks like `<digits>:<characters>`. Keep it secret. Save it in a file outside the repository, with mode 0600.
2. **Get the chat id.** Add the bot to the group or channel. Send one message there. Open this URL in a browser, with your token in place of the placeholder:

   ```
   https://api.telegram.org/bot<BOT_TOKEN>/getUpdates
   ```

   Read `result[].message.chat.id` (or `result[].channel_post.chat.id` for a channel). Groups and channels have negative ids that start with `-100`. If `result` is empty, send another message in the chat and try again. The URL contains the token, so do not paste it anywhere.
3. **Optional: thread id.** For a forum topic in a group, the thread id is the second number in a topic message link, `https://t.me/c/<group>/<thread>/<message>`. Set `OVPN_TELEGRAM_THREAD_ID` to that number. Leave it empty for a plain group or channel.

Then set the variables, put the token in the mounted file, and start the stack:

```
OVPN_TELEGRAM_ENABLED=true
OVPN_TELEGRAM_BOT_TOKEN_FILE=/run/secrets/telegram-bot-token
OVPN_TELEGRAM_CHAT_ID=<chat id, e.g. -100XXXXXXXXXX>
```

In `docker-compose.yaml` (and the slave file), uncomment the read-only mount and point it at your token file:

```
- /path/on/host/telegram-bot-token:/run/secrets/telegram-bot-token:ro
```

The start log should print `telegram notifications: enabled`. A wrong setting prints one `ERROR` line that names it. The VPN still starts, with notifications off. `[QA 9]` `[P15 F, F2, G]`

## Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `OVPN_TELEGRAM_ENABLED` | `false` | `true` turns notifications on. Needs a token and a chat id. Any value other than `true` or `false` is an error and leaves notifications off |
| `OVPN_TELEGRAM_BOT_TOKEN` | empty | Bot token from BotFather. Visible in container configuration (see Token security) |
| `OVPN_TELEGRAM_BOT_TOKEN_FILE` | empty | Path inside the container to a file whose first line is the token. Wins over `OVPN_TELEGRAM_BOT_TOKEN` |
| `OVPN_TELEGRAM_CHAT_ID` | empty | Integer chat id (`-100...` for groups and channels), or `@channelname` |
| `OVPN_TELEGRAM_THREAD_ID` | empty | Optional forum topic id, a positive integer |
| `OVPN_TELEGRAM_API_BASE` | `https://api.telegram.org` | Bot API base URL. Use `https://`. Only set it for a self-hosted endpoint |
| `OVPN_TELEGRAM_ALLOW_HTTP` | `false` | Accepts an `http://` base. For local mock tests only |

`[compose defaults at d6dcd40]` `[P15 compose render]` `[delta F2, F3, F4]`

## Message example

Plain text, no `parse_mode`, one message per new ban:

```
🚫 ovpn-admin: banned 203.0.113.10
Reason: auth-failed
Attempts: 3
Until: 2026-11-18 03:51 UTC
Server: <container hostname>
```

- `Reason` is `auth-failed`, `revoked-certificate`, both joined with `+`, or `fail2ban` when the log shows no matching failure line.
- `Until` is the UTC expiry of the ban.
- `Server` is the hostname of the `openvpn` container, not the host.
- Without a thread id, `message_thread_id` is not sent. `[QA 3]` `[commit ovpn-ban.sh reason_for]`

## Failure behavior

- **The ban comes first.** The DROP rule and the `bans.tsv` row are written before any message. A Telegram error never removes or reverses a ban, and the ban action still exits 0. `[audit ban-before-notify, static]` `[QA 7]`
- **One attempt per new ban.** No retry, no queue. A ban of an address that is already banned sends nothing. `[delta 7]` `[P15 B]` `[QA 7]`
- **One warning on failure.** The warning goes to the fail2ban log and to container output. Examples measured in QA:
  - `ovpn-telegram-notify: WARNING: notification for 203.0.113.11 failed: Telegram answered HTTP 500`
  - `ovpn-telegram-notify: WARNING: notification for 203.0.113.10 failed: cannot reach the Telegram API (ConnectionRefusedError errno 111)`

  The warning never contains the token, the URL or the response body. `[QA 7]`
- **Timing.** The HTTP timeout is 10 seconds. The ban action waits at most 20 seconds for the notifier. A slow Telegram endpoint can therefore delay later ban actions. It cannot undo a ban. `[delta F5]` `[commit ovpn-telegram-notify.py TIMEOUT_SECONDS=10]` `[ovpn-ban.sh timeout 20]`
- **Bad settings at start.** With `OVPN_TELEGRAM_ENABLED=true`, a missing or malformed token, chat id, thread id or API base logs one `ERROR` line. Notifications stay off and the VPN starts. `[QA 9]` `[P15 F, F2, G]`
- **Restarts send again.** After a container restart, any address with enough failures inside the find time is banned again. Each re-ban sends a new message. QA measured three re-bans and three messages. `[QA N1]`

## Token security

- The bot token is a secret. Anyone who has it can send as the bot. If it leaks, revoke it in `@BotFather` and update the file.
- **Prefer the token file.** Use `OVPN_TELEGRAM_BOT_TOKEN_FILE` with a mode 0600 file, outside the repository, mounted read-only. QA measured this with a wrong token in the variable and the right one in the file: the file token was used, and the wrong variable value appeared in no log. `[QA 6, tokfile]`
- **Setting both does not hide the variable.** The variable value still appears in the Compose configuration. Use the file alone.
- **With notifications on, the token is in the `fail2ban-server` environment** in both input modes. Anyone who can read that process environment as a privileged user can read the token. Restrict daemon and process inspection on the host. `[delta F3]` `[QA N2]`
- **With the variable and notifications off,** the token is still in the environment of one short-lived `configure.sh` child process. `[QA N2]`
- **The token is not in:** process arguments, the `openvpn` process, the `ovpn-admin` container, container logs, the fail2ban log, the OpenVPN log, audit files, or any file in the container. `[QA 6, N2]`
- **`docker inspect` and `docker exec` show the variable** when the variable input is used. That is how Compose passes variables. `[QA N2]`
- **Keep env files out of Git and the build context.** `.env` and `*.env` are ignored now. The ignore rules do not remove a copy that is already committed or cached. If a real token ever reached Git, an image, a cache or shell history, revoke it and create a new one. `[delta F1]`
- **Do not type the token on a command line.** It stays in shell history and process listings. Use a file.
- **Keep the base on HTTPS.** With `http://`, the token is in the URL path on the wire. The API base must not contain user info, a query or a fragment. `[delta F2, F4]`

## Upgrade notes

- **Rebuild the images. No database migration.** `easyrsa_master/`, `ccd_master/` and `users.db` do not change. The diff from `v0.1.4` has no schema or SQL change. `[diff v0.1.4..d6dcd40]`
- **Notifications are off by default.** Upgrading changes nothing for sending until you set `OVPN_TELEGRAM_ENABLED=true`.
- Step-by-step: [UPGRADING.md](UPGRADING.md#v014--v015).

## Known limitations

- **Not published.** Candidate only. Publishing needs approval.
- **Real Telegram API not tested.** All QA deliveries went to a local mock (`http://mock:8081`, with `OVPN_TELEGRAM_ALLOW_HTTP=true`). Real HTTPS with certificates was not tested. Real Telegram errors, such as a bot that is not in the chat, take the same warning path, but that was not checked against the API.
- **Not tested in QA:** a slow or hanging endpoint (the 10 s and 20 s limits, auditor F5), redirects, an HTTP 200 without `ok:true`, the slave compose file, the Helm chart (it has no Telegram settings), UDP listeners, a malformed token or thread id at start, an unreadable or empty token file, and `OVPN_BAN_ENABLED=false` with Telegram on. `[QA Known Limitations]`
- **Token visibility (auditor F3, partly closed).** With notifications on, the token is in the `fail2ban-server` environment in both input modes. The file input reduces exposure but does not remove it. Anyone with privileged container or process inspection can read it. Accepted by the Conductor. `[delta F3]`
- **Slow endpoint delays later bans (auditor F5, open).** The ban action waits up to 20 seconds for delivery. The DROP rule is already in place, but later actions can be delayed if the jail runs them one at a time. Accepted by the Conductor. `[delta F5]`
- **Restarts send again** (QA N1). Each re-ban sends one message, and the `Until` time starts again.
- **Closed port:** "exactly one attempt" was shown by one warning and a ban within 2 s, not by counting packets. `[QA Known Limitations]`
- **Unban sends nothing** by design. The 30-minute expiry was not waited for.
- **Downgrade** from v0.1.5 to an older release was not tested.
- **The `OVPN_BAN_ENABLED=false` warning** (Telegram on, bans off) is in the start code. It was not run in QA.
