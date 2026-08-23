# cerberus-bot

Ban/kill audit IRC bot, inspired by Libera Chat's
[Beryllia](https://github.com/Libera-Chat/beryllia). Opers up and
listens for every KLINE, DLINE, XLINE, RESV, and KILL on the network --
from Atheme services, other bots, or staff directly, it's all the same
underlying server notice -- records each one in Postgres, and answers
`KCHECK <query>` searches over that history via PM.

## Requirements

- Go 1.22+ (or just Docker)
- A Postgres database
- An IRC operator account for the bot with `usermode:servnotice`
  (needed to receive the `+s`/`+k` snomask categories this bot listens
  on) and a NickServ account for it to identify with

## Run

```sh
docker build -t cerberus-bot .
docker run -d --name cerberus-bot \
  -e CERBERUS_NICKSERV_PASSWORD=... \
  -e CERBERUS_OPER_PASSWORD=... \
  -e CERBERUS_ADMIN_ACCOUNTS=youraccount \
  -e DATABASE_URL="postgres://user:pass@host:5432/cerberus?sslmode=disable" \
  cerberus-bot
```

Optional env vars (with their defaults): `IRC_SERVER`
(irc.chatnet.gg), `IRC_PORT` (6697), `CERBERUS_NICK` (Cerberus),
`CERBERUS_CHANNEL` (#CN-Bot).

## Commands

All via `/msg Cerberus <command>`, admin-only (WHOIS-verified against
`CERBERUS_ADMIN_ACCOUNTS`):

- `KCHECK <nick|host|ip|mask|text>` -- substring search across every
  recorded ban/kill's target, reason, and issuing oper.
- `HELP`

## License

MIT, see [LICENSE](LICENSE).
