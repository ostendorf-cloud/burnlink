# burnlink

One time secret sharing: the browser encrypts, the server hands it out exactly once.

## What it does

burnlink lets someone share a secret, text or a file, through a link that works exactly once.
The browser encrypts the secret before it ever leaves the device; the server stores only
ciphertext and never sees a key. A lifetime, a size limit and a rate limit bound what the server
will hold, and every link it will not serve, whether unknown, expired or already opened, gets the
same answer, so the response itself cannot be used to tell those cases apart. A passphrase can
protect a secret in addition to the link key. The payload format is a contract with the page, not
an implementation detail: changing it means a new version, not a silent edit. The store is
Redis-compatible, read with `GETDEL` so a reveal and a delete happen in one step, and written with
`SET NX PX` so a second write can never overwrite an existing one; the deployment runs Valkey
behind it.

The server side is implemented: the store client and the five API endpoints in
`docs/concepts/burnlink.md`. The page that encrypts, and the CLI and the notification, are still
ahead. See `AGENTS.md`'s "Scope of this milestone" for what is built and what is not.

## Install

```sh
task setup
```

Installs the pinned toolchain (Go, Node, pnpm, Helm and the rest) through `mise`.

## Use

```sh
task build
./bin/burnlink
```

The server reads its configuration from the environment; see the Configuration table below.
The store credentials are the only secret-shaped variables and have `_FILE` twins. `/healthz`,
`/readyz` and `/metrics` answer on a second, administrative listener (`ADMIN_ADDR`), never on the
public one.

## Configuration

| Variable | Purpose | Default | Required |
| --- | --- | --- | --- |
| `ADDR` | Address the public HTTP server listens on | `:8080` | no |
| `ADMIN_ADDR` | Address govue's admin listener listens on: `/healthz`, `/readyz` and `/metrics` | `:8081` | no |
| `LOG_LEVEL` | `debug`, `info`, `warn` or `error` | `info` | no |
| `STORE_ADDR` | Address of the Redis-compatible store, `host:port` | none | yes |
| `TRUSTED_PROXY_CIDRS` | CIDRs, comma separated, whose `X-Forwarded-For` is trusted | empty, trust none | no |
| `SECRET_MAX_BYTES` | Largest ciphertext accepted, decoded, in bytes (1 to 67108864) | `1048576` | no |
| `SECRET_LIFETIME_MIN` | Shortest lifetime a sender may ask for, for example `30s` or `7d` | `1m` | no |
| `SECRET_LIFETIME_MAX` | Longest lifetime a sender may ask for (up to `30d`) | `7d` | no |
| `SECRET_LIFETIME_DEFAULT` | Lifetime used when none is asked for, between min and max | `24h` | no |
| `RATE_LIMIT_BURST` | Requests per client address at once | `10` | no |
| `RATE_LIMIT_PER` | Period over which the burst refills completely | `1m` | no |

## Container

```sh
docker compose up --build
```

Builds the image from `Dockerfile` (a Node stage for the frontend, a Go stage for the binary, a
distroless runtime) and publishes both listeners on `127.0.0.1`. The Helm chart lives in
`charts/burnlink`; see its own `README.md` for installation and values.

## Development

```sh
task check
```

Runs every lint, test and build target in one pass, the same gate CI runs. `task --list` shows the
individual targets.

## License

[Apache-2.0](LICENSE).
