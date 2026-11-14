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
`SET NX PX` so a second write can never overwrite an existing one; the deployment runs Dragonfly
behind it.

None of the above is implemented yet. This repository is currently a scaffold: it wires the Go
service to the embedded Vue build and to health, readiness and metrics, with no crypto, no store
client and no API routes. See `AGENTS.md`'s "Scope of this milestone" for what is built and what
is still ahead.

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
There is no secret-shaped variable yet. `/healthz`, `/readyz` and `/metrics` answer on a
second, administrative listener (`ADMIN_ADDR`), never on the public one.

## Configuration

| Variable | Purpose | Default | Required |
| --- | --- | --- | --- |
| `ADDR` | Address the public HTTP server listens on | `:8080` | no |
| `ADMIN_ADDR` | Address govue's admin listener listens on: `/healthz`, `/readyz` and `/metrics` | `:8081` | no |
| `LOG_LEVEL` | `debug`, `info`, `warn` or `error` | `info` | no |

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
