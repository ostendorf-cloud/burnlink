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

The server side and the page are implemented: the store client, the five API endpoints in
`docs/concepts/burnlink.md`, the pages that share and reveal a secret, and `burnlink-cli`, which
does the same from a terminal. The mail notification is still ahead. A webhook notification when
a link is opened exists. See
`AGENTS.md`'s "Scope of this milestone" for what is built and what is not.

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

## Command line client

`burnlink-cli` encrypts on your machine with the same format as the page. The archives for Linux,
macOS and Windows (amd64 and arm64) are attached to every release, with a checksum file.

```sh
# Text from standard input, prints one link
echo 'the secret' | burnlink-cli send --lifetime 12h

# A file, under the name it has or --name
burnlink-cli send --file ./id_ed25519.pub

# Open a link: text goes to standard output, a file is saved without replacing another
burnlink-cli open 'https://burnlink.de/s/<id>#<key>'
burnlink-cli open --out ./received/ 'https://burnlink.de/s/<id>#<key>'
```

| Setting | Purpose |
| --- | --- |
| `--server URL` or `BURNLINK_SERVER` | Server to send to, default `https://burnlink.de`. `open` uses the link's own server |
| `--lifetime` | How long the link stays valid, such as `30m`, `12h` or `7d`. The server's limits apply |
| `BURNLINK_PASSPHRASE` or `BURNLINK_PASSPHRASE_FILE` (`--passphrase-file`) | Passphrase for `send` and `open`. Never a flag, which would show up in the process list |
| `--out` | `open` only: a path that must not exist, a directory, or `-` for standard output |
| `open -` | Reads the link from standard input, which keeps the key out of the process list |

- The link is the only output of `send` on standard output, everything else goes to standard
  error.
- Limitation: the server deletes a secret when it is opened, and the client cannot ask whether a
  passphrase is needed first. A missing or wrong passphrase means the secret is gone and the
  sender has to send a new one.
- On a terminal, `open` shows control characters as escapes. Redirect the output or use `--out`
  to get the exact bytes.

## Configuration

| Variable | Purpose | Default | Required |
| --- | --- | --- | --- |
| `ADDR` | Address the public HTTP server listens on | `:8080` | no |
| `ADMIN_ADDR` | Address govue's admin listener listens on: `/healthz`, `/readyz` and `/metrics` | `:8081` | no |
| `LOG_LEVEL` | `debug`, `info`, `warn` or `error` | `info` | no |
| `STORE_ADDR` | Address of the Redis-compatible store, `host:port` | none | yes |
| `TRUSTED_PROXIES` | CIDRs, comma separated, whose `X-Forwarded-For` is trusted | empty, trust none | no |
| `SECRET_MAX_BYTES` | Largest ciphertext accepted, decoded, in bytes (1 to 67108864) | `1048576` | no |
| `SECRET_LIFETIME_MIN` | Shortest lifetime a sender may ask for, in whole seconds, for example `30s` or `7d` | `1m` | no |
| `SECRET_LIFETIME_MAX` | Longest lifetime a sender may ask for (up to `30d`) | `7d` | no |
| `SECRET_LIFETIME_DEFAULT` | Lifetime used when none is asked for, between min and max | `24h` | no |
| `RATE_LIMIT_BURST` | Requests per client address at once | `10` | no |
| `RATE_LIMIT_PER` | Period over which the burst refills completely | `1m` | no |
| `UMAMI_URL` | Base URL of the Umami instance that receives page views. Counting is off unless this and `UMAMI_WEBSITE_ID` are both set; one alone is a startup error | empty, off | no |
| `UMAMI_WEBSITE_ID` | UUID of the website in Umami | empty, off | no |
| `SITE_URL` | Public origin without a path, https unless localhost. Base of the sitemap, robots.txt and canonical links; its bare host is reported to Umami as the hostname of a view | `https://burnlink.de` | no |
| `UMAMI_TIMEOUT` | Bound of one post to Umami, 1s to 30s | `5s` | no |
| `UMAMI_QUEUE_SIZE` | Views that may wait to be sent, 1 to 10000. A full queue drops the view | `256` | no |

## Page view counting

The server counts page views and reports them to Umami after the page was served, through
govue's `analytics` package. Nothing runs in the browser and no cookie is set.

- Counted: the route pattern of a page, such as `/` or `/r/{id}`, never the path, an id or a query
  string. Every request link is the one entry `/r/{id}`.
- Sent with it: the site's host, the first language tag, the user agent, the referring origin
  without a path, and the client address masked to its /24 (IPv4) or /48 (IPv6).
- Not counted: the API, files the page loads, the health and metrics routes, a visitor with Do
  Not Track or Global Privacy Control, a prefetch, a bot and a client on a private address.
- A slow or failing Umami never delays or fails a response.
- The server still never receives a key or a plaintext: the key stays in the URL fragment.

The text a visitor reads is on the security page (`web/src/views/SecurityView.vue`). The legal
privacy notice of the operator is `web/src/legal/PrivacyText.vue`.

## Legal pages

- `/de/imprint`, `/en/imprint`, `/de/privacy` and `/en/privacy` are prerendered at build time
  with govue's `GovueLegalPage` and `govue-prerender`, and served by `cmd/burnlink/legal.go`.
- `language.HandleLegal` redirects `/imprint`, `/privacy` and the German aliases `/impressum`,
  `/datenschutz` and `/datenschutzerklaerung` to the matching page. There is no terms page, so
  `/terms` and `/agb` answer 404.
- `govue-check-legal` runs in `pnpm run build` and fails when a prerendered page lacks the
  footer links.
- A change to what the server stores, logs or counts changes `PrivacyText.vue` in the same
  commit.

## Container

```sh
docker compose up --build
```

Builds the image from `Dockerfile` (a Node stage for the frontend, a Go stage for the binary, a
distroless runtime) and publishes both listeners on `127.0.0.1`. The Helm chart lives in
`charts/burnlink`; see its own `README.md` for installation and values.

The published image `ghcr.io/ostendorf-cloud/burnlink` is one manifest list for `linux/amd64` and
`linux/arm64`.

## Development

```sh
task check
```

Runs every lint, test and build target in one pass, the same gate CI runs. `task --list` shows the
individual targets.

## License

[Apache-2.0](LICENSE).
