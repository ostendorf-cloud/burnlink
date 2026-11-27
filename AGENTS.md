# burnlink

One time secret sharing: the browser encrypts, the server stores only ciphertext and hands it
out exactly once.

The global baseline already applies here and is not repeated below.

## Layout

- `cmd/burnlink` wires the app: `main.go` builds the public handler (the embedded SPA behind
  govue's default security headers and access log) and the admin handler (health, readiness and
  metrics on a second listener, through `httpserver.RunAdmin`), and runs both.
  `embed.go` embeds `dist/` (the built SPA, written by `task web:build`) next to the Go source
  file, which is why it sits under `cmd/` rather than `internal/`.
- `internal/config` loads and validates this service's own environment once, aggregated into
  one error. The store's address (`STORE_ADDR`, required), `STORE_TLS` and its two credentials,
  `STORE_USERNAME` and `STORE_PASSWORD`, each with a `_FILE` twin, are in `config.Store`, which
  never prints a credential.
- `internal/depsync` checks that `go.mod` and `web/package.json` pin the same govue version, and
  that `web/pnpm-lock.yaml` still resolves govue's Vue package to its `/web` subdirectory. Ported
  from ostendorf.tech's own package of the same name, which this one is a close copy of: the
  check is generic to any repository consuming govue's two halves.
- `internal/store` defines `Store`, the small key/value contract (`SET NX PX`, a plain `Get`, and
  `GETDEL`) every handler that needs persistence is written against; `internal/store/memstore` is
  an in-process implementation for tests only, never wired into `cmd/burnlink`.
  `store.Secrets` (`Put`, `Take`, `Exists`, `Ping`) is the one time secret API over a
  `store.Backend`. `Exists` is a plain `GET`, which leaves the TTL alone. It has two sentinels:
  `ErrExists`, and `ErrNotFound` for expired, taken and never existed alike.
  `internal/store/redisstore` is the production client (go-redis), wired into `cmd/burnlink`
  through readiness. Size limit, id validation and lifetime choice belong to the API layer.
  Its tests against a real server need `BURNLINK_TEST_REDIS_ADDR=host:port`, set from a service
  container in CI, and skip loudly without it.
- `internal/webapp/secrets` serves the five endpoints of a one time secret link under
  `/api/v1` (store, check, open, config, version), written against `store.Secrets`. Every link it
  will not serve gets one fixed 404, see "API surface" in `docs/concepts/burnlink.md`. It uses
  govue's `ratelimit`, `clientip`, `csrf` and `api`, and `internal/buildinfo` for the version.
  `internal/config` also loads `SECRET_*` and `RATE_LIMIT_*`, none of them secret shaped.
- Page views are counted by govue's `analytics`, wired in `cmd/burnlink` directly around the mux
  (innermost: it reads the route pattern the mux sets, which `RequestID` and the security
  middleware would hide). `UMAMI_URL` and `UMAMI_WEBSITE_ID` come from
  `internal/config`, and so does `SITE_URL` (default `https://burnlink.de`), whose bare hostname
  is the one reported. `mountLegal` rewrites the origin the web build bakes into the legal
  pages, `sitemap.xml` and `robots.txt` to `SITE_URL`. Never count an id, a query or an API
  route; the tests in `cmd/burnlink/analytics_test.go` pin that. A change to what is reported
  also changes the "What is counted" card in `SecurityView.vue`.
- The legal pages (`web/src/legal/`: `ImprintText.vue`, `PrivacyText.vue`, `LegalView.vue`) are
  the site's own texts in German and English. `web/src/site.ts` is the SSR entry: `pnpm run
  build` runs the client build, the SSR build into `web/.ssr`, `govue-prerender --out-dir` and
  `govue-check-legal`, all into `cmd/burnlink/dist`. `cmd/burnlink/legal.go` serves the four
  pages and mounts `language.HandleLegal` without `Terms`: the site has no terms, so no
  `/terms` and no `/agb`. `main.ts` mounts the legal view when the path is a legal page, else
  `App`. A change to what the server stores, logs or counts changes `PrivacyText.vue` in the
  same commit.
- `internal/webapp/requestlink` answers the request link's own endpoints: create a link, submit a
  sealed payload to it, and open everything waiting for the owner. Written against
  `internal/store.Store`, not against `memstore` directly, so swapping in the real client changes
  no call site here.
- `web/` is the Vue SPA, consuming govue's Vue package as a pnpm git dependency. There is still no
  router dependency: `App.vue` tells a request link's own page (`/r/<id>`, `RequestLinkView.vue`)
  and a secret link's page (`/s/<id>`, `RevealSecretView.vue`) apart from the home page
  (`ShareSecret.vue` and `CreateRequestLink.vue`) by the URL path alone, and shows
  `SecurityView.vue` on `/security`; `cmd/burnlink` answers exactly `/security`, `/r/<id>` and
  `/s/<id>` (one path segment) with `index.html`, every other unknown path, `/api/` included,
  with 404. The share and reveal pages call `secrets-api.ts` (the five endpoints through govue's
  client) and use `crypto.ts` unchanged; `secret-link.ts` builds and reads `/s/<id>#<key>`. The
  reveal page opens the secret only on a click, never on load, so a link preview does not burn
  it. `/s/<id>` is served with `Cache-Control: no-store` and `X-Robots-Tag: noindex`, and the
  reveal page wipes the key, the payload and the plaintext on unmount and on `pagehide` and
  `pageshow` (persisted), so a page from the back/forward cache never shows a secret again.
  The app pages stay English only; the legal pages carry German and English.
  Every view renders inside `GovuePage`, the `main#main` the skip link points to.
  `SecurityView.vue` explains the encryption and marks what is not running yet, so it changes in
  the same commit as the format or the store wiring. `web/src/lib/request-link-crypto.ts` is the request
  link's own sealed-box crypto, Web Crypto only like `crypto.ts`, which it sits alongside and
  never changes; `request-link-keys.ts` is the thin, intentionally untested IndexedDB glue that
  stores the owner's non-extractable private key; `request-link.ts` builds and reads the link's
  own URL and fragment; `request-link-api.ts` calls `internal/webapp/requestlink`'s endpoints
  through govue's own API client.
- `charts/burnlink/` is the Helm chart. See its own `README.md` for installation and values.

## A build needs the frontend first

`cmd/burnlink` cannot compile against an empty `dist/` directory, because `go:embed` fails when
its pattern matches no file at all. `dist/` is gitignored, generated by `task web:build`.

`task build` and `task test:go` both declare that dependency, so running either one through Task
always populates the frontend first. A bare `go build ./cmd/burnlink` or `go test
./cmd/burnlink/...` outside Task fails on a fresh checkout for that reason; run `task build` or
`task test:go` instead, or `task web:build` once by hand before reaching for the Go toolchain
directly.

## govue's two halves move together

govue releases a Go module and a Vue package under one tag. `go.mod`'s
`require github.com/ostendorf-cloud/govue` and `web/package.json`'s `@ostendorf-cloud/govue`
pnpm git dependency must always name the same tag. `task check:govue-version`
(`internal/depsync`) enforces this; see that package's own comments for the full reasoning,
including the pnpm/pnpm#12304 lockfile check `TestLockfilePinsGovueSubdirectory` exists for.

Renovate proposes a govue release as one pull request, group `govue`. A regex manager in
`renovate.json` reads the tag from `web/package.json`, because the npm manager skips that
specifier. The shared `govue-lockfile` preset regenerates `web/pnpm-lock.yaml`. The rule's
`constraints.pnpm` must equal the pnpm pin in `mise.toml`, and `internal/depsync` tests it. A
`pnpm` group rule moves both pins in one pull request.

## Verify before committing

```sh
task check
```

`task --list` shows the individual targets, including the small ones `task check` aggregates.

## Scope of this milestone

The Go entry point, the embedded Vue build, health, readiness and metrics on govue's admin
listener, the Helm chart, the container build, the store client and the five secret endpoints
exist, and so does the page that encrypts in the browser, calls the endpoints and reveals a
secret once. Left out, tracked as later milestones:

- A CLI client: sending a secret from a terminal with the same crypto the page uses.
- A pickup notification: a sender optionally leaves a webhook or a mail address and learns when
  their link was redeemed, with the server learning nothing about the secret's content either way.

The request-link feature, the reverse direction where an owner publishes a link and a stranger
seals a secret back to it, is implemented: the crypto, `internal/webapp/requestlink`'s three
endpoints, and the two views above. It is not yet reachable from the running binary:
`cmd/burnlink`'s handler registers no routes under `internal/webapp/requestlink` because doing so
needs a `store.Store` backed by something that survives a restart and is shared across replicas.
`redisstore.Client` is that store; only the wiring is missing. `internal/store/memstore` exists
only so this feature's own handler tests do not have to wait for that; wiring it into
`cmd/burnlink` instead would quietly break the Helm chart's multi-replica assumption, since two
pods would then each hold submissions the other cannot see.

## Deviations

- Apache-2.0, not the predecessor repository's MIT. Deliberate: this is a new organisation
  repository, and the baseline's default license applies.
- Every CI job runs on `ubuntu-latest`, with a `codeql.yaml` workflow and a `license` job, instead
  of a self-hosted Blacksmith runner: this repository is public, so its minutes are not billed,
  and it needs GitHub Advanced Security for code scanning rather than lacking it.
- release-me, not release-please, owns the version, `CHANGELOG.md` and the tag.
- The Helm chart ships no single-replica guard and no `strategy.type: Recreate`: this scaffold
  keeps no server-side session state, so more than one replica, or two pods briefly coexisting
  during a rollout, is harmless.
- `values.schema.json` does not mark `config.store.addr` or the `existingSecret` keys required:
  the template's fail guards enforce them, like the other values with no usable default. The
  store credentials are optional, a store without authentication being valid, and reach the pod
  as mounted files through the `_FILE` variables, never as environment values.
- `web/src/theme/burnlink.css` is generated by govue's theme generator from
  `web/src/theme/burnlink.seeds.json` (a warm grey neutral, a red orange accent). The seeds are
  a proposal the owner may swap: edit the two hex values and regenerate.
