# burnlink

## Problem

- old_burnlink, this app's predecessor, runs on a personal-namespace scaffold and HTTP library
  (`simonostendorf/scaffold`, `simonostendorf/web-kit`), not on this organisation's own tooling.
- Nobody in this organisation can fix a server-layer bug in old_burnlink through a version bump:
  the fix has to be copied in by hand, the drift web-kit itself was built to stop.
- A user sharing a one-time secret is unaffected either way; the app that serves them just lives
  outside the conventions, the CI and the release tooling every other repository here follows.
- A later maintainer inherits an MIT-licensed, personally-owned codebase for a service this
  organisation operates.

## Goals

- Run on govue: the server layer, the security headers, the probes and the metrics come from this
  organisation's own library, not a personal one.
- Carry the crypto contract forward unchanged: same payload format, same algorithms, same HKDF
  info string, ported from old_burnlink rather than rewritten.
- Deliver one-time delivery: a reveal reads and deletes a secret in the same store operation.
- Enforce a size limit, a rate limit and a lifetime on every stored secret.
- Answer every link it will not serve, unknown, expired, already opened or malformed, with one
  indistinguishable response.
- Run against any Redis-compatible store that speaks `SET NX PX` and `GETDEL`; the deployment
  runs Valkey behind it. The owner chose Valkey on 2026-11-18, replacing Dragonfly.

## Non goals

- The three additions below ship in later milestones. This document designs them ahead of that
  work. The webhook variant of the pickup notification exists; the CLI client and the mail
  variant do not.
- No migration of old_burnlink's own stored secrets: their lifetime is at most a week, so nothing
  outlives the cutover.
- No link issued by otp.ostendorf.cloud or old_burnlink gains new compatibility; the format and
  the service name are unchanged from old_burnlink, so old_burnlink's own links keep working, but
  nothing further is done for the generation before that.
- No chosen visual identity yet: the theme stays a placeholder palette until a brand is picked.
- No change to the payload format's version or byte layout. See
  [0002](../adr/0002-the-payload-format-stays-from-old-burnlink.md).

## Approach

- A Go binary, `cmd/burnlink`, wired on govue: timeouts, graceful shutdown, security headers,
  health, readiness and metrics on a second, administrative listener. A Vue 3 SPA, embedded into
  the same binary, consumes govue's design-token contract and components.
- The browser does every cryptographic operation. The server stores and serves ciphertext only
  and is never handed a key.
- The payload is a fixed, versioned binary contract, not an implementation detail: version, flags,
  an optional salt, an IV, then AES-256-GCM ciphertext and tag, with everything before the
  ciphertext as additional authenticated data. See the README and
  [0002](../adr/0002-the-payload-format-stays-from-old-burnlink.md) for the full layout.
- Three endpoints carry a secret's lifecycle: store it, ask whether it is still there without
  taking it, open and delete it in one step. Config and version endpoints sit alongside them.
  See "API surface" below.
- The store contract is two primitives: `SET NX PX` so a write never overwrites an existing
  secret, `GETDEL` so a reveal and a delete happen atomically and two readers cannot both win.
  The check that asks without taking is a third, a plain `GET`. Valkey's `GET` does not touch the
  key's TTL, so asking never extends a lifetime.
- The wiring, the store client, the five endpoints and the page that calls them exist, and
  readiness reports the store.
- The sender's page encrypts under a fresh 32 byte link key, stores the payload and shows
  `/s/<id>#<key>`. The recipient's page at `/s/<id>` checks that the fragment holds a valid key,
  then asks the check endpoint whether the secret is still there, which takes nothing. It waits
  for a click before it calls the open endpoint, so a preview that loads the page does not burn
  the link. It decrypts in the browser and strips the key from the address bar. The
  server has already deleted the secret by then, so a passphrase is asked for after the fetch and
  the payload is kept in the page's memory for retries. Closing the page loses the secret.
  The recipient's browser history still records `/s/<id>#<key>` when the page loads, and
  `replaceState` does not remove that entry: an unrevealed link there can be opened by someone
  with local access. The page is served `no-store` and `noindex`, and it wipes the key, the
  payload and the plaintext when it is hidden or unmounted. An offline brute force of a weak
  passphrase by someone holding the link is a property of the design; the page tells senders to
  choose a strong one. Argon2id instead of PBKDF2 would be a format change.

### API surface

| Method and path | Request | Answers |
| --- | --- | --- |
| `POST /api/v1/secrets` | JSON `{"ciphertext": <standard base64>, "lifetimeSeconds": <optional>, "notifyUrl": <optional>}` | `201` with `{"id", "expiresAt"}`, `400`, `403`, `413`, `415`, `429` |
| `HEAD /api/v1/secrets/{id}` | none | `200` with no body, or the one refusal |
| `POST /api/v1/secrets/{id}/open` | JSON content type, body ignored | `200` with `{"ciphertext"}` and the secret is gone, or the one refusal |
| `GET /api/v1/config` | none | `200` with `{"maxCiphertextBytes", "lifetime": {"minSeconds", "maxSeconds", "defaultSeconds"}}` |
| `GET /api/v1/version` | none | `200` with `{"version", "commit", "goVersion"}` |

- The id is 16 bytes from `crypto/rand`, 128 bits, as 22 characters of unpadded base64url. Only
  the canonical encoding is valid.
- The one refusal is `404` with a fixed body in govue's error shape and no request id, for an
  unknown, expired, already opened or malformed id alike, and for every other method or path under
  `/api/v1/secrets/`. On the `{id}` and `{id}/open` routes a malformed id is looked up under a
  fixed dummy id, so the store round trip happens either way. The catch-all answers without a
  store call and so in microseconds instead of milliseconds. That difference depends only on the
  path shape the client chose, never on stored state. Other timing is not equalised.
- `POST` requires the `application/json` content type, and a request the browser reports as
  cross site is refused with `403`. Every answer carries `Cache-Control: no-store`, the mux's own
  redirect of an unclean path under `/api/` included, through a middleware around the mux.
- The size limit applies to the decoded ciphertext and is enforced while the body is read. The
  JSON envelope gets 1 KiB of room on top of the base64 text, sized for compact JSON as
  `JSON.stringify` writes it. A client that escapes `/` as `\/`, as PHP does by default, can see
  a ciphertext near the limit refused with `413`. A lifetime outside the configured bounds is
  refused with `400`, never clamped. Lifetime settings are whole seconds.
- The JSON decoder is Go's own: field names match case insensitively, the last of two duplicate
  keys wins, and the base64 decoder ignores `\n` and `\r` inside the string. A space is a `400`.
- The rate limit is one budget per resolved client address across the three secret endpoints.
  The address comes from `X-Forwarded-For` only through the configured trusted proxy ranges.

Known limits:

- govue's limiter keeps at most 100000 client addresses and evicts one arbitrary bucket when it
  is full. An evicted client gets a fresh burst early.
- The check reads the whole value through `GET` and drops it, so one `HEAD` transfers up to the
  size limit from the store. The rate limit bounds that bandwidth.

### Request link

- The reverse flow: an owner publishes a link, anyone holding it can send the owner a secret back,
  and only the owner can open what arrives.
- Key material: the owner needs a keypair that lets a stranger encrypt to them without the owner
  being online at the time, which an asymmetric scheme fits. Settled in
  [0003](../adr/0003-request-link-key-material.md): a sealed box over X25519 with the existing
  AES-256-GCM AEAD, Web Crypto only, no dependency.
- Where the public key comes from: the request link's fragment carries it, the same way a send
  link's fragment carries the one-time link key, because the server must never see it either.
  Settled in 0003, with no server-side copy and no fallback.
- Where the private key lives: also settled in 0003. It is a non-extractable key in the browser's
  own storage, with no exportable copy and no second private link. A private link would be
  portable and backupable, and for that reason a long lived credential travelling through history,
  clipboards and chat logs, where one leak exposes every submission at once.
- Loss: losing the private key makes every secret ever sent to that request link permanently
  unrecoverable. The server holds only ciphertext and cannot help recover it either, because it
  was never given a key to begin with. 0003 names what destroys it: cleared site data, another
  browser or device, a private window, or a browser that drops script written storage after a
  period without interaction.
- Effect: the server still never learns the content of a submission, and is never handed key
  material either; it stores ciphertext it cannot decrypt, exactly as the send flow does. What is
  new is that a submitter has to trust the link they were given, because nothing lets them confirm
  the public key in it belongs to the owner.

### CLI client

- Shape: a second Go binary in this repository, `cmd/burnlink-cli`, alongside `cmd/burnlink`,
  rather than a separate repository. It needs no server-layer dependency, only this repository's
  payload format and the public API, and a second repository would buy it nothing but a second
  release to keep in step.
- Drift: the page's crypto is TypeScript, ported and reviewed as `web/src/lib/crypto.ts`; a Go
  CLI reimplementing the same payload format is a second language against one format, exactly what
  old_burnlink's own ADR 0002 flagged as a risk for a single implementation. A golden-file,
  cross-language test suite, encrypting in one language and decrypting in the other against the
  documented payload format, is proposed to hold the two honest, the same way old_burnlink's own
  crypto tests build a payload from the documented format and decrypt it. Whether this lands as a
  dedicated task target or as part of `task test` is open.
- Effect: the CLI changes nothing about what the server learns. It speaks the same public API as
  the page and carries no server-side counterpart of its own.

### Pickup notification

- New state: a sender may attach a notification target, a webhook URL or a mail address, to a
  secret. That target is new, genuinely new state the server stores alongside the id, the
  payload and the lifetime it already holds; unlike the payload, the server is not blind to it.
- Delivery: redeeming the secret, the same step that already reads and deletes it, becomes the
  trigger that fires the webhook or sends the mail, something the store operation does not do
  today.
- Cost: the server now learns who wants to know about a redemption and how to reach them. That is
  new information about the transaction's participants, not only a cost in storage: an outbound
  webhook call is also a new piece of attack surface, including the SSRF risk of calling a
  sender-supplied URL, that this app does not carry today.
- Effect: the server still never learns the secret's content. It does, for the first time, learn
  something about who is involved in exchanging it, which the core design otherwise never
  collects.

Built for the webhook, as decided:

- Scope: the sender may add `notifyUrl` to the store call, or nothing, which is the default. The
  mail address is a separate later milestone.
- Storage: the target sits under its own key `notify:<id>` with the secret's lifetime. Store
  writes the target first, then the secret, and drops the target when the secret write fails.
  Redeeming takes the secret first, then the target. The target is gone with the secret, and at
  the latest when the lifetime ends. A crash between the two takes loses the notification.
- Page: the field where the sender types the address says that the server stores it and learns
  it. The security page and the privacy text say the same.
- Delivery: after the secret is taken, one asynchronous POST with a JSON body of `id` and
  `redeemedAt` in UTC. The payload and the key never enter the notifier, and a test proves the
  body holds nothing else. A failed delivery never blocks or reverses a redemption.
- Validation at store time: scheme https, port 443 or none, no userinfo or fragment, printable
  ASCII, at most 2048 bytes, no blocked IP literal. A refusal is one fixed `400` that does not
  repeat the address.
- Validation at connect time: a `net.Dialer.Control` checks the resolved `ip:port` of every
  connection, so a name that resolves to a blocked address after the store call is still
  refused. Blocked IPv4: 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24,
  192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4.
  IPv6 allows only 2000::/3 minus 2001::/23, 2001:db8::/32, 2002::/16 and 3fff::/20. An IPv4
  mapped address is unmapped first and a zone is refused.
- Transport: no proxy, no keep-alive, redirects are never followed and a 3xx is a permanent
  failure. The response is read to 4 KiB and headers to 8 KiB.
- Retry and timeout: 3 attempts, 5 s each, 20 s in total, backoff 1 s then 4 s. A 2xx succeeds.
  A 5xx, 429, 408 or a transport error is retried. Any other 4xx, a 3xx and a blocked address
  stop at once. At most 32 notifications run at the same time, a further one is dropped and
  logged.
- Logging: one line with a fixed reason, never the URL, the host or the id.
- Guarantee: none beyond this. A notification can be lost, and the page says so.
- Known limits: a sender can make the server send one fixed POST to any public https host on
  port 443, bounded by the rate limit and the cap of 32. The request is not signed. A server
  restart drops notifications in flight, the shutdown waits for them up to a fixed time.

### Page view counting

- Shape: govue's `analytics` package, wired directly around the mux in `cmd/burnlink`. Off unless
  `UMAMI_URL` and `UMAMI_WEBSITE_ID` are both set. The server reports a view after the page was
  served, so nothing reaches the browser and no cookie is set.
- What is reported: the route pattern only, `/r/{id}` for every request link, never an id, a
  query string or the URL fragment. The fragment never reaches the server at all. The client
  address is masked to its /24 or /48. Do Not Track, Global Privacy Control, prefetch, bots and
  private client addresses are left out, and so are the API and every file the page loads.
- Effect: a counted view says that some page was opened. It never says which link, and a reveal is
  not an event. The server still never receives a key or a plaintext.
- The visitor facing text is the "What is counted" section of the security page.

## Alternatives considered

- Keep rewriting old_burnlink in place. Smaller change, no new repository. Rejected: old_burnlink's
  tooling, web-kit and its `simonostendorf/scaffold` generator, belongs to a personal namespace;
  moving the code without moving the repository leaves that mismatch unresolved.
- Depend on web-kit directly instead of govue. Reuses the exact library old_burnlink already runs
  on. Rejected: web-kit is not this organisation's library, and this repository already builds on
  govue, this organisation's own equivalent. Whether govue is a deliberate successor to web-kit or
  an independent library is not recorded anywhere either author's own documentation covers; see
  Open questions.
- Keep a server-rendered page instead of a Vue SPA. Keeps old_burnlink's no-build-step property.
  Rejected for the reason old_burnlink's own ADR 0001 already gave for its predecessor: the design
  system here is Vue components, and a hand-written page is exactly what that system replaces.

## Open questions

- Is govue a deliberate successor to web-kit, or an independent library this organisation wrote
  for the same purpose. Neither repository's own docs say. Next step: ask whoever set up govue, or
  check web-kit's own history once it is reachable.
- Request link's keypair primitive and where the keys live: decided in
  [0003](../adr/0003-request-link-key-material.md). Still open there: whether a submitter can be
  given any way to confirm the public key they were handed belongs to the owner, with the owner
  offline. Nothing was found that does this for an anonymous submitter. Next step: none known.
- The CLI's drift-prevention mechanism, a golden-file cross-language test suite, is proposed but
  not built. Next step: confirm the approach when `cmd/burnlink-cli` is scheduled.
- Pickup notification by mail. Not designed yet, tracked as its own issue. The webhook variant
  is built and decided, see "Pickup notification". Still open there: an operator switch to turn
  the webhook off, a signature on the request, and whether port 443 is too strict.

## Related ADRs

- [0001](../adr/0001-burnlink-succeeds-old-burnlink.md)
- [0002](../adr/0002-the-payload-format-stays-from-old-burnlink.md)
- [0003](../adr/0003-request-link-key-material.md)
