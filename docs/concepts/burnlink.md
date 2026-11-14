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
  runs Dragonfly behind it.

## Non goals

- The three additions below ship in later milestones. This document designs them ahead of that
  work; none of them exist in the running app yet.
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
- The store contract is two primitives: `SET NX PX` so a write never overwrites an existing
  secret, `GETDEL` so a reveal and a delete happen atomically and two readers cannot both win.
- Everything above runs today only as a scaffold: the wiring exists, the crypto, the store client
  and the three endpoints are the next milestone, not yet built.

### Request link

- The reverse flow: an owner publishes a link, anyone holding it can send the owner a secret back,
  and only the owner can open what arrives.
- Key material: the owner needs a keypair that lets a stranger encrypt to them without the owner
  being online at the time, which an asymmetric scheme fits, X25519 is the natural candidate paired
  with the existing AES-256-GCM AEAD. No primitive is chosen anywhere yet; this document proposes
  X25519 as the leading candidate and leaves the choice open for its own ADR once settled.
- Where it lives: the request link's fragment can carry only the public key, the same way a send
  link's fragment carries the one-time link key, because the server must never see it either. The
  owner's private key cannot live there too, since the owner returns to the same link repeatedly to
  decrypt submissions that arrive over time; it has to live in the owner's own browser storage, or
  in a second, private link the owner keeps separately. Browser storage never leaves the device but
  is lost with cleared site data or a changed browser; a second private link is portable and
  backupable but is then a credential as sensitive as the secrets it decrypts, and leaking it
  compromises every submission at once. Which of the two this design uses stays open.
- Loss: whichever path is chosen, losing the private key makes every secret ever sent to that
  request link permanently unrecoverable. The server holds only ciphertext and cannot help recover
  it either, because it was never given a key to begin with.
- Effect: the server still never learns the content of a submission; it stores ciphertext it
  cannot decrypt, exactly as the send flow does. What is new is that the server now holds and hands
  out key material, the owner's public key, to any unauthenticated requester who asks for it by id,
  something the one-way send flow never has to do.

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
- Request link's exact keypair primitive and where the owner's private key lives, browser storage
  or a second private link. Proposed above, not decided. Next step: its own ADR once settled.
- The CLI's drift-prevention mechanism, a golden-file cross-language test suite, is proposed but
  not built. Next step: confirm the approach when `cmd/burnlink-cli` is scheduled.
- Pickup notification's delivery guarantees: retries, timeouts and SSRF guarding for a
  sender-supplied webhook URL. Not designed yet. Next step: owner of that milestone.

## Related ADRs

- [0001](../adr/0001-burnlink-succeeds-old-burnlink.md)
- [0002](../adr/0002-the-payload-format-stays-from-old-burnlink.md)
