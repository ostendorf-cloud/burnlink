# 0001. burnlink succeeds old-burnlink

## Status

accepted

## Context

- This repository already exists and is scaffolded on govue: `cmd/burnlink`'s wiring, the
  embedded Vue SPA, health, readiness and metrics on a second listener, the Helm chart and CI.
- old_burnlink, this repository's predecessor, is built on `simonostendorf/web-kit` and generated
  from `simonostendorf/scaffold`, both personal-namespace tooling outside this organisation.
- govue is this organisation's own library for the same server-plus-Vue layer: timeouts,
  shutdown, security headers, probes, metrics, the error shape and a Vue design-token contract,
  the role old_burnlink's own ADR 0001 describes web-kit as holding.
- old_burnlink already succeeded `otp.ostendorf.cloud`, the original hand-written Go and template
  app, recorded in its own ADR 0001; that succession is not re-litigated here.
- The licence moves from MIT, old_burnlink's choice tied to its personal-namespace origin, to
  Apache-2.0, this organisation's baseline default for a new repository.
- The crypto, the store client and the three endpoints that make burnlink actually store and hand
  out a secret are not ported yet; they are this milestone's next step, not part of this decision.

## Decision

We will carry burnlink forward as this organisation's own repository, scaffolded on govue, and
retire old_burnlink once this app serves its traffic.

- `cmd/burnlink` wires govue: the server and its timeouts, the shutdown sequence, the security
  headers, the probes and the metrics through a second, administrative listener, replacing the
  equivalent wiring old_burnlink did against web-kit.
- The frontend stays a Vue 3 SPA, now consuming govue's Vue package and design-token contract
  instead of web-kit's component package.
- `internal/secrets`, a RESP2 store client and the crypto library carry old_burnlink's design
  forward unchanged in shape, the three endpoints, the id, the lifetimes, the one indistinguishable
  answer, ported when that milestone starts.
- The repository takes Apache-2.0 instead of MIT, matching this organisation's baseline.

## Consequences

- Positive: a fix to the server layer reaches this app through a govue version bump, the same
  benefit old_burnlink got from web-kit.
- Positive: the repository already matches this organisation's conventions, CI, release-me, the
  Helm chart, from the start, instead of carrying personal-namespace tooling into an org repository.
- Positive: the succession is recorded, so a reader does not have to infer from two unrelated
  repositories why burnlink exists twice.
- Negative: anything scripting old_burnlink's API breaks; nothing does outside its own page, the
  same situation old_burnlink recorded for `otp.ostendorf.cloud`.
- Negative: old_burnlink has to keep running until its own secrets expire, at most a week, before
  it is retired.
- Negative: a contributor relying on MIT terms for old_burnlink's code sees different terms once
  that code is carried into this repository under Apache-2.0.

## Alternatives considered

### Keep rewriting old_burnlink in place

- Smaller change: no new repository, no new succession record.
- Rejected: old_burnlink's tooling, web-kit and the `simonostendorf/scaffold` generator, belongs
  to a personal namespace, not this organisation; moving the code without moving the repository
  leaves that mismatch unresolved.

### Depend on web-kit directly instead of govue

- Would reuse the exact library old_burnlink already ran on.
- Rejected: web-kit is not this organisation's library. Whether govue is a deliberate successor to
  web-kit, or an independent library built for this organisation, is not recorded in either
  repository; this decision uses govue because it is what this organisation's repositories already
  build on, not because a lineage from web-kit was confirmed. See the concept doc's open questions.

### Rebuild it but keep a server-rendered page

- Keeps the no-build-step property and old_burnlink's hand-written static files.
- Rejected for the reason old_burnlink's own ADR 0001 already gave for `otp.ostendorf.cloud`: the
  design system here is Vue components, now govue's, and a hand-written page is exactly what that
  system replaces.

## References

- [docs/concepts/burnlink.md](../concepts/burnlink.md)
- [0002](0002-the-payload-format-stays-from-old-burnlink.md)
- old_burnlink, the predecessor repository this succeeds, and `otp.ostendorf.cloud`, the
  repository old_burnlink itself succeeded (both outside this organisation, not linked).
