# 0002. The payload format stays, ported from old-burnlink

## Status

accepted

## Context

- old_burnlink already carries the payload format forward from `otp.ostendorf.cloud` unchanged
  apart from its HKDF info string, recorded in its own ADR 0002: a versioned binary payload,
  AES-256-GCM with the header as additional data, HKDF over the link key, 600000 PBKDF2
  iterations for an optional passphrase, padding, and strict base64 on both sides, with tests that
  build a payload from the documented format and decrypt it.
- old_burnlink's crypto lives in `web/src/lib/crypto.ts`, TypeScript ported from the original
  `crypto.js`; that is the file this rewrite carries forward again.
- The domain and the service name do not change in this rewrite, unlike the
  `otp.ostendorf.cloud`-to-`burnlink.de` move: the HKDF info string `burnlink.de v1 aes-256-gcm`
  already names the service this repository still serves.
- The frontend framework does not change either: both old_burnlink and this repository render with
  Vue, so the Trusted Types question old_burnlink's own ADR 0002 settled, dropped, because Vue's
  renderer uses HTML sinks, still applies unchanged.
- The crypto, the store client and the three endpoints are not yet ported into this repository;
  this decision fixes what they must carry forward once that milestone starts.

## Decision

We will port `web/src/lib/crypto.ts` from old_burnlink into this repository unchanged, keep the
payload version and the HKDF info string as they are, and keep Trusted Types out of the content
security policy.

- The payload layout, the algorithms, the constants and the strictness stay exactly as
  old_burnlink's ADR 0002 recorded them; this is a port, not a rewrite.
- The HKDF info string stays `burnlink.de v1 aes-256-gcm`, unchanged, because the service it
  names has not changed in this rewrite.
- The payload version stays 1.
- govue's own default content security policy, a per-response nonce, deny by default, applies
  with no Trusted Types directive, the same choice old_burnlink made against web-kit's equivalent
  default.

## Consequences

- Positive: the format stays reviewable as a diff against old_burnlink's file, not as new crypto.
- Positive: old_burnlink's crypto tests, including the ones that build a payload from the
  documented format and decrypt it, port with the file and keep the format honest here too.
- Positive: a link already issued by old_burnlink keeps working once this repository takes over,
  since neither the version nor the info string changes this time.
- Negative: the second-language problem old_burnlink's ADR 0002 avoided by porting instead of
  rewriting returns the moment a second implementation appears, for instance a Go CLI client; this
  decision does not address that by itself.
- Negative: Trusted Types stays unavailable for the reason old_burnlink gave: Vue's renderer uses
  HTML sinks, and the directive would break the app rather than harden it.
- Neutral: a page documenting these properties, old_burnlink's own security page or this
  repository's equivalent, still has to change in the same commit as the format, once that page
  exists here.

## Alternatives considered

### Rewrite the crypto fresh in this repository

- Would be a chance to write idiomatic TypeScript against govue's own conventions instead of a
  ported file.
- Rejected for the reason old_burnlink gave: the ported implementation is the reviewed one, and
  rewriting working crypto to make it read better is how a format quietly changes.

### Change the HKDF info string again

- Would mark this rewrite the way the `otp.ostendorf.cloud`-to-`burnlink.de` move once did.
- Rejected: the service name has not changed this time, only the repository and its base library
  have. Changing the string without a reason breaks every link old_burnlink issued for no benefit,
  where the earlier change at least bought a correctly named service.

### Bring Trusted Types back now that govue is the baseline instead of web-kit

- govue might default differently than web-kit did.
- Not taken: govue's own default content security policy is also a per-response nonce without
  Trusted Types, so the move from web-kit to govue changes nothing about the reasoning
  old_burnlink's ADR 0002 already gave.

## References

- [docs/concepts/burnlink.md](../concepts/burnlink.md)
- [0001](0001-burnlink-succeeds-old-burnlink.md)
- old_burnlink's `web/src/lib/crypto.ts`, the file this ports (different repository, not linked).
