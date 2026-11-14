# 0003. The request link seals to an X25519 public key carried in the link's fragment

## Status

accepted

## Context

- The request link reverses the flow: the owner publishes a link, a stranger submits a secret to
  it, and only the owner can open what arrives. The sender encrypts while the owner is offline, so
  no shared key can be agreed at submission time.
- The send flow's crypto is settled and must not change: payload version 1, AES-256-GCM with the
  header as additional data, HKDF over the link key, info string `burnlink.de v1 aes-256-gcm`. See
  [0002](0002-the-payload-format-stays-from-old-burnlink.md).
- The send flow added no dependency: `web/src/lib/crypto.ts` is Web Crypto only. A primitive that
  needs a library has to earn it.
- The send flow already has a channel the server cannot read: the link's fragment, which a browser
  does not send. It carries the one-time link key today, and it is the only channel the owner
  controls end to end.
- The owner returns to the same request link repeatedly, so the owner's private key cannot live in
  the link's fragment the way a send link's one-time key does.
- Submitters are strangers. Nothing in the product establishes who they are, and nothing is
  planned that would.

## Decision

We will seal each submission to the owner's X25519 public key with an ephemeral keypair and the
existing AES-256-GCM AEAD, using Web Crypto only, carry that public key in the request link's
fragment, and keep the owner's private key as a non-extractable `CryptoKey` in IndexedDB.

- Per submission the sender generates an ephemeral X25519 keypair, derives the shared secret
  against the owner's public key with `deriveBits`, runs HKDF-SHA-256 over it to an AES-256-GCM
  key, encrypts, and discards the ephemeral private key. This is a sealed box: anonymous to the
  owner, decryptable only by the owner, and not replayable into the send flow.
- The HKDF input covers both public keys: the info string is this flow's own label, then the
  ephemeral public key, then the owner's public key. The derived key is therefore bound to this
  pair of parties and to this flow, and cannot be derived for another recipient or for the send
  flow. The ephemeral public key also travels in the payload header and is covered by the GCM
  additional data, which proves the header was not altered but does not separate recipients.
- The AES key is derived once per submission and never cached or reused, the ephemeral scalar
  being fresh each time. That invariant is what makes a random 12-byte IV safe; an implementation
  that caches a derived key per owner key breaks it.
- The owner's public key, 32 raw bytes, travels only in the request link's fragment. The server is
  never given it and serves no copy, not even as a fallback: a fallback the page takes silently
  when the fragment is empty is the same substitution risk with an extra step, and the submitter
  cannot see which path was used. A request link without the fragment is not submittable, and the
  page says so rather than asking the server.
- The submission payload is its own payload version with its own HKDF info string naming this
  flow. Version 1 and the send flow are untouched; the exact byte layout and the constants are
  fixed with the implementation.
- The private key is generated non-extractable, stored in IndexedDB, and never leaves the device.
  There is no second private link and no server-side escrow.

## Consequences

- Positive: no new dependency. X25519 `generateKey`, `importKey` and `deriveBits` are in Web
  Crypto across all three engines, and HKDF plus AES-256-GCM are already in the ported file.
- Positive: the server is handed no key material at all, so it stores ciphertext it cannot decrypt
  and holds nothing it could substitute, exactly as in the send flow. The private key is
  non-extractable on top of that, which bounds how long a page compromise keeps paying rather than
  what it reaches: script on the page can decrypt and exfiltrate every submission it can read
  while it runs, it just cannot carry the key away and keep reading afterwards.
- Negative: a substituted public key is still not detected, it is only harder to place. Whoever
  can alter the link between the owner and the submitter, in a chat log, a mail, or a page that
  republishes it, can swap the fragment and read every submission that follows, and neither party
  can see it. The page code also still comes from the server, so an operator who serves hostile
  page code reaches the plaintext regardless of where the key came from. What this decision removes
  is the server as a second, independent place to substitute the key, not substitution itself.
- Negative: a submitter whose browser has no X25519 in Web Crypto cannot submit at all. The floor
  is Chrome 133, Edge 133, Firefox 130 and Safari 17.0, and a submitter is a stranger on a browser
  nobody here controls. The page has to detect the missing algorithm and say so plainly instead of
  failing opaquely.
- Negative: losing the key is final and no backup can be taken later, because the key is
  non-extractable by choice. Cleared site data, a different browser or device, or a private window
  destroys every secret ever submitted to that request link, and the server cannot help because it
  was never given a key. Eviction under storage pressure is not Safari-specific; Safari adds a
  seven-day cap on script-writable storage that only counts days of Safari use without interaction
  on the site, so an owner returning to read submissions resets it. `navigator.storage.persist()`
  is the one lever the page has and is requested at creation. The owner has to accept the loss
  before publishing a link, stated on the page at creation, not in a help text.
- Negative: a submission is not authenticated. The AEAD proves the ciphertext was not altered
  after sealing; it proves nothing about who sealed it. Anyone holding the request link can submit.
  The owner cannot tell two submissions apart beyond arrival order, and cannot tell a real one from
  one an attacker injected. The page must not present a submission as being from anyone.
- Open: whether a submitter's own browser can be given any way to confirm the public key it was
  handed belongs to the owner, without the owner being online. Nothing was found that does this
  for an anonymous submitter. Left open rather than answered, and tracked in the concept doc.

## Alternatives considered

### libsodium.js `crypto_box_seal`, or an HPKE library such as `hpke-js`

- Both give a reviewed sealed-box construction instead of one assembled here, and HPKE is the
  standardised one (RFC 9180 base mode).
- Rejected: each adds a dependency to a file that deliberately has none, and a WASM build of
  libsodium is a large one. HPKE's `LabeledExtract` and `LabeledExpand` need only HMAC-SHA-256,
  which is native, so a library is not the only way to get there; what it would buy is a wire
  format nothing here consumes. This construction is accordingly not wire-compatible with
  `crypto_box_seal`, which uses XSalsa20-Poly1305 and a BLAKE2b-derived nonce, and a CLI client
  implements this repository's format rather than libsodium's.

### ECDH over P-256 instead of X25519

- Supported in Web Crypto far longer than X25519, so no availability question at all.
- Rejected: the curve carries invalid-point handling X25519 does not, and Web Crypto's X25519
  rejects an all-zero shared secret in constant time, which closes the low-order-point case with
  no code here. A raw P-256 public key is also 65 bytes where X25519's is 32; a page can compress
  the point to 33 itself, so the length is a cost rather than a blocker.

### RSA-OAEP

- Also native in Web Crypto, and no key agreement step to get wrong.
- Rejected: a 3072-bit public key does not belong in a link, there is no AEAD, and key generation
  in the browser is slow enough to be felt.

### A hybrid post-quantum KEM, ML-KEM-768 with X25519

- Google's own client-side encryption guidance names it the default for new work, and Web Crypto
  is growing `encapsulateKey` and `decapsulateKey` for it.
- Not taken now: it is Chromium-only at the time of writing, where X25519 has shipped in every
  engine, so the gap it leaves is every non-Chromium submitter rather than an older version of
  one. Revisit when it is available across browsers; the payload is versioned, which is what makes
  that revisit cheap.

### A second, private link carrying the owner's private key

- Portable and backupable, works on a new browser or device, survives cleared site data.
- Rejected: it turns the private key into a long-lived credential that decrypts every submission
  ever made to that link, carried in a URL through history, clipboards and chat logs, and leaking
  it once compromises all of them at the same moment. It also forces an extractable key, which
  gives up the one property browser storage has. Permanent loss is the cost taken instead, because
  it is bounded to one owner's own link and cannot be caused by someone else.

## References

- [docs/concepts/burnlink.md](../concepts/burnlink.md)
- [0002](0002-the-payload-format-stays-from-old-burnlink.md), the send flow's format this leaves
  unchanged
- [Sealed boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes), libsodium:
  the recipient "can verify the integrity of the message" but "cannot verify the identity of the
  sender", the format `ephemeral_pk ‖ box(m, recipient_pk, ephemeral_sk, nonce=...)`, and the nonce
  `blake2b(ephemeral_pk ‖ recipient_pk)`, which is where it binds the recipient's key
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), HPKE: base mode provides message
  secrecy and no sender authentication, and `kem_context = enc ‖ pkRm` carries the recipient's
  public key into the key schedule
- [Secure Curves in the Web Cryptography API](https://wicg.github.io/webcrypto-secure-curves/),
  WICG: X25519 `generateKey`, `importKey`, `exportKey` and `deriveBits`, raw 32-byte public keys,
  and "If secret is the all-zero value, then throw a OperationError", in constant time
- [`api.SubtleCrypto.deriveBits.x25519`](https://caniuse.com/mdn-api_subtlecrypto_derivebits_x25519),
  browser compatibility data for the per-algorithm support floor: Chrome 133, Edge 133,
  Firefox 130, Safari 17.0. The `deriveBits()` page's own Baseline banner covers the method, not
  the algorithm, and says "widely available" since January 2020 with an asterisk for parts that
  vary
- [Can I use Secure Curves in the Web Platform?](https://blogs.igalia.com/jfernandez/2025/02/28/can-i-use-secure-curves-in-the-web-platform/),
  Igalia: Firefox 130 shipped X25519 in September 2024, WebKit enabled it in December 2024, and
  Chrome 133 shipped it in February 2025
- [Web Cryptography API](https://w3c.github.io/webcrypto/), W3C: section 5.2 Key Storage, a
  `CryptoKey` is serializable so IndexedDB can store it without exposing the material, and section
  6.2 Security considerations for authors, "key material is not exposed to script, except through
  the use of the `exportKey` and `wrapKey` operations"
- [Full Third-Party Cookie Blocking and More](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/),
  WebKit: "deleting all of a website's script-writable storage after seven days of Safari use
  without user interaction on the site", IndexedDB included
- [StorageManager.persist()](https://developer.mozilla.org/en-US/docs/Web/API/StorageManager/persist),
  MDN: a granted request means storage "will not be cleared except by explicit user action", where
  the default is that it "may be cleared by the UA under storage pressure". Whether a granted
  request also exempts an origin from Safari's seven-day cap is not established
- [Client-side encryption](https://github.com/GoogleChrome/modern-web-guidance/blob/main/skills/modern-web-guidance/guides/security/client-side-encryption.md),
  Chrome's modern web guidance: `MLKEM768-X25519` as the default for new work
