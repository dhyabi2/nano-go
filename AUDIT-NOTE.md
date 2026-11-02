# Audit note (self-assessment, not an audit)

Nobody outside this project has audited this code. This note says what a reviewer can check quickly.

## Scope
`blake2b.go` (RFC 7693, unkeyed), `address.go`, `ed25519.go` (RFC 8032 with BLAKE2b-512 replacing SHA-512,
`math/big`), `block.go` (state-block hash, work). Nothing else; no network, no files, no globals mutated after `init`.

## Evidence
1. Real ledger data: a mainnet send and open block, hash recomputed and signature verified, two nodes agreeing.
2. Official vector: docs.nano.org zero seed.
3. Cross-implementation: BLAKE2b against `hashlib`; accounts and signatures against the Python reference, itself
   proven against the RFC 8032 SHA-512 vectors with the hash as a parameter (see nano-wallet-xno tests).
4. Negative cases listed in the README.
5. `go test -race` passes; `go vet` clean.

## Known limits
* **`Sign` is not constant time** (variable-length `math/big` exponentiation, with the secret scalar as the
  exponent). Do not run it where another tenant can time it. Use `Verify`, `Hash`, `DecodeAddress` and
  `WorkValid` freely; for signing in production use a constant-time library or a hardware signer.
* `Verify` is the cofactorless equation `[s]B = R + [k]A` and refuses non-canonical `S`; it does not reject
  small-order public keys (as the Nano node does not either). A caller that needs that must add it.
* Speed: a `Verify` takes milliseconds, not microseconds. Fine for a facilitator, wrong for a validator.
* Mainnet constants (thresholds) are epoch 2; a future epoch changes them.

## What would make it "audited"
Someone independent reading these four files against the RFCs and the Nano protocol docs and publishing the
result. A review checklist is the Evidence list above; each item is one `go test` away.
