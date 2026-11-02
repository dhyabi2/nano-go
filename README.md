# nano-go

Nano (XNO) primitives in Go with **no dependencies** (standard library only, `go list -deps` lists nothing else):

| Need | Call |
|---|---|
| BLAKE2b, any digest size 1..64 (RFC 7693) | `Blake2b(size, parts...)` |
| Address encode / decode with checksum (`nano_`, `xrb_`) | `EncodeAddress`, `DecodeAddress` |
| Seed to key, key to public key | `PrivateKeyFromSeed`, `PublicKey` |
| Ed25519 with BLAKE2b (Nano's variant) | `Verify`, `Sign` |
| State-block hash, signature check, work root | `StateBlock.Hash`, `.VerifySignature`, `.WorkRoot` |
| Proof of work check, send and receive thresholds | `WorkValid`, `WorkDifficulty`, `SendThreshold`, `ReceiveThreshold` |

```
go get github.com/dhyabi2/nano-go@v0.1.0
```

## Why this exists

A Go x402 maintainer wrote that they "only accept audited implementations" and that "Nano's Ed25519-with-Blake2b
variant isn't available to us in an audited Go library today"
(rudizee007/spt-txn-x402-arc#5). This module is the smallest thing that can be audited by reading: about 450
lines of non-test code, no third-party import, and a test set built from things other people can check.

## Test vectors (all in `testdata/`, all re-runnable with `go test ./...`)

* **Two real mainnet blocks**, a send and the open block that received it
  (`F6BF9D8D...D6B8` and `BCE62122...D85B`), read from two independent nodes (rpc.nano.to and rainstorm.city) on
  2026-11-02. The tests recompute each block hash from its fields, verify the network's own signature, and
  check the work against the send and receive thresholds. A different balance, root, or flipped bit must fail.
* **The official zero-seed vector** from docs.nano.org (private key, public key, address).
* **BLAKE2b**: RFC 7693 Appendix A ("abc") plus 40 digests (lengths 0..1000, sizes 5/8/32/64) generated with
  Python `hashlib.blake2b`.
* **Accounts and signatures** from the Python reference in
  [nano-wallet-xno](https://github.com/dhyabi2/nano-wallet-xno) (`ed25519_blake2b.py`); Ed25519 is deterministic, so
  the Go signature must equal the Python one byte for byte.
* **Refusals**: every single-character substitution in an address body fails; bad alphabet, bad prefix, nonzero
  pad bits, wrong length; non-canonical `S` (malleable) signatures; short inputs; balances outside 128 bits;
  malformed work is invalid, never a panic.

## What this is not

Not independently audited. See [AUDIT-NOTE.md](AUDIT-NOTE.md) for what is evidenced, what is not, and the
timing caveat on `Sign`. `Verify` touches only public data.

MIT.
