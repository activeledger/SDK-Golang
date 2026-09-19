<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger SDK for Go

Go SDK for [Activeledger](https://github.com/activeledger/activeledger), with post-quantum identity support.

**Requires Activeledger 4.7.0+** for `ml-dsa-65`. Go 1.21+.

> **Rewritten.** The previous version dated from 2021, targeted Go 1.15, vendored a 2012 secp256k1 implementation and had no tests.

---

## Key types

| Key type | Wire string | Public | Private | Signature | Encoding |
|---|---|---|---|---|---|
| ML-DSA-65 | `ml-dsa-65` | 1952 | 4032 | 3309 | base64 |
| secp256k1 | `secp256k1` | 33 or 65 | 32 | ~70-72, variable | `0x` hex |
| Falcon-512 | `falcon-512` | — | — | not supported here | — |

Use **secp256k1** unless the identity must outlive a cryptographically
relevant quantum computer: it is roughly **22x smaller** per transaction, and
every byte is stored on the ledger permanently and replicated to every node.
It also works with hardware wallets and HSMs, and is the only way to sign for
an identity created before post-quantum support.

```go
key, err := eckeys.Generate()                 // compressed public key
full, err := eckeys.GenerateWith(false)       // uncompressed

public := key.PublicKey()                     // "0x02a1b2..."
private, err := key.PrivateKey()

restored, err := eckeys.FromKeys(public, private)
verifier, err := eckeys.FromPublicKey(public)
```

### secp256k1 is encoded nothing like the post-quantum keys

- **Keys are `0x`-prefixed hex, not base64.** The prefix is required rather
  than tolerated, because hex without it can decode as base64 into
  plausible-looking bytes of the wrong length.
- **Public keys have two valid lengths**, 33 compressed and 65 uncompressed,
  and the ledger accepts both. A length and a SEC1 point prefix that disagree
  are rejected by name.
- **Private scalars are always 32 bytes**, left-padded. A leading zero byte
  occurs about once in 400 keys, and a value that dropped it is a different
  scalar.
- **Signatures are SHA-256 → ECDSA → DER**, and DER length varies.

### low-S, in both directions

**Signing** is RFC 6979 deterministic and low-S. That is not for the ledger,
which accepts either, but for `@noble/curves` — the reference for the
JavaScript side — and for libsecp256k1 and Rust's `k256`, all of which reject
high-S by default.

**Verification accepts high-S**, because the ledger verifies through OpenSSL
and produces high-S freely. Rejecting those would fail on roughly half of all
valid signatures, and the half that succeeded would look like an intermittent
fault. `decred/dcrd`'s DER path accepts both, which is why it is used here —
verified against the published vectors rather than assumed.

Because signing is deterministic, this SDK's signatures are byte-identical to
`@noble/curves` for the same key and message, asserted against published
reference bytes on every test run.

`bitcoin` and `ethereum` parse as secp256k1 via `ParseKeyType` and are never
emitted.

## Post-quantum support: ML-DSA-65 only

**`ml-dsa-65` is fully supported. `falcon-512` is not, and cannot be without cgo.**

No maintained pure-Go library emits the compressed variable-length Falcon-512 the ledger uses:

| Library | Why not |
| --- | --- |
| `algorand/falcon` | Falcon-**1024**, non-standard deterministic salt |
| `lattice-safe/falcon-go` | public `Sign()` emits only the padded form; 11-commit project |
| `cloudflare/circl` | no Falcon at all |

Only `liboqs-go` (cgo) produces the right bytes, which costs cross-compilation, static binaries and plain `go get`.

Asking for Falcon returns `ErrFalconUnsupported`, whose message says exactly this — you will not get a silent wrong-algorithm signature.

ML-DSA-65 is the post-quantum scheme to use from Go, and it is the one this programme treats as portable across every language.

---

## Seeds and recovery phrases

```go
ec, err := eckeys.FromSeed(seed, true)                  // 32 bytes
ec, err := eckeys.FromPhrase(phrase, "", true)          // BIP-39
pq, err := pqkeys.FromSeed(seed)                        // 32 bytes
pq, err := pqkeys.FromPhrase(phrase, "")
```

The same seed gives the same identity in every Activeledger SDK, which is what
makes a seed the portable private-key format — it is how a private key moves
between languages. It matters most for PHP, whose ML-DSA-65 private key **is**
a 32-byte seed and whose 4032-byte form does not exist.

A seed of the wrong length is **refused, not padded**: a padded seed is a
different identity, not a malformed one.

For `secp256k1` the seed **is** the private scalar, so it has to be a valid
one. This is worth stating because `secp256k1.PrivKeyFromBytes` **reduces mod
n rather than refusing** — so without an explicit range check an out-of-range
seed returns a perfectly functional key belonging to a different identity, and
nothing downstream ever reports a problem. `FromSeed` checks first.

The phrase is validated, wordlist **and** checksum. A mistyped phrase that is
not checked does not fail; it derives a valid key for an identity nobody owns,
and the only symptom is the ledger not recognising it.

`eckeys.FromLegacyPhrase` recovers a phrase made by the older
`@activeledger/sdk-bip39` package — recovery only, never for new keys.

### The derivation

| Type | Seed from the BIP-39 seed `S` |
| --- | --- |
| `secp256k1` | `HMAC-SHA512("Bitcoin seed", S)[0..32]` |
| `ml-dsa-65` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)` |
| `falcon-512` | `HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)` |

`secp256k1` deliberately does not use HKDF: the JavaScript SDK shipped that
derivation before the post-quantum types existed, so phrases are already in
use, and changing it would hand those users a different key for a phrase that
used to work.

`recovery.DeriveSeed` implements all three — including `falcon-512`, which
this SDK cannot otherwise use, so a phrase here can still produce the seed for
a Falcon identity created elsewhere.

## Install

```bash
go get github.com/activeledger/SDK-Golang/v2
```

The `/v2` suffix is required, not optional. Go demands that a module's path
carry its major version from v2 onward, and the proxy refuses a tag whose
`go.mod` disagrees — so `go get github.com/activeledger/SDK-Golang@v2.x` fails
with *"module path must match major version"* rather than resolving. Imports
carry it too: `github.com/activeledger/SDK-Golang/v2/eckeys`.

---

## Quick start

```go
package main

import (
	"context"
	"fmt"

	activeledger "github.com/activeledger/SDK-Golang/v2"
	"github.com/activeledger/SDK-Golang/v2/pqkeys"
)

func main() {
	client := activeledger.NewClient("http://localhost:5260")
	ctx := context.Background()

	key, err := pqkeys.Generate()
	if err != nil {
		panic(err)
	}

	identity, err := client.Onboard(ctx, key)
	if err != nil {
		panic(err)
	}
	fmt.Println("identity:", identity.StreamID)
}
```

---

## Keys

| Type | Wire string | Public | Private | Signature |
| --- | --- | --- | --- | --- |
| ML-DSA-65 | `ml-dsa-65` | 1952 B | 4032 B | 3309 B, fixed |
| Falcon-512 | `falcon-512` | — | — | **not supported, see above** |

```go
key, _ := pqkeys.Generate()

key.PublicKeyB64()          // give this to the ledger
priv, _ := key.PrivateKeyB64()

sig, _ := key.Sign([]byte("some bytes"))
key.Verify([]byte("some bytes"), sig)   // true

// Reload later
same, _ := pqkeys.FromKeys(pub, priv)

// Verify-only
checker, _ := pqkeys.FromPublic(pub)
```

`Verify` returns `false` for a malformed signature rather than an error — a caller should not have to tell "invalid" from "wrong shape".

---

## Transactions

```go
tx, err := activeledger.NewBuilder().
	Namespace("mynamespace").
	Contract("mycontract").
	Input(identity.StreamID, identity.Signer,
		activeledger.NewObject().Set("message", "hello")).
	Output(target, activeledger.NewObject().Set("amount", 10)).
	Build()

response, err := client.Submit(ctx, tx)
if !response.Committed() {
	panic(response.Errors())
}

response.NewStreams()   // ids created
response.Responses()    // returnToRemote values
```

`.Entry("update")` sets `$entry` for contracts with multiple entry points.

---

## Reading state

There is no separate read API and no storage URL. A node's storage service listens only on the node's own host, so a client cannot reach it.

State is read **through a transaction**: name streams in `$r`, and the contract hands values back with `returnToRemote`.

```go
tx, _ := activeledger.NewBuilder().
	Namespace("mynamespace").
	Contract("mycontract").
	Input(identity.StreamID, identity.Signer, nil).
	ReadOnly("target", someStreamID).      // becomes $r
	Build()

response, _ := client.Submit(ctx, tx)
for _, value := range response.Responses() {
	fmt.Println(value)
}
```

---

## Events (SSE)

`Subscribe` returns a channel and an error channel. Cancelling the context closes the connection:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

events, errs := client.Subscribe(ctx, "/events")
for event := range events {
	fmt.Println(event.Name, event.ID, event.Data)
	if finished {
		cancel()      // closes the connection
	}
}
if err := <-errs; err != nil {
	panic(err)
}
```

The parser handles the framing rules that actually matter:

- multiple `data:` lines in one event concatenate with newlines — treating them as separate events is the classic SSE bug
- `:` comment lines (heartbeats) are ignored, not delivered as empty events
- `event:` and `id:` never leak into the following event
- an event still pending when the stream ends is delivered

There is no client timeout on SSE: event streams are long-lived, and a timeout would close them for being quiet.

---

## Signing elsewhere

Anything satisfying `Signer` works, so an HSM or a remote signing service needs no change to this SDK:

```go
type Signer interface {
	KeyType() KeyType
	PublicKeyB64() string
	Sign(message []byte) ([]byte, error)
}
```

---

## Things that will bite you

**Always send the key type.** The ledger defaults a missing `type` to `"rsa"` and then attempts RSA verification against a base64 post-quantum blob. This SDK always sends it.

**A rejected transaction is HTTP 200.** Check `response.Committed()`, never the status code.

**Errors are unhelpful by design.** A wrong type string, a wrong-length key, or signed bytes differing by one escape all come back as **1220 "Signature Incorrect"**. This SDK validates key lengths up front so these fail locally with a message naming the problem.

**Signatures cover `$tx` only**, not the envelope. `tx.SignedBytes()` shows exactly what was signed — the fastest way to diagnose a 1220.

---

## Canonical JSON

Signatures cover the exact bytes of `JSON.stringify($tx)` encoded UTF-8 — no hash prefix, no length prefix, no key sorting.

`encoding/json` **cannot** produce these bytes, which is why this SDK carries its own serialiser and an ordered `Object` type:

| Behaviour | Fixable? |
| --- | --- |
| HTML-escapes `<`, `>`, `&` into `<` etc. | yes, `SetEscapeHTML(false)` |
| **sorts map keys** | **no** — a Go `map` has no insertion order to preserve |

Measured: `map[string]int{"zebra":1,"alpha":2,"middle":3}` marshals as `{"alpha":2,"middle":3,"zebra":1}`. The ledger does not canonicalise key order, so the signer must reproduce the order the caller wrote.

Both defects produce correct output on an ASCII-only payload with one key and no angle brackets — which is exactly why a port can ship broken and only fail later on real data.

```go
body := activeledger.NewObject().
	Set("whole", 1.0).           // serialises as 1, the way JavaScript prints it
	Set("note", "café")          // raw UTF-8, never é

s, _ := activeledger.CanonicalJSON(body)
```

---

## Testing

```bash
go test ./...
```

Integration tests need a live network. From an `activeledger` checkout:

```bash
npm run test:network:serve
```

then, with the URLs it prints:

```bash
AL_NODES=http://127.0.0.1:5510 AL_STORAGE=http://127.0.0.1:5509 go test -run TestLive ./...
```

They skip when `AL_NODES` is unset.

Correctness is established against published cross-language vectors and a real 4-node network — onboarding, submitting transactions and confirming a tampered payload is rejected — not against a reading of the reference implementation.

---

## Licence

MIT
