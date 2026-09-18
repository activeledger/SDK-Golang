<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger SDK for Go

Go SDK for [Activeledger](https://github.com/activeledger/activeledger), with post-quantum identity support.

**Requires Activeledger 4.7.0+** for `ml-dsa-65`. Go 1.21+.

> **Rewritten.** The previous version dated from 2021, targeted Go 1.15, vendored a 2012 secp256k1 implementation and had no tests.

---

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

## Install

```bash
go get github.com/activeledger/SDK-Golang
```

---

## Quick start

```go
package main

import (
	"context"
	"fmt"

	activeledger "github.com/activeledger/SDK-Golang"
	"github.com/activeledger/SDK-Golang/pqkeys"
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
