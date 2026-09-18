package activeledger

import "fmt"

// KeyType is a key algorithm as the ledger names it.
//
// These strings are the whole contract: the ledger validates nothing else
// about them. A typo, or a key of the wrong length, surfaces as 1220
// "Signature Incorrect" and never as "unknown algorithm".
//
// The ledger also DEFAULTS a missing type to "rsa" and then attempts RSA
// verification against whatever it was given, so this SDK always sends the
// type explicitly and never relies on a default.
type KeyType string

const (
	KeyTypeRSA       KeyType = "rsa"
	KeyTypeSecp256k1 KeyType = "secp256k1"
	KeyTypeMLDSA65   KeyType = "ml-dsa-65"

	// KeyTypeFalcon512 is recognised so an error can name it, but this SDK
	// cannot create or use Falcon identities. See ErrFalconUnsupported.
	KeyTypeFalcon512 KeyType = "falcon-512"
)

// ErrFalconUnsupported explains why Falcon is absent rather than leaving a
// caller to infer it from a missing constant.
//
// No maintained pure-Go library emits the compressed variable-length
// Falcon-512 the ledger uses: algorand/falcon is Falcon-1024 with a
// non-standard deterministic salt, lattice-safe/falcon-go emits only the
// padded form, and CIRCL has no Falcon at all. Only cgo (liboqs-go) produces
// the right bytes, which costs cross-compilation, static binaries and plain
// `go get`.
//
// ml-dsa-65 is fully supported and is the scheme to use from Go.
var ErrFalconUnsupported = fmt.Errorf(
	"falcon-512 is not supported by the Go SDK: no maintained pure-Go " +
		"implementation emits the compressed variable-length form the ledger " +
		"uses, and the alternatives require cgo. Use ml-dsa-65 instead")

// Signer is anything that can sign transaction bytes and name its key type.
//
// An interface rather than a concrete type so a caller can sign elsewhere --
// an HSM, a remote signing service, a key held in a user's wallet -- without
// this SDK needing to know about it.
type Signer interface {
	KeyType() KeyType
	PublicKeyB64() string
	Sign(message []byte) ([]byte, error)
}
