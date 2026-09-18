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

	// PublicKey is the string the ledger stores, in whatever encoding the
	// scheme uses: base64 for the post-quantum keys, 0x-prefixed hex for
	// secp256k1. Whatever this returns goes into the transaction verbatim,
	// which is why it is not named for one encoding.
	PublicKey() string

	Sign(message []byte) ([]byte, error)
}

// ParseKeyType converts a wire string, rejecting anything unrecognised.
//
// Deliberately strict and case-sensitive: the ledger compares these exactly,
// so accepting "ML-DSA-65" here would only move the failure somewhere less
// informative.
//
// "bitcoin" and "ethereum" parse as secp256k1, because the ledger routes them
// to identical verification and an existing identity may already carry
// either. They are never emitted: KeyTypeSecp256k1 always writes "secp256k1".
func ParseKeyType(wire string) (KeyType, error) {
	switch wire {
	case string(KeyTypeRSA):
		return KeyTypeRSA, nil
	case string(KeyTypeSecp256k1), "bitcoin", "ethereum":
		return KeyTypeSecp256k1, nil
	case string(KeyTypeMLDSA65):
		return KeyTypeMLDSA65, nil
	case string(KeyTypeFalcon512):
		return KeyTypeFalcon512, nil
	default:
		return "", fmt.Errorf(
			"unknown key type %q - expected rsa, secp256k1, ml-dsa-65 or falcon-512", wire)
	}
}
