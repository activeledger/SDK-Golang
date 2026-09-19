// Package eckeys implements secp256k1 identities, encoded the way
// Activeledger stores them.
//
// Kept apart from pqkeys because almost nothing is shared. Post-quantum keys
// are raw bytes in base64; these are hex with an "0x" prefix. Post-quantum
// signatures are fixed-length raw blobs; these are variable-length DER.
// Folding the two together invites the one mistake that matters here --
// reusing a base64 path for a hex key, which produces material the ledger
// rejects as 1220 "Signature Incorrect" while saying nothing else.
package eckeys

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	activeledger "github.com/activeledger/SDK-Golang/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Sizes fixed by the curve and by SEC1.
const (
	PublicKeyCompressedSize   = 33
	PublicKeyUncompressedSize = 65
	PrivateKeySize            = 32
)

// halfOrder divides low S from high S.
var halfOrder = new(big.Int).Rsh(secp256k1.S256().N, 1)

// ErrVerifyOnly is returned when signing with a key pair that has no private
// half.
var ErrVerifyOnly = errors.New(
	"this key pair has no private key - it was created for verification only")

// KeyPair is a secp256k1 identity.
type KeyPair struct {
	private   *secp256k1.PrivateKey
	public    *secp256k1.PublicKey
	publicRaw []byte
}

// Generate creates a key pair with a compressed public key.
//
// Compressed by default: 33 bytes rather than 65, and this key is written into
// a transaction and then stored on an identity stream permanently.
func Generate() (*KeyPair, error) {
	return GenerateWith(true)
}

// GenerateWith creates a key pair, choosing the public key form.
//
// The ledger accepts both and tells them apart by length.
func GenerateWith(compressed bool) (*KeyPair, error) {
	private, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generating secp256k1 key: %w", err)
	}

	public := private.PubKey()
	return &KeyPair{
		private:   private,
		public:    public,
		publicRaw: encodePoint(public, compressed),
	}, nil
}

// FromPublicKey builds a verify-only key pair from a stored public key.
func FromPublicKey(publicKey string) (*KeyPair, error) {
	raw, err := decodeHex(publicKey, "public")
	if err != nil {
		return nil, err
	}
	if err := checkPublic(raw); err != nil {
		return nil, err
	}

	public, err := secp256k1.ParsePubKey(raw)
	if err != nil {
		return nil, fmt.Errorf("secp256k1 public key was rejected: %w", err)
	}

	return &KeyPair{public: public, publicRaw: raw}, nil
}

// FromKeys restores a signing key pair from stored key material.
func FromKeys(publicKey, privateKey string) (*KeyPair, error) {
	pair, err := FromPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	scalar, err := decodeHex(privateKey, "private")
	if err != nil {
		return nil, err
	}
	if len(scalar) != PrivateKeySize {
		return nil, fmt.Errorf(
			"secp256k1 private key is %d bytes, expected %d", len(scalar), PrivateKeySize)
	}

	pair.private = secp256k1.PrivKeyFromBytes(scalar)
	return pair, nil
}

// KeyType reports secp256k1.
func (k *KeyPair) KeyType() activeledger.KeyType {
	return activeledger.KeyTypeSecp256k1
}

// PublicKey is the 0x-prefixed hex the ledger stores.
func (k *KeyPair) PublicKey() string {
	return encodeHex(k.publicRaw)
}

// PrivateKey is the 0x-prefixed hex scalar, always 32 bytes.
//
// Left-padded deliberately: a big integer drops leading zero bytes, which
// happens to roughly one key in 400, and the shorter value is a different
// scalar to anything that reads it strictly.
func (k *KeyPair) PrivateKey() (string, error) {
	if k.private == nil {
		return "", ErrVerifyOnly
	}

	scalar := k.private.Serialize()
	if len(scalar) != PrivateKeySize {
		padded := make([]byte, PrivateKeySize)
		copy(padded[PrivateKeySize-len(scalar):], scalar)
		scalar = padded
	}
	return encodeHex(scalar), nil
}

// CanSign reports whether a private key is present.
func (k *KeyPair) CanSign() bool { return k.private != nil }

// Sign signs a message, deterministically and low-S.
//
// Both properties come from the library rather than being applied here, and
// both are load-bearing.
//
// Deterministic k (RFC 6979) is about testability, not security: the same key
// and message give the same bytes in every correct implementation, so exact
// expected bytes can be published as cross-language vectors -- and an exact
// comparison is the only kind of test that can catch a low-S regression. A
// verify-round-trip test passes just as happily on a high-S signature.
//
// Low S is not for the ledger, which accepts either. It is for
// @noble/curves, the reference for the JavaScript side, and for libsecp256k1
// and k256 -- all of which reject high-S by default. A signer emitting high-S
// half the time fails against them half the time, which reads as flakiness
// rather than as a signature format problem.
func (k *KeyPair) Sign(message []byte) ([]byte, error) {
	if k.private == nil {
		return nil, ErrVerifyOnly
	}

	hash := sha256.Sum256(message)
	return ecdsa.Sign(k.private, hash[:]).Serialize(), nil
}

// Verify checks a signature, accepting HIGH-S as well as low.
//
// The ledger verifies through OpenSSL, which neither normalises nor requires
// low-S, so roughly half of everything it produces is high-S. A verifier that
// rejected those would fail on about half of all valid signatures -- and the
// half that succeeded would make it look like an intermittent fault rather
// than a crypto one.
//
// Returns false rather than an error for malformed input: a caller checking a
// signature wants a yes or a no, and a signature of the wrong shape is a no.
func (k *KeyPair) Verify(message, signature []byte) bool {
	parsed, err := ecdsa.ParseDERSignature(signature)
	if err != nil {
		return false
	}

	hash := sha256.Sum256(message)
	return parsed.Verify(hash[:], k.public)
}

// IsHighS reports whether a DER signature's S is in the upper half of the
// curve order.
//
// Exported because a test that cannot tell the two apart can prove neither
// that this SDK emits only low-S nor that it still accepts high-S from
// elsewhere.
func IsHighS(signature []byte) bool {
	parsed, err := ecdsa.ParseDERSignature(signature)
	if err != nil {
		return false
	}

	s := parsed.S()
	bytes := s.Bytes()
	return new(big.Int).SetBytes(bytes[:]).Cmp(halfOrder) > 0
}

// IsHighSBase64 is IsHighS for a base64 DER signature.
func IsHighSBase64(signature string) bool {
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return IsHighS(raw)
}

func encodePoint(public *secp256k1.PublicKey, compressed bool) []byte {
	if compressed {
		return public.SerializeCompressed()
	}
	return public.SerializeUncompressed()
}

func encodeHex(raw []byte) string {
	return "0x" + hex.EncodeToString(raw)
}

// decodeHex reads an 0x-prefixed hex key.
//
// The prefix is required rather than tolerated: it is part of what the ledger
// stores, and a hex string without it can decode as base64 into
// plausible-looking bytes of the wrong length.
func decodeHex(value, role string) ([]byte, error) {
	if !strings.HasPrefix(value, "0x") {
		return nil, fmt.Errorf(
			"secp256k1 %s key must start with '0x' - that prefix is part of what the "+
				"ledger stores, not decoration. Post-quantum keys are base64; these are not",
			role)
	}

	raw, err := hex.DecodeString(value[2:])
	if err != nil {
		return nil, fmt.Errorf("secp256k1 %s key is not valid hex: %w", role, err)
	}
	return raw, nil
}

// checkPublic validates the length and that the SEC1 point prefix agrees with
// it. A mismatch means the caller has mixed up the two forms somewhere.
func checkPublic(raw []byte) error {
	var compressed bool
	switch len(raw) {
	case PublicKeyCompressedSize:
		compressed = true
	case PublicKeyUncompressedSize:
		compressed = false
	default:
		return fmt.Errorf(
			"secp256k1 public key is %d bytes, expected %d (compressed) or %d (uncompressed)",
			len(raw), PublicKeyCompressedSize, PublicKeyUncompressedSize)
	}

	prefix := raw[0]
	ok := prefix == 0x04
	if compressed {
		ok = prefix == 0x02 || prefix == 0x03
	}
	if !ok {
		return fmt.Errorf(
			"secp256k1 public key starts with %#02x, which does not match its length of %d "+
				"bytes (expected 0x02/0x03 for %d, 0x04 for %d)",
			prefix, len(raw), PublicKeyCompressedSize, PublicKeyUncompressedSize)
	}
	return nil
}

// String never prints private key material.
func (k *KeyPair) String() string {
	if k.CanSign() {
		return "secp256k1 KeyPair(public+private)"
	}
	return "secp256k1 KeyPair(public only)"
}
