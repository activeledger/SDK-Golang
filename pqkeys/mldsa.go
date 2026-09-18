// Package pqkeys implements post-quantum key handling for Activeledger.
//
// ML-DSA-65 only. See activeledger.ErrFalconUnsupported for why Falcon-512 is
// absent from the Go SDK.
package pqkeys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	activeledger "github.com/activeledger/SDK-Golang"
)

// Sizes the ledger expects. Verified against the published cross-language
// vectors: circl's own constants match these exactly.
const (
	PublicKeySize  = mldsa65.PublicKeySize  // 1952
	PrivateKeySize = mldsa65.PrivateKeySize // 4032
	SignatureSize  = mldsa65.SignatureSize  // 3309
)

// KeyPair is an ML-DSA-65 key pair that interoperates with Activeledger.
//
// Keys are base64 of raw algorithm bytes, matching the JavaScript SDK's
// on-disk format.
type KeyPair struct {
	public  *mldsa65.PublicKey
	private *mldsa65.PrivateKey
}

// Generate creates a new key pair.
func Generate() (*KeyPair, error) {
	public, private, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ml-dsa-65: %w", err)
	}
	return &KeyPair{public: public, private: private}, nil
}

// FromKeys loads a signing key pair from base64 key material.
func FromKeys(publicB64, privateB64 string) (*KeyPair, error) {
	public, err := decodePublic(publicB64)
	if err != nil {
		return nil, err
	}
	privateBytes, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return nil, fmt.Errorf("private key is not valid base64: %w", err)
	}
	// Checked here rather than at a node. A wrong-length key reaching the
	// ledger comes back as 1220 "Signature Incorrect", which says nothing
	// about length and sends the caller hunting the signer.
	if len(privateBytes) != PrivateKeySize {
		return nil, fmt.Errorf("ml-dsa-65 private key should be %d bytes, got %d",
			PrivateKeySize, len(privateBytes))
	}
	var private mldsa65.PrivateKey
	if err := private.UnmarshalBinary(privateBytes); err != nil {
		return nil, fmt.Errorf("private key rejected: %w", err)
	}
	return &KeyPair{public: public, private: &private}, nil
}

// FromPublic loads a verify-only key pair.
func FromPublic(publicB64 string) (*KeyPair, error) {
	public, err := decodePublic(publicB64)
	if err != nil {
		return nil, err
	}
	return &KeyPair{public: public}, nil
}

func decodePublic(b64 string) (*mldsa65.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("public key is not valid base64: %w", err)
	}
	if len(raw) != PublicKeySize {
		return nil, fmt.Errorf("ml-dsa-65 public key should be %d bytes, got %d",
			PublicKeySize, len(raw))
	}
	var public mldsa65.PublicKey
	if err := public.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("public key rejected: %w", err)
	}
	return &public, nil
}

// KeyType satisfies activeledger.Signer.
func (k *KeyPair) KeyType() activeledger.KeyType { return activeledger.KeyTypeMLDSA65 }

// PublicKey returns the public key as the string the ledger stores.
//
// The encoding depends on the scheme, which is why this is not named for
// one: post-quantum keys are base64 and secp256k1 keys are 0x-prefixed hex.
func (k *KeyPair) PublicKey() string {
	raw, _ := k.public.MarshalBinary()
	return base64.StdEncoding.EncodeToString(raw)
}

// PrivateKeyB64 returns the private key. Errors if verify-only.
func (k *KeyPair) PrivateKeyB64() (string, error) {
	if k.private == nil {
		return "", fmt.Errorf("this key pair has no private key - it is verify-only")
	}
	raw, err := k.private.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// CanSign reports whether a private key is present.
func (k *KeyPair) CanSign() bool { return k.private != nil }

// Sign signs a message.
//
// ctx is nil: the ledger uses FIPS 204 pure with an EMPTY context. Passing a
// context string here would produce a signature that is individually
// well-formed and universally rejected.
func (k *KeyPair) Sign(message []byte) ([]byte, error) {
	if k.private == nil {
		return nil, fmt.Errorf("this key pair has no private key - it is verify-only")
	}
	signature := make([]byte, SignatureSize)
	if err := mldsa65.SignTo(k.private, message, nil, false, signature); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return signature, nil
}

// Verify reports whether a signature is valid.
//
// Returns false rather than an error for malformed input: a caller should not
// have to distinguish "invalid" from "wrong shape", and making one an error
// invites handling that swallows the other.
func (k *KeyPair) Verify(message, signature []byte) bool {
	return mldsa65.Verify(k.public, message, nil, signature)
}
