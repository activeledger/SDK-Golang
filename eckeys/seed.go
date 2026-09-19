package eckeys

import (
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	activeledger "github.com/activeledger/SDK-Golang"
	"github.com/activeledger/SDK-Golang/recovery"
)

// SeedSize is the length of a secp256k1 seed. For this curve the seed IS the
// private scalar, so there is no derivation step.
const SeedSize = 32

// FromSeed derives a key pair from a 32-byte seed.
//
// The same seed gives the same identity in every Activeledger SDK, which is
// what makes a seed the portable private-key format - it is how a private key
// moves between languages.
//
// A seed outside [1, n-1] is refused rather than reduced mod n. Reducing
// produces a perfectly functional key belonging to a different identity, and
// nothing downstream ever reports a problem.
func FromSeed(seed []byte, compressed bool) (*KeyPair, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf(
			"secp256k1 needs a %d-byte seed, got %d. It is refused rather than padded: "+
				"a padded seed is a different identity, not a malformed one",
			SeedSize, len(seed))
	}

	// Checked before handing the bytes to secp256k1.PrivKeyFromBytes, which
	// reduces mod n rather than refusing.
	var scalar secp256k1.ModNScalar
	if overflow := scalar.SetByteSlice(seed); overflow || scalar.IsZero() {
		return nil, fmt.Errorf(
			"seed is not a valid secp256k1 private key - the scalar must be in [1, n-1]")
	}

	private := secp256k1.NewPrivateKey(&scalar)

	return FromKeys(
		encodeHex(encodePoint(private.PubKey(), compressed)),
		encodeHex(seed),
	)
}

// FromPhrase derives a key pair from a BIP-39 recovery phrase.
func FromPhrase(phrase, passphrase string, compressed bool) (*KeyPair, error) {
	bip39Seed, err := recovery.ToSeed(phrase, passphrase)
	if err != nil {
		return nil, err
	}

	seed, err := recovery.DeriveSeed(activeledger.KeyTypeSecp256k1, bip39Seed)
	if err != nil {
		return nil, err
	}

	return FromSeed(seed, compressed)
}

// FromLegacyPhrase recovers a key pair from a phrase made by the original
// @activeledger/sdk-bip39 package.
//
// That scheme is SHA256(phrase) used directly as the scalar - no key
// stretching, no domain separation, no passphrase. It exists so an old phrase
// can be recovered, never so a new key can be made with it.
//
// Deliberately does NOT validate the mnemonic: the original package hashed
// the string as given and never consulted the wordlist, so rejecting a phrase
// here that it accepted would make a recoverable identity unrecoverable.
func FromLegacyPhrase(phrase string, compressed bool) (*KeyPair, error) {
	sum := sha256.Sum256([]byte(phrase))
	return FromSeed(sum[:], compressed)
}
