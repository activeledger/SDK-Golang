package pqkeys

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	activeledger "github.com/activeledger/SDK-Golang"
	"github.com/activeledger/SDK-Golang/recovery"
)

// SeedSize is ML-DSA-65's seed length, FIPS 204's xi.
const SeedSize = mldsa65.SeedSize

// FromSeed derives a key pair from a 32-byte seed.
//
// This is how an ML-DSA-65 private key moves between Activeledger SDKs. The
// PHP SDK's private key IS a seed - its library implements FIPS 204 key
// generation from a seed but not skEncode/skDecode - so the 4032-byte
// encoding this SDK exports cannot be loaded there. The seed can be, and
// gives an identical public key: verified against the published vectors and
// against BouncyCastle.
func FromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf(
			"ml-dsa-65 needs a %d-byte seed, got %d. It is refused rather than padded: "+
				"a padded seed is a different identity, not a malformed one",
			SeedSize, len(seed))
	}

	var fixed [mldsa65.SeedSize]byte
	copy(fixed[:], seed)

	public, private := mldsa65.NewKeyFromSeed(&fixed)
	return &KeyPair{public: public, private: private}, nil
}

// FromPhrase derives a key pair from a BIP-39 recovery phrase.
//
// One phrase can back an ml-dsa-65 and a secp256k1 identity at once: each
// type derives its own seed, so neither reveals the other.
func FromPhrase(phrase, passphrase string) (*KeyPair, error) {
	bip39Seed, err := recovery.ToSeed(phrase, passphrase)
	if err != nil {
		return nil, err
	}

	seed, err := recovery.DeriveSeed(activeledger.KeyTypeMLDSA65, bip39Seed)
	if err != nil {
		return nil, err
	}

	return FromSeed(seed)
}
