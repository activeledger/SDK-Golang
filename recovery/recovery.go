// Package recovery implements BIP-39 recovery phrases and the seed each
// Activeledger key type derives from one.
//
// There are two layers, and conflating them is the mistake this package is
// arranged to prevent. A phrase becomes a 64-byte BIP-39 seed; that seed
// becomes the seed the chosen algorithm actually takes. They are different
// lengths and different constructions, and DeriveSeed is the step between.
//
// The derivation:
//
//	BIP-39 seed S = PBKDF2-HMAC-SHA512(phrase, "mnemonic"+passphrase, 2048, 64)
//
//	ml-dsa-65   HKDF-SHA512(S, salt="", info="activeledger-seed-v1:ml-dsa-65", 32)
//	falcon-512  HKDF-SHA512(S, salt="", info="activeledger-seed-v1:falcon-512", 48)
//	secp256k1   HMAC-SHA512("Bitcoin seed", S)[0..32]
//
// secp256k1 does not use HKDF, and that is not an oversight. The JavaScript
// SDK has shipped restoreBIP39Key with the construction above since before
// the post-quantum types existed, so phrases are already in use. Changing it
// would hand every one of those users a different key for a phrase that used
// to work - not an error, just an identity that is no longer theirs. The
// post-quantum types are new and carry no such debt, so they get the
// construction with proper domain separation.
//
// Published, with cross-language vectors, in the JavaScript SDK's
// vectors/seed-vectors.json.
//
// No new dependency: crypto/pbkdf2 and crypto/hkdf are both in the standard
// library as of Go 1.24.
package recovery

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/text/unicode/norm"

	activeledger "github.com/activeledger/SDK-Golang"
)

// BIP-39's fixed PBKDF2 parameters. Not tunable: changing one changes every
// identity ever derived from a phrase.
const (
	iterations    = 2048
	BIP39SeedSize = 64
)

// SeedSize returns the seed length the given key type takes. A wrong length
// must be refused, never padded - a padded seed is a different identity, not
// a malformed one.
func SeedSize(keyType activeledger.KeyType) (int, error) {
	switch keyType {
	case activeledger.KeyTypeSecp256k1, activeledger.KeyTypeMLDSA65:
		return 32, nil
	case activeledger.KeyTypeFalcon512:
		return 48, nil
	default:
		return 0, fmt.Errorf("%s keys cannot be derived from a seed", keyType)
	}
}

//go:embed bip39-english.txt
var wordlistFile string

var (
	wordlistOnce sync.Once
	wordlist     []string
	wordIndex    map[string]int
)

func loadWordlist() {
	wordlistOnce.Do(func() {
		wordlist = strings.Fields(wordlistFile)
		wordIndex = make(map[string]int, len(wordlist))
		for position, word := range wordlist {
			wordIndex[word] = position
		}
	})
}

// Validate checks a phrase and returns it normalised and single-spaced.
//
// The checksum is verified, not just word membership. A mistyped phrase that
// is not checked does not fail: it derives a perfectly valid key for an
// identity nobody owns, and the only symptom is the ledger not recognising
// it.
func Validate(phrase string) (string, error) {
	loadWordlist()

	if len(wordlist) != 2048 {
		return "", fmt.Errorf("the BIP-39 wordlist should hold 2048 words, found %d", len(wordlist))
	}

	words := strings.Fields(norm.NFKD.String(phrase))

	// 12, 15, 18, 21 and 24 are the only valid lengths.
	if len(words) < 12 || len(words) > 24 || len(words)%3 != 0 {
		return "", fmt.Errorf("a BIP-39 phrase is 12, 15, 18, 21 or 24 words, got %d", len(words))
	}

	var bits strings.Builder
	for position, word := range words {
		index, ok := wordIndex[word]
		if !ok {
			return "", fmt.Errorf("word %d (%q) is not in the BIP-39 English wordlist", position+1, word)
		}
		for bit := 10; bit >= 0; bit-- {
			if index&(1<<bit) != 0 {
				bits.WriteByte('1')
			} else {
				bits.WriteByte('0')
			}
		}
	}

	all := bits.String()
	checksumBits := len(words) / 3
	entropyBits := len(all) - checksumBits

	entropy := make([]byte, entropyBits/8)
	for i := range entropy {
		var b byte
		for bit := 0; bit < 8; bit++ {
			b <<= 1
			if all[i*8+bit] == '1' {
				b |= 1
			}
		}
		entropy[i] = b
	}

	sum := sha256.Sum256(entropy)
	var expected strings.Builder
	for bit := 0; bit < checksumBits; bit++ {
		if sum[0]&(1<<(7-bit)) != 0 {
			expected.WriteByte('1')
		} else {
			expected.WriteByte('0')
		}
	}

	if all[entropyBits:] != expected.String() {
		return "", fmt.Errorf(
			"the BIP-39 checksum does not match - the phrase has a typo or the words are in " +
				"the wrong order. Deriving from it anyway would produce a valid key for an " +
				"identity nobody owns")
	}

	return strings.Join(words, " "), nil
}

// ToSeed turns a recovery phrase into its 64-byte BIP-39 seed.
func ToSeed(phrase, passphrase string) ([]byte, error) {
	normalised, err := Validate(phrase)
	if err != nil {
		return nil, err
	}

	// BIP-39's salt: the passphrase is appended to the literal "mnemonic",
	// not passed separately.
	return pbkdf2.Key(sha512.New, normalised,
		[]byte("mnemonic"+norm.NFKD.String(passphrase)), iterations, BIP39SeedSize)
}

// DeriveSeed turns a BIP-39 seed into the seed the given key type takes.
func DeriveSeed(keyType activeledger.KeyType, bip39Seed []byte) ([]byte, error) {
	if len(bip39Seed) != BIP39SeedSize {
		return nil, fmt.Errorf("a BIP-39 seed is %d bytes, got %d", BIP39SeedSize, len(bip39Seed))
	}

	size, err := SeedSize(keyType)
	if err != nil {
		return nil, err
	}

	if keyType == activeledger.KeyTypeSecp256k1 {
		mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
		mac.Write(bip39Seed)
		return mac.Sum(nil)[:32], nil
	}

	// A nil salt means a block of zero bytes of the hash length, which is
	// what RFC 5869 specifies - checked byte for byte against node's
	// crypto.hkdfSync and PHP's hash_hkdf.
	return hkdf.Key(sha512.New, bip39Seed, nil,
		fmt.Sprintf("activeledger-seed-v1:%s", keyType), size)
}
