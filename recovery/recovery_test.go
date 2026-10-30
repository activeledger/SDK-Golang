package recovery_test

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"

	activeledger "github.com/activeledger/SDK-Golang/v2"
	"github.com/activeledger/SDK-Golang/v2/recovery"
)

// The recovery package on its own. The cross-language vectors in the root
// package's seed_test.go exercise it end to end; these pin the pieces so a
// failure says which step broke.

const abandon12 = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

func TestSeedSizePerKeyType(t *testing.T) {
	want := map[activeledger.KeyType]int{
		activeledger.KeyTypeSecp256k1: 32,
		activeledger.KeyTypeMLDSA65:   32,
		activeledger.KeyTypeFalcon512: 48,
	}
	for keyType, size := range want {
		got, err := recovery.SeedSize(keyType)
		if err != nil || got != size {
			t.Errorf("%s: got (%d, %v), want %d", keyType, got, err, size)
		}
	}
}

func TestRSAHasNoSeedSize(t *testing.T) {
	if size, err := recovery.SeedSize(activeledger.KeyTypeRSA); err == nil {
		t.Fatalf("rsa cannot be derived from a seed, got size %d", size)
	}
	if _, err := recovery.SeedSize(activeledger.KeyType("nonsense")); err == nil {
		t.Fatal("an unknown key type was given a seed size")
	}
}

// Every length BIP-39 allows, using the all-zero-entropy phrase, whose final
// word differs by length because it carries the checksum.
func TestEveryValidPhraseLengthIsAccepted(t *testing.T) {
	last := map[int]string{12: "about", 15: "address", 18: "agent", 21: "admit", 24: "art"}
	for count, word := range last {
		phrase := strings.Repeat("abandon ", count-1) + word
		got, err := recovery.Validate(phrase)
		if err != nil {
			t.Errorf("%d words: %v", count, err)
		}
		if got != phrase {
			t.Errorf("%d words: phrase changed to %q", count, got)
		}
	}
}

func TestInvalidPhraseLengthsAreRejected(t *testing.T) {
	for _, count := range []int{0, 1, 11, 13, 14, 16, 25, 27} {
		phrase := strings.TrimSpace(strings.Repeat("abandon ", count))
		if _, err := recovery.Validate(phrase); err == nil {
			t.Errorf("%d words were accepted", count)
		}
	}
}

func TestValidateReturnsASingleSpacedPhrase(t *testing.T) {
	messy := "  " + strings.ReplaceAll(abandon12, " ", " \t\n  ") + "  "
	got, err := recovery.Validate(messy)
	if err != nil {
		t.Fatal(err)
	}
	if got != abandon12 {
		t.Fatalf("got %q, want %q", got, abandon12)
	}
}

// One word swapped for another valid word: membership passes, so only the
// checksum can catch it.
func TestASwappedWordFailsTheChecksum(t *testing.T) {
	phrase := strings.Repeat("abandon ", 11) + "ability"
	_, err := recovery.Validate(phrase)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected a checksum error, got %v", err)
	}
}

func TestAnUnknownWordIsReportedWithItsPosition(t *testing.T) {
	phrase := strings.Repeat("abandon ", 4) + "notaword " + strings.Repeat("abandon ", 6) + "about"
	_, err := recovery.Validate(phrase)
	if err == nil || !strings.Contains(err.Error(), "word 5") || !strings.Contains(err.Error(), "notaword") {
		t.Fatalf("expected word 5 to be named, got %v", err)
	}
}

// The published BIP-39 test vector (trezor/python-mnemonic) for this phrase
// with the passphrase TREZOR.
func TestToSeedMatchesTheBIP39TestVector(t *testing.T) {
	want := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" +
		"1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

	seed, err := recovery.ToSeed(abandon12, "TREZOR")
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != recovery.BIP39SeedSize {
		t.Fatalf("seed is %d bytes, want %d", len(seed), recovery.BIP39SeedSize)
	}
	if got := hex.EncodeToString(seed); got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

func TestThePassphraseChangesTheSeed(t *testing.T) {
	plain, err := recovery.ToSeed(abandon12, "")
	if err != nil {
		t.Fatal(err)
	}
	salted, err := recovery.ToSeed(abandon12, "x")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(plain) == hex.EncodeToString(salted) {
		t.Fatal("a passphrase made no difference")
	}
}

func TestToSeedRefusesAnInvalidPhrase(t *testing.T) {
	if _, err := recovery.ToSeed("abandon abandon", ""); err == nil {
		t.Fatal("an invalid phrase produced a seed")
	}
}

func TestDeriveSeedRefusesAWrongSizedBIP39Seed(t *testing.T) {
	for _, length := range []int{0, 32, 63, 65} {
		if _, err := recovery.DeriveSeed(activeledger.KeyTypeMLDSA65, make([]byte, length)); err == nil {
			t.Errorf("a %d-byte BIP-39 seed was accepted", length)
		}
	}
}

func TestDeriveSeedRefusesKeyTypesWithoutSeeds(t *testing.T) {
	if _, err := recovery.DeriveSeed(activeledger.KeyTypeRSA, make([]byte, 64)); err == nil {
		t.Fatal("rsa was given a derived seed")
	}
}

func TestDerivedSeedLengthsMatchSeedSize(t *testing.T) {
	bip39, err := recovery.ToSeed(abandon12, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, keyType := range []activeledger.KeyType{
		activeledger.KeyTypeSecp256k1, activeledger.KeyTypeMLDSA65, activeledger.KeyTypeFalcon512,
	} {
		size, _ := recovery.SeedSize(keyType)
		seed, err := recovery.DeriveSeed(keyType, bip39)
		if err != nil {
			t.Fatalf("%s: %v", keyType, err)
		}
		if len(seed) != size {
			t.Errorf("%s: derived %d bytes, want %d", keyType, len(seed), size)
		}
	}
}

// secp256k1 deliberately does not use HKDF (see the package comment): it is
// the first half of HMAC-SHA512("Bitcoin seed", S). Computed independently
// here so a switch to HKDF is caught.
func TestSecp256k1DerivationIsHMACNotHKDF(t *testing.T) {
	bip39, err := recovery.ToSeed(abandon12, "")
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(bip39)
	want := mac.Sum(nil)[:32]

	got, err := recovery.DeriveSeed(activeledger.KeyTypeSecp256k1, bip39)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}
