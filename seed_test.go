package activeledger_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	activeledger "github.com/activeledger/SDK-Golang"
	"github.com/activeledger/SDK-Golang/eckeys"
	"github.com/activeledger/SDK-Golang/pqkeys"
	"github.com/activeledger/SDK-Golang/recovery"
)

// Seed and recovery-phrase derivation, against the published cross-language
// vectors.
//
// Six other SDKs derive keys from the same seeds and phrases. A derivation
// that drifts does not fail loudly - it produces a perfectly valid key for an
// identity that is not the caller's, and the only symptom arrives much later
// as 1220 "Signature Incorrect" from somewhere else entirely.

type seedVector struct {
	Type          string `json:"type"`
	SeedName      string `json:"seedName"`
	Seed          string `json:"seed"`
	PublicKeyForm string `json:"publicKeyForm"`
	PublicKey     string `json:"publicKey"`
	PrivateKey    string `json:"privateKey"`
	Valid         *bool  `json:"valid"`
}

type phraseVector struct {
	Type          string `json:"type"`
	PhraseName    string `json:"phraseName"`
	Phrase        string `json:"phrase"`
	Passphrase    string `json:"passphrase"`
	BIP39Seed     string `json:"bip39Seed"`
	DerivedSeed   string `json:"derivedSeed"`
	Scheme        string `json:"scheme"`
	PublicKeyForm string `json:"publicKeyForm"`
	PublicKey     string `json:"publicKey"`
	PrivateKey    string `json:"privateKey"`
}

type seedDoc struct {
	SeedVectors   []seedVector   `json:"seedVectors"`
	PhraseVectors []phraseVector `json:"phraseVectors"`
}

func loadSeedVectors(t *testing.T) seedDoc {
	t.Helper()

	raw, err := os.ReadFile("testdata/seed-vectors.json")
	if err != nil {
		t.Fatalf("seed-vectors.json: %v", err)
	}

	var doc seedDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("seed-vectors.json: %v", err)
	}
	if len(doc.SeedVectors) == 0 || len(doc.PhraseVectors) == 0 {
		t.Fatal("seed-vectors.json is empty - the tests below would pass by not running")
	}

	return doc
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("bad hex in vector: %v", err)
	}
	return raw
}

func TestSecp256k1FromSeedMatchesTheVectors(t *testing.T) {
	doc := loadSeedVectors(t)
	seen := 0

	for _, v := range doc.SeedVectors {
		if v.Type != "secp256k1" || (v.Valid != nil && !*v.Valid) {
			continue
		}
		seen++

		pair, err := eckeys.FromSeed(mustHex(t, v.Seed), v.PublicKeyForm == "compressed")
		if err != nil {
			t.Fatalf("%s/%s: %v", v.SeedName, v.PublicKeyForm, err)
		}

		if pair.PublicKey() != v.PublicKey {
			t.Errorf("%s/%s: public key differs", v.SeedName, v.PublicKeyForm)
		}
		private, err := pair.PrivateKey()
		if err != nil {
			t.Fatalf("%s: %v", v.SeedName, err)
		}
		if private != v.PrivateKey {
			t.Errorf("%s/%s: private key differs - got %s, want %s",
				v.SeedName, v.PublicKeyForm, private, v.PrivateKey)
		}
	}

	if seen == 0 {
		t.Fatal("no secp256k1 seed vectors ran")
	}
}

// An invalid scalar must be refused, never reduced. decred's
// PrivKeyFromBytes reduces mod n rather than refusing, so without the
// explicit check this returns a perfectly functional key for a different
// identity and nothing downstream reports a problem.
func TestSecp256k1RefusesAnInvalidScalar(t *testing.T) {
	doc := loadSeedVectors(t)
	seen := 0

	for _, v := range doc.SeedVectors {
		if v.Type != "secp256k1" || v.Valid == nil || *v.Valid {
			continue
		}
		seen++

		if _, err := eckeys.FromSeed(mustHex(t, v.Seed), true); err == nil {
			t.Errorf("%s: accepted an invalid scalar", v.SeedName)
		} else if !strings.Contains(err.Error(), "[1, n-1]") {
			t.Errorf("%s: wrong error: %v", v.SeedName, err)
		}
	}

	if seen < 2 {
		t.Fatalf("expected at least 2 invalid seed vectors, ran %d", seen)
	}
}

func TestMLDSAFromSeedMatchesTheVectors(t *testing.T) {
	doc := loadSeedVectors(t)
	seen := 0

	for _, v := range doc.SeedVectors {
		if v.Type != "ml-dsa-65" {
			continue
		}
		seen++

		pair, err := pqkeys.FromSeed(mustHex(t, v.Seed))
		if err != nil {
			t.Fatalf("%s: %v", v.SeedName, err)
		}
		if pair.PublicKey() != v.PublicKey {
			t.Errorf("%s: public key differs", v.SeedName)
		}
		private, err := pair.PrivateKeyB64()
		if err != nil {
			t.Fatalf("%s: %v", v.SeedName, err)
		}
		if private != v.PrivateKey {
			t.Errorf("%s: private key differs", v.SeedName)
		}
	}

	if seen == 0 {
		t.Fatal("no ml-dsa-65 seed vectors ran")
	}
}

func TestPhraseRecoveryMatchesTheVectors(t *testing.T) {
	doc := loadSeedVectors(t)
	seen := 0

	for _, v := range doc.PhraseVectors {
		compressed := v.PublicKeyForm == "compressed"

		var (
			public, private string
			err             error
		)

		switch {
		case v.Type == "secp256k1" && v.Scheme == "legacy":
			var pair *eckeys.KeyPair
			pair, err = eckeys.FromLegacyPhrase(v.Phrase, compressed)
			if err == nil {
				public, private = pair.PublicKey(), mustPrivate(t, pair)
			}
		case v.Type == "secp256k1":
			var pair *eckeys.KeyPair
			pair, err = eckeys.FromPhrase(v.Phrase, v.Passphrase, compressed)
			if err == nil {
				public, private = pair.PublicKey(), mustPrivate(t, pair)
			}
		case v.Type == "ml-dsa-65":
			var pair *pqkeys.KeyPair
			pair, err = pqkeys.FromPhrase(v.Phrase, v.Passphrase)
			if err == nil {
				public = pair.PublicKey()
				private, err = pair.PrivateKeyB64()
			}
		default:
			// falcon-512 is not supported by this SDK at all.
			continue
		}

		seen++
		if err != nil {
			t.Fatalf("%s/%s/%s: %v", v.Type, v.PhraseName, v.Scheme, err)
		}
		if public != v.PublicKey || private != v.PrivateKey {
			t.Errorf("%s/%s/%s: key differs", v.Type, v.PhraseName, v.Scheme)
		}
	}

	if seen == 0 {
		t.Fatal("no phrase vectors ran")
	}
}

func mustPrivate(t *testing.T, pair *eckeys.KeyPair) string {
	t.Helper()
	private, err := pair.PrivateKey()
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	return private
}

// Checked separately from the key so a failure says WHICH step drifted.
func TestDerivationMatchesThePublishedIntermediates(t *testing.T) {
	doc := loadSeedVectors(t)

	for _, v := range doc.PhraseVectors {
		if v.Scheme != "v1" {
			continue
		}

		bip39, err := recovery.ToSeed(v.Phrase, v.Passphrase)
		if err != nil {
			t.Fatalf("%s: %v", v.PhraseName, err)
		}
		if hex.EncodeToString(bip39) != v.BIP39Seed {
			t.Fatalf("%s: BIP-39 seed differs", v.PhraseName)
		}

		seed, err := recovery.DeriveSeed(activeledger.KeyType(v.Type), bip39)
		if err != nil {
			t.Fatalf("%s/%s: %v", v.Type, v.PhraseName, err)
		}
		if hex.EncodeToString(seed) != v.DerivedSeed {
			t.Errorf("%s/%s: derived seed differs", v.Type, v.PhraseName)
		}
	}
}

// Domain separation. Without it one phrase gives an ml-dsa-65 seed equal to
// the secp256k1 scalar, so two identities share entropy.
func TestEachKeyTypeDerivesADifferentSeed(t *testing.T) {
	doc := loadSeedVectors(t)

	bip39, err := recovery.ToSeed(doc.PhraseVectors[0].Phrase, "")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	for _, keyType := range []activeledger.KeyType{
		activeledger.KeyTypeSecp256k1,
		activeledger.KeyTypeMLDSA65,
		activeledger.KeyTypeFalcon512,
	} {
		seed, err := recovery.DeriveSeed(keyType, bip39)
		if err != nil {
			t.Fatalf("%s: %v", keyType, err)
		}
		encoded := hex.EncodeToString(seed)
		if other, clash := seen[encoded]; clash {
			t.Fatalf("%s derives the same seed as %s", keyType, other)
		}
		seen[encoded] = string(keyType)
	}
}

// falcon-512 has no implementation here, but its SEED still derives - so a
// phrase can back a Falcon identity created in another SDK.
func TestFalconSeedDerivesEvenThoughFalconDoesNot(t *testing.T) {
	doc := loadSeedVectors(t)

	bip39, err := recovery.ToSeed(doc.PhraseVectors[0].Phrase, "")
	if err != nil {
		t.Fatal(err)
	}

	seed, err := recovery.DeriveSeed(activeledger.KeyTypeFalcon512, bip39)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 48 {
		t.Errorf("falcon-512 seed should be 48 bytes, got %d", len(seed))
	}
}

func TestASeedOfTheWrongLengthIsRefusedRatherThanPadded(t *testing.T) {
	// Padding would produce a valid key for a different identity - the same
	// failure as reducing a scalar, by another route.
	for _, length := range []int{0, 31, 33, 48} {
		if _, err := eckeys.FromSeed(make([]byte, length), true); err == nil {
			t.Errorf("secp256k1 accepted a %d-byte seed", length)
		}
	}
	for _, length := range []int{0, 31, 33, 48} {
		if _, err := pqkeys.FromSeed(make([]byte, length)); err == nil {
			t.Errorf("ml-dsa-65 accepted a %d-byte seed", length)
		}
	}
}

func TestAPhraseWithABadChecksumIsRejected(t *testing.T) {
	// An unchecked phrase is a silent failure: it derives a perfectly valid
	// key for an identity nobody owns.
	_, err := recovery.ToSeed(strings.Repeat("abandon ", 11)+"abandon", "")
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected a checksum error, got %v", err)
	}
}

func TestAWordOutsideTheWordlistIsNamed(t *testing.T) {
	_, err := recovery.ToSeed(strings.Repeat("abandon ", 11)+"zzzz", "")
	if err == nil || !strings.Contains(err.Error(), "zzzz") {
		t.Fatalf("expected the word to be named, got %v", err)
	}
}

func TestAWrongWordCountIsRejected(t *testing.T) {
	_, err := recovery.ToSeed("abandon abandon abandon", "")
	if err == nil || !strings.Contains(err.Error(), "12, 15, 18, 21 or 24") {
		t.Fatalf("expected a length error, got %v", err)
	}
}

func TestASeedDerivedKeySignsAndVerifies(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0x11
	}

	ec, err := eckeys.FromSeed(seed, true)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := ec.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !ec.Verify([]byte("payload"), signature) {
		t.Error("secp256k1 seed-derived key did not verify its own signature")
	}

	pq, err := pqkeys.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pqSignature, err := pq.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if !pq.Verify([]byte("payload"), pqSignature) {
		t.Error("ml-dsa-65 seed-derived key did not verify its own signature")
	}
}
