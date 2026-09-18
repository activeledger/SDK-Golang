package eckeys_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	activeledger "github.com/activeledger/SDK-Golang"
	"github.com/activeledger/SDK-Golang/eckeys"
)

// secp256k1 conformance against the published cross-language vectors.
//
// Its encoding has nothing in common with the post-quantum schemes, and every
// test here exists because reusing the base64 path produces material the
// ledger rejects as 1220 "Signature Incorrect" while saying nothing else.

type vector struct {
	Type                   string `json:"type"`
	MessageName            string `json:"messageName"`
	PublicKeyForm          string `json:"publicKeyForm"`
	Message                string `json:"message"`
	PublicKey              string `json:"publicKey"`
	PrivateKey             string `json:"privateKey"`
	Signature              string `json:"signature"`
	DeterministicSignature string `json:"deterministicSignature"`
	HighSSignature         string `json:"highSSignature"`
}

func vectors(t *testing.T) []vector {
	t.Helper()

	raw, err := os.ReadFile("../testdata/pq-vectors.json")
	if err != nil {
		t.Fatalf("vector file: %v", err)
	}

	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("vector json: %v", err)
	}

	var out []vector
	for _, v := range doc.Vectors {
		if v.Type == "secp256k1" {
			out = append(out, v)
		}
	}
	return out
}

func decode(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return raw
}

// The ledger accepts both forms, so a port that only ever sees one never
// learns to read the other.
func TestBothPublicKeyFormsArePresent(t *testing.T) {
	all := vectors(t)
	var compressed, uncompressed bool
	for _, v := range all {
		switch v.PublicKeyForm {
		case "compressed":
			compressed = true
		case "uncompressed":
			uncompressed = true
		}
	}

	if !compressed || !uncompressed {
		t.Fatal("vectors must cover both compressed and uncompressed public keys")
	}
	if len(all) < 12 {
		t.Fatalf("expected at least 12 vectors, found %d", len(all))
	}
}

func TestVerifiesEveryPublishedSignature(t *testing.T) {
	for _, v := range vectors(t) {
		key, err := eckeys.FromPublicKey(v.PublicKey)
		if err != nil {
			t.Fatalf("%s/%s: %v", v.MessageName, v.PublicKeyForm, err)
		}
		if !key.Verify([]byte(v.Message), decode(t, v.Signature)) {
			t.Errorf("failed to verify published secp256k1/%s/%s", v.MessageName, v.PublicKeyForm)
		}
	}
}

// High-S signatures must still verify.
//
// The ledger verifies through OpenSSL, which neither normalises nor requires
// low-S, so it produces high-S freely. A verifier enforcing low-S would
// reject roughly half of everything the ledger makes, and the half that
// succeeded would make it look like an intermittent fault. k256 and
// libsecp256k1 both enforce it by default; this must not.
func TestHighSSignaturesFromElsewhereStillVerify(t *testing.T) {
	for _, v := range vectors(t) {
		// The fixture must be what it claims. A "high-S" signature that is not
		// high-S would pass a permissive verifier for the wrong reason: green,
		// and proving nothing.
		if !eckeys.IsHighSBase64(v.HighSSignature) {
			t.Fatalf("%s/%s: the published high-S fixture is not high-S",
				v.MessageName, v.PublicKeyForm)
		}

		key, err := eckeys.FromPublicKey(v.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !key.Verify([]byte(v.Message), decode(t, v.HighSSignature)) {
			t.Errorf("rejected a high-S signature (%s/%s) - low-S is being enforced on verify",
				v.MessageName, v.PublicKeyForm)
		}
	}
}

// Permissive about s only. Accepting high-S must not have quietly widened
// anything else.
func TestTheHighSFormStillRejectsATamperedMessage(t *testing.T) {
	for _, v := range vectors(t) {
		key, err := eckeys.FromPublicKey(v.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if key.Verify([]byte(v.Message+" "), decode(t, v.HighSSignature)) {
			t.Errorf("a tampered message verified against the high-S form (%s/%s)",
				v.MessageName, v.PublicKeyForm)
		}
	}
}

// The strongest test here: the exact bytes, not merely a valid signature.
//
// These expected values come from @noble/curves, an entirely separate
// implementation. Agreeing byte for byte means agreeing on RFC 6979's k, on
// low-S normalisation and on DER encoding at once -- none of which a
// verify-round-trip test can see. Only possible because ECDSA signing is
// deterministic; the post-quantum schemes are hedged and never can be.
func TestSignaturesAreByteIdenticalToTheReference(t *testing.T) {
	for _, v := range vectors(t) {
		key, err := eckeys.FromKeys(v.PublicKey, v.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		signature, err := key.Sign([]byte(v.Message))
		if err != nil {
			t.Fatal(err)
		}

		mine := base64.StdEncoding.EncodeToString(signature)
		if mine != v.DeterministicSignature {
			t.Errorf("%s/%s: signature differs from the reference.\n  expected %s\n  got      %s\n"+
				"  If r matches and only s differs, low-S normalisation is the cause.",
				v.MessageName, v.PublicKeyForm, v.DeterministicSignature, mine)
		}
	}
}

func TestSigningIsDeterministic(t *testing.T) {
	all := vectors(t)
	key, err := eckeys.FromKeys(all[0].PublicKey, all[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	first, _ := key.Sign([]byte(all[0].Message))
	second, _ := key.Sign([]byte(all[0].Message))
	if string(first) != string(second) {
		t.Error("signing the same message twice produced different bytes")
	}

	other, _ := key.Sign([]byte(all[1].Message))
	if string(first) == string(other) {
		t.Error("different messages produced the same signature")
	}
}

func TestEverySignatureEmittedIsLowS(t *testing.T) {
	key, err := eckeys.Generate()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 200; i++ {
		signature, err := key.Sign([]byte(fmt.Sprintf("message %d", i)))
		if err != nil {
			t.Fatal(err)
		}
		if eckeys.IsHighS(signature) {
			t.Fatalf("signature %d was high-S", i)
		}
	}
}

func TestSignaturesMadeHereVerifyWithTheReferenceKey(t *testing.T) {
	for _, v := range vectors(t) {
		signer, err := eckeys.FromKeys(v.PublicKey, v.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := eckeys.FromPublicKey(v.PublicKey)
		if err != nil {
			t.Fatal(err)
		}

		signature, _ := signer.Sign([]byte(v.Message))
		if !verifier.Verify([]byte(v.Message), signature) {
			t.Errorf("reference key rejected a signature made here (%s/%s)",
				v.MessageName, v.PublicKeyForm)
		}
	}
}

func TestRoundTripsPublishedKeysExactly(t *testing.T) {
	for _, v := range vectors(t) {
		key, err := eckeys.FromKeys(v.PublicKey, v.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		if key.PublicKey() != v.PublicKey {
			t.Errorf("public key changed: %s -> %s", v.PublicKey, key.PublicKey())
		}
		private, err := key.PrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		if private != v.PrivateKey {
			t.Errorf("private key changed: %s -> %s", v.PrivateKey, private)
		}
	}
}

func TestTamperedMessageDoesNotVerify(t *testing.T) {
	for _, v := range vectors(t) {
		key, err := eckeys.FromPublicKey(v.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if key.Verify([]byte(v.Message+" "), decode(t, v.Signature)) {
			t.Errorf("a tampered message verified (%s/%s)", v.MessageName, v.PublicKeyForm)
		}
	}
}

func TestGeneratedKeysUseTheLedgersEncoding(t *testing.T) {
	key, err := eckeys.Generate()
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(key.PublicKey(), "0x") {
		t.Errorf("public key is not 0x hex: %s", key.PublicKey())
	}
	// Compressed by default: 33 bytes, so "0x" plus 66 hex characters.
	if len(key.PublicKey()) != 68 {
		t.Errorf("public key is %d chars, expected 68", len(key.PublicKey()))
	}

	private, _ := key.PrivateKey()
	if len(private) != 66 {
		t.Errorf("private key is %d chars, expected 66", len(private))
	}
	if prefix := key.PublicKey()[2:4]; prefix != "02" && prefix != "03" {
		t.Errorf("compressed key has prefix %s", prefix)
	}
}

func TestUncompressedGenerationIsAvailable(t *testing.T) {
	key, err := eckeys.GenerateWith(false)
	if err != nil {
		t.Fatal(err)
	}

	if len(key.PublicKey()) != 132 {
		t.Errorf("uncompressed key is %d chars, expected 132", len(key.PublicKey()))
	}
	if !strings.HasPrefix(key.PublicKey(), "0x04") {
		t.Errorf("uncompressed key does not start 0x04: %s", key.PublicKey()[:6])
	}

	signature, _ := key.Sign([]byte("x"))
	if !key.Verify([]byte("x"), signature) {
		t.Error("uncompressed key could not verify its own signature")
	}
}

// A leading zero byte occurs roughly once in 400 keys, and a value that
// dropped it is a different scalar to anything reading it strictly.
func TestPrivateKeysAreAlwaysLeftPaddedTo32Bytes(t *testing.T) {
	for i := 0; i < 1500; i++ {
		key, err := eckeys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		private, _ := key.PrivateKey()
		if len(private) != 66 {
			t.Fatalf("key %d has a %d-char private key, expected 66", i, len(private))
		}
	}
}

// The 0x prefix is part of what the ledger stores, not decoration.
func TestAKeyWithoutTheHexPrefixIsRefused(t *testing.T) {
	key, _ := eckeys.Generate()
	stripped := key.PublicKey()[2:]

	_, err := eckeys.FromPublicKey(stripped)
	if err == nil {
		t.Fatal("a key without the 0x prefix was accepted")
	}
	if !strings.Contains(err.Error(), "0x") {
		t.Errorf("the error does not mention the prefix: %v", err)
	}
}

func TestWrongLengthPublicKeyNamesBothValidLengths(t *testing.T) {
	_, err := eckeys.FromPublicKey("0x" + strings.Repeat("aa", 20))
	if err == nil {
		t.Fatal("a 20-byte public key was accepted")
	}
	if !strings.Contains(err.Error(), "33") || !strings.Contains(err.Error(), "65") {
		t.Errorf("the error does not name both valid lengths: %v", err)
	}
}

// A length and a point prefix that disagree means the forms got mixed.
func TestAPrefixThatContradictsTheLengthIsRejected(t *testing.T) {
	_, err := eckeys.FromPublicKey("0x04" + strings.Repeat("aa", 32))
	if err == nil {
		t.Fatal("a 33-byte key claiming to be uncompressed was accepted")
	}
	if !strings.Contains(err.Error(), "0x04") {
		t.Errorf("the error does not name the prefix: %v", err)
	}
}

func TestNonHexIsRejected(t *testing.T) {
	if _, err := eckeys.FromPublicKey("0xzzzz"); err == nil {
		t.Fatal("non-hex was accepted")
	}
}

func TestVerifyOnlyKeyPairRefusesToSign(t *testing.T) {
	all := vectors(t)
	key, err := eckeys.FromPublicKey(all[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if key.CanSign() {
		t.Error("a verify-only key pair claims it can sign")
	}
	if _, err := key.Sign([]byte("x")); err == nil {
		t.Error("a verify-only key pair signed")
	}
	if _, err := key.PrivateKey(); err == nil {
		t.Error("a verify-only key pair returned a private key")
	}
}

func TestMalformedSignatureReturnsFalse(t *testing.T) {
	all := vectors(t)
	key, err := eckeys.FromPublicKey(all[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte(all[0].Message)
	for name, signature := range map[string][]byte{
		"empty":    {},
		"short":    make([]byte, 10),
		"raw r||s": make([]byte, 64),
	} {
		if key.Verify(message, signature) {
			t.Errorf("a %s signature verified", name)
		}
	}
}

// The ledger routes bitcoin and ethereum to identical secp256k1
// verification, so an existing identity may carry either.
func TestBitcoinAndEthereumParseAsSecp256k1(t *testing.T) {
	for _, wire := range []string{"bitcoin", "ethereum", "secp256k1"} {
		parsed, err := activeledger.ParseKeyType(wire)
		if err != nil {
			t.Fatalf("%s: %v", wire, err)
		}
		if parsed != activeledger.KeyTypeSecp256k1 {
			t.Errorf("%s parsed as %s", wire, parsed)
		}
		// Never emitted as anything but secp256k1.
		if string(parsed) != "secp256k1" {
			t.Errorf("%s would be written back as %s", wire, parsed)
		}
	}
}

func TestKeyTypeIsSecp256k1(t *testing.T) {
	key, _ := eckeys.Generate()
	if key.KeyType() != activeledger.KeyTypeSecp256k1 {
		t.Errorf("key type is %s", key.KeyType())
	}
}

// String output must never carry private key material: it ends up in logs.
func TestStringDoesNotLeakThePrivateKey(t *testing.T) {
	key, _ := eckeys.Generate()
	private, _ := key.PrivateKey()

	rendered := key.String()
	if strings.Contains(rendered, private) || strings.Contains(rendered, key.PublicKey()) {
		t.Errorf("String() leaked key material: %s", rendered)
	}
}
