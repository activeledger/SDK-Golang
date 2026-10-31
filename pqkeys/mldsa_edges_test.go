package pqkeys_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/activeledger/SDK-Golang/v2/pqkeys"
)

func TestGeneratedKeysHaveTheLedgersSizesAndSignAndVerify(t *testing.T) {
	pair, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !pair.CanSign() {
		t.Fatal("a generated pair cannot sign")
	}
	public, err := base64.StdEncoding.DecodeString(pair.PublicKey())
	if err != nil || len(public) != pqkeys.PublicKeySize {
		t.Errorf("public key: %d bytes, err %v", len(public), err)
	}

	message := []byte("generated")
	signature, err := pair.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != pqkeys.SignatureSize {
		t.Errorf("signature is %d bytes", len(signature))
	}
	if !pair.Verify(message, signature) || pair.Verify([]byte("other"), signature) {
		t.Error("verification did not separate the signed message from another")
	}
}

func TestTwoGeneratedPairsAreDifferent(t *testing.T) {
	a, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey() == b.PublicKey() {
		t.Error("two generated pairs share a public key")
	}
}

func TestGeneratedKeysRestoreThroughFromKeys(t *testing.T) {
	original, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	private, err := original.PrivateKeyB64()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := pqkeys.FromKeys(original.PublicKey(), private)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := restored.Sign([]byte("restored"))
	if err != nil {
		t.Fatal(err)
	}
	if !original.Verify([]byte("restored"), signature) {
		t.Error("the original does not accept the restored pair's signature")
	}
}

func TestFromKeysRejectsBadKeyMaterialAndSaysWhy(t *testing.T) {
	pair, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	private, err := pair.PrivateKeyB64()
	if err != nil {
		t.Fatal(err)
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 10))

	cases := []struct {
		name, public, private, want string
	}{
		{"public not base64", "***", private, "public key is not valid base64"},
		{"public wrong length", short, private, "public key should be"},
		{"private not base64", pair.PublicKey(), "***", "private key is not valid base64"},
		{"private wrong length", pair.PublicKey(), short, "private key should be"},
		{"empty public", "", private, "public key should be"},
	}
	for _, c := range cases {
		restored, err := pqkeys.FromKeys(c.public, c.private)
		if err == nil || restored != nil {
			t.Errorf("%s: accepted (pair %v, err %v)", c.name, restored, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestFromPublicRejectsBadKeysAndHasNoPrivateHalf(t *testing.T) {
	if _, err := pqkeys.FromPublic("***"); err == nil {
		t.Error("non-base64 public key accepted")
	}
	if _, err := pqkeys.FromPublic(base64.StdEncoding.EncodeToString(make([]byte, 10))); err == nil {
		t.Error("short public key accepted")
	}

	pair, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	verifyOnly, err := pqkeys.FromPublic(pair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if verifyOnly.CanSign() {
		t.Error("a verify-only pair claims it can sign")
	}
	if private, err := verifyOnly.PrivateKeyB64(); err == nil || private != "" {
		t.Errorf("verify-only pair returned a private key %q, %v", private, err)
	}
}

func TestFromKeysRejectsAMismatchedPair(t *testing.T) {
	first, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	otherPrivate, err := second.PrivateKeyB64()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := pqkeys.FromKeys(first.PublicKey(), otherPrivate)
	if err == nil || restored != nil {
		t.Fatalf("accepted a mismatched pair (pair %v, err %v)", restored, err)
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error %q does not say the keys do not match", err)
	}
}
