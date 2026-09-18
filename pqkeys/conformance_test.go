package pqkeys_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	activeledger "github.com/activeledger/SDK-Golang"
	"github.com/activeledger/SDK-Golang/pqkeys"
)

// Conformance against the vectors published by the ledger repository.
//
// This is what makes "done" an observation rather than an assertion: these
// signatures were produced by the reference implementation and accepted by a
// real network, so agreeing with them is agreeing with the thing that
// matters.

type vector struct {
	Type        string `json:"type"`
	MessageName string `json:"messageName"`
	Message     string `json:"message"`
	PublicKey   string `json:"publicKey"`
	PrivateKey  string `json:"privateKey"`
	Signature   string `json:"signature"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("../testdata/pq-vectors.json")
	if err != nil {
		t.Fatalf("vectors missing: %v", err)
	}
	var doc struct {
		Vectors []vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var mldsa []vector
	for _, v := range doc.Vectors {
		if v.Type == "ml-dsa-65" {
			mldsa = append(mldsa, v)
		}
	}
	if len(mldsa) == 0 {
		t.Fatal("no ml-dsa-65 vectors found; the published file lost them")
	}
	return mldsa
}

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifiesEveryPublishedSignature(t *testing.T) {
	for _, v := range loadVectors(t) {
		kp, err := pqkeys.FromPublic(v.PublicKey)
		if err != nil {
			t.Fatalf("%s: %v", v.MessageName, err)
		}
		if !kp.Verify([]byte(v.Message), decode(t, v.Signature)) {
			t.Errorf("failed to verify published signature for %s", v.MessageName)
		}
	}
}

func TestRoundTripsPublishedKeysWithoutReDeriving(t *testing.T) {
	for _, v := range loadVectors(t) {
		kp, err := pqkeys.FromKeys(v.PublicKey, v.PrivateKey)
		if err != nil {
			t.Fatalf("%s: %v", v.MessageName, err)
		}
		if got := kp.PublicKey(); got != v.PublicKey {
			t.Errorf("%s: public key did not round-trip", v.MessageName)
		}
		priv, err := kp.PrivateKeyB64()
		if err != nil {
			t.Fatal(err)
		}
		if priv != v.PrivateKey {
			t.Errorf("%s: private key did not round-trip", v.MessageName)
		}
	}
}

func TestSignaturesMadeHereVerifyWithTheReferencePublicKey(t *testing.T) {
	for _, v := range loadVectors(t) {
		signer, err := pqkeys.FromKeys(v.PublicKey, v.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		mine, err := signer.Sign([]byte(v.Message))
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := pqkeys.FromPublic(v.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !verifier.Verify([]byte(v.Message), mine) {
			t.Errorf("%s: reference public key rejected a signature made here", v.MessageName)
		}
	}
}

func TestSignatureAndKeySizesMatchTheLedger(t *testing.T) {
	if pqkeys.PublicKeySize != 1952 || pqkeys.PrivateKeySize != 4032 || pqkeys.SignatureSize != 3309 {
		t.Fatalf("sizes drifted: %d/%d/%d",
			pqkeys.PublicKeySize, pqkeys.PrivateKeySize, pqkeys.SignatureSize)
	}
	kp, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(decode(t, kp.PublicKey())); n != 1952 {
		t.Errorf("generated public key was %d bytes", n)
	}
	priv, _ := kp.PrivateKeyB64()
	if n := len(decode(t, priv)); n != 4032 {
		t.Errorf("generated private key was %d bytes", n)
	}
	sig, err := kp.Sign([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 3309 {
		t.Errorf("signature was %d bytes", len(sig))
	}
}

func TestTamperedMessageDoesNotVerify(t *testing.T) {
	for _, v := range loadVectors(t) {
		kp, err := pqkeys.FromPublic(v.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if kp.Verify([]byte(v.Message+" "), decode(t, v.Signature)) {
			t.Errorf("%s: a tampered message verified", v.MessageName)
		}
	}
}

// Returning false rather than an error: a caller should not have to tell
// "invalid" from "wrong shape", and making one an error invites handling that
// swallows the other.
func TestMalformedSignatureReturnsFalseNotPanic(t *testing.T) {
	v := loadVectors(t)[0]
	kp, err := pqkeys.FromPublic(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, {}, make([]byte, 10), make([]byte, 4000)} {
		if kp.Verify([]byte(v.Message), bad) {
			t.Errorf("malformed signature of %d bytes verified", len(bad))
		}
	}
}

func TestWrongLengthKeyIsRejectedAtConstruction(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 100))
	if _, err := pqkeys.FromPublic(short); err == nil {
		t.Error("expected an error for a 100-byte public key")
	}
}

func TestVerifyOnlyKeyPairRefusesToSign(t *testing.T) {
	v := loadVectors(t)[0]
	kp, err := pqkeys.FromPublic(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if kp.CanSign() {
		t.Error("verify-only key pair reported CanSign")
	}
	if _, err := kp.Sign([]byte("x")); err == nil {
		t.Error("verify-only key pair signed")
	}
	if _, err := kp.PrivateKeyB64(); err == nil {
		t.Error("verify-only key pair exported a private key")
	}
}

func TestKeyPairSatisfiesSignerInterface(t *testing.T) {
	kp, err := pqkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var signer activeledger.Signer = kp
	if signer.KeyType() != activeledger.KeyTypeMLDSA65 {
		t.Errorf("key type was %q", signer.KeyType())
	}
}

// Falcon is absent on purpose, and the error has to say why rather than
// leaving a caller to infer it from a missing constant.
func TestFalconIsUnsupportedWithAnExplanation(t *testing.T) {
	msg := activeledger.ErrFalconUnsupported.Error()
	for _, want := range []string{"falcon-512", "cgo", "ml-dsa-65"} {
		if !contains(msg, want) {
			t.Errorf("error message should mention %q, was: %s", want, msg)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
