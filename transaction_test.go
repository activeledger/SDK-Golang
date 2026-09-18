package activeledger

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A Signer needing no crypto, so these tests stay fast and independent of the
// key implementation.
type stubSigner struct {
	keyType KeyType
	public  string
	signed  [][]byte
}

func (s *stubSigner) KeyType() KeyType     { return s.keyType }
func (s *stubSigner) PublicKey() string { return s.public }
func (s *stubSigner) Sign(message []byte) ([]byte, error) {
	s.signed = append(s.signed, append([]byte(nil), message...))
	return []byte("SIGNATURE"), nil
}

func newStub() *stubSigner {
	return &stubSigner{keyType: KeyTypeMLDSA65, public: "PUBLICKEY"}
}

// Onboarding is $selfsign with $sigs keyed by the $i LABEL, not a stream id -
// there is no stream yet. The most likely first integration failure.
func TestOnboardIsSelfSignAndLabelKeyed(t *testing.T) {
	tx, err := OnboardTransaction(newStub(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !tx.SelfSign {
		t.Error("onboard should be self-signed")
	}
	if _, ok := tx.Sigs["identity"]; !ok || len(tx.Sigs) != 1 {
		t.Errorf("sigs should be keyed by the label, got %v", tx.Sigs)
	}
	inputs, _ := tx.Body.Get("$i")
	if keys := inputs.(*Object).Keys(); len(keys) != 1 || keys[0] != "identity" {
		t.Errorf("$i keys were %v", keys)
	}
}

// The ledger defaults a missing type to "rsa" and then verifies RSA against a
// base64 post-quantum blob, reported as 1220.
func TestOnboardAlwaysCarriesAnExplicitType(t *testing.T) {
	tx, err := OnboardTransaction(newStub(), "")
	if err != nil {
		t.Fatal(err)
	}
	inputs, _ := tx.Body.Get("$i")
	identity, _ := inputs.(*Object).Get("identity")
	typ, _ := identity.(*Object).Get("type")
	if typ != "ml-dsa-65" {
		t.Errorf("type was %v", typ)
	}
}

func TestOnboardSignsTheBodyNotTheEnvelope(t *testing.T) {
	signer := newStub()
	tx, err := OnboardTransaction(signer, "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := CanonicalBytes(tx.Body)
	if len(signer.signed) != 1 || string(signer.signed[0]) != string(body) {
		t.Error("signature did not cover exactly the canonical body")
	}
	envelope, _ := CanonicalBytes(tx.Envelope())
	if string(signer.signed[0]) == string(envelope) {
		t.Error("signature covered the envelope, which the ledger does not verify")
	}
}

func TestCustomLabelUsedForInputAndSignature(t *testing.T) {
	tx, err := OnboardTransaction(newStub(), "mylabel")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tx.Sigs["mylabel"]; !ok {
		t.Errorf("sigs were %v", tx.Sigs)
	}
}

func TestBuilderRequiresNamespaceContractAndSigner(t *testing.T) {
	if _, err := NewBuilder().Contract("c").Input("s", newStub(), nil).Build(); err == nil {
		t.Error("expected an error without a namespace")
	}
	if _, err := NewBuilder().Namespace("n").Input("s", newStub(), nil).Build(); err == nil {
		t.Error("expected an error without a contract")
	}
	if _, err := NewBuilder().Namespace("n").Contract("c").Build(); err == nil {
		t.Error("expected an error without an input")
	}
}

func TestBuilderPreservesInsertionOrder(t *testing.T) {
	tx, err := NewBuilder().Namespace("default").Contract("demo").
		Input("streamA", newStub(), NewObject().Set("zebra", 1).Set("alpha", 2)).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := tx.SignedBytes()
	s := string(body)
	if strings.Index(s, "zebra") > strings.Index(s, "alpha") {
		t.Errorf("insertion order was not preserved: %s", s)
	}
}

func TestReadOnlyAddsDollarROnlyWhenUsed(t *testing.T) {
	without, err := NewBuilder().Namespace("n").Contract("c").Input("s", newStub(), nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := without.Body.Get("$r"); ok {
		t.Error("$r should be absent when no readonly stream was added")
	}

	with, err := NewBuilder().Namespace("n").Contract("c").
		Input("s", newStub(), nil).ReadOnly("target", "streamXYZ").Build()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := with.Body.Get("$r")
	if !ok {
		t.Fatal("$r missing")
	}
	if v, _ := r.(*Object).Get("target"); v != "streamXYZ" {
		t.Errorf("$r was %v", v)
	}
}

func TestEntryEmittedOnlyWhenSet(t *testing.T) {
	without, _ := NewBuilder().Namespace("n").Contract("c").Input("s", newStub(), nil).Build()
	if _, ok := without.Body.Get("$entry"); ok {
		t.Error("$entry should be absent")
	}
	with, _ := NewBuilder().Namespace("n").Contract("c").Entry("update").
		Input("s", newStub(), nil).Build()
	if v, _ := with.Body.Get("$entry"); v != "update" {
		t.Errorf("$entry was %v", v)
	}
}

func TestMultipleInputsEachGetASignature(t *testing.T) {
	a, b := newStub(), newStub()
	tx, err := NewBuilder().Namespace("n").Contract("c").
		Input("streamA", a, nil).Input("streamB", b, nil).Build()
	if err != nil {
		t.Fatal(err)
	}
	if len(tx.Sigs) != 2 {
		t.Fatalf("expected two signatures, got %v", tx.Sigs)
	}
	// Both signed the identical body.
	if string(a.signed[0]) != string(b.signed[0]) {
		t.Error("signers saw different bytes")
	}
}

func TestNonASCIIPayloadSignsCanonicalBytes(t *testing.T) {
	signer := newStub()
	tx, err := NewBuilder().Namespace("default").Contract("demo").
		Input("streamA", signer, NewObject().Set("note", "café 日本語")).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := tx.SignedBytes()
	s := string(body)
	if !strings.Contains(s, "café") {
		t.Errorf("non-ascii missing: %s", s)
	}
	if strings.Contains(s, "\\u00e9") {
		t.Error("non-ascii was escaped")
	}
}

func TestEnvelopeShape(t *testing.T) {
	tx, err := OnboardTransaction(newStub(), "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := tx.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"$tx"`, `"$sigs"`, `"$selfsign":true`} {
		if !strings.Contains(out, want) {
			t.Errorf("envelope missing %s: %s", want, out)
		}
	}

	ordinary, _ := NewBuilder().Namespace("n").Contract("c").Input("s", newStub(), nil).Build()
	plain, _ := ordinary.JSON()
	if strings.Contains(plain, "selfsign") {
		t.Error("an ordinary transaction should not be self-signed")
	}
}

func TestSignaturesAreBase64(t *testing.T) {
	tx, err := OnboardTransaction(newStub(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.StdEncoding.DecodeString(tx.Sigs["identity"]); err != nil {
		t.Errorf("signature was not base64: %v", err)
	}
}
