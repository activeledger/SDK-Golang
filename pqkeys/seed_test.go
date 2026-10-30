package pqkeys_test

import (
	"strings"
	"testing"

	"github.com/activeledger/SDK-Golang/v2/pqkeys"
)

func TestFromPhraseRefusesAnInvalidPhrase(t *testing.T) {
	_, err := pqkeys.FromPhrase(strings.Repeat("abandon ", 11)+"abandon", "")
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected a checksum error, got %v", err)
	}
}

func TestFromPhraseIsDeterministicAndPassphraseSensitive(t *testing.T) {
	const phrase = "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon about"

	a, err := pqkeys.FromPhrase(phrase, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := pqkeys.FromPhrase(phrase, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := pqkeys.FromPhrase(phrase, "other")
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey() != b.PublicKey() {
		t.Error("the same phrase gave two identities")
	}
	if a.PublicKey() == c.PublicKey() {
		t.Error("a different passphrase gave the same identity")
	}
}
