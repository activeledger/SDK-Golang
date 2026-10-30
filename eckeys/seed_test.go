package eckeys_test

import (
	"strings"
	"testing"

	"github.com/activeledger/SDK-Golang/v2/eckeys"
)

func TestFromPhraseRefusesAnInvalidPhrase(t *testing.T) {
	_, err := eckeys.FromPhrase(strings.Repeat("abandon ", 11)+"abandon", "", true)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("expected a checksum error, got %v", err)
	}
}

func TestFromPhraseIsDeterministicAndPassphraseSensitive(t *testing.T) {
	const phrase = "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon about"

	a, err := eckeys.FromPhrase(phrase, "", true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := eckeys.FromPhrase(phrase, "", true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := eckeys.FromPhrase(phrase, "other", true)
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

// The legacy scheme must NOT validate: the original package hashed whatever
// string it was given, and rejecting one it accepted would strand an identity.
func TestFromLegacyPhraseAcceptsAnInvalidMnemonic(t *testing.T) {
	a, err := eckeys.FromLegacyPhrase("not a bip39 phrase at all", true)
	if err != nil {
		t.Fatalf("a legacy phrase was rejected: %v", err)
	}
	b, err := eckeys.FromLegacyPhrase("not a bip39 phrase at all!", true)
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey() == b.PublicKey() {
		t.Fatal("different legacy phrases gave the same identity")
	}
}
