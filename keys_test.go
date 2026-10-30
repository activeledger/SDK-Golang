package activeledger

import "testing"

func TestParseKeyTypeAcceptsTheWireNames(t *testing.T) {
	want := map[string]KeyType{
		"rsa":        KeyTypeRSA,
		"secp256k1":  KeyTypeSecp256k1,
		"ml-dsa-65":  KeyTypeMLDSA65,
		"falcon-512": KeyTypeFalcon512,
	}
	for wire, expected := range want {
		got, err := ParseKeyType(wire)
		if err != nil || got != expected {
			t.Errorf("%q: got (%q, %v), want %q", wire, got, err, expected)
		}
	}
}

// Existing identities may carry either name; both are verified identically
// by the ledger and are never emitted.
func TestBitcoinAndEthereumParseAsSecp256k1(t *testing.T) {
	for _, wire := range []string{"bitcoin", "ethereum"} {
		got, err := ParseKeyType(wire)
		if err != nil || got != KeyTypeSecp256k1 {
			t.Errorf("%q: got (%q, %v)", wire, got, err)
		}
	}
}

// The ledger compares these exactly, so the parser must too.
func TestParseKeyTypeIsStrictAndCaseSensitive(t *testing.T) {
	for _, wire := range []string{"", "RSA", "ML-DSA-65", "Secp256k1", " rsa", "rsa ", "ml-dsa", "ed25519", "Bitcoin"} {
		if got, err := ParseKeyType(wire); err == nil {
			t.Errorf("%q was accepted as %q", wire, got)
		}
	}
}
