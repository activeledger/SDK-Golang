package eckeys_test

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/activeledger/SDK-Golang/v2/eckeys"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func generated(t *testing.T, compressed bool) (*eckeys.KeyPair, string) {
	t.Helper()
	pair, err := eckeys.GenerateWith(compressed)
	if err != nil {
		t.Fatal(err)
	}
	private, err := pair.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pair, private
}

// A restored pair must sign exactly what the original did: signing is
// deterministic, so equal bytes prove the private half came back intact.
func TestFromKeysRestoresASigningPairInBothPublicKeyForms(t *testing.T) {
	for _, compressed := range []bool{true, false} {
		original, private := generated(t, compressed)
		restored, err := eckeys.FromKeys(original.PublicKey(), private)
		if err != nil {
			t.Fatalf("compressed=%v: %v", compressed, err)
		}
		if !restored.CanSign() || restored.PublicKey() != original.PublicKey() {
			t.Fatalf("compressed=%v: restored pair differs", compressed)
		}
		message := []byte("restore me")
		want, _ := original.Sign(message)
		got, err := restored.Sign(message)
		if err != nil || string(got) != string(want) {
			t.Errorf("compressed=%v: restored pair signs differently (err %v)", compressed, err)
		}
	}
}

func TestFromKeysRejectsBadKeyMaterial(t *testing.T) {
	pair, private := generated(t, true)
	public := pair.PublicKey()

	cases := []struct {
		name, public, private, want string
	}{
		{"public without prefix", strings.TrimPrefix(public, "0x"), private, "must start with '0x'"},
		{"private without prefix", public, strings.TrimPrefix(private, "0x"), "private key must start with '0x'"},
		{"private not hex", public, "0xzz", "not valid hex"},
		{"private too short", public, "0x" + strings.Repeat("ab", 31), "31 bytes, expected 32"},
		{"private too long", public, "0x" + strings.Repeat("ab", 33), "33 bytes, expected 32"},
		{"empty private", public, "", "must start with '0x'"},
		{"public off the curve", "0x02" + strings.Repeat("00", 32), private, "rejected"},
	}
	for _, c := range cases {
		restored, err := eckeys.FromKeys(c.public, c.private)
		if err == nil || restored != nil {
			t.Errorf("%s: accepted (pair %v, err %v)", c.name, restored, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestPrivateKeyOfAVerifyOnlyPairIsAnError(t *testing.T) {
	pair, _ := generated(t, true)
	verifyOnly, err := eckeys.FromPublicKey(pair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	private, err := verifyOnly.PrivateKey()
	if !errors.Is(err, eckeys.ErrVerifyOnly) || private != "" {
		t.Errorf("got %q, %v", private, err)
	}
}

func TestStringNamesWhichHalvesArePresent(t *testing.T) {
	pair, _ := generated(t, true)
	verifyOnly, err := eckeys.FromPublicKey(pair.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := pair.String(); got != "secp256k1 KeyPair(public+private)" {
		t.Errorf("signing pair: %q", got)
	}
	if got := verifyOnly.String(); got != "secp256k1 KeyPair(public only)" {
		t.Errorf("verify-only pair: %q", got)
	}
}

func TestIsHighSIsFalseForInputThatIsNotADERSignature(t *testing.T) {
	for name, raw := range map[string][]byte{
		"nil":       nil,
		"garbage":   []byte("not a signature"),
		"truncated": {0x30, 0x44, 0x02, 0x20},
	} {
		if eckeys.IsHighS(raw) {
			t.Errorf("%s reported as high-S", name)
		}
	}
}

func TestIsHighSBase64SeparatesLowFromHighAndRefusesBadBase64(t *testing.T) {
	pair, _ := generated(t, true)
	low, err := pair.Sign([]byte("message"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ecdsa.ParseDERSignature(low)
	if err != nil {
		t.Fatal(err)
	}

	// The same signature with S replaced by N-S: valid, and always the other half.
	r, s := parsed.R(), parsed.S()
	var flipped secp256k1.ModNScalar
	flipped.NegateVal(&s)
	high := derSignature(r.Bytes(), flipped.Bytes())

	if eckeys.IsHighSBase64(base64.StdEncoding.EncodeToString(low)) {
		t.Error("a low-S signature was reported as high-S")
	}
	if !eckeys.IsHighSBase64(base64.StdEncoding.EncodeToString(high)) {
		t.Error("a high-S signature was reported as low-S")
	}
	if !eckeys.IsHighS(high) {
		t.Error("the flipped signature is not above half the order")
	}
	if eckeys.IsHighSBase64("***not base64***") {
		t.Error("invalid base64 reported as high-S")
	}
	if !pair.Verify([]byte("message"), high) {
		t.Error("the high-S twin should still verify")
	}
}

// derSignature encodes r and s by hand: the library's own serialiser
// normalises S to the low half, which would defeat building a high-S input.
func derSignature(r, s [32]byte) []byte {
	integer := func(b [32]byte) []byte {
		v := b[:]
		for len(v) > 1 && v[0] == 0 {
			v = v[1:]
		}
		if v[0]&0x80 != 0 {
			v = append([]byte{0}, v...)
		}
		return append([]byte{0x02, byte(len(v))}, v...)
	}
	body := append(integer(r), integer(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// An uncompressed point that is not on y^2 = x^3 + 7 must be refused, or a
// key that can never verify (and enables invalid-curve attacks) is accepted.
func TestUncompressedPointOffTheCurveIsRejected(t *testing.T) {
	// (1, 1) is not on secp256k1: 1 != 1 + 7.
	offCurve := "0x04" + strings.Repeat("00", 31) + "01" + strings.Repeat("00", 31) + "01"
	if pair, err := eckeys.FromPublicKey(offCurve); err == nil || pair != nil {
		t.Fatalf("FromPublicKey accepted an off-curve point (pair %v, err %v)", pair, err)
	}
	_, private := generated(t, false)
	if pair, err := eckeys.FromKeys(offCurve, private); err == nil || pair != nil {
		t.Fatalf("FromKeys accepted an off-curve point (pair %v, err %v)", pair, err)
	}
}
