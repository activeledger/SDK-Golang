package activeledger_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	activeledger "github.com/activeledger/SDK-Golang/v2"
)

// Canonical number formatting, against the published vectors.
//
// What gets signed is JSON.stringify($tx) and the ledger verifies against a
// re-stringified $tx, so JavaScript's number formatting is the specification.
// A number written differently produces a signature the ledger rejects as
// 1220, with nothing in the message about numbers.
//
// These exist because the `float` case in pq-vectors.json - 1, 0.1, -2.5, 0 -
// sits entirely inside the range where every language already agrees.

type numberVector struct {
	Name     string  `json:"name"`
	Value    float64 `json:"value"`
	Expected string  `json:"expected"`
}

func loadNumberVectors(t *testing.T) []numberVector {
	t.Helper()

	raw, err := os.ReadFile("testdata/number-vectors.json")
	if err != nil {
		t.Fatalf("number-vectors.json: %v", err)
	}
	var doc struct {
		Vectors []numberVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("number-vectors.json: %v", err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no number vectors - the tests below would pass by not running")
	}
	return doc.Vectors
}

func TestJSNumberMatchesTheReference(t *testing.T) {
	for _, v := range loadNumberVectors(t) {
		if got := activeledger.JSNumber(v.Value); got != v.Expected {
			t.Errorf("%s: got %q, want %q", v.Name, got, v.Expected)
		}
	}
}

// The formatter being right is not enough if the encoder does not call it.
func TestCanonicalJSONUsesJSNumber(t *testing.T) {
	for _, v := range loadNumberVectors(t) {
		obj := activeledger.NewObject().Set("n", v.Value)
		b, err := activeledger.CanonicalJSON(obj)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		want := fmt.Sprintf(`{"n":%s}`, v.Expected)
		if string(b) != want {
			t.Errorf("%s: got %s, want %s", v.Name, b, want)
		}
	}
}

func TestNegativeZeroLosesItsSign(t *testing.T) {
	// Go's strconv prints "-0"; JavaScript prints "0".
	z := 0.0
	if got := activeledger.JSNumber(-z); got != "0" {
		t.Errorf("negative zero: got %q, want \"0\"", got)
	}
}

func TestExponentHasNoLeadingZeros(t *testing.T) {
	// strconv's 'g' gives 1e-07; JavaScript writes 1e-7.
	for _, c := range []struct {
		in   float64
		want string
	}{
		{1e-7, "1e-7"}, {1e21, "1e+21"}, {-1.5e-9, "-1.5e-9"},
	} {
		if got := activeledger.JSNumber(c.in); got != c.want {
			t.Errorf("%v: got %q, want %q", c.in, got, c.want)
		}
	}
}

// Both sides of both boundaries - where implementations part company.
func TestThePlainExponentBoundaries(t *testing.T) {
	for _, c := range []struct {
		in   float64
		want string
	}{
		{1e20, "100000000000000000000"}, {1e21, "1e+21"},
		{1e-6, "0.000001"}, {1e-7, "1e-7"},
	} {
		if got := activeledger.JSNumber(c.in); got != c.want {
			t.Errorf("%v: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIntegersTakeDoublePrecision(t *testing.T) {
	// JavaScript has no integer type, so the ledger parses this into a double
	// whatever is sent. Signing the unrounded value gives a signature it
	// cannot verify.
	obj := activeledger.NewObject().Set("n", 9007199254740993)
	b, err := activeledger.CanonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "9007199254740992") {
		t.Errorf("got %s, want the double-rounded value", b)
	}
}
