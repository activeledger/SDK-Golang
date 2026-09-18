package activeledger

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

// Reference bytes produced by the JavaScript SDK and accepted by a real
// ledger. If this file and my reading of JSON.stringify ever disagree, this
// file is right.
func referenceMessages(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("testdata/pq-vectors.json")
	if err != nil {
		t.Fatalf("vectors missing: %v", err)
	}
	var doc struct {
		Vectors []struct {
			MessageName string `json:"messageName"`
			Message     string `json:"message"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, v := range doc.Vectors {
		if _, seen := out[v.MessageName]; !seen {
			out[v.MessageName] = v.Message
		}
	}
	return out
}

func mustJSON(t *testing.T, v Value) string {
	t.Helper()
	s, err := CanonicalJSON(v)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	return s
}

func TestAsciiBaseline(t *testing.T) {
	ref := referenceMessages(t)
	if got := mustJSON(t, NewObject().Set("greeting", "hello")); got != ref["ascii"] {
		t.Errorf("got %s want %s", got, ref["ascii"])
	}
}

// Go's encoding/json escapes these to < etc. by default.
func TestHTMLCharactersAreNotEscaped(t *testing.T) {
	ref := referenceMessages(t)
	got := mustJSON(t, NewObject().
		Set("expr", "a < b && c > d").
		Set("amp", "Tom & Jerry"))
	if got != ref["html"] {
		t.Errorf("got %s want %s", got, ref["html"])
	}
}

// The defect encoding/json can never fix: it sorts map keys, and a Go map has
// no insertion order to preserve in the first place.
func TestKeyOrderIsInsertionOrderNotSorted(t *testing.T) {
	ref := referenceMessages(t)
	got := mustJSON(t, NewObject().Set("zebra", 1).Set("alpha", 2).Set("middle", 3))
	if got != ref["ordering"] {
		t.Errorf("got %s want %s", got, ref["ordering"])
	}

	// Prove the stdlib really would get this wrong, so the test documents why
	// the hand-written serialiser exists rather than merely asserting it.
	stdlib, _ := json.Marshal(map[string]int{"zebra": 1, "alpha": 2, "middle": 3})
	if string(stdlib) == ref["ordering"] {
		t.Error("encoding/json preserved order; this serialiser may no longer be needed")
	}
}

func TestNonASCIIIsRaw(t *testing.T) {
	ref := referenceMessages(t)
	got := mustJSON(t, NewObject().Set("greeting", "café 日本語 ☕"))
	if got != ref["non-ascii"] {
		t.Errorf("got %s want %s", got, ref["non-ascii"])
	}
	if strings.Contains(got, "\\u00e9") {
		t.Error("non-ascii was escaped")
	}
}

func TestWholeFloatsPrintAsIntegers(t *testing.T) {
	ref := referenceMessages(t)
	got := mustJSON(t, NewObject().
		Set("whole", 1.0).
		Set("third", 0.1).
		Set("negative", -2.5).
		Set("zero", 0))
	if got != ref["float"] {
		t.Errorf("got %s want %s", got, ref["float"])
	}
}

func TestOnboardShapeMatchesReference(t *testing.T) {
	ref := referenceMessages(t)
	reference := ref["onboard"]

	// Lift the generated values out rather than hardcoding a key that would
	// go stale on the next regeneration.
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(reference), &doc); err != nil {
		t.Fatal(err)
	}
	identity := doc["$i"].(map[string]interface{})["identity"].(map[string]interface{})

	built := NewObject().
		Set("$namespace", "default").
		Set("$contract", "onboard").
		Set("$i", NewObject().Set("identity", NewObject().
			Set("type", identity["type"].(string)).
			Set("publicKey", identity["publicKey"].(string)))).
		Set("$o", NewObject())

	if got := mustJSON(t, built); got != reference {
		t.Errorf("got %s want %s", got, reference)
	}
}

func TestNestedStructuresArraysAndNull(t *testing.T) {
	got := mustJSON(t, NewObject().
		Set("a", []Value{1, "two", true, nil}).
		Set("b", NewObject().Set("c", false)))
	want := `{"a":[1,"two",true,null],"b":{"c":false}}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestEmptyContainers(t *testing.T) {
	if got := mustJSON(t, NewObject()); got != "{}" {
		t.Errorf("got %s", got)
	}
	if got := mustJSON(t, []Value{}); got != "[]" {
		t.Errorf("got %s", got)
	}
}

func TestEscapesOnlyWhatJSONRequires(t *testing.T) {
	got := mustJSON(t, NewObject().Set("s", `a"b\c`))
	want := `{"s":"a\"b\\c"}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestControlCharacters(t *testing.T) {
	// Built from a rune rather than written as a literal, so the source file
	// itself contains no control characters.
	got := mustJSON(t, NewObject().Set("s", "\n\t"+string(rune(1))))
	want := "{\"s\":\"" + "\\n" + "\\t" + "\\u0001" + "\"}"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestNaNAndInfinityRefused(t *testing.T) {
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := CanonicalJSON(NewObject().Set("x", bad)); err == nil {
			t.Errorf("expected an error for %v", bad)
		}
	}
}

func TestUnsupportedTypeIsRefusedNotGuessed(t *testing.T) {
	// No reflection fallback: an inferred conversion could change the signed
	// bytes without anyone having written it.
	if _, err := CanonicalJSON(NewObject().Set("t", struct{ A int }{1})); err == nil {
		t.Error("expected an error for an unsupported type")
	}
}

func TestReplacingAKeyKeepsItsPosition(t *testing.T) {
	got := mustJSON(t, NewObject().Set("a", 1).Set("b", 2).Set("a", 3))
	want := `{"a":3,"b":2}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}
