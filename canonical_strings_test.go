package activeledger

import "testing"

// Every control character below 0x20 is escaped: the short form where
// JSON.stringify has one, \u00xx otherwise. 0x7f and above pass through raw.
func TestEveryControlCharacterIsEscapedTheWayJSONStringifyDoes(t *testing.T) {
	short := map[rune]string{'\b': `\b`, '\t': `\t`, '\n': `\n`, '\f': `\f`, '\r': `\r`}
	for r := rune(0); r < 0x20; r++ {
		want, ok := short[r]
		if !ok {
			want = `\u00` + string("0123456789abcdef"[r>>4]) + string("0123456789abcdef"[r&0xf])
		}
		got := mustJSON(t, "x"+string(r)+"y")
		if got != `"x`+want+`y"` {
			t.Errorf("U+%04X: got %s want %s", r, got, `"x`+want+`y"`)
		}
	}
}

func TestDeleteAndNonASCIIPassThroughUnescaped(t *testing.T) {
	for _, s := range []string{"\x7f", "\u0080", " ", "\U0001F600"} {
		if got := mustJSON(t, s); got != `"`+s+`"` {
			t.Errorf("%+q was altered: %+q", s, got)
		}
	}
}

func TestQuotesAndBackslashesInKeysAreEscapedToo(t *testing.T) {
	got := mustJSON(t, NewObject().Set("a\"b\\c\n", 1))
	if want := `{"a\"b\\c\n":1}`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestEmptyStringIsJustQuotes(t *testing.T) {
	if got := mustJSON(t, ""); got != `""` {
		t.Errorf("got %s", got)
	}
}

// An invalid UTF-8 byte is written as U+FFFD, and escapes in the middle of a
// long plain run land in the right place.
func TestInvalidUTF8AndEscapesInsideRuns(t *testing.T) {
	if got, want := mustJSON(t, "a\xffb\xc3"), "\"a�b�\""; got != want {
		t.Errorf("got %+q want %+q", got, want)
	}
	if got, want := mustJSON(t, "abc\"def\\ghé\x01ij"), `"abc\"def\\ghé\u0001ij"`; got != want {
		t.Errorf("got %s want %s", got, want)
	}
}
