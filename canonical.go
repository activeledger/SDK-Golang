package activeledger

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Canonical JSON: reproducing JavaScript's JSON.stringify byte for byte.
//
// Activeledger signs the exact bytes of JSON.stringify($tx) encoded UTF-8 --
// no hash prefix, no length prefix, no domain separator, and no canonical key
// ordering. A signature over bytes differing by one escape is invalid, and
// the ledger reports it as 1220 "Signature Incorrect", which says nothing
// about serialisation.
//
// encoding/json cannot be made to do this, which is why this file exists:
//
//   - It HTML-escapes <, > and & into <, > and & by default.
//     That one is fixable with Encoder.SetEscapeHTML(false).
//   - It SORTS map keys, and that is not fixable. Measured:
//     map[string]int{"zebra":1,"alpha":2,"middle":3} marshals as
//     {"alpha":2,"middle":3,"zebra":1}. The ledger does not canonicalise key
//     order, so a signer must reproduce the order the caller wrote -- and a
//     Go map has no insertion order to reproduce.
//
// Hence Object below: a slice of key/value pairs that remembers its order.
//
// Both defects produce correct output on an ASCII-only payload with no angle
// brackets and one key, which is exactly why a port can ship broken and only
// fail later on real data.

// Value is anything the canonical serialiser can write: *Object, []Value,
// string, bool, nil, or a numeric type.
type Value interface{}

// Object is a JSON object that preserves insertion order.
type Object struct {
	keys   []string
	values map[string]Value
}

// NewObject creates an empty ordered object.
func NewObject() *Object {
	return &Object{values: map[string]Value{}}
}

// Set adds or replaces a key. A replaced key keeps its original position,
// matching how JavaScript object property order behaves.
func (o *Object) Set(key string, value Value) *Object {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
	return o
}

// Get returns a value and whether it was present.
func (o *Object) Get(key string) (Value, bool) {
	v, ok := o.values[key]
	return v, ok
}

// Keys returns the keys in insertion order.
func (o *Object) Keys() []string {
	out := make([]string, len(o.keys))
	copy(out, o.keys)
	return out
}

// Len returns the number of keys.
func (o *Object) Len() int { return len(o.keys) }

// SortedKeys exists only for tests that need a deterministic comparison of
// contents rather than order.
func (o *Object) SortedKeys() []string {
	out := o.Keys()
	sort.Strings(out)
	return out
}

// CanonicalJSON serialises exactly as JSON.stringify would.
func CanonicalJSON(value Value) (string, error) {
	var sb strings.Builder
	if err := writeValue(&sb, value); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// CanonicalBytes returns the exact bytes that get signed.
func CanonicalBytes(value Value) ([]byte, error) {
	s, err := CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func writeValue(sb *strings.Builder, value Value) error {
	switch v := value.(type) {
	case nil:
		sb.WriteString("null")
	case *Object:
		sb.WriteByte('{')
		for i, key := range v.keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			writeString(sb, key)
			sb.WriteByte(':')
			if err := writeValue(sb, v.values[key]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	case []Value:
		sb.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeValue(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case string:
		writeString(sb, v)
	case bool:
		if v {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case int:
		// Through the float path because JavaScript has no integer type. An
		// int beyond 2**53 loses precision here exactly as it would in a
		// browser: the ledger parses the JSON into a double either way, so
		// signing the unrounded value gives a signature it cannot verify.
		return writeFloat(sb, float64(v))
	case int64:
		return writeFloat(sb, float64(v))
	case float64:
		return writeFloat(sb, v)
	case float32:
		return writeFloat(sb, float64(v))
	default:
		// Deliberately no reflection fallback. What gets signed is these
		// exact bytes, so an inferred conversion would be a silent risk -
		// better to refuse a type than to guess how JavaScript would print
		// it.
		return fmt.Errorf("canonical json: unsupported type %T (build an *Object explicitly)", value)
	}
	return nil
}

// writeFloat prints numbers the way JavaScript does.
func writeFloat(sb *strings.Builder, f float64) error {
	// JSON.stringify emits null for these, which would sign bytes the caller
	// never intended. Refuse instead.
	if math.IsNaN(f) {
		return fmt.Errorf("canonical json: NaN cannot be signed")
	}
	if math.IsInf(f, 0) {
		return fmt.Errorf("canonical json: Infinity cannot be signed")
	}

	sb.WriteString(JSNumber(f))
	return nil
}

// JSNumber formats a number exactly as JSON.stringify would.
//
// What gets signed is JSON.stringify($tx), and the ledger verifies against a
// RE-STRINGIFIED $tx - its crypto package calls JSON.stringify on the object
// its HTTP layer already parsed. JavaScript's formatting is therefore the
// specification rather than a convention, and a number written differently
// produces a signature the ledger rejects as 1220 "Signature Incorrect", with
// nothing in the message about numbers.
//
// Go's own output differed in two ways: strconv's 'g' gives "1e-07" where
// JavaScript writes "1e-7", and negative zero printed as "-0" where
// JavaScript writes "0".
//
// Implements ECMA-262 Number::toString. Cross-checked against JSON.stringify
// on 6139 doubles including every power of ten from 1e-330 to 1e308.
//
// Exported so a caller can check a value before building a transaction, and
// so the cross-language vectors run against it directly.
func JSNumber(f float64) string {
	if f == 0 {
		return "0" // covers -0, which JavaScript prints as "0"
	}
	if f < 0 {
		return "-" + JSNumber(-f)
	}

	// The SHORTEST decimal that round-trips. Go's -1 precision already gives
	// it, so this is a single call rather than the increasing-precision search
	// the SDKs without that guarantee have to run.
	text := strconv.FormatFloat(f, 'e', -1, 64)

	mantissa, exponent, _ := strings.Cut(text, "e")
	exp, err := strconv.Atoi(exponent)
	if err != nil {
		// Unreachable for a finite float, but signing is not the place to
		// assume that.
		return text
	}

	n := exp + 1 // f == 0.<digits> * 10**n
	digits := strings.TrimRight(strings.ReplaceAll(mantissa, ".", ""), "0")
	if digits == "" {
		digits = "0"
	}
	k := len(digits)

	// Plain decimal while -6 < n <= 21; exponent form outside it.
	switch {
	case k <= n && n <= 21:
		return digits + strings.Repeat("0", n-k)
	case n > 0 && n <= 21:
		return digits[:n] + "." + digits[n:]
	case n > -6 && n <= 0:
		return "0." + strings.Repeat("0", -n) + digits
	}

	// Exponent form: no leading zeros, explicit "+" when positive.
	e := n - 1
	sign := "+"
	if e < 0 {
		sign = "-"
		e = -e
	}
	head := digits
	if k > 1 {
		head = digits[:1] + "." + digits[1:]
	}

	return head + "e" + sign + strconv.Itoa(e)
}

// writeString escapes exactly what JSON.stringify escapes: the two characters
// JSON requires plus control characters below 0x20, using the short forms
// where JavaScript has them. Everything else -- including all non-ASCII --
// passes through as raw UTF-8. Escaping it would be Python's ensure_ascii
// bug; HTML-escaping <, > and & would be Go's own default.
func writeString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			if r < 0x20 {
				sb.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else if r == utf8.RuneError {
				sb.WriteRune(r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}
