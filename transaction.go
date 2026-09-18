package activeledger

import (
	"encoding/base64"
	"fmt"
)

// Transaction is a signed transaction, ready to submit.
//
// Body is the $tx object. Sigs maps a signer label to a base64 signature over
// the canonical bytes of Body and NOTHING ELSE -- not the envelope, not a
// hash of it, not a length-prefixed form.
type Transaction struct {
	Body     *Object
	Sigs     map[string]string
	SelfSign bool

	sigOrder []string
}

// Envelope returns the full submittable document.
func (t *Transaction) Envelope() *Object {
	out := NewObject().Set("$tx", t.Body)
	if t.SelfSign {
		out.Set("$selfsign", true)
	}
	sigs := NewObject()
	for _, label := range t.sigOrder {
		sigs.Set(label, t.Sigs[label])
	}
	return out.Set("$sigs", sigs)
}

// JSON renders the envelope for submission.
func (t *Transaction) JSON() (string, error) { return CanonicalJSON(t.Envelope()) }

// SignedBytes returns the exact bytes that were signed. The fastest way to
// diagnose a 1220.
func (t *Transaction) SignedBytes() ([]byte, error) { return CanonicalBytes(t.Body) }

// OnboardTransaction builds the onboarding transaction for a new identity.
//
// Two things here are the most common first failure in any port, so they
// happen in one place rather than being left to a caller:
//
//   - $selfsign is true and $sigs is keyed by the $i LABEL ("identity"), not
//     by a stream id. There is no stream yet.
//   - type is always present. The ledger defaults a missing type to "rsa" and
//     then attempts RSA verification against a base64 post-quantum blob,
//     returning 1220 with nothing said about key types.
func OnboardTransaction(signer Signer, label string) (*Transaction, error) {
	if label == "" {
		label = "identity"
	}
	body := NewObject().
		Set("$namespace", "default").
		Set("$contract", "onboard").
		Set("$i", NewObject().Set(label, NewObject().
			Set("type", string(signer.KeyType())).
			Set("publicKey", signer.PublicKeyB64()))).
		Set("$o", NewObject())

	message, err := CanonicalBytes(body)
	if err != nil {
		return nil, err
	}
	signature, err := signer.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("signing onboard transaction: %w", err)
	}
	return &Transaction{
		Body:     body,
		Sigs:     map[string]string{label: base64.StdEncoding.EncodeToString(signature)},
		SelfSign: true,
		sigOrder: []string{label},
	}, nil
}

// Builder builds an ordinary transaction.
//
// Insertion order is preserved throughout, because the ledger does not
// canonicalise key order and the signature covers the order actually written.
type Builder struct {
	namespace string
	contract  string
	entry     string
	inputs    *Object
	outputs   *Object
	readonly  *Object
	signers   map[string]Signer
	signOrder []string
}

// NewBuilder starts a transaction.
func NewBuilder() *Builder {
	return &Builder{
		inputs:   NewObject(),
		outputs:  NewObject(),
		readonly: NewObject(),
		signers:  map[string]Signer{},
	}
}

func (b *Builder) Namespace(v string) *Builder { b.namespace = v; return b }
func (b *Builder) Contract(v string) *Builder  { b.contract = v; return b }
func (b *Builder) Entry(v string) *Builder     { b.entry = v; return b }

// Input adds an input stream, its signing key and any payload fields.
func (b *Builder) Input(streamID string, signer Signer, payload *Object) *Builder {
	if payload == nil {
		payload = NewObject()
	}
	b.inputs.Set(streamID, payload)
	if _, seen := b.signers[streamID]; !seen {
		b.signOrder = append(b.signOrder, streamID)
	}
	b.signers[streamID] = signer
	return b
}

// Output adds an output stream and its payload.
func (b *Builder) Output(streamID string, payload *Object) *Builder {
	if payload == nil {
		payload = NewObject()
	}
	b.outputs.Set(streamID, payload)
	return b
}

// ReadOnly adds a stream to $r.
//
// This is how state is read from Activeledger. There is no separate read API:
// a node's storage service listens only on its own host, so reading is a
// transaction like anything else. The contract receives the named streams and
// hands values back with returnToRemote, which arrive in Response.Responses.
func (b *Builder) ReadOnly(label, streamID string) *Builder {
	b.readonly.Set(label, streamID)
	return b
}

// Build signs and returns the transaction.
func (b *Builder) Build() (*Transaction, error) {
	if b.namespace == "" {
		return nil, fmt.Errorf("namespace is required")
	}
	if b.contract == "" {
		return nil, fmt.Errorf("contract is required")
	}
	if len(b.signers) == 0 {
		return nil, fmt.Errorf("at least one input with a signing key is required")
	}

	body := NewObject()
	if b.entry != "" {
		body.Set("$entry", b.entry)
	}
	body.Set("$namespace", b.namespace).Set("$contract", b.contract).Set("$i", b.inputs)
	if b.outputs.Len() > 0 {
		body.Set("$o", b.outputs)
	}
	if b.readonly.Len() > 0 {
		body.Set("$r", b.readonly)
	}

	message, err := CanonicalBytes(body)
	if err != nil {
		return nil, err
	}
	sigs := map[string]string{}
	for _, label := range b.signOrder {
		signature, err := b.signers[label].Sign(message)
		if err != nil {
			return nil, fmt.Errorf("signing for %s: %w", label, err)
		}
		sigs[label] = base64.StdEncoding.EncodeToString(signature)
	}
	return &Transaction{Body: body, Sigs: sigs, sigOrder: b.signOrder}, nil
}
