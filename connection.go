package activeledger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Response is the ledger's reply to a submitted transaction.
type Response struct {
	Raw string

	doc map[string]interface{}
}

func newResponse(raw string) *Response {
	r := &Response{Raw: raw}
	_ = json.Unmarshal([]byte(raw), &r.doc)
	return r
}

// Errors the network reported.
//
// Non-empty means the transaction did NOT commit, even though the HTTP status
// was 200. The ledger answers 200 for a rejected transaction, so treating
// HTTP success as ledger success is wrong -- and wrong in a way that looks
// fine until something important silently did not happen.
func (r *Response) Errors() []string {
	summary, _ := r.doc["$summary"].(map[string]interface{})
	raw, _ := summary["errors"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		out = append(out, fmt.Sprint(e))
	}
	return out
}

// Committed reports whether the transaction was accepted.
func (r *Response) Committed() bool { return len(r.Errors()) == 0 }

// NewStreams returns stream ids this transaction created.
func (r *Response) NewStreams() []string {
	streams, _ := r.doc["$streams"].(map[string]interface{})
	raw, _ := streams["new"].([]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if m, ok := item.(map[string]interface{}); ok {
			if id, ok := m["id"].(string); ok {
				out = append(out, id)
			}
		}
	}
	return out
}

// Responses returns values contracts handed back with returnToRemote.
func (r *Response) Responses() []interface{} {
	raw, _ := r.doc["$responses"].([]interface{})
	return raw
}

// Identity is an onboarded identity: its stream id and the key controlling it.
type Identity struct {
	StreamID string
	Signer   Signer
}

// Client talks to one Activeledger node.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient creates a client with sensible timeouts.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Submit sends a signed transaction.
func (c *Client) Submit(ctx context.Context, tx *Transaction) (*Response, error) {
	body, err := tx.JSON()
	if err != nil {
		return nil, err
	}
	return c.SubmitRaw(ctx, body)
}

// SubmitRaw sends a pre-built envelope.
//
// For envelopes built elsewhere, and for testing rejection paths -- a
// tampered body cannot be expressed through Submit, because the builder would
// re-sign it into a valid transaction.
func (c *Client) SubmitRaw(ctx context.Context, body string) (*Response, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.BaseURL+"/", bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	response, err := c.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return newResponse(string(raw)), nil
}

// Onboard creates a new identity.
//
// Returns an error if the ledger rejected it, rather than an Identity with an
// empty StreamID -- an onboarding that silently produced no identity is a
// failure that surfaces three calls later.
func (c *Client) Onboard(ctx context.Context, signer Signer) (*Identity, error) {
	tx, err := OnboardTransaction(signer, "identity")
	if err != nil {
		return nil, err
	}
	response, err := c.Submit(ctx, tx)
	if err != nil {
		return nil, err
	}
	streams := response.NewStreams()
	if len(streams) == 0 {
		return nil, fmt.Errorf("onboard failed: %s", response.Raw)
	}
	return &Identity{StreamID: streams[0], Signer: signer}, nil
}
