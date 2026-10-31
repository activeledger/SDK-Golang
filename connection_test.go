package activeledger

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Response parsing and the HTTP client, against a local httptest server. No
// ledger and no external network.

const committedReply = `{"$umid":"abc","$summary":{"total":1,"vote":1,"commit":true,"errors":[]},` +
	`"$streams":{"new":[{"id":"stream-one","name":"a"},{"id":"stream-two"}],"updated":[]},` +
	`"$responses":["hello",{"balance":5}]}`

const rejectedReply = `{"$summary":{"total":1,"vote":0,"commit":false,` +
	`"errors":["1220 Signature Incorrect",{"code":1510}]}}`

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestACommittedResponseHasNoErrors(t *testing.T) {
	r := newResponse(committedReply)
	if errs := r.Errors(); len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !r.Committed() {
		t.Fatal("a response with no errors was not committed")
	}
}

// The ledger answers 200 for a rejected transaction, so the body decides.
func TestAResponseWithErrorsIsNotCommitted(t *testing.T) {
	r := newResponse(rejectedReply)
	if r.Committed() {
		t.Fatal("a response carrying errors was reported as committed")
	}
	errs := r.Errors()
	if len(errs) != 2 || errs[0] != "1220 Signature Incorrect" {
		t.Fatalf("got errors %v", errs)
	}
	if !strings.Contains(errs[1], "1510") {
		t.Fatalf("a non-string error lost its content: %q", errs[1])
	}
}

func TestNewStreamsReturnsEveryCreatedID(t *testing.T) {
	got := newResponse(committedReply).NewStreams()
	if !equalStrings(got, []string{"stream-one", "stream-two"}) {
		t.Fatalf("got %v", got)
	}
}

func TestNewStreamsSkipsEntriesWithoutAStringID(t *testing.T) {
	r := newResponse(`{"$streams":{"new":[{"id":7},"bare",{"name":"x"},{"id":"ok"}]}}`)
	if got := r.NewStreams(); !equalStrings(got, []string{"ok"}) {
		t.Fatalf("got %v", got)
	}
}

func TestResponsesReturnsWhatContractsHandedBack(t *testing.T) {
	got := newResponse(committedReply).Responses()
	if len(got) != 2 || got[0] != "hello" {
		t.Fatalf("got %v", got)
	}
	second, ok := got[1].(map[string]interface{})
	if !ok || second["balance"] != float64(5) {
		t.Fatalf("second response was %v", got[1])
	}
}

// A reply that is not JSON must not panic, and must not be mistaken for a
// success with data.
func TestAMalformedReplyYieldsEmptyAccessorsAndKeepsTheRaw(t *testing.T) {
	for _, raw := range []string{"", "not json", "<html>502 Bad Gateway</html>", "[1,2]", "null"} {
		r := newResponse(raw)
		if r.Raw != raw {
			t.Errorf("Raw changed for %q", raw)
		}
		if len(r.NewStreams()) != 0 || len(r.Responses()) != 0 {
			t.Errorf("%q produced data", raw)
		}
		if r.Committed() || len(r.Errors()) == 0 {
			t.Errorf("%q was reported as committed", raw)
		}
	}
}

func TestWronglyTypedSectionsProduceNoData(t *testing.T) {
	r := newResponse(`{"$summary":"oops","$streams":[],"$responses":{}}`)
	if len(r.NewStreams()) != 0 || len(r.Responses()) != 0 {
		t.Fatal("wrongly typed sections produced data")
	}
}

// A committed reply always carries a $summary object; without one there is
// nothing to say the ledger accepted it.
func TestAnObjectWithoutASummaryObjectIsNotCommitted(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"$streams":{"new":[{"id":"x"}]}}`, `{"$summary":"oops"}`,
		`{"$summary":null}`, `{"$summary":[]}`,
	} {
		r := newResponse(raw)
		if r.Committed() {
			t.Errorf("%s was reported as committed", raw)
		}
		if errs := r.Errors(); len(errs) != 1 || !strings.Contains(errs[0], "no $summary") {
			t.Errorf("%s: errors %v", raw, errs)
		}
	}
}

func TestASummaryWithoutErrorsOrCommitCountIsCommitted(t *testing.T) {
	if !newResponse(`{"$summary":{}}`).Committed() {
		t.Fatal("an empty $summary object with no errors was rejected")
	}
}

func TestNewClientTrimsTrailingSlashes(t *testing.T) {
	c := NewClient("http://node.example:5260//")
	if c.BaseURL != "http://node.example:5260" {
		t.Fatalf("BaseURL = %q", c.BaseURL)
	}
	if c.HTTP == nil || c.HTTP.Timeout == 0 {
		t.Fatal("the client has no timeout")
	}
}

type captured struct {
	method, path, contentType, body string
}

func serve(t *testing.T, reply string, status int) (*Client, *captured) {
	t.Helper()
	got := &captured{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.method, got.path = r.Method, r.URL.Path
		got.contentType, got.body = r.Header.Get("Content-Type"), string(body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL + "/"), got
}

func TestSubmitRawPostsTheBodyUnchanged(t *testing.T) {
	client, got := serve(t, committedReply, http.StatusOK)
	const body = `{"$tx":{"a":"é<>&"},"$sigs":{}}`

	response, err := client.SubmitRaw(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/" {
		t.Errorf("sent %s %s", got.method, got.path)
	}
	if got.contentType != "application/json; charset=utf-8" {
		t.Errorf("content type %q", got.contentType)
	}
	if got.body != body {
		t.Errorf("the body was altered in transit: %q", got.body)
	}
	if response.Raw != committedReply || !response.Committed() {
		t.Errorf("response not parsed: %q", response.Raw)
	}
}

// HTTP 200 with errors in the body is the ledger's normal rejection.
func TestSubmitRawReturnsARejectionAsAResponseNotAnError(t *testing.T) {
	client, _ := serve(t, rejectedReply, http.StatusOK)
	response, err := client.SubmitRaw(context.Background(), "{}")
	if err != nil {
		t.Fatal(err)
	}
	if response.Committed() {
		t.Fatal("a rejection was reported as committed")
	}
}

func TestSubmitSendsTheTransactionsOwnEnvelope(t *testing.T) {
	client, got := serve(t, committedReply, http.StatusOK)
	tx, err := OnboardTransaction(newStub(), "identity")
	if err != nil {
		t.Fatal(err)
	}
	want, err := tx.JSON()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Submit(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if got.body != want {
		t.Fatalf("sent %q, want %q", got.body, want)
	}
}

func TestSubmitRawFailsWhenTheNodeIsUnreachable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	if _, err := NewClient(url).SubmitRaw(context.Background(), "{}"); err == nil {
		t.Fatal("expected a connection error")
	}
}

func TestSubmitRawHonoursACancelledContext(t *testing.T) {
	client, _ := serve(t, committedReply, http.StatusOK)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.SubmitRaw(ctx, "{}"); err == nil {
		t.Fatal("a cancelled context still sent the request")
	}
}

func TestSubmitRawRejectsAnInvalidBaseURL(t *testing.T) {
	if _, err := NewClient("http://bad host").SubmitRaw(context.Background(), "{}"); err == nil {
		t.Fatal("expected a request error")
	}
}

func TestOnboardReturnsTheFirstNewStream(t *testing.T) {
	client, got := serve(t, committedReply, http.StatusOK)
	signer := newStub()

	identity, err := client.Onboard(context.Background(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if identity.StreamID != "stream-one" {
		t.Errorf("StreamID = %q", identity.StreamID)
	}
	if identity.Signer != Signer(signer) {
		t.Error("the identity does not hold the signer it was onboarded with")
	}
	if !strings.Contains(got.body, `"$selfsign":true`) || !strings.Contains(got.body, "PUBLICKEY") {
		t.Errorf("not an onboarding envelope: %s", got.body)
	}
}

func TestOnboardFailsWhenNoStreamWasCreated(t *testing.T) {
	client, _ := serve(t, rejectedReply, http.StatusOK)
	identity, err := client.Onboard(context.Background(), newStub())
	if err == nil || identity != nil {
		t.Fatalf("got (%v, %v), want an error and no identity", identity, err)
	}
	if !strings.Contains(err.Error(), "1220") {
		t.Errorf("the ledger's reason was dropped: %v", err)
	}
}

func TestOnboardPropagatesTransportErrors(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	if _, err := NewClient(url).Onboard(context.Background(), newStub()); err == nil {
		t.Fatal("expected a connection error")
	}
}

// A proxy or failed node answers with a non-2xx status and often no JSON.
func TestSubmitRawReportsANon2xxStatusAsNotCommitted(t *testing.T) {
	for _, reply := range []string{"", "<html>502 Bad Gateway</html>", committedReply} {
		client, _ := serve(t, reply, http.StatusBadGateway)
		response, err := client.SubmitRaw(context.Background(), "{}")
		if err != nil {
			t.Fatal(err)
		}
		if response.Committed() {
			t.Errorf("a 502 with body %q was reported as committed", reply)
		}
		if errs := response.Errors(); len(errs) == 0 || !strings.Contains(errs[0], "502") {
			t.Errorf("errors %v do not name the status", errs)
		}
	}
}

func TestSubmitRawReportsANonObject2xxBodyAsNotCommitted(t *testing.T) {
	for _, reply := range []string{"", "<html>ok</html>", "[]", "null"} {
		client, _ := serve(t, reply, http.StatusOK)
		response, err := client.SubmitRaw(context.Background(), "{}")
		if err != nil {
			t.Fatal(err)
		}
		if response.Committed() {
			t.Errorf("a 200 with body %q was reported as committed", reply)
		}
	}
}

func TestOnboardFailsOnANon2xxStatus(t *testing.T) {
	client, _ := serve(t, committedReply, http.StatusBadGateway)
	if _, err := client.Onboard(context.Background(), newStub()); err == nil {
		t.Fatal("onboarding succeeded on a 502")
	}
}

// A reply cut off mid-body is a transport failure, not a short response: the
// partial text would parse as nothing and read as "not committed" rather than
// as the dropped connection it was.
func TestSubmitRawReportsAReplyCutOffMidBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte(`{"$summary":`))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(server.Close)

	response, err := NewClient(server.URL).SubmitRaw(context.Background(), "{}")
	if err == nil {
		t.Fatalf("a truncated reply was returned as a response: %q", response.Raw)
	}
}

func TestSubmitRawGivesUpOnANodeThatNeverAnswers(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	client := NewClient(server.URL)
	client.HTTP.Timeout = 50 * time.Millisecond
	if _, err := client.SubmitRaw(context.Background(), "{}"); err == nil {
		t.Fatal("a silent node did not time out")
	}
}

func TestACancelledContextInterruptsASubmitAlreadyInFlight(t *testing.T) {
	arrived := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		<-release
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := NewClient(server.URL).SubmitRaw(ctx, "{}")
		done <- err
	}()
	<-arrived
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled in-flight request reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the context did not interrupt the request")
	}
}
