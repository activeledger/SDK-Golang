package activeledger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sseServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(body))
	}))
}

func collect(t *testing.T, body string) []Event {
	t.Helper()
	server := sseServer(body)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, errs := NewClient(server.URL).Subscribe(ctx, "/events")
	var out []Event
	for event := range events {
		out = append(out, event)
	}
	if err := <-errs; err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	return out
}

func TestParsesASimpleEvent(t *testing.T) {
	events := collect(t, "data: hello\n\n")
	if len(events) != 1 || events[0].Data != "hello" {
		t.Errorf("got %+v", events)
	}
}

// Multiple data: lines in one event concatenate with newlines. Treating them
// as separate events is the classic SSE parsing bug.
func TestReassemblesMultiLineData(t *testing.T) {
	events := collect(t, "data: line one\ndata: line two\n\n")
	if len(events) != 1 || events[0].Data != "line one\nline two" {
		t.Errorf("got %+v", events)
	}
}

// A line starting ':' is a comment, used as a heartbeat. Emitting these would
// deliver a stream of empty payloads to a subscriber.
func TestIgnoresCommentsAndHeartbeats(t *testing.T) {
	events := collect(t, ": heartbeat\n\ndata: real\n\n: another\n\n")
	if len(events) != 1 || events[0].Data != "real" {
		t.Errorf("got %+v", events)
	}
}

func TestCarriesEventNameAndID(t *testing.T) {
	events := collect(t, "event: commit\nid: 42\ndata: payload\n\n")
	if len(events) != 1 {
		t.Fatalf("got %+v", events)
	}
	if events[0].Name != "commit" || events[0].ID != "42" || events[0].Data != "payload" {
		t.Errorf("got %+v", events[0])
	}
}

func TestNameAndIDDoNotLeakIntoTheNextEvent(t *testing.T) {
	events := collect(t, "event: first\nid: 1\ndata: a\n\ndata: b\n\n")
	if len(events) != 2 {
		t.Fatalf("got %+v", events)
	}
	if events[1].Name != "" || events[1].ID != "" {
		t.Errorf("state leaked into the second event: %+v", events[1])
	}
}

func TestDataContainingAColonSurvives(t *testing.T) {
	events := collect(t, "data: {\"url\":\"http://example.com\"}\n\n")
	if len(events) != 1 || events[0].Data != `{"url":"http://example.com"}` {
		t.Errorf("got %+v", events)
	}
}

func TestTrailingEventWithoutBlankLineIsDelivered(t *testing.T) {
	events := collect(t, "data: last\n")
	if len(events) != 1 || events[0].Data != "last" {
		t.Errorf("got %+v", events)
	}
}

func TestEmptyStreamYieldsNothing(t *testing.T) {
	if events := collect(t, ""); len(events) != 0 {
		t.Errorf("got %+v", events)
	}
}

// The reason Subscribe takes a context: cancelling must close the connection
// rather than leaving the node holding it.
func TestCancellingTheContextStopsTheStream(t *testing.T) {
	// A stream that never ends on its own.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 10000; i++ {
			if _, err := w.Write([]byte("data: tick\n\n")); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	events, _ := NewClient(server.URL).Subscribe(ctx, "/events")

	<-events // one event proves the stream is live
	cancel()

	// The channel must close rather than hang.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, open := <-events:
			if !open {
				return // closed as required
			}
		case <-deadline:
			t.Fatal("channel did not close after the context was cancelled")
		}
	}
}
