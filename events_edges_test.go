package activeledger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSubscribeDefaultsToTheEventsPath(t *testing.T) {
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path + "|" + r.Header.Get("Accept")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, _ := NewClient(server.URL).Subscribe(ctx, "")
	for range events {
	}
	if got := <-paths; got != "/events|text/event-stream" {
		t.Errorf("request was %q", got)
	}
}

func TestSubscribeUsesTheGivenPath(t *testing.T) {
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, _ := NewClient(server.URL).Subscribe(ctx, "/custom/stream")
	for range events {
	}
	if got := <-paths; got != "/custom/stream" {
		t.Errorf("path was %q", got)
	}
}

func TestSubscribeReportsAnUnreachableNode(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	url := server.URL
	server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, errs := NewClient(url).Subscribe(ctx, "/events")
	for range events {
		t.Error("an event arrived from a node that is not there")
	}
	if err := <-errs; err == nil {
		t.Error("no error for an unreachable node")
	}
}

func TestSubscribeReportsAnInvalidURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, errs := NewClient("http://127.0.0.1").Subscribe(ctx, "/bad\npath")
	for range events {
		t.Error("an event arrived for an invalid URL")
	}
	if err := <-errs; err == nil {
		t.Error("no error for an invalid URL")
	}
}

// A single line past the 1 MiB scanner limit ends the stream with an error
// rather than being silently dropped.
func TestSubscribeReportsAnOverlongLine(t *testing.T) {
	server := sseServer("data: " + strings.Repeat("x", 1024*1024+1) + "\n\n")
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, errs := NewClient(server.URL).Subscribe(ctx, "/events")
	for event := range events {
		t.Errorf("an overlong line produced an event of %d bytes", len(event.Data))
	}
	if err := <-errs; err == nil {
		t.Error("no error for a line over the limit")
	}
}

// Events the caller has not read must not pin the goroutine once the context
// is cancelled.
func TestCancellingWhileAnEventIsUnreadClosesTheChannel(t *testing.T) {
	server := sseServer("data: one\n\ndata: two\n\ndata: three\n\n")
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	events, _ := NewClient(server.URL).Subscribe(ctx, "/events")
	cancel()

	deadline := time.After(5 * time.Second)
	for {
		select {
		case _, open := <-events:
			if !open {
				return
			}
		case <-deadline:
			t.Fatal("channel stayed open after cancellation")
		}
	}
}
