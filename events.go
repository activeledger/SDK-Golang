package activeledger

import (
	"bufio"
	"context"
	"net/http"
	"strings"
)

// Event is one server-sent event.
type Event struct {
	Name string
	Data string
	ID   string
}

// Subscribe streams events until the context is cancelled or the stream ends.
//
// Cancelling the context closes the underlying connection -- the same
// guarantee the Kotlin Flow and the Python generator give, expressed the Go
// way. With a callback API closing would be the caller's job and the thing
// they forget, leaving a node holding connections for subscribers that are
// gone.
//
// The returned channel is closed when the stream ends; errors arrive on the
// error channel, which is buffered so a caller that stops reading cannot
// block the producer.
func (c *Client) Subscribe(ctx context.Context, path string) (<-chan Event, <-chan error) {
	if path == "" {
		path = "/events"
	}
	events := make(chan Event)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
		if err != nil {
			errs <- err
			return
		}
		request.Header.Set("Accept", "text/event-stream")
		request.Header.Set("Cache-Control", "no-cache")

		// No client timeout for SSE: event streams are long-lived by design,
		// and a timeout would close them for being quiet.
		client := &http.Client{}
		response, err := client.Do(request)
		if err != nil {
			errs <- err
			return
		}
		defer response.Body.Close()

		var name, id string
		var data []string

		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for scanner.Scan() {
			line := strings.TrimRight(scanner.Text(), "\r")

			switch {
			case line == "":
				if len(data) > 0 {
					select {
					case events <- Event{Name: name, Data: strings.Join(data, "\n"), ID: id}:
					case <-ctx.Done():
						return
					}
					data, name, id = nil, "", ""
				}
			case strings.HasPrefix(line, ":"):
				// Comment or heartbeat. Ignored deliberately: emitting these
				// would deliver a stream of empty payloads to a subscriber.
			case strings.HasPrefix(line, "event:"):
				name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "id:"):
				id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			case strings.HasPrefix(line, "data:"):
				data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}

		// A stream ending without a trailing blank line still has a complete
		// event pending.
		if len(data) > 0 {
			select {
			case events <- Event{Name: name, Data: strings.Join(data, "\n"), ID: id}:
			case <-ctx.Done():
			}
		}
		if err := scanner.Err(); err != nil && ctx.Err() == nil {
			errs <- err
		}
	}()

	return events, errs
}
