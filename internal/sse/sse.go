package sse

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/activeledger/SDK-Golang/v2/internal/alerror"
)

type Event struct {
	Name string
	ID   string
	Data map[string]interface{}
}

var (
	ErrUrlOpenFail alerror.ALSDKError = *alerror.NewAlError("failed to open url")
	// Err
)

// OpenUrl - Listen for stream events on the given URL
func OpenUrl(url string) (chan Event, error) {
	resp, err := get(url)
	if err != nil {
		return nil, ErrUrlOpenFail.SetError(err)
	}

	events := make(chan Event)

	reader := bufio.NewReader(resp.Body)

	go eventLoop(reader, events)

	return events, nil
}

func eventLoop(reader *bufio.Reader, events chan Event) {
	event := Event{}
	var buffer bytes.Buffer

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			log.Println("error reading resp.body read:", err)

			close(events)
			break
		}

		switch {
		// ID
		case hasPrefix(line, "id:"):
			event.ID = string(line[3:])

		case hasPrefix(line, "id: "):
			event.ID = string(line[4:])

		// Name
		case hasPrefix(line, "event:"):
			event.ID = string(line[7 : len(line)-1])

		case hasPrefix(line, "event: "):
			event.ID = string(line[8 : len(line)-1])

		// Data
		case hasPrefix(line, "data:"):
			event.ID = string(line[5:])

		case hasPrefix(line, "data: "):
			event.ID = string(line[6:])

		// End
		case bytes.Equal(line, []byte("\n")):
			b := buffer.Bytes()

			if hasPrefix(b, "{") {
				var data map[string]interface{}

				if err := json.Unmarshal(b, &data); err != nil {
					log.Printf("error unmarshaling byte data: %s\n", err.Error())
				}

				event.Data = data
				buffer.Reset()
				events <- event
				event = Event{}
			}

		default:
			log.Printf("error: len%d\n%s", len(line), line)

			close(events)
		}

	}

}

func get(url string) (*http.Response, error) {
	resp, errGet := http.Get(url)
	if errGet != nil {
		return &http.Response{}, errGet
	}

	if resp.StatusCode != 200 {
		return &http.Response{}, fmt.Errorf("status code not 200, got %d", resp.StatusCode)
	}

	return resp, nil
}

func hasPrefix(data []byte, prefix string) bool {
	return bytes.HasPrefix(data, []byte(prefix))
}
