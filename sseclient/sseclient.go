// Copyright (C) 2014 Peter Hellberg

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
package sseclient

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// Event represents a Server-Sent Event
type Event struct {
	Name string
	ID   string
	Data map[string]interface{}
}

// OpenURL opens a connection to a stream of server sent events
func OpenURL(url string) (events chan Event, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got response status code %d\n", resp.StatusCode)
	}

	events = make(chan Event)
	var buf bytes.Buffer

	go func() {
		ev := Event{}

		reader := bufio.NewReader(resp.Body)

		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "error during resp.Body read:%s\n", err)
				close(events)
			}

			switch {
			// OK line
			case bytes.HasPrefix(line, []byte(":ok")):
				// Do nothing

			// id of event
			case bytes.HasPrefix(line, []byte("id: ")):
				ev.ID = string(line[4:])
			case bytes.HasPrefix(line, []byte("id:")):
				ev.ID = string(line[3:])

			// name of event
			case bytes.HasPrefix(line, []byte("event: ")):
				ev.Name = string(line[7 : len(line)-1])
			case bytes.HasPrefix(line, []byte("event:")):
				ev.Name = string(line[6 : len(line)-1])

			// event data
			case bytes.HasPrefix(line, []byte("data: ")):
				buf.Write(line[6:])
			case bytes.HasPrefix(line, []byte("data:")):
				buf.Write(line[5:])

			// end of event
			case bytes.Equal(line, []byte("\n")):
				b := buf.Bytes()

				if bytes.HasPrefix(b, []byte("{")) {
					var data map[string]interface{}
					err := json.Unmarshal(b, &data)

					if err == nil {
						ev.Data = data
						buf.Reset()
						events <- ev
						ev = Event{}
					}
				}

			default:
				fmt.Fprintf(os.Stderr, "Error: len:%d\n%s", len(line), line)
				close(events)
			}
		}
	}()

	return events, nil
}
