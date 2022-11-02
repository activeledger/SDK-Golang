package alsdk_test

import (
	"testing"

	alsdk "github.com/activeledger/SDK-Golang/v2"
)

func TestCreateHTTPConnection(t *testing.T) {
	protocol := alsdk.HTTP
	url := "activeledger.io"
	port := "1234"

	c := alsdk.CreateConnection(protocol, url, port)

	if c == (alsdk.Connection{}) {
		t.Error("Got empty connection")
	}

	s := c.String()
	correct := "http://activeledger.io:1234"
	if s != correct {
		t.Errorf("Got %q, wanted %q", s, correct)
	}

}

func TestCreateHTTPSConnection(t *testing.T) {
	protocol := alsdk.HTTPS
	url := "activeledger.io"
	port := "1234"

	c := alsdk.CreateConnection(protocol, url, port)

	if c == (alsdk.Connection{}) {
		t.Errorf("Got empty connection")
	}

	s := c.String()
	correct := "https://activeledger.io:1234"
	if s != correct {
		t.Errorf("Got %q, wanted %q", s, correct)
	}

}
