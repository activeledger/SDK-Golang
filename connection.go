package alsdk

import (
	"fmt"
	"net/url"
)

type Connection struct {
	Protocol Protocol
	Url      string
	Port     string
}

type Protocol string

const (
	HTTP  Protocol = "http"
	HTTPS Protocol = "https"
)

// CreateConnection - Create a new connection
func CreateConnection(protocol Protocol, url string, port string) Connection {
	var c = Connection{
		Protocol: protocol,
		Url:      url,
		Port:     port,
	}

	return c
}

// String - Returns the URL as a string
func (c Connection) String() string {
	host := fmt.Sprintf("%s:%s", c.Url, c.Port)

	u := url.URL{
		Scheme: string(c.Protocol),
		Host:   host,
	}

	return u.String()
}
