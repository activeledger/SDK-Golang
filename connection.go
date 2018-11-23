package sdk

import (
	"net/url"
)
type Connection struct{
	Scheme string
	Url string
	Port string
}

var conn string

func SetUrl(connection Connection) {

	u := &url.URL{
		Scheme:   connection.Scheme,
		Host:     connection.Url+":"+connection.Port,
	}
	conn=u.String()
}

func GetUrl() string{
	return conn
}
