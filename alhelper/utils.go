package alhelper

import (
	"net/http"
	"net/url"
)

func TestConnection(protocol string, host string) (Success bool, Status int, Error error) {
	type status struct {
		Status int `json:"status"`
	}

	base := url.URL{
		Scheme: protocol,
		Host:   host,
		Path:   "/a/status",
	}

	resp, err := http.Get(base.String())

	if err != nil {
		return false, 0, err
	}

	defer resp.Body.Close()

	/* May be unneeded

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	var respJsn status

	if err := json.Unmarshal(body, &respJsn); err != nil {
		return false, 0, err
	}

	if respJsn.Status > 0 {
		return true, resp.StatusCode, nil
	} */

	if resp.StatusCode > 0 {
		return true, resp.StatusCode, nil
	}

	return false, 0, nil
}
