package alsdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"net/http"

	"github.com/activeledger/SDK-Golang/v2/internal/alerror"
)

// Response - Holds the response data from Activeledger
type Response struct {
	UMID           string        `json:"$umid"`
	Summary        Summary       `json:"$summary"`
	Response       []interface{} `json:"$responses"`
	Territoriality string        `json:"$territoriality"`
	Streams        Streams       `json:"$streams"`
}

// Summary - Summary structure in Response
type Summary struct {
	Total  int      `json:"total"`
	Vote   int      `json:"vote"`
	Commit int      `json:"commit"`
	Errors []string `json:"errors"`
}

// Streams - Streams structure in Response
type Streams struct {
	New     []StreamData `json:"new"`
	Updated []StreamData `json:"updated"`
}

// StreamData - Stream data structure in Streams
type StreamData struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var (
	ErrActiveledgerResp error              = errors.New("activeledger returned errors, see response.summary.errors")
	ErrJSON             alerror.ALSDKError = *alerror.NewAlError("there was an error converting the transaction into a json string")
	ErrSend             alerror.ALSDKError = *alerror.NewAlError("sending the request to the activeledger node failed")
)

func Send(tx Transaction, c Connection) (Response, error) {
	r := Response{}

	txBytes, err := json.Marshal(tx)
	if err != nil {
		return r, ErrJSON.SetError(err)
	}

	url := c.String()

	httpResp, err := sendRequest(url, txBytes)
	if err != nil {
		return r, ErrSend.SetError(err)
	}

	defer httpResp.Body.Close()

	processResponse(&r, httpResp.Body)

	if len(r.Summary.Errors) > 0 {
		return r, ErrActiveledgerResp
	}

	return r, nil
}

func sendRequest(url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return &http.Response{}, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	httpResp, err := client.Do(req)
	if err != nil {
		return &http.Response{}, err
	}

	return httpResp, nil
}

func processResponse(response *Response, body io.ReadCloser) error {
	txResp, err := io.ReadAll(body)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(txResp, response); err != nil {
		return err
	}

	return nil
}
