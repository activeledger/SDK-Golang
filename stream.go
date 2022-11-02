package alsdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/activeledger/SDK-Golang/v2/internal/alerror"
)

type StreamResponse map[string]interface{}

type NodeHandler interface {
	GetList(StreamIDs []string) (StreamResponse, error)
	GetData(StreamID string) (StreamResponse, error)
	GetVolatile(StreamID string) (StreamResponse, error)
	SetVolatile(StreamID string, VolatileData interface{}) (StreamResponse, error)
	GetChanges() (StreamResponse, error)
	FindTransaction(UMID string) (StreamResponse, error)
}

type Node struct {
	connection Connection
}

type requestType string

const (
	get  requestType = "GET"
	post requestType = "POST"
)

var (
	ErrMarshalFail alerror.ALSDKError = *alerror.NewAlError("error marshaling stream")
	errUrl         alerror.ALSDKError = *alerror.NewAlError("error parsing url")
	errFail        alerror.ALSDKError = *alerror.NewAlError("request failed")
)

func ConnectNode(c Connection) NodeHandler {
	return &Node{
		c,
	}
}

// GetList - Returns an array of stream data from the specified streams
func (n *Node) GetList(streamIds []string) (StreamResponse, error) {
	idBytes, err := json.Marshal(streamIds)
	if err != nil {
		return StreamResponse{}, ErrMarshalFail.SetError(err)
	}

	url, err := n.parseUrl("/api/stream")
	if err != nil {
		return StreamResponse{}, errUrl.SetError(err)
	}

	streams, err := n.makeRequest(post, url, idBytes)
	if err != nil {
		return StreamResponse{}, errFail.SetError(err)
	}

	return streams, nil
}

// GetData - Returns the stream data of the speicifed stream
func (n *Node) GetData(streamId string) (StreamResponse, error) {
	path := fmt.Sprintf("/api/stream/%s", streamId)
	url, err := n.parseUrl(path)
	if err != nil {
		return StreamResponse{}, errUrl.SetError(err)
	}

	data, err := n.makeRequest(get, url, nil)
	if err != nil {
		return StreamResponse{}, errFail.SetError(err)
	}

	return data, nil
}

// GetVolatile - Returns the volatile data of the specified stream
func (n *Node) GetVolatile(streamId string) (StreamResponse, error) {
	path := fmt.Sprintf("/api/stream/%s/volatile", streamId)
	url, err := n.parseUrl(path)
	if err != nil {
		return StreamResponse{}, errUrl.SetError(err)
	}

	data, err := n.makeRequest(get, url, nil)
	if err != nil {
		return StreamResponse{}, errFail.SetError(err)
	}

	return data, nil
}

// SetVolatile - Sets the volatile data of a specified stream
func (n *Node) SetVolatile(streamId string, volatileData interface{}) (StreamResponse, error) {
	volatileBytes, err := json.Marshal(volatileData)
	if err != nil {
		return StreamResponse{}, ErrMarshalFail.SetError(err)
	}

	path := fmt.Sprintf("/api/stream/%s/volatile", streamId)
	url, err := n.parseUrl(path)
	if err != nil {
		return StreamResponse{}, errUrl.SetError(err)
	}

	resp, err := n.makeRequest(post, url, volatileBytes)
	if err != nil {
		return StreamResponse{}, errFail.SetError(err)
	}

	return resp, nil
}

// GetChanges - Returns the latest activity stream changes
func (n *Node) GetChanges() (StreamResponse, error) {
	url, err := n.parseUrl("/api/stream/changes")
	if err != nil {
		return StreamResponse{}, errUrl.SetError(err)
	}

	data, err := n.makeRequest(get, url, nil)
	if err != nil {
		return StreamResponse{}, errFail.SetError(err)
	}

	return data, nil
}

// FindTransaction - Find a transaction using its UMID
func (n *Node) FindTransaction(umid string) (StreamResponse, error) {
	path := fmt.Sprintf("/api/tx/%s", umid)
	url, err := n.parseUrl(path)
	if err != nil {
		return StreamResponse{}, errUrl.SetError(err)
	}

	data, err := n.makeRequest(get, url, nil)
	if err != nil {
		return StreamResponse{}, errFail.SetError(err)
	}

	return data, nil
}

func (n *Node) parseUrl(path string) (string, error) {
	urlRaw := n.connection.String()

	urlBase, err := url.Parse(urlRaw)
	if err != nil {
		return "", err
	}

	url, err := urlBase.Parse(path)
	if err != nil {
		return "", err
	}

	urlString := url.String()

	return urlString, nil
}

func (n *Node) makeRequest(reqType requestType, url string, data []byte) (map[string]interface{}, error) {
	if reqType == post {
		return postRequest(url, data)
	} else {
		return getRequest(url)
	}
}

func postRequest(url string, data []byte) (map[string]interface{}, error) {
	buffer := bytes.NewBuffer(data)

	req, err := http.NewRequest("POST", url, buffer)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	return readResponse(resp.Body)
}

func getRequest(url string) (map[string]interface{}, error) {
	req, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	defer req.Body.Close()

	return readResponse(req.Body)
}

func readResponse(response io.ReadCloser) (map[string]interface{}, error) {
	var data map[string]interface{}

	readResp, err := io.ReadAll(response)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(readResp, &data); err != nil {
		return nil, err
	}

	return data, nil
}
