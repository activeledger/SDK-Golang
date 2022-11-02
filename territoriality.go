package alsdk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Nodes []string

type status struct {
	Status        int           `json:"status"`
	Reference     string        `json:"reference"`
	Left          string        `json:"left"`
	Right         string        `json:"right"`
	Neighbourhood Neighbourhood `json:"neighbourhood"`
	PEM           string        `json:"pem"`
}

type Neighbourhood struct {
	Neighbours map[string]Neighbour `json:"neighbours"`
}

type Neighbour struct {
	IsHome bool `json:"isHome"`
}

func GetNodeReferences(connection Connection) (Nodes, error) {
	baseUrl := connection.String()

	body, err := sendStatusRequest(baseUrl)
	if err != nil {
		return []string{}, fmt.Errorf("getnodereferences - sending status request failed: %v", err)
	}

	nodes, errExtract := extractNodes(body)
	if errExtract != nil {
		return []string{}, fmt.Errorf("getnodereferences - extracting node data failed: %v", errExtract)
	}

	return nodes, nil

}

func sendStatusRequest(baseUrl string) ([]byte, error) {
	url := fmt.Sprintf("%s/a/status", baseUrl)

	req, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set("Content-Type", "application/json")

	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return []byte{}, err
	}

	return body, nil
}

func extractNodes(body []byte) (Nodes, error) {

	var nodeStatus status
	nodes := []string{}

	if err := json.Unmarshal(body, &nodeStatus); err != nil {
		return []string{}, err
	}

	neighbours := nodeStatus.Neighbourhood.Neighbours

	for k, v := range neighbours {
		if v.IsHome {
			nodes = append(nodes, k)
		}
	}

	return nodes, nil

}
