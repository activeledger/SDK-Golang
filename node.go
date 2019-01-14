package sdk

import(
  "io/ioutil"
  "net/http"
  "encoding/json"
)

/*
Returns references of all the nodes. Used for Territoriality.
*/
func GetNodeReferences(url string)([]string){


	req, _ := http.Get(url+"/a/status")
	req.Header.Set("Content-Type", "application/json")
	defer req.Body.Close()

	bdy, _ := ioutil.ReadAll(req.Body)

	var result map[string]interface{}
	json.Unmarshal([]byte(bdy), &result)
	nodes := []string{}
	neighbours:= result["neighbourhood"].(map[string]interface{})
	refs:=neighbours["neighbours"].(map[string]interface{})
// if the node is online, add to the list
	for key, value := range refs{
		ishome:=value.(map[string]interface {})
		online:=ishome["isHome"].(bool)
		if(online){
		nodes=append(nodes,key)
		}
		
	}
	return nodes
}