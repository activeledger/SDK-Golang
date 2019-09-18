/*
 * MIT License (MIT)
 * Copyright (c) 2018
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package sdk

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

/*
Returns references of all the nodes. Used for Territoriality.
*/
func GetNodeReferences(url string) []string {

	req, _ := http.Get(url + "/a/status")
	req.Header.Set("Content-Type", "application/json")
	defer req.Body.Close()

	bdy, _ := ioutil.ReadAll(req.Body)

	var result map[string]interface{}
	json.Unmarshal([]byte(bdy), &result)
	nodes := []string{}
	neighbours := result["neighbourhood"].(map[string]interface{})
	refs := neighbours["neighbours"].(map[string]interface{})
	// if the node is online, add to the list
	for key, value := range refs {
		ishome := value.(map[string]interface{})
		online := ishome["isHome"].(bool)
		if online {
			nodes = append(nodes, key)
		}

	}
	return nodes
}
