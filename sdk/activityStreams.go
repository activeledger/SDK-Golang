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
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

/*
 GetActivityStreams returns All Activity streams passed in request.
 host:http://ip:port
*/
func GetActivityStreams(host string, ids []string) map[string]interface{} {

	idList, _ := json.Marshal(ids)

	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/stream")
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.NewRequest("POST", rel.String(), bytes.NewBuffer(idList))

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)

	defer resp.Body.Close()

	txResp, _ := ioutil.ReadAll(resp.Body)

	r := make(map[string]interface{})
	_ = json.Unmarshal(txResp, &r)

	return r
}

/*
 GetActivityStream returns a single Activity stream passed in request.
 host:http://ip:port
*/
func GetActivityStream(host string, id string) map[string]interface{} {

	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/stream/" + id)
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.Get(rel.String())
	req.Header.Set("Content-Type", "application/json")
	defer req.Body.Close()

	bdy, _ := ioutil.ReadAll(req.Body)

	var result map[string]interface{}
	json.Unmarshal([]byte(bdy), &result)

	return result
}

/*
 GetActivityStreamVolatile returns the passed activity stream volatile .
 host:http://ip:port
*/
func GetActivityStreamVolatile(host string, id string) map[string]interface{} {

	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/stream/" + id + "/volatile")
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.Get(rel.String())
	req.Header.Set("Content-Type", "application/json")
	defer req.Body.Close()

	bdy, _ := ioutil.ReadAll(req.Body)

	var result map[string]interface{}
	json.Unmarshal([]byte(bdy), &result)

	return result
}

/*
 SetActivityStreamVolatile sets the passed activity stream id volatiles.
 host:http://ip:port

*/
func SetActivityStreamVolatile(host string, id string, bdy interface{}) map[string]interface{} {

	bdyJSON, _ := json.Marshal(bdy)
	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/stream/" + id + "/volatile")
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.NewRequest("POST", rel.String(), bytes.NewBuffer(bdyJSON))

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)

	defer resp.Body.Close()

	txResp, _ := ioutil.ReadAll(resp.Body)

	r := make(map[string]interface{})
	_ = json.Unmarshal(txResp, &r)

	return r
}

/*
 GetActivityStreamChanges returns All Activity streams changes.
 host:http://ip:port
*/
func GetActivityStreamChanges(host string) map[string]interface{} {

	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/stream/changes")
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.Get(rel.String())
	req.Header.Set("Content-Type", "application/json")
	defer req.Body.Close()

	bdy, _ := ioutil.ReadAll(req.Body)

	var result map[string]interface{}
	json.Unmarshal([]byte(bdy), &result)

	return result
}

/*
 SearchActivityStreamPost runs the passed query on Activeledger and returns the resposne.
 host:http://ip:port

*/
func SearchActivityStreamPost(host string, query map[string]interface{}) map[string]interface{} {

	queryJson, _ := json.Marshal(query)

	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/stream/search")
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.NewRequest("POST", rel.String(), bytes.NewBuffer(queryJson))

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)

	defer resp.Body.Close()

	txResp, _ := ioutil.ReadAll(resp.Body)

	r := make(map[string]interface{})
	_ = json.Unmarshal(txResp, &r)

	return r
}

/*
 SearchActivityStreamGet searches the past query in Activeledger and returns the response
 host:http://ip:port
*/
func SearchActivityStreamGet(host string, query string) map[string]interface{} {

	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/stream/search")
	if err != nil {
		log.Fatal(err)
	}

	q := rel.Query()
	q.Set("sql", query)
	rel.RawQuery = q.Encode()

	req, _ := http.Get(rel.String())
	req.Header.Set("Content-Type", "application/json")
	defer req.Body.Close()

	bdy, _ := ioutil.ReadAll(req.Body)

	var result map[string]interface{}
	json.Unmarshal([]byte(bdy), &result)

	return result
}

/*
 FindTransaction finds the transaction using the umid in request
host:http://ip:port
*/
func FindTransaction(host string, umid string) map[string]interface{} {

	u, err := url.Parse(host)
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/api/tx/" + umid)
	if err != nil {
		log.Fatal(err)
	}

	req, _ := http.Get(rel.String())
	req.Header.Set("Content-Type", "application/json")
	defer req.Body.Close()

	bdy, _ := ioutil.ReadAll(req.Body)

	var result map[string]interface{}
	json.Unmarshal([]byte(bdy), &result)

	return result
}
