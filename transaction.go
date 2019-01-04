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

import(
	"io/ioutil"
	"bytes"
	"net/http"
	"encoding/json"
)
 
 type Transaction struct {
	 TxObject TxObject `json:"$tx"` 
	 SelfSign bool `json:"$selfsign"`
	 Signature map[string]interface{} `json:"$sigs"`
  }
  type TxObject struct {
	Namespace string  `json:"$namespace"`
	Contract string `json:"$contract"`
	Input map[string]interface{} `json:"$i"`
	Output map[string]interface{} `json:"$o,omitempty"`
	ReadOnly map[string]interface{} `json:"$r,omitempty"`
	
 }


 func SendTransaction(transaction Transaction,url string){

	sendtr, err:=json.Marshal(transaction)
	checkError(err)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(sendtr))
	checkError(err)
	req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    checkError(err)
   
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	checkError(err)
}
