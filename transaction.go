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
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/titanous/bitcoin-crypto/bitecdsa"
)

//Encryption enum
type Encryption int

//Types of Encryption
const (
	RSA = iota
	EC
)

//Encrptype stores types of Encryption available
var Encrptype = [...]string{
	"rsa",
	"secp256k1",
}

//Transaction elements
type Transaction struct {
	Territoriality string                 `json:"$territoriality,omitempty"`
	TxObject       TxObject               `json:"$tx"`
	SelfSign       bool                   `json:"$selfsign"`
	Signature      map[string]interface{} `json:"$sigs"`
}

// TxObject within a transaction
type TxObject struct {
	Namespace string                 `json:"$namespace"`
	Contract  string                 `json:"$contract"`
	Entry     string                 `json:"$entry,omitempty"`
	Input     map[string]interface{} `json:"$i"`
	Output    map[string]interface{} `json:"$o,omitempty"`
	ReadOnly  map[string]interface{} `json:"$r,omitempty"`
}

//Response Object to store activeledger response
type Response struct {
	UMID 						string 				`json:"$umid"`
	Summary 				Summary 			`json:"$summary"`
	Response 				[]interface{} `json:"$responses"`
	Territoriality 	string 				`json:"$territoriality"`
	Streams 				Streams 			`json:"$streams"`
}

type Summary struct {
	Total 	int 			`json:"total"`
	Vote 		int 			`json:"vote"`
	Commit 	int 			`json:"commit"`
	Errors	[]string 	`json:"errors"`
}

type Streams struct {
	New 		[]StreamData `json:"new"`
	Updated []StreamData `json:"updated"`
}

type StreamData struct {
	ID 		string `json:"id"`
	Name 	string `json:"name"`
}

//Response Object to store activeledger response
type TransactionReq struct {
	TxObject       TxObject
	Territoriality string
	SelfSign       bool
	StreamID       string
	KeyName        string
	RsaKey         *rsa.PrivateKey
	EcKey          *bitecdsa.PrivateKey
	KeyType        string
}

func (encrp Encryption) String() string { return Encrptype[encrp] }

//SendTransaction function sends complete transaction the activeledger network.
//input: transaction,url
func SendTransaction(transaction Transaction, url string) (Response, error) {
	respObj := Response{}

	txStr, errJsn := json.Marshal(transaction)
	if errJsn != nil {
		return respObj, errJsn
	}

	req, errReq := http.NewRequest("POST", url, bytes.NewBuffer(txStr))
	if errReq != nil {
		return respObj, errReq
	}
	
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	httpResp, errDo := client.Do(req)
	if errDo != nil {
		return respObj, errDo
	}

	defer httpResp.Body.Close()

	txResp, errRead := ioutil.ReadAll(httpResp.Body)
	if errRead != nil {
		return respObj, errRead
	}

	if errUnmar := json.Unmarshal(txResp, &respObj); errUnmar != nil {
		return Response{}, errUnmar
	}

	if len(respObj.Summary.Errors) > 0 {
		return respObj, errors.New("Activeledger error, see response.Summary.Errors")
	}

	return respObj, nil
}

// CreateTransaction function create a transaction object and returns it to User. 
// This function is for when user need to add multiple signature to the sigs object.
func CreateTransaction(txReq TransactionReq) *Transaction {
	temp := make(map[string]interface{})
	sig := make(map[string]interface{})

	tempMap := make(map[string]interface{})
	tempMap[txReq.KeyName] = nil

	m := txReq.TxObject.Input[txReq.StreamID].(map[string]interface{})
	m["$stream"] = txReq.StreamID
	temp[txReq.KeyName] = m

	txReq.TxObject.Input = temp

	txObjectByte, _ := json.Marshal(txReq.TxObject)
	if txReq.KeyType == Encrptype[RSA] {

		sign, _ := RsaSign(*txReq.RsaKey, txObjectByte)
		sig[txReq.StreamID] = sign

	} else {

		sign := EcdsaSign(txReq.EcKey, string(txObjectByte))
		sig[txReq.StreamID] = sign
	}

	var tx = new(Transaction)
	tx.TxObject = txReq.TxObject
	tx.Signature = sig
	tx.SelfSign = txReq.SelfSign
	tx.Territoriality = txReq.Territoriality
	//st, _ := json.Marshal(tx)
	return tx

}

//CreateAndSendTransaction  function creates and sends the transaction to acitveledger. Send the Response object back to user
func CreateAndSendTransaction(txReq TransactionReq) (Response, error) {

	var tx = CreateTransaction(txReq)
	return SendTransaction(*tx, GetUrl())

}
