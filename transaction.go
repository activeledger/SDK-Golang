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
