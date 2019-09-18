package sdk

import (
	"app/bitcoin-crypto/bitecdsa"
	"crypto/rsa"
	"encoding/json"
)

func onboardRSA(keyPair *rsa.PrivateKey, encryption Encryption, keyname string) Response {

	var tx = new(Transaction)
	tx.TxObject.Contract = "onboard"
	tx.TxObject.Namespace = "default"
	input := make(map[string]interface{})
	inputMap := make(map[string]interface{})
	pubKey := RsaToPem(keyPair.PublicKey)

	inputMap["publicKey"] = pubKey

	inputMap["type"] = Encrptype[encryption]
	input[keyname] = inputMap
	tx.TxObject.Input = input
	tx.SelfSign = true
	sig := make(map[string]interface{})
	b, _ := json.Marshal(tx.TxObject)
	sign, _ := RsaSign(*keyPair, b)
	sig[keyname] = sign

	tx.Signature = sig
	//ll, _ := json.Marshal(tx)

	resp := SendTransaction(*tx, GetUrl())
	if resp.Code == 200 {
		Stream = resp.Desc // storing stream id in local storage
		KeyName = keyname
	}
	return resp
}

func onboardEC(keyPair *bitecdsa.PrivateKey, encryption Encryption, keyname string) Response {

	var tx = new(Transaction)
	tx.TxObject.Contract = "onboard"
	tx.TxObject.Namespace = "default"
	input := make(map[string]interface{})
	inputMap := make(map[string]interface{})
	_, pubKey := EcdsaToPem(keyPair)

	inputMap["publicKey"] = pubKey
	inputMap["type"] = encryption
	input[keyname] = inputMap
	tx.TxObject.Input = input
	tx.SelfSign = true
	sig := make(map[string]interface{})
	b, _ := json.Marshal(tx.TxObject)
	sign := EcdsaSign(keyPair, string(b))
	sig[keyname] = sign
	tx.Signature = sig
	resp := SendTransaction(*tx, GetUrl())
	if resp.Code == 200 {
		Stream = resp.Desc // storing stream id in local storage
		KeyName = keyname
	}
	return resp
}
