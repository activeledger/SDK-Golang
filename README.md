<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger - Golang SDK

The Activeledger Golang SDK has been built to provide an easy way to connect your Go application to an Activeledger Network

### Activeledger

[Visit Activeledger.io](https://activeledger.io/)

[Read Activeledgers documentation](https://github.com/activeledger/activeledger)


## Usage

The SDK currently supports the following functionality

- Connection handling
- Key generation
- Key onboarding
- Transaction building

### Connection

When sending a transaction, you must pass a connection that provides the information needed to establish a link to the network and specified node.

To do this a connection object must be created. This object must be passed the protocol, address, and port.

```go
sdk.SetUrl(sdk.Connection{Scheme:"protocol",Url:"url",Port:"port"})
```
#### Example
```go
sdk.SetUrl(sdk.Connection{Scheme:"http",Url:"testnet-uk.activeledger.io",Port:"5260"})
```

---

### Key

There are two key types that can be generated currently, more are planned and will be implemented into Activeledger first. These types are RSA and Elliptic Curve.

#### Generating a key


##### Example

```go
//RSA
  privatekey:=sdk.RsaKeyGen()
  publicKey:=privatekey.PublicKey
//ECDSA  
  privateKey,_ := sdk.EcdsaKeyGen() // public key can be extract using private key e.g. privateKey.PublicKey


```

#### Exporting Key


##### Example

```go
 publicKeyString:=sdk.RsaToPem(publicKey)
 privatekeyStr,publicKeyString:=sdk.EcdsaToPem(privateKey)
```


#### Onboarding a key

Once you have a key generated, to use it to sign transactions it must be onboarded to the ledger network

##### Example
```go
resp := onboardRSA(key, sdk.RSA/sdk.EC, <keyName>) //resp is on object with code and description. Description in this case is  a StreamID or error(Can be distinguished using the code)
```


#### Creating a transaction
```go
  tx := new(sdk.TxObject) //create a new TxObject
  tx.Namespace = <namespace>
  tx.Contract = <contract>
  tx.entry = <entry> //optional
  tx.Input=<input> // map[string]interface{}
  tx.Output=<output> // map[string]interface{}. optional
  tx.ReadOnly=<readOnly> // map[string]interface{}. Optional
  
  
  
  var trxReq = new(sdk.TransactionReq)// a transaction request object
  trxReq.TxObject = *tx
  trxReq.SelfSign = true/false
  trxReq.StreamID = <StreamId>
  trxReq.KeyName = <keyName>
  trxReq.RsaKey = <key>
  trxReq.KeyType = sdk.Encrptype[sdk.RSA/sdk.EC]
  
  
  txObject:=sdk.TxObject{Namespace:"default",Contract:"onboard",Input:input,Output:output,ReadOnly:readOnly}
  
  sdk.SetUrl(sdk.Connection{Scheme:"protocol",Url:"url",Port:"port"}) //Set connection url
  txResp := sdk.CreateTransaction(*trxReq) //Returns a transaction object
  sdk.SendTransaction(*txResp,sdk.GetUrl()) // Returns Response object with Code and Description. Description is either a stream ID or error(Can be distinguished using code)
  
  or
  
  sdk.CreateAndSendTransaction(*txResp)// Creates and Sends the transaction. Returns Response object with Code and Description. Description is either a stream ID or error(Can be distinguished using code)
  
 
```

---

## License

---

This project is licensed under the [MIT](https://github.com/activeledger/SDK-Golang/blob/master/LICENSE) License


