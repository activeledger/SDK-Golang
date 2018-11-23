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
  privateKey,_ := sdk.EcdsaKeyGen()


```

#### Exporting Key


##### Example

```go
 publicKeyString:=sdk.RsaToPem(publicKey)
 privatekeyStr,publicKeyString:=sdk.EcdsaToPem(privateKey)
```


#### Onboarding a key and creating a transaction

Once you have a key generated, to use it to sign transactions it must be onboarded to the ledger network

##### Example

```go
 txObject:=sdk.TxObject{Namespace:"default",Contract:"onboard",Input:input,Output:output,ReadOnly:readOnly}
  tx,_:=json.Marshal(txObject)
  //rsa
  signedMessage,_:=sdk.RsaSign(*privatekey,[]byte(tx))
  //ecdsa
  pemPrivate := sdk.EcdsaFromPem(privatekeyStr)
  signedMessage := sdk.EcdsaSign(pemPrivate,string(tx))
  
  signature["identity"]=signedMessage
  selfsign:=true
  transaction:=sdk.Transaction{TxObject:txObject,SelfSign:selfsign,Signature:signature}
  sdk.SetUrl(sdk.Connection{Scheme:"protocol",Url:"url",Port:"port"})
  sdk.SendTransaction(transaction,sdk.GetUrl())
```

---

#### Signing & sending a transaction

When signing a transaction you must send the finished version of it. No changes can be made after signing as this will cause the ledger to reject it.

The key must be one that has been successfully onboarded to the ledger which the transaction is being sent to.

## License

---

This project is licensed under the [MIT](https://github.com/activeledger/activeledger/blob/master/LICENSE) License


