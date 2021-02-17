<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger - Golang SDK

The Activeledger Golang SDK has been built to provide an easy way to connect your Go application to an Activeledger Network

### Activeledger

[Visit Activeledger.io](https://activeledger.io/)

[Read Activeledgers documentation](https://github.com/activeledger/activeledger)

## Installation

```sh
go get github.com/activeledger/SDK-Golang
```

## Usage

The SDK currently supports the following functionality

- Connection handling
- Key generation
- Key onboarding
- Transaction building

### Import

```go
import (
  sdk "github.com/activeledger/SDK-Golang"
)
```

### Connection

When sending a transaction, you must pass a connection that provides the information needed to establish a link to the network and specified node.

To do this a connection object must be created. This object must be passed the protocol, address, and port.

```go
connection := sdk.Connection {
  Scheme:"protocol",
  Url:"url",
  Port:"port"
}

sdk.SetUrl(connection)
```

#### Example - Connecting to the Activeledger public testnet

```go
connection := sdk.Connection {
  Scheme:"http",
  Url:"testnet-uk.activeledger.io",
  Port:"5260"
}

sdk.SetUrl(connection)
```

---

### Key

There are two key types that can be generated currently, more are planned and will be implemented into Activeledger first. These types are RSA and Elliptic Curve.

#### Generating a key

##### Example

```go
// RSA
// Generate the private key
privatekey := sdk.RsaKeyGen()
// Get the public key from the private key
publicKey := privatekey.PublicKey

// ECDSA
privateKey, _ := sdk.EcdsaKeyGen()

// See key exporting to get ECDSA Public key
```

#### Exporting Key

##### Example

```go
// RSA Public key string PEM
 publicKeyString := sdk.RsaToPem(publicKey)

// ECDSA private and public key PEMs
 privatekeyStr, publicKeyString := sdk.EcdsaToPem(privateKey)
```

#### Onboarding a key and creating a transaction

Once you have a key generated, to use it to sign transactions it must be onboarded to the ledger network

##### Example

```go
 txObject := sdk.TxObject {
   Namespace: "default",
   Contract: "onboard",
   Input: input,
   Output: output,
   ReadOnly: readOnly,
  }

  tx, _ := json.Marshal(txObject)

  // RSA
  signedMessage,_ := sdk.RsaSign(*privatekey, []byte(tx))

  // ECDSA (Elliptic curve)
  pemPrivate := sdk.EcdsaFromPem(privatekeyStr)
  signedMessage := sdk.EcdsaSign(pemPrivate,string(tx))

  signature["identity"] = signedMessage
  selfsign := true
  transaction := sdk.Transaction {
    TxObject: txObject,
    SelfSign: selfsign,
    Signature:signature,
  }

  sdk.SetUrl(sdk.Connection {
    Scheme:"protocol",
    Url:"url",
    Port:"port"
  })

  // Response contains Code (int) and Desc (string)
  response := sdk.SendTransaction(transaction, sdk.GetUrl())
```

---

#### Signing & sending a transaction

When signing a transaction you must send the finished version of it. No changes can be made after signing as this will cause the ledger to reject it.

The key must be one that has been successfully onboarded to the ledger which the transaction is being sent to.

## Events Subscription

SDK contains different helper functions for the purpose of subscribing to different events.

- Subscribe(host) // host=protocol://ip:port
- SubscribeStream(host,stream)
- EventSubscribeContract(host,contract,event)
- EventSubscribe(host,contract)
- AllEventSubscribe(host)

They all return events which can then be used by developers.

## ActivityStreams

SDK also contains helper functions to get and search streams from Activeledger.

- GetActivityStreams(host, ids) // host=protocol://ip:port
- GetActivityStream(host, id)
- GetActivityStreamVolatile(host, id)
- SetActivityStreamVolatile(host, id, bdy) // Anything in the bdy will be written to that location for that stream id.
- GetActivityStreamChanges(host)
- SearchActivityStreamPost(host, query) //post request
- SearchActivityStreamGet(host, query) //get Request
- FindTransaction(host, umid )

They all return map[string]interface{}.

## License

---

This project is licensed under the [MIT](https://github.com/activeledger/SDK-Golang/blob/master/LICENSE) License
