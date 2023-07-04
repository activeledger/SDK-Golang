<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger - Golang SDK

The Activeledger Golang SDK has been built to provide an easy way to connect your Go application to an Activeledger Network

### Activeledger

[Visit Activeledger.io](https://activeledger.io/)

[Read Activeledgers documentation](https://github.com/activeledger/activeledger)

## Installation

```sh
go get github.com/activeledger/SDK-Golang/v2
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
  alsdk "github.com/activeledger/SDK-Golang/v2"
)
```

### Connection

When sending a transaction, you must pass a connection that provides the information needed to establish a link to the network and specified node.

To do this a connection object must be created. This object must be passed the protocol, address, and port.

```go
address := "localhost"
port := "2560"

connection := alsdk.NewConnection(alsdk.HTTP, {address}, {port})
```

#### Example - Connecting to the Activeledger public testnet

```go
address := "localhost"
port := "2560"

connection := alsdk.NewConnection(alsdk.HTTP, address, port)
```

NewConnection() returns a Connection{} object which looks like this:
```go
type Connection struct {
	Protocol Protocol
	Url      string
	Port     string
}
```
Later this is passed to the `Send()` function and used to connect to the given node. 

---

### Key

Activeledger uses RSA and Elliptic Curve keys. Currently EC is only partialy implemented in this SDK. RSA is fully implemented.

#### Generating a key

##### Example

```go
// RSA
// Generate the private key
keyHandler := alsdk.GenerateRSA()
```

#### Exporting Key

##### Example

```go
// RSA Public key string PEM
publicKey := keyHandler.GetPublicPem()
```

#### Onboarding a key and creating a transaction

Once you have a key generated, to use it to sign transactions it must be onboarded to the ledger network

##### Example
```go
// The identity of the stream
streamId := "someidentity"

// Create a new RSA key handler
keyHandler, err := alsdk.GenerateRSA()
if err != nil {// ... }

// Convert our stream ID to a StreamID struct
alStreamId := alsdk.StreamID(streamId)

// Create a new instance of the DataWrapper to hold the Tx input data
input := alsdk.DataWrapper{
	"type":      "rsa",
	"publicKey": keyHandler.GetPublicPEM(),
}

// Use our previously created data to create an object of transaction objects
// which will be used to build the transaction
txOpts := alsdk.TransactionOpts{
	StreamID:  alStreamId,
	Contract:  "onboard",
	Namespace: "namespace",
	Input:     input,
	SelfSign:  true,
	Key:       keyHandler,
}

// Build transaction returns the following:
// txHandler - This handles making modifications to the tx we have just built
// hash      - The checksum hash generated when signing the transaction, 
//              you can use this to perform validity checks
txHandler, hash, err := alsdk.BuildTransaction(txOpts)
if err != nil {// ... }

// Get the transaction object
tx := txHandler.GetTransaction()

// Send the transaction to the network and receive the Activeledger response data
resp, err := alsdk.Send(tx, l.conn)
if err != nil {// ... }
```

The `resp` returns the following structs
```go
// Holds the response data from Activeledger
type Response struct {
	UMID           string        `json:"$umid"`
	Summary        Summary       `json:"$summary"`
	Response       []interface{} `json:"$responses"`
	Territoriality string        `json:"$territoriality"`
	Streams        Streams       `json:"$streams"`
}

// Summary structure in Response
type Summary struct {
	Total  int      `json:"total"`
	Vote   int      `json:"vote"`
	Commit int      `json:"commit"`
	Errors []string `json:"errors"`
}

// Streams structure in Response
type Streams struct {
	New     []StreamData `json:"new"`
	Updated []StreamData `json:"updated"`
}

// Stream data structure in Streams
type StreamData struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
```

---

#### Signing & sending a transaction

When signing a transaction you must send the finished version of it. No changes can be made after signing as this will cause the ledger to reject it as the signature will no longer be valid.

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
