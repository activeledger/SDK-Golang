package alsdk

import (
	"encoding/json"
	"errors"
	"fmt"
)

type StreamID string
type StreamIDWrapper map[StreamID]interface{}
type DataWrapper map[string]interface{}

type TransactionHandler interface {
	Sign(Key KeyHandler, ID StreamID) error
	SetInput(ID StreamID, Input map[string]interface{})
	SetOutput(ID StreamID, Output map[string]interface{})
	SetReadonly(ID StreamID, ReadOnly map[string]interface{})
	GetTransaction() Transaction
}

type Transaction struct {
	Territoriality string          `json:"$territoriality,omitempty"`
	Transaction    TxBody          `json:"$tx"`
	SelfSign       bool            `json:"$selfsign"`
	Signature      StreamIDWrapper `json:"$sigs"`
}

type TxBody struct {
	Namespace string          `json:"$namespace"`
	Contract  string          `json:"$contract"`
	Entry     string          `json:"$entry,omitempty"`
	Input     StreamIDWrapper `json:"$i"`
	Output    StreamIDWrapper `json:"$o,omitempty"`
	ReadOnly  StreamIDWrapper `json:"$t,omitempty"`
}

type TransactionOpts struct {
	StreamID         StreamID
	OutputStreamID   StreamID
	ReadOnlyStreamID StreamID
	Key              KeyHandler
	Namespace        string
	Contract         string
	Entry            string
	SelfSign         bool
	Territoriality   string
	Input            DataWrapper
	Output           DataWrapper
	ReadOnly         DataWrapper
}

var (
	ErrNoStreamID error = errors.New("stream id not given")
)

func (t Transaction) GetTransaction() Transaction {
	return t
}

// Sign - Sign a transaction
func (t *Transaction) Sign(key KeyHandler, id StreamID) error {
	sigWrap := make(StreamIDWrapper)

	toSign, err := json.Marshal(t.Transaction)
	if err != nil {
		return fmt.Errorf("marshaling transaction to JSON failed: %v", err)
	}

	signature, _, err := key.Sign(toSign)
	if err != nil {
		return err
	}

	sigWrap[id] = signature
	t.Signature = sigWrap

	return nil
}

// SetInput - Set the input data of the transaction
func (t *Transaction) SetInput(id StreamID, d map[string]interface{}) {
	t.Transaction.Input[id] = d
}

// SetOutput - Set the output data of the transaction
func (t *Transaction) SetOutput(id StreamID, d map[string]interface{}) {
	t.Transaction.Output[id] = d
}

// SetReadonly - Set the readonly data of a transaction
func (t *Transaction) SetReadonly(id StreamID, d map[string]interface{}) {
	t.Transaction.ReadOnly[id] = d
}

// BuildTransaction - Pass all required data and create a transaction from it
func BuildTransaction(o TransactionOpts) (Tx TransactionHandler, Hash []byte, TXError error) {

	if o.StreamID == "" {
		return &Transaction{}, []byte{}, ErrNoStreamID
	}

	t := Transaction{}

	txBody := TxBody{
		Namespace: o.Namespace,
		Contract:  o.Contract,
	}

	if o.Entry != "" {
		txBody.Entry = o.Entry
	}

	if o.SelfSign {
		t.SelfSign = true
	}

	if o.Territoriality != "" {
		t.Territoriality = o.Territoriality
	}

	if o.Input != nil {
		txBody.Input = make(StreamIDWrapper)
		txBody.Input[o.StreamID] = o.Input
	}

	if o.Output != nil {
		txBody.Output = make(StreamIDWrapper)

		// If OutputStreamID not provided assume StreamID
		outStreamId := o.StreamID

		if o.OutputStreamID != "" {
			outStreamId = o.OutputStreamID
		}

		txBody.Output[outStreamId] = o.Output
	}

	if o.ReadOnly != nil {
		txBody.ReadOnly = make(StreamIDWrapper)

		readStreamId := o.StreamID

		if o.ReadOnlyStreamID != "" {
			readStreamId = o.ReadOnlyStreamID
		}

		txBody.ReadOnly[readStreamId] = o.ReadOnly
	}

	t.Transaction = txBody

	toSign, err := json.Marshal(t.Transaction)
	if err != nil {
		return &Transaction{}, []byte{}, nil
	}

	sig, hash, err := o.Key.Sign(toSign)
	if err != nil {
		return &Transaction{}, []byte{}, nil
	}

	sigWrap := make(StreamIDWrapper)
	sigWrap[o.StreamID] = sig
	t.Signature = sigWrap

	return &t, hash, nil
}
