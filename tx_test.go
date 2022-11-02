package alsdk_test

import (
	"testing"

	alsdk "github.com/activeledger/SDK-Golang/v2"
)

func TestBuild(t *testing.T) {
	tops, err := genTxOpts()
	if err != nil {
		t.Errorf("Error getting transaction options %q\n", err)
	}

	txHan, err := buildTx(tops)
	if err != nil {
		t.Errorf("Error building transaction %q\n", err)
	}

	tx := txHan.GetTransaction()

	if tx.Transaction.Input == nil {
		t.Error("Tx input empty")
	}

	if tx.Transaction.Output == nil {
		t.Error("Tx output empty")
	}

	if tx.Transaction.ReadOnly == nil {
		t.Error("Tx readonly empty")
	}

	if tx.Signature == nil {
		t.Error("Tx readonly empty")
	}

	if tx.SelfSign != tops.SelfSign {
		t.Errorf("Tx selfsign doesn't match, got %t, expected %t", tx.SelfSign, tops.SelfSign)
	}

	if tx.Territoriality != tops.Territoriality {
		t.Errorf("Tx territoriality doesn't match, got %q, expected %q", tx.Territoriality, tops.Territoriality)
	}

	if tx.Transaction.Namespace != tops.Namespace {
		t.Errorf("Tx Namespace doesn't match, got %q, expected %q", tx.Transaction.Namespace, tops.Namespace)
	}

	if tx.Transaction.Contract != tops.Contract {
		t.Errorf("Tx Contract doesn't match, got %q, expected %q", tx.Transaction.Contract, tops.Contract)
	}

	if tx.Transaction.Entry != tops.Entry {
		t.Errorf("Tx Entry doesn't match, got %q, expected %q", tx.Transaction.Entry, tops.Entry)
	}
}

func TestSign(t *testing.T) {
	tops, err := genTxOpts()
	if err != nil {
		t.Errorf("Error getting transaction options %q\n", err)
	}
	txHan, err := buildTx(tops)
	if err != nil {
		t.Errorf("Error building transaction %q\n", err)
	}

	txHan.Sign(tops.Key, tops.StreamID)
}

func TestSetInput(t *testing.T) {
	tops, err := genTxOpts()
	if err != nil {
		t.Errorf("Error getting transaction options %q\n", err)
	}
	txHan, err := buildTx(tops)
	if err != nil {
		t.Errorf("Error building transaction %q\n", err)
	}

	newIn := make(map[string]interface{})
	newIn["replacement"] = "data"

	txHan.SetInput(tops.StreamID, newIn)

	tx := txHan.GetTransaction()
	stored := tx.Transaction.Input[tops.StreamID].(map[string]interface{})["replacement"].(string)

	if stored != "data" {
		t.Errorf("Input doesn't match expected, got %q, expected data", stored)
	}
}

func TestSetOutput(t *testing.T) {
	tops, err := genTxOpts()
	if err != nil {
		t.Errorf("Error getting transaction options %q\n", err)
	}
	txHan, err := buildTx(tops)
	if err != nil {
		t.Errorf("Error building transaction %q\n", err)
	}

	newOut := make(map[string]interface{})
	newOut["replacement"] = "data"

	txHan.SetOutput(tops.StreamID, newOut)

	tx := txHan.GetTransaction()
	stored := tx.Transaction.Output[tops.StreamID].(map[string]interface{})["replacement"].(string)

	if stored != "data" {
		t.Errorf("Output doesn't match expected, got %q, expected data", stored)
	}
}

func TestSetReadOnly(t *testing.T) {
	tops, err := genTxOpts()
	if err != nil {
		t.Errorf("Error getting transaction options %q\n", err)
	}
	txHan, err := buildTx(tops)
	if err != nil {
		t.Errorf("Error building transaction %q\n", err)
	}

	newRo := make(map[string]interface{})
	newRo["replacement"] = "data"

	txHan.SetReadonly(tops.StreamID, newRo)

	tx := txHan.GetTransaction()
	stored := tx.Transaction.ReadOnly[tops.StreamID].(map[string]interface{})["replacement"].(string)

	if stored != "data" {
		t.Errorf("Readonly doesn't match expected, got %q, expected data", stored)
	}
}

func buildTx(ops alsdk.TransactionOpts) (alsdk.TransactionHandler, error) {
	tx, _, err := alsdk.BuildTransaction(ops)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func genTxOpts() (alsdk.TransactionOpts, error) {
	key, err := alsdk.GenerateRSA()
	if err != nil {
		return alsdk.TransactionOpts{}, err
	}

	streamID := alsdk.StreamID("testStreamId")

	iData := make(alsdk.DataWrapper)
	oData := make(alsdk.DataWrapper)
	rData := make(alsdk.DataWrapper)

	iData[streamID] = map[string]string{
		"input": "data",
	}

	oData[streamID] = map[string]string{
		"output": "data",
	}

	rData[streamID] = map[string]string{
		"readonly": "data",
	}

	return alsdk.TransactionOpts{
		StreamID:       streamID,
		Key:            key,
		Namespace:      "testnamespace",
		Contract:       "testcontract",
		Entry:          "testentry",
		SelfSign:       false,
		Territoriality: "territorialitytest",
		Input:          iData,
		Output:         oData,
		ReadOnly:       rData,
	}, nil

}
