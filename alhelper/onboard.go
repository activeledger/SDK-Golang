package alhelper

import (
	"encoding/json"

	alsdk "github.com/activeledger/SDK-Golang/v2"
	"github.com/activeledger/SDK-Golang/v2/internal/alerror"
)

type OnboardOpts struct {
	Namespace string
	Contract  string
	Entry     string
	Key       alsdk.Key
	InputKey  string
}

var (
	ErrMarshal alerror.ALSDKError = *alerror.NewAlError("error marshalling transaction to json")
	ErrSign    alerror.ALSDKError = *alerror.NewAlError("error signing onboard transaction")
	ErrOnboard alerror.ALSDKError = *alerror.NewAlError("error onboarding transaction")
)

func Onboard(opts OnboardOpts) (Transaction alsdk.Transaction, err error) {
	pubPem := alsdk.Key.GetPublicPEM(opts.Key)

	inputMap := map[string]string{
		"publicKey": pubPem,
		"type":      string(opts.Key.GetType()),
	}

	input := alsdk.DataWrapper{
		"identity": inputMap,
	}

	txObj := alsdk.TxBody{
		Namespace: opts.Namespace,
		Contract:  opts.Contract,
		Input:     input,
	}

	if opts.Entry != "" {
		txObj.Entry = opts.Entry
	}

	t := alsdk.Transaction{
		Transaction: txObj,
		SelfSign:    true,
	}

	toSign, err := json.Marshal(t.Transaction)
	if err != nil {
		return alsdk.Transaction{}, ErrMarshal.SetError(err)
	}

	sig, _, err := opts.Key.Sign(toSign)
	if err != nil {
		return alsdk.Transaction{}, ErrSign.SetError(err)
	}

	sigWrap := alsdk.DataWrapper{
		"identity": sig,
	}

	t.Signature = sigWrap

	return t, nil
}

func OnboardAndSend(opts OnboardOpts, c alsdk.Connection) (StreamID string, AlResponse alsdk.Response, err error) {
	t, err := Onboard(opts)
	if err != nil {
		return "", alsdk.Response{}, err
	}

	resp, err := alsdk.Send(t, c)
	if err != nil {
		return "", alsdk.Response{}, ErrOnboard.SetError(err)
	}

	return resp.Streams.New[0].ID, resp, nil
}
