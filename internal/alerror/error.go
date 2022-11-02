package alerror

import "fmt"

type ALSDKError struct {
	Context string
	Err     error
}

func (ae *ALSDKError) Error() string {
	return fmt.Sprintf("%s: %v", ae.Context, ae.Err)
}

func NewAlError(info string) *ALSDKError {
	return &ALSDKError{
		Context: info,
	}
}

func Wrap(e error, info string) *ALSDKError {
	return &ALSDKError{
		Context: info,
		Err:     e,
	}
}

func (ae *ALSDKError) SetError(e error) *ALSDKError {
	ae.Err = e
	return ae
}
