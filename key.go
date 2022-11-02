package alsdk

import (
	"crypto/rsa"
	"errors"

	"github.com/activeledger/SDK-Golang/v2/internal/key"
)

type KeyHandler interface {
	Sign(Data []byte) (Signature []byte, Hash []byte, SignError error)
	Verify(Signature []byte, Checksum []byte) (Ok bool, VerifError error)
	GetType() KeyType
	GetRSAKey() (Key *rsa.PrivateKey)
	GetEllipticKey()
	GetPrivatePEM() (KeyPublicPem string)
	GetPublicPEM() (KeyPrivatePem string)
}

type Key struct {
	RSA key.RSAHandler
	// Elliptic elliptic.IElliptic
	keyType KeyType
}

type KeyType string

const (
	RSA      KeyType = "rsa"
	Elliptic KeyType = "elliptic"
)

var (
	ErrNotImplemented = errors.New("not implemented")
)

func GenerateRSA() (KeyHandler, error) {
	rsaKey, err := key.GenerateRSA()
	if err != nil {
		return Key{}, err
	}

	k := Key{
		RSA:     rsaKey,
		keyType: RSA,
	}

	return k, nil
}

func GenerateElliptic() error {
	return ErrNotImplemented
}

func (k Key) Sign(data []byte) (Signature []byte, Hash []byte, SignError error) {
	if k.keyType == RSA {
		return k.RSA.Sign(data)
	} else {
		// return k.Elliptic.Sign(data)
		return []byte{}, []byte{}, ErrNotImplemented
	}
}

func (k Key) Verify(signature []byte, checksum []byte) (bool, error) {
	if k.keyType == RSA {
		return k.RSA.Verify(signature, checksum)
	} else {
		return false, ErrNotImplemented
	}
}

func (k Key) GetType() KeyType {
	return k.keyType
}

func (k Key) GetRSAKey() *rsa.PrivateKey {
	return k.RSA.GetKey()
}

func (k Key) GetEllipticKey() {}

func (k Key) GetPrivatePEM() string {
	var pem string
	if k.keyType == RSA {
		pem = k.RSA.GetPrivatePEM()
	} else {
		// return k.Elliptic.GetPrivatePEM()
		pem = ""
	}

	return pem
}

func (k Key) GetPublicPEM() string {
	if k.keyType == RSA {
		return k.RSA.GetPublicPEM()
	} else {
		// return k.Elliptic.GetPublicPEM()
		return ""
	}
}

func SetKey(pem string, keyType KeyType) (KeyHandler, error) {
	k := Key{}

	if keyType == RSA {

		key, errSet := key.SetRSAKey(pem)
		if errSet != nil {
			return Key{}, errSet
		}

		k.RSA = key
		k.keyType = RSA

	} else {
		/* handler := elliptic.InitEllipticHandler()
		return */
		return k, ErrNotImplemented
	}

	return k, nil
}
