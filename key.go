package alsdk

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/activeledger/SDK-Golang/v2/internal/key"
)

type KeyHandler interface {
	Sign(Data []byte) (Signature []byte, Hash []byte, SignError error)
	Verify(Signature []byte, Checksum []byte) (Ok bool, VerifError error)

	GetType() KeyType
	GetRSAKey() (Key *rsa.PrivateKey)
	GetEllipticKey() (Key *ecdsa.PrivateKey)
	GetPrivatePEM() (KeyPublicPem string)
	GetPublicPEM() (KeyPrivatePem string)
}

type Key struct {
	RSA      key.RSAHandler
	Elliptic key.EllipticHandler
	keyType  KeyType
}

type KeyType string

const (
	RSA      KeyType = "rsa"
	Elliptic KeyType = "elliptic"
)

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrUnknownKey     = errors.New("unknown key type")
)

// Generate a new RSA key
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

// Generate new Elliptic Curve Key
func GenerateElliptic() (KeyHandler, error) {
	eccKey, err := key.GenerateECC()
	if err != nil {
		return Key{}, err
	}

	k := Key{
		Elliptic: eccKey,
		keyType:  Elliptic,
	}

	return k, nil
}

// VerifyUsingPem - Verify a given signature using a given public key PEM
func VerifyUsingPem(sig []byte, checksum []byte, pubPem string, keyType KeyType) (bool, error) {

	switch keyType {
	case RSA:
		return key.VerifyUsingRSAPem(sig, checksum, pubPem)

	case Elliptic:
		return key.VerifyUsingECCPem(sig, checksum, pubPem)

	default:
		return false, ErrUnknownKey
	}
}

// Sign a byte slice, returns the signature and checksum hash
func (k Key) Sign(data []byte) (Signature []byte, Hash []byte, SignError error) {

	switch k.keyType {
	case RSA:
		return k.RSA.Sign(data)

	case Elliptic:
		return k.Elliptic.Sign(data)

	default:
		return []byte{}, []byte{}, ErrUnknownKey
	}

}

// Verify a signature with a given checksum
func (k Key) Verify(signature []byte, checksum []byte) (bool, error) {

	switch k.keyType {
	case RSA:
		return k.RSA.Verify(signature, checksum)

	case Elliptic:
		return k.Elliptic.Verify(signature, checksum), nil

	default:
		return false, ErrUnknownKey
	}
}

func (k Key) GetType() KeyType {
	return k.keyType
}

func (k Key) GetRSAKey() *rsa.PrivateKey {
	return k.RSA.GetKey()
}

func (k Key) GetEllipticKey() *ecdsa.PrivateKey {
	return k.Elliptic.GetKey()
}

func (k Key) GetPrivatePEM() string {
	var pem string
	if k.keyType == RSA {
		pem = k.RSA.GetPrivatePEM()
	} else {
		return k.Elliptic.GetPrivatePEM()
	}

	return pem
}

func (k Key) GetPublicPEM() string {
	if k.keyType == RSA {
		return k.RSA.GetPublicPEM()
	} else {
		return k.Elliptic.GetPublicPEM()
	}
}

func SetKey(pem string, keyType KeyType) (KeyHandler, error) {
	k := Key{}

	switch keyType {
	case RSA:
		key, err := key.SetRSAKey(pem)
		if err != nil {
			return Key{}, err
		}

		k.RSA = key
		k.keyType = RSA

		return k, nil

	case Elliptic:
		key, err := key.SetECCKey(pem)
		if err != nil {
			return Key{}, err
		}

		k.Elliptic = key
		k.keyType = Elliptic

		return k, nil

	default:
		return Key{}, ErrUnknownKey
	}
}
