package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/activeledger/SDK-Golang/v2/internal/alerror"
	"github.com/dustinxie/ecc"
)

var oid = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

type EllipticHandler interface {
	Sign(Data []byte) (Signature []byte, Hash []byte, SignError error)
	Verify(Signature []byte, Checksum []byte) (Verified bool)
	GetPublicPEM() string
	GetPrivatePEM() string
	GetKey() *ecdsa.PrivateKey
}

type ECCKey struct {
	PrivateKey *ecdsa.PrivateKey
	PublicPEM  string
	PrivatePEM string
}

type ecPrivate struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

var (
	ErrVerify            alerror.ALSDKError = *alerror.NewAlError("error verifying signature")
	ErrUnMarshalEC       alerror.ALSDKError = *alerror.NewAlError("failed to parse private key")
	ErrUnknownVersion    alerror.ALSDKError = *alerror.NewAlError("unknown EC private key version")
	ErrInvalidCurveValue alerror.ALSDKError = *alerror.NewAlError("invalid elliptic curve value")
	ErrInvalidKeyLength  alerror.ALSDKError = *alerror.NewAlError("invalid key length")
)

func GenerateECC() (ECCKey, error) {
	p256k1 := ecc.P256k1()
	privKey, err := ecdsa.GenerateKey(p256k1, rand.Reader)
	if err != nil {
		return ECCKey{}, err
	}

	publicPem, err := publicToPemECC(&privKey.PublicKey)
	if err != nil {
		return ECCKey{}, err
	}

	privatePem, err := privateToPemECC(privKey)
	if err != nil {
		return ECCKey{}, err
	}

	k := ECCKey{
		PrivateKey: privKey,
		PublicPEM:  publicPem,
		PrivatePEM: privatePem,
	}

	return k, nil
}

func SetECCKey(privatePEM string) (EllipticHandler, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil, errors.New("key not found")
	}

	var privKey ecPrivate
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return ECCKey{}, ErrUnMarshalEC.SetError(err)
	}

	if privKey.Version != 1 {
		return nil, &ErrUnknownVersion
	}

	curve := ecc.P256k1()

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return ECCKey{}, &ErrInvalidCurveValue
	}

	key := new(ecdsa.PrivateKey)
	key.Curve = curve
	key.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return ECCKey{}, &ErrInvalidKeyLength
		}

		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)

	key.X, key.Y = curve.ScalarBaseMult(privateKey)

	publicPem, err := publicToPemECC(&key.PublicKey)
	if err != nil {
		return ECCKey{}, err
	}

	privatePem, err := privateToPemECC(key)
	if err != nil {
		return ECCKey{}, err
	}

	eKey := ECCKey{
		PrivateKey: key,
		PublicPEM:  publicPem,
		PrivatePEM: privatePem,
	}

	return eKey, nil

}

func (e ECCKey) Sign(d []byte) (Signature []byte, Hash []byte, SignError error) {
	h := sha256.New()
	h.Write(d)
	digest := h.Sum(nil)

	sig, err := ecc.SignBytes(e.PrivateKey, digest[:], ecc.Normal)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	verified := e.Verify(sig, digest)

	if !verified {
		return []byte{}, []byte{}, &ErrVerify
	}

	return sig, digest, nil

}

func VerifyUsingECCPem(signature []byte, checksum []byte, pubPem string) (bool, error) {

	block, _ := pem.Decode([]byte(pubPem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return false, fmt.Errorf("could not decode PEM, block type %s", block.Type)
	}

	var kAlgo pkix.AlgorithmIdentifier
	kAlgo.Algorithm = oid

	var paramBytes []byte
	paramBytes, err := asn1.Marshal(oid)
	if err != nil {
		return false, err
	}

	var pkixKey = pkixPublicKey{}
	if _, err := asn1.UnmarshalWithParams(block.Bytes, &pkixKey, string(paramBytes)); err != nil {
		return false, err
	}

	var pubKey = ecdsa.PublicKey{
		Curve: ecc.P256k1(),
	}

	pubKey.X, pubKey.Y = elliptic.Unmarshal(ecc.P256k1(), pkixKey.BitString.Bytes)

	return ecc.VerifyBytes(&pubKey, checksum[:], signature, ecc.Normal), nil
}

func (e ECCKey) Verify(signature []byte, checksum []byte) bool {
	return ecc.VerifyBytes(&e.PrivateKey.PublicKey, checksum[:], signature, ecc.Normal)
}

func (e ECCKey) GetPublicPEM() string {
	return e.PublicPEM
}

func (e ECCKey) GetPrivatePEM() string {
	return e.PrivatePEM
}

func (e ECCKey) GetKey() *ecdsa.PrivateKey {
	return e.PrivateKey
}

func privateToPemECC(k *ecdsa.PrivateKey) (string, error) {

	privateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
	pBytes, err := asn1.Marshal(ecPrivate{
		Version:       1,
		PrivateKey:    k.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
	})

	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: pBytes,
		},
	)), err

}

func publicToPemECC(k *ecdsa.PublicKey) (string, error) {

	var kAlgo pkix.AlgorithmIdentifier

	kBytes := elliptic.Marshal(k.Curve, k.X, k.Y)

	kAlgo.Algorithm = oid

	var paramBytes []byte
	paramBytes, err := asn1.Marshal(oid)
	if err != nil {
		return "", err
	}

	kAlgo.Parameters.FullBytes = paramBytes

	pBytes, _ := asn1.Marshal(pkixPublicKey{
		Algo: kAlgo,
		BitString: asn1.BitString{
			Bytes:     kBytes,
			BitLength: 8 * len(kBytes),
		},
	})

	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pBytes,
		},
	)), nil
}
