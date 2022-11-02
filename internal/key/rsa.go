package key

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type RSAHandler interface {
	Sign(Data []byte) (Signature []byte, Hash []byte, SignError error)
	Verify(Signature []byte, Checksum []byte) (bool, error)
	GetPublicPEM() string
	GetPrivatePEM() string
	GetKey() *rsa.PrivateKey
}

type RSAKey struct {
	PrivateKey *rsa.PrivateKey
	PublicPEM  string
	PrivatePEM string
}

const (
	bitSize = 2048
)

func GenerateRSA() (RSAHandler, error) {
	key := RSAKey{}

	reader := rand.Reader

	k, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return RSAKey{}, err
	}

	publicPem, err := publicToPem(k)
	if err != nil {
		return RSAKey{}, err
	}

	privatePem := privateToPem(k)

	key.PrivateKey = k
	key.PublicPEM = publicPem
	key.PrivatePEM = privatePem

	return key, nil
}

// SetRSAKey - Set the private key by converting its PEM
func SetRSAKey(privatePEM string) (RSAHandler, error) {

	// k.PrivatePEM = privatePEM

	block, _ := pem.Decode([]byte(privatePEM))

	if block == nil {
		return RSAKey{}, errors.New("failed to decode pem to private key")
	}

	p, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return RSAKey{}, fmt.Errorf("parsing block data failed during private pem decode: %v", err)
	}

	pubPem, err := publicToPem(p)
	if err != nil {
		return RSAKey{}, fmt.Errorf("encoding public key to pem failed: %v", err)
	}

	var k RSAHandler = RSAKey{
		PrivateKey: p,
		PublicPEM:  pubPem,
		PrivatePEM: privatePEM,
	}

	// log.Println(k.GetPrivatePEM())

	return k, nil
}

// GetKey - Return the private key
func (r RSAKey) GetKey() *rsa.PrivateKey {
	return r.PrivateKey
}

// Sign - Sign data using the set key
func (r RSAKey) Sign(d []byte) (Signature []byte, Hash []byte, SignError error) {
	h := sha256.New()
	h.Write(d)
	digest := h.Sum(nil)

	signature, err := r.PrivateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return []byte{}, []byte{}, err
	}

	_, err = r.Verify(signature, digest)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("signature verification failed: %v", err)
	}

	return signature, digest, nil
}

// Verify - Verify a signature
func (r RSAKey) Verify(signature []byte, checksum []byte) (bool, error) {
	if err := rsa.VerifyPKCS1v15(&r.PrivateKey.PublicKey, crypto.SHA256, checksum, signature); err != nil {
		return false, err
	}
	/* if err := rsa.VerifyPSS(&r.PrivateKey.PublicKey, crypto.SHA256, checksum, signature, nil); err != nil {
		return false, err
	} */

	return true, nil
}

// GetPrivatePEM - Return the PEM of the private key
func (r RSAKey) GetPrivatePEM() string {
	return r.PrivatePEM
}

// GetPublicPEM - Return the PEM of the public key
func (r RSAKey) GetPublicPEM() string {
	return r.PublicPEM
}

func publicToPem(k *rsa.PrivateKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", err
	}

	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		},
	)

	return string(pubKeyPem), nil
}

func privateToPem(k *rsa.PrivateKey) string {
	bytes := x509.MarshalPKCS1PrivateKey(k)

	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: bytes,
		},
	)

	return string(pem)
}
