package sdk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

func RsaKeyGen() *rsa.PrivateKey{
	reader:= rand.Reader
	bitSize:=2048
	key, err:=rsa.GenerateKey(reader, bitSize)
	checkError(err)
	return key
}

func  RsaSign(r rsa.PrivateKey,data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)

	return r.Sign(rand.Reader,d,crypto.SHA256)
}

func RsaToPem(pubkey rsa.PublicKey) (string) {
	
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(&pubkey)
    checkError(err)
    pubkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "PUBLIC KEY",
                    Bytes: pubkey_bytes,
            },
    )

    return string(pubkey_pem)
}