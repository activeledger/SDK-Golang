package sdk

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	b64 "encoding/base64"
	"encoding/pem"
	"math/big"
	"github.com/titanous/bitcoin-crypto/bitecdsa"
	"github.com/titanous/bitcoin-crypto/bitelliptic"
)

// Private Key PEM Struct
type ecPrivateKey struct {
	Version int
	PrivateKey
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// Public Key PEM Struct
type pkixPublicKey struct {
	Algo      AlgorithmIdentifier
	BitString asn1.BitString
}

// Algorithm Struct
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// Private Key points struct
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// Public Key points struct
type PublicKey struct {
	X, Y *big.Int
}

// Wrapper for key generation
func EcdsaKeyGen() (priv *bitecdsa.PrivateKey, err error) {
	return bitecdsa.GenerateKey(bitelliptic.S256(), rand.Reader)
}

// Sign Wrapper exports signature as comptible activeledger string
func EcdsaSign(prv *bitecdsa.PrivateKey, data string) string {
	// Convert Data into byte array
	dataArray := []byte(data)

	// Hash data
	h256 := sha256.New()
	h256.Write(dataArray)
	dataHash := h256.Sum(nil)

	// bitecdsa Sign
	r, s, _ := bitecdsa.Sign(rand.Reader, prv, dataHash)

	// Convert to DER & return as b64 string
	return b64.StdEncoding.EncodeToString(pointsToDER(r, s))
}

// Convert Private key object into PCKS1 PEM Private & Public
func EcdsaToPem(prv *bitecdsa.PrivateKey) (string, string) {

	// Marshel Public key points to array
	publicKeyBytes := prv.PublicKey.Marshal(prv.PublicKey.X, prv.PublicKey.Y)

	// Create Private Key ASN
	asnPrv, _ := asn1.Marshal(ecPrivateKey{
		Version: 1,
		PrivateKey: PrivateKey{
			D: prv.D,
			PublicKey: PublicKey{
				X: prv.PublicKey.X,
				Y: prv.PublicKey.Y,
			},
		},
		NamedCurveOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
		PublicKey:     asn1.BitString{Bytes: publicKeyBytes},
	})

	// Get Private Key PEM
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: asnPrv})

	// Create Public Key ASN
	asnPub, _ := asn1.Marshal(pkixPublicKey{
		Algo: AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
		},
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	})

	// Get Public Key PEM
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: asnPub})

	// Return PEMs
	return string(pemEncoded), string(pemEncodedPub)
}

// Convery PEM to Private Public key object
func EcdsaFromPem(pemEncoded string) *bitecdsa.PrivateKey {

	// Decode PEM
	block, _ := pem.Decode([]byte(pemEncoded))

	// Ready the object created from the pem
	pemObject := new(ecPrivateKey)

	// Unmarshel pem blocks to object
	asn1.Unmarshal(block.Bytes, pemObject)

	// Create bitecdsa private key object
	privateKey := new(bitecdsa.PrivateKey)
	privateKey.PublicKey.BitCurve = bitelliptic.S256()
	privateKey.D = pemObject.PrivateKey.D
	privateKey.PublicKey.X = pemObject.PrivateKey.PublicKey.X
	privateKey.PublicKey.Y = pemObject.PrivateKey.PublicKey.Y

	return privateKey
}

// Convert an ECDSA signature (points R and S) to a byte array using ASN.1 DER encoding.
// This is a port of Bitcore's Key.rs2DER method.
// Author : https://github.com/codelittinc/gobitauth/blob/master/sign.go
func pointsToDER(r, s *big.Int) []byte {
	// Ensure MSB doesn't break big endian encoding in DER sigs
	prefixPoint := func(b []byte) []byte {
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			paddedBytes := make([]byte, len(b)+1)
			copy(paddedBytes[1:], b)
			b = paddedBytes
		}
		return b
	}

	rb := prefixPoint(r.Bytes())
	sb := prefixPoint(s.Bytes())

	// DER encoding:
	// 0x30 + z + 0x02 + len(rb) + rb + 0x02 + len(sb) + sb
	length := 2 + len(rb) + 2 + len(sb)

	der := append([]byte{0x30, byte(length), 0x02, byte(len(rb))}, rb...)
	der = append(der, 0x02, byte(len(sb)))
	der = append(der, sb...)

	return der
}
