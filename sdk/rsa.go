/*
 * MIT License (MIT)
 * Copyright (c) 2018
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package sdk

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

/*
  Generate a pair of RSA private and public key.
  Output: Private key object.
  Public key can be extracted using
  publicKey:=key.PublicKey
*/
func RsaKeyGen() *rsa.PrivateKey {
	reader := rand.Reader
	bitSize := 2048
	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)
	RSAKey = key
	KeyType = Encrptype[RSA]
	return key
}

/*
Sign a transaction using your private key. Data is hashed using SHA256 before signing.
Input: Private Key,Transaction byte array
Output: Signature byte Array
*/
func RsaSign(r rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)

	return r.Sign(rand.Reader, d, crypto.SHA256)
}

/*
Convertying your public key into pem format. This is necessary when sending public key in a transaction.
Input: Public Key
Output: Pem formated public key
*/
func RsaToPem(pubkey rsa.PublicKey) string {

	pubkey_bytes, err := x509.MarshalPKIXPublicKey(&pubkey)
	checkError(err)
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)
	// asn1Bytes, err := asn1.Marshal(pubkey)
	// checkError(err)

	// var pemkey = &pem.Block{
	// 	Type:  "PUBLIC KEY",
	// 	Bytes: asn1Bytes,
	// }

	// Create Public Key ASN
	// asnPub, _ := asn1.Marshal(pkixPublicKey{
	// 	Algo: AlgorithmIdentifier{
	// 		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
	// 	},
	// 	BitString: asn1.BitString{
	// 		Bytes:     asn1Bytes,
	// 		BitLength: 8 * len(asn1Bytes),
	// 	},
	// })

	// Get Public Key PEM
	//pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: asnPub})

	return string(pubkey_pem)
}

func RsaPrivToPem(pubkey rsa.PrivateKey) string {
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(&pubkey)})
	return string(privkey_pem)
}
