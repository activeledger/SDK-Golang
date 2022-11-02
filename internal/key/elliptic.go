package key

// ! TODO: Implement and test based on this package: https://github.com/dustinxie/ecc

/* type EllipticHandler interface {
	Sign(Data []byte) (r, s *big.Int, SigningError error)
	Verify(Checksum []byte, r *big.Int, s *big.Int) bool
	GetPublicPEM() string
	GetPrivatePEM() string
	GetKey() *secp256k1.PrivateKey
}

type Elliptic struct {
	PrivateKey *secp256k1.PrivateKey
	PrivatePEM string
	PublicPEM  string
}

func Generate() (EllipticHandler, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return Elliptic{}, err
	}

	e := Elliptic{
		PrivateKey: k,
	}

	return e, nil
}

func (e Elliptic) Sign(d []byte) (r, s *big.Int, err error) {
	hash := sha256.New()
	hash.Write(d)
	digest := hash.Sum(nil)

	r, s, err = ecdsa.Sign(rand.Reader, e.PrivateKey, digest)
}

func (e Elliptic) Verify(checksum []byte, r *big.Int, s *big.Int) bool {
	return false
}

func (e Elliptic) GetPublicPEM() string {
	return ""
}

func (e Elliptic) GetPrivatePEM() string {
	return ""
}

func (e Elliptic) GetKey() *secp256k1.PrivateKey {
	return e.PrivateKey
} */
