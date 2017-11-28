package fakeca

import (
	"crypto"
	"crypto/x509"
)

// Identity is a certificate and private key.
type Identity struct {
	Issuer      *Identity
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	NextSN      int64
}

// New creates a new CA.
func New(opts ...Option) *Identity {
	c := &configuration{}

	for _, opt := range opts {
		option(opt)(c)
	}

	return c.generate()
}

// Issue issues a new Identity with this one as its parent.
func (id *Identity) Issue(opts ...Option) *Identity {
	opts = append(opts, Issuer(id))
	return New(opts...)
}

// Chain builds a slice of *x509.Certificate from this CA and its issuers.
func (id *Identity) Chain() []*x509.Certificate {
	chain := []*x509.Certificate{}
	for this := id; this != nil; this = this.Issuer {
		chain = append(chain, this.Certificate)
	}

	return chain
}

// ChainPool builds an *x509.CertPool from this CA and its issuers.
func (id *Identity) ChainPool() *x509.CertPool {
	chain := x509.NewCertPool()
	for this := id; this != nil; this = this.Issuer {
		chain.AddCert(this.Certificate)
	}

	return chain
}

// IncrementSN returns the next serial number.
func (id *Identity) IncrementSN() int64 {
	defer func() {
		id.NextSN++
	}()

	return id.NextSN
}
