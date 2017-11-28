package fakeca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
)

var (
	// DefaultCountry is the default subject Country.
	DefaultCountry = []string{"US"}

	// DefaultProvince is the default subject Province.
	DefaultProvince = []string{"CA"}

	// DefaultLocality is the default subject Locality.
	DefaultLocality = []string{"San Francisco"}

	// DefaultStreetAddress is the default subject StreetAddress.
	DefaultStreetAddress = []string(nil)

	// DefaultPostalCode is the default subject PostalCode.
	DefaultPostalCode = []string(nil)

	// DefaultCommonName is the default subject CommonName.
	DefaultCommonName = "fakeca"
)

// CA represents a CertificateAuthority.
type CA struct {
	// options
	subject *pkix.Name
	issuer  *CA
	nextSN  *int64
	priv    *crypto.Signer

	// generated fields
	cert *x509.Certificate
}

// New creates a new CA.
func New(opts ...Option) *CA {
	ca := &CA{}

	for _, opt := range opts {
		option(opt)(ca)
	}

	if err := ca.generate(); err != nil {
		panic(err)
	}

	return ca
}

func (ca *CA) generate() error {
	templ := &x509.Certificate{
		Subject: ca.getSubject(),
		IsCA:    true,
	}

	var parent *x509.Certificate
	if ca.issuer != nil {
		parent = ca.issuer.cert
		templ.SerialNumber = big.NewInt(ca.issuer.getNextSN())
	} else {
		parent = templ
		sn, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
		if err != nil {
			return err
		}
		templ.SerialNumber = sn
	}

	der, err := x509.CreateCertificate(rand.Reader, templ, parent, ca.GetPublicKey(), ca.GetPrivateKey())
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	ca.cert = cert

	return nil
}

var cnCounter int64

func (ca *CA) getSubject() pkix.Name {
	if ca.subject != nil {
		return *ca.subject
	}

	var cn string
	if cnCounter == 0 {
		cn = DefaultCommonName
	} else {
		cn = fmt.Sprintf("%s #%d", DefaultCommonName, cnCounter)
	}
	cnCounter++

	return pkix.Name{
		Country:       DefaultCountry,
		Province:      DefaultProvince,
		Locality:      DefaultLocality,
		StreetAddress: DefaultStreetAddress,
		PostalCode:    DefaultPostalCode,
		CommonName:    cn,
	}
}

func (ca *CA) getNextSN() int64 {
	if ca.nextSN == nil {
		one := int64(1)
		ca.nextSN = &one
	}

	defer func() {
		*ca.nextSN++
	}()

	return *ca.nextSN
}

// GetCertificate gets the CA's certificate.
func (ca *CA) GetCertificate() *x509.Certificate {
	return ca.cert
}

// GetPrivateKey gets the CA's private key.
func (ca *CA) GetPrivateKey() crypto.Signer {
	if ca.priv == nil {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		signer := crypto.Signer(priv)

		ca.priv = &signer
	}

	return *ca.priv
}

// GetPublicKey gets the CA's public key.
func (ca *CA) GetPublicKey() crypto.PublicKey {
	return ca.GetPrivateKey().Public()
}

// GetChain builds an *x509.CertPool from this CA and its issuers.
func (ca *CA) GetChain() *x509.CertPool {
	chain := x509.NewCertPool()
	for thisCA := ca; thisCA != nil; thisCA = thisCA.issuer {
		chain.AddCert(thisCA.GetCertificate())
	}

	return chain
}

// Intermediate creates a new intermediate CA with this CA as its issuer.
func (ca *CA) Intermediate(opts ...Option) *CA {
	opts = append(opts, Issuer(ca))
	return New(opts...)
}

// Option is an option that can be passed to New().
type Option option
type option func(ca *CA)

// Subject is an Option that sets a CA's subject field.
func Subject(value pkix.Name) Option {
	return func(ca *CA) {
		ca.subject = &value
	}
}

// NextSerialNumber is an Option that determines the SN of the next issued
// certificate.
func NextSerialNumber(value int64) Option {
	return func(ca *CA) {
		ca.nextSN = &value
	}
}

// PrivateKey is an Option for setting the CA's private key.
func PrivateKey(value crypto.Signer) Option {
	return func(ca *CA) {
		ca.priv = &value
	}
}

// Issuer is an Option for setting the CA's issuer.
func Issuer(value *CA) Option {
	return func(ca *CA) {
		ca.issuer = value
	}
}
