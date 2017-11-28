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

type configuration struct {
	subject *pkix.Name
	issuer  *Identity
	nextSN  *int64
	priv    *crypto.Signer
	isCA    bool
}

func (c *configuration) generate() *Identity {
	templ := &x509.Certificate{
		Subject: c.getSubject(),
		IsCA:    c.isCA,
		BasicConstraintsValid: true,
	}

	var parent *x509.Certificate
	if c.issuer != nil {
		parent = c.issuer.Certificate
		templ.SerialNumber = big.NewInt(c.issuer.IncrementSN())
	} else {
		parent = templ
		templ.SerialNumber = randSN()
	}

	priv := c.getPrivateKey()
	der, err := x509.CreateCertificate(rand.Reader, templ, parent, priv.Public(), priv)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return &Identity{
		Certificate: cert,
		PrivateKey:  priv,
		Issuer:      c.issuer,
		NextSN:      c.getNextSN(),
	}
}

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

	cnCounter int64
)

func (c *configuration) getSubject() pkix.Name {
	if c.subject != nil {
		return *c.subject
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

func (c *configuration) getNextSN() int64 {
	if c.nextSN == nil {
		sn := randSN().Int64()
		c.nextSN = &sn
	}

	return *c.nextSN
}

func randSN() *big.Int {
	i, err := rand.Int(rand.Reader, big.NewInt(int64(math.MaxInt64)))
	if err != nil {
		panic(err)
	}

	return i
}

func (c *configuration) getPrivateKey() crypto.Signer {
	if c.priv == nil {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}

		signer := crypto.Signer(priv)

		c.priv = &signer
	}

	return *c.priv
}

// Option is an option that can be passed to New().
type Option option
type option func(c *configuration)

// Subject is an Option that sets a CA's subject field.
func Subject(value pkix.Name) Option {
	return func(c *configuration) {
		c.subject = &value
	}
}

// NextSerialNumber is an Option that determines the SN of the next issued
// certificate.
func NextSerialNumber(value int64) Option {
	return func(c *configuration) {
		c.nextSN = &value
	}
}

// PrivateKey is an Option for setting the CA's private key.
func PrivateKey(value crypto.Signer) Option {
	return func(c *configuration) {
		c.priv = &value
	}
}

// Issuer is an Option for setting the CA's issuer.
func Issuer(value *Identity) Option {
	return func(c *configuration) {
		c.issuer = value
	}
}

// IsCA is an Option for making a CA a certificate authority.
var IsCA Option = func(c *configuration) {
	c.isCA = true
}
