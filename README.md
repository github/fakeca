# fakeca [![GoDoc](https://godoc.org/github.com/github/fakeca?status.svg)](http://godoc.org/github.com/github/fakeca) [![Report card](https://goreportcard.com/badge/github.com/github/fakeca)](https://goreportcard.com/report/github.com/github/fakeca) [![Travis CI](https://travis-ci.org/github/fakeca.svg?branch=main)](https://travis-ci.org/github/fakeca)

This is a package for creating fake certificate authorities for test fixtures.

## Example

```go
package main

import (
	"crypto/x509/pkix"

	"github.com/github/fakeca"
)

func main() {
	// Change defaults for cert subjects.
	fakeca.DefaultProvince = []string{"CO"}
	fakeca.DefaultLocality = []string{"Denver"}

	// Create a root CA.
	root := fakeca.New(fakeca.IsCA, fakeca.Subject(pkix.Name{
		CommonName: "root.myorg.com",
	}))

	// Create an intermediate CA under the root.
	intermediate := root.Issue(fakeca.IsCA, fakeca.Subject(pkix.Name{
		CommonName: "intermediate.myorg.com",
	}))

	// Create a leaf certificate under the intermediate.
	leaf := intermediate.Issue(fakeca.Subject(pkix.Name{
		CommonName: "leaf.myorg.com",
	}))

	// Get PFX (PKCS12) blob containing certificate and encrypted private key.
	leafPFX := leaf.PFX("pa55w0rd")

	// Get an *x509.CertPool containing certificate chain from CA to leaf for use
	// with Go's TLS libraries.
	leafPool := leaf.ChainPool()
}

```
