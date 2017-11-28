package fakeca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"testing"
)

func TestDefaults(t *testing.T) {
	assertNoPanic(t, func() {
		New()
	})
}

func TestIntermediate(t *testing.T) {
	assertNoPanic(t, func() {
		New().Intermediate()
	})
}

func TestSubject(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			expected = "foobar"
			root     = New(Subject(pkix.Name{CommonName: expected}))
			actual   = root.GetCertificate().Subject.CommonName
		)

		if actual != expected {
			t.Fatalf("bad subject. expected '%s', got '%s'", expected, actual)
		}
	})
}

func TestNextSerialNumber(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			expected = int64(123)
			ca       = New(NextSerialNumber(expected)).Intermediate()
			actual   = ca.GetCertificate().SerialNumber.Int64()
		)

		if actual != expected {
			t.Fatalf("bad sn. expected '%d', got '%d'", expected, actual)
		}
	})
}

func TestPrivateKey(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			expected, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ca          = New(PrivateKey(expected))
			actual      = ca.GetPrivateKey().(*ecdsa.PrivateKey)
		)

		if actual.D.Cmp(expected.D) != 0 {
			t.Fatalf("bad D. expected '%s', got '%s'", expected.D.String(), actual.D.String())
		}

		if actual.X.Cmp(expected.X) != 0 {
			t.Fatalf("bad X. expected '%s', got '%s'", expected.X.String(), actual.X.String())
		}

		if actual.Y.Cmp(expected.Y) != 0 {
			t.Fatalf("bad Y. expected '%s', got '%s'", expected.Y.String(), actual.Y.String())
		}
	})
}

func TestIssuer(t *testing.T) {
	assertNoPanic(t, func() {
		var (
			root  = New()
			inter = New(Issuer(root))

			expected = root.GetCertificate().RawSubject
			actual   = inter.GetCertificate().RawIssuer
		)

		if !bytes.Equal(actual, expected) {
			t.Fatalf("bad issuer. expected '%s', got '%s'", string(expected), string(actual))
		}
	})
}

func assertNoPanic(t *testing.T, cb func()) {
	t.Helper()

	defer func() {
		if r := recover(); r != nil {
			t.Fatal(r)
		}
	}()

	cb()
}
