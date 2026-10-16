package x509facts

import (
	"crypto/x509"
	"testing"
)

// TestParserPanicIsContained proves the recovery boundary around the
// standard-library parsers: a panic becomes an unparseable certificate with
// a stable message and the ParserPanicked diagnostic, so it is never silent.
func TestParserPanicIsContained(t *testing.T) {
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x00}

	t.Run("certificate parser", func(t *testing.T) {
		original := parseCertificate
		t.Cleanup(func() { parseCertificate = original })
		parseCertificate = func([]byte) (*x509.Certificate, error) { panic("parser exploded") }

		p := FromDER(der)
		if p.Kind != KindUnparseable || !p.ParserPanicked || p.Unparseable.ParseError != parserPanicMessage {
			t.Errorf("got kind %s panicked %v (%+v)", p.Kind, p.ParserPanicked, p.Unparseable)
		}
	})

	t.Run("certificate request parser", func(t *testing.T) {
		original := parseCertificateRequest
		t.Cleanup(func() { parseCertificateRequest = original })
		parseCertificateRequest = func([]byte) (*x509.CertificateRequest, error) { panic("parser exploded") }

		p := FromDER(der)
		if p.Kind != KindUnparseable || !p.ParserPanicked {
			t.Errorf("got kind %s panicked %v", p.Kind, p.ParserPanicked)
		}
	})

	t.Run("request-framed block", func(t *testing.T) {
		original := parseCertificateRequest
		t.Cleanup(func() { parseCertificateRequest = original })
		parseCertificateRequest = func([]byte) (*x509.CertificateRequest, error) { panic("parser exploded") }

		p := FromRequestDER(der)
		if p.Kind != KindUnparseableRequest || !p.ParserPanicked || p.UnparseableRequest.ParseError != parserPanicMessage {
			t.Errorf("got kind %s panicked %v (%+v)", p.Kind, p.ParserPanicked, p.UnparseableRequest)
		}
	})

	t.Run("no panic, no flag", func(t *testing.T) {
		if p := FromDER(der); p.ParserPanicked {
			t.Error("ParserPanicked set without a panic")
		}
	})
}
