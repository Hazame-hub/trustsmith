package purpose_test

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/purpose"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
)

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// leaf issues a certificate with the given extended key usage and key usage
// (0 omits the key usage extension; nil omits extended key usage).
func leaf(t *testing.T, eku []x509.ExtKeyUsage, ku x509.KeyUsage) *x509.Certificate {
	t.Helper()
	return testpki.Issue(t, testpki.Template{
		CommonName: "subject.example.test", Serial: 2, NotBefore: date(2026, 9, 1), NotAfter: date(2027, 9, 1),
		DNSNames: []string{"subject.example.test"}, KeyUsage: ku, ExtKeyUsage: eku,
	}, testpki.ECDSAKey(t), nil).Cert
}

func TestParseIsExact(t *testing.T) {
	for _, p := range purpose.All() {
		got, err := purpose.Parse(string(p))
		if err != nil || got != p {
			t.Errorf("Parse(%q) = %q, %v", p, got, err)
		}
	}
	for _, s := range []string{"", "banana", "TLS-Server", "tls_server", "server", "tls-server ", "ocsp-signing"} {
		if _, err := purpose.Parse(s); err == nil {
			t.Errorf("Parse(%q) must fail: purposes have no aliases", s)
		}
	}
}

func TestExtKeyUsageMapping(t *testing.T) {
	for p, want := range map[purpose.Purpose]x509.ExtKeyUsage{
		purpose.Any:         x509.ExtKeyUsageAny,
		purpose.TLSServer:   x509.ExtKeyUsageServerAuth,
		purpose.TLSClient:   x509.ExtKeyUsageClientAuth,
		purpose.CodeSigning: x509.ExtKeyUsageCodeSigning,
		purpose.Email:       x509.ExtKeyUsageEmailProtection,
	} {
		if got, ok := p.ExtKeyUsage(); !ok || got != want {
			t.Errorf("%s maps to %v", p, got)
		}
	}
	if _, ok := purpose.Purpose("banana").ExtKeyUsage(); ok {
		t.Error("an unknown purpose has no extended key usage")
	}
	if len(purpose.All()) != 5 {
		t.Errorf("supported purposes changed: %v", purpose.All())
	}
}

// Any asserts no application purpose, so nothing is evaluated.
func TestAnyIsNotEvaluated(t *testing.T) {
	r := purpose.Evaluate(leaf(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, x509.KeyUsageCertSign), purpose.Any)
	if r.State != purpose.NotEvaluated || len(r.Reasons) != 0 {
		t.Errorf("%+v", r)
	}
}

type evaluation struct {
	name    string
	eku     []x509.ExtKeyUsage
	ku      x509.KeyUsage
	purpose purpose.Purpose
	state   purpose.State
	reasons []purpose.Reason
}

func runEvaluations(t *testing.T, cases []evaluation) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := purpose.Evaluate(leaf(t, tc.eku, tc.ku), tc.purpose)
			want := tc.reasons
			if want == nil {
				want = []purpose.Reason{}
			}
			if r.State != tc.state || !slices.Equal(r.Reasons, want) {
				t.Errorf("%s/%v, want %s/%v (eku %v, ku %v)", r.State, r.Reasons, tc.state, want, r.ExtKeyUsages, r.KeyUsages)
			}
		})
	}
}

var (
	server = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	client = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	sig    = x509.KeyUsageDigitalSignature
	eku    = []purpose.Reason{purpose.ReasonExtKeyUsage}
	ku     = []purpose.Reason{purpose.ReasonKeyUsage}
)

// Tests 3 to 11: extended key usage semantics.
func TestExtendedKeyUsage(t *testing.T) {
	runEvaluations(t, []evaluation{
		{"3 server auth for tls-server", server, sig, purpose.TLSServer, purpose.Suitable, nil},
		{"4 client auth only for tls-server", client, sig, purpose.TLSServer, purpose.Unsuitable, eku},
		{"5 client auth for tls-client", client, sig, purpose.TLSClient, purpose.Suitable, nil},
		{"6 server auth only for tls-client", server, sig, purpose.TLSClient, purpose.Unsuitable, eku},
		{"7 code signing for code-signing", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, sig, purpose.CodeSigning, purpose.Suitable, nil},
		{"8 server auth only for code-signing", server, sig, purpose.CodeSigning, purpose.Unsuitable, eku},
		{"9 email protection for email", []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, sig, purpose.Email, purpose.Suitable, nil},
		{"both usages listed", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, sig, purpose.TLSClient, purpose.Suitable, nil},
		// 10. No extended key usage extension: no restriction (RFC 5280 4.2.1.12).
		{"10 no EKU for tls-server", nil, sig, purpose.TLSServer, purpose.Suitable, nil},
		{"10 no EKU for code-signing", nil, sig, purpose.CodeSigning, purpose.Suitable, nil},
		{"10 no EKU for email", nil, sig, purpose.Email, purpose.Suitable, nil},
		// 11. anyExtendedKeyUsage permits every purpose.
		{"11 any EKU for tls-server", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, sig, purpose.TLSServer, purpose.Suitable, nil},
		{"11 any EKU for code-signing", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, sig, purpose.CodeSigning, purpose.Suitable, nil},
	})
}

// Tests 12, 13: key usage semantics (RFC 5280 consistent bits, no cipher-suite
// policy).
func TestKeyUsage(t *testing.T) {
	runEvaluations(t, []evaluation{
		{"12 key usage absent", server, 0, purpose.TLSServer, purpose.Suitable, nil},
		{"key encipherment only is consistent with tls-server", server, x509.KeyUsageKeyEncipherment, purpose.TLSServer, purpose.Suitable, nil},
		{"key agreement only is consistent with tls-server", server, x509.KeyUsageKeyAgreement, purpose.TLSServer, purpose.Suitable, nil},
		{"13 certificate signing only for tls-server", server, x509.KeyUsageCertSign | x509.KeyUsageCRLSign, purpose.TLSServer, purpose.Unsuitable, ku},
		{"13 key encipherment only for code-signing", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, x509.KeyUsageKeyEncipherment, purpose.CodeSigning, purpose.Unsuitable, ku},
		{"13 key encipherment only for tls-client", client, x509.KeyUsageKeyEncipherment, purpose.TLSClient, purpose.Unsuitable, ku},
		{"content commitment only for email", []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, x509.KeyUsageContentCommitment, purpose.Email, purpose.Suitable, nil},
		{"both extensions disallow", client, x509.KeyUsageCertSign, purpose.TLSServer, purpose.Unsuitable, []purpose.Reason{purpose.ReasonExtKeyUsage, purpose.ReasonKeyUsage}},
	})
}

func TestResultFacts(t *testing.T) {
	r := purpose.Evaluate(leaf(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny}, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement), purpose.TLSServer)
	if !r.ExtKeyUsagePresent || !slices.Equal(r.ExtKeyUsages, []string{"client_auth", "any"}) ||
		!r.KeyUsagePresent || !slices.Equal(r.KeyUsages, []string{"digital_signature", "key_agreement"}) || r.CA {
		t.Errorf("facts %+v", r)
	}
	absent := purpose.Evaluate(leaf(t, nil, 0), purpose.TLSServer)
	if absent.ExtKeyUsagePresent || absent.KeyUsagePresent || absent.ExtKeyUsages == nil || absent.KeyUsages == nil {
		t.Errorf("absent extensions %+v", absent)
	}
	if got := purpose.TLSServer.ConsistentKeyUsages(); !slices.Equal(got, []string{"digital_signature", "key_encipherment", "key_agreement"}) {
		t.Errorf("tls-server consistent key usages %v", got)
	}
	if purpose.Email.ExtKeyUsageName() != "email_protection" {
		t.Errorf("email usage name %q", purpose.Email.ExtKeyUsageName())
	}
}

// A CA certificate is reported as such but RFC 5280 does not make it
// unsuitable on that ground alone.
func TestCARoleIsAFactNotAVerdict(t *testing.T) {
	ca := testpki.Issue(t, testpki.Template{
		CommonName: "CA", Serial: 1, NotBefore: date(2026, 1, 1), NotAfter: date(2031, 1, 1),
		IsCA: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}, testpki.ECDSAKey(t), nil).Cert
	r := purpose.Evaluate(ca, purpose.TLSServer)
	if r.State != purpose.Suitable || !r.CA {
		t.Errorf("%+v", r)
	}
}

func TestUnparsedOrUnknown(t *testing.T) {
	if r := purpose.Evaluate(nil, purpose.TLSServer); r.State != purpose.Unverifiable || !slices.Equal(r.Reasons, []purpose.Reason{purpose.ReasonNotParsed}) {
		t.Errorf("nil certificate %+v", r)
	}
	if r := purpose.Evaluate(leaf(t, server, sig), purpose.Purpose("banana")); r.State != purpose.Unverifiable || !slices.Equal(r.Reasons, []purpose.Reason{purpose.ReasonUnknownPurpose}) {
		t.Errorf("unknown purpose %+v", r)
	}
}
