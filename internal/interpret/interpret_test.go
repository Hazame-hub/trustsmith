package interpret_test

import (
	"crypto"
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
	"github.com/Hazame-hub/trustsmith/internal/testpki"
	"github.com/Hazame-hub/trustsmith/internal/x509facts"
)

var (
	notBefore = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	th        = interpret.DefaultThresholds()
)

func serverTemplate(cn string) testpki.Template {
	return testpki.Template{
		CommonName: cn, Serial: 2, NotBefore: notBefore, NotAfter: notAfter,
		DNSNames:    []string{cn},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

func caTemplate(cn string) testpki.Template {
	return testpki.Template{
		CommonName: cn, Serial: 1, NotBefore: notBefore, NotAfter: notAfter.AddDate(10, 0, 0),
		IsCA: true, MaxPathLen: -1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func parsed(t *testing.T, der []byte) *x509facts.Parsed {
	t.Helper()
	p := x509facts.FromDER(der)
	return &p
}

func certBlock(der []byte) artifact.Block {
	return artifact.Block{Entry: 0, Kind: artifact.KindCertificate, Label: "CERTIFICATE", DER: der}
}

// inspect interprets one certificate at now and checks every emitted code is
// catalogued.
func inspect(t *testing.T, der []byte, now time.Time) interpret.Entry {
	t.Helper()
	e := interpret.Block(certBlock(der), parsed(t, der), interpret.Issuers{}, now, th)
	assertCatalogued(t, e.Findings)
	return e
}

func assertCatalogued(t *testing.T, fs []findings.Finding) {
	t.Helper()
	for _, f := range fs {
		if _, ok := findings.Describe(f.Code); !ok {
			t.Errorf("emitted code %q is not in the catalog", f.Code)
		}
		if f.Severity == "" {
			t.Errorf("%s has no severity", f.Code)
		}
	}
}

// codes renders findings as "code:severity" for compact comparison.
func codes(fs []findings.Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, string(f.Code)+":"+string(f.Severity))
	}
	slices.Sort(out)
	return out
}

func assertCodes(t *testing.T, fs []findings.Finding, want ...string) {
	t.Helper()
	slices.Sort(want)
	if want == nil {
		want = []string{}
	}
	if got := codes(fs); !slices.Equal(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

func evidence(f findings.Finding, key string) string {
	for _, e := range f.Evidence {
		if e.Key == key {
			return e.Value
		}
	}
	return ""
}

func TestValidityBoundaries(t *testing.T) {
	ca := testpki.Issue(t, caTemplate("CA"), testpki.ECDSAKey(t), nil)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), ca)

	cases := []struct {
		name  string
		now   time.Time
		state interpret.ValidityState
		want  []string
	}{
		{"one second before notBefore", notBefore.Add(-time.Second), interpret.NotYetValid, []string{"cert.not_yet_valid:critical"}},
		{"exactly notBefore", notBefore, interpret.Valid, nil},
		{"midway", notBefore.AddDate(0, 0, 10), interpret.Valid, nil},
		{"exactly notAfter (still valid, expiring)", notAfter, interpret.Valid, []string{"cert.expiring_soon:critical"}},
		{"one second after notAfter", notAfter.Add(time.Second), interpret.Expired, []string{"cert.expired:critical"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := inspect(t, leaf.DER, tc.now)
			if e.Summary == nil || e.Summary.Validity.State != tc.state {
				t.Fatalf("validity state %+v, want %s", e.Summary, tc.state)
			}
			assertCodes(t, e.Findings, tc.want...)
		})
	}
}

func TestExpiryThresholds(t *testing.T) {
	ca := testpki.Issue(t, caTemplate("CA"), testpki.ECDSAKey(t), nil)
	leaf := testpki.Issue(t, serverTemplate("api.example.test"), testpki.ECDSAKey(t), ca)
	day := 24 * time.Hour

	for _, tc := range []struct {
		name      string
		remaining time.Duration
		want      []string
	}{
		{"30 days + 1s", 30*day + time.Second, nil},
		{"exactly 30 days", 30 * day, []string{"cert.expiring_soon:warning"}},
		{"7 days + 1s", 7*day + time.Second, []string{"cert.expiring_soon:warning"}},
		{"exactly 7 days", 7 * day, []string{"cert.expiring_soon:critical"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := inspect(t, leaf.DER, notAfter.Add(-tc.remaining))
			assertCodes(t, e.Findings, tc.want...)
		})
	}

	e := inspect(t, leaf.DER, notAfter.Add(-10*day-time.Hour))
	if e.Summary.Validity.DaysRemaining != 10 {
		t.Errorf("days remaining %d, want 10", e.Summary.Validity.DaysRemaining)
	}
	if len(e.Findings) != 1 || evidence(e.Findings[0], "not_after") != "2026-12-01T00:00:00Z" || evidence(e.Findings[0], "days_remaining") != "10" {
		t.Errorf("evidence %+v", e.Findings)
	}
}

func TestSelfSigned(t *testing.T) {
	now := notBefore.AddDate(0, 0, 1)
	t.Run("leaf", func(t *testing.T) {
		leaf := testpki.Issue(t, serverTemplate("self.example.test"), testpki.ECDSAKey(t), nil)
		e := inspect(t, leaf.DER, now)
		assertCodes(t, e.Findings, "cert.self_signed_leaf:warning")
		if e.Summary.SelfSigned != interpret.SelfSignedVerified {
			t.Errorf("self-signed %s", e.Summary.SelfSigned)
		}
	})
	t.Run("root CA", func(t *testing.T) {
		root := testpki.Issue(t, caTemplate("Root"), testpki.ECDSAKey(t), nil)
		e := inspect(t, root.DER, now)
		assertCodes(t, e.Findings)
		if e.Summary.Kind != "Self-signed CA certificate" || !slices.Contains(e.Summary.Purposes, "ca") {
			t.Errorf("kind %q purposes %v", e.Summary.Kind, e.Summary.Purposes)
		}
	})
}

func TestWeakSignatures(t *testing.T) {
	now := notBefore.AddDate(0, 0, 1)
	caKey := testpki.RSAKey(t, 2048)
	ca := testpki.Issue(t, caTemplate("RSA CA"), caKey, nil)
	leaf := testpki.Issue(t, serverTemplate("legacy.example.test"), testpki.ECDSAKey(t), ca)

	for _, tc := range []struct {
		alg        testpki.SigAlg
		code       string
		selfSigned interpret.SelfSigned // Go still verifies SHA-1 signatures, refuses MD5
	}{
		{testpki.RSAWithSHA1, "sig.sha1", interpret.SelfSignedVerified},
		{testpki.RSAWithMD5, "sig.md5", interpret.SelfSignedUnverifiable},
	} {
		t.Run(tc.code+" on a leaf", func(t *testing.T) {
			der := testpki.Resign(t, leaf.DER, nil, tc.alg, caKey)
			e := inspect(t, der, now)
			assertCodes(t, e.Findings, tc.code+":critical")
			if evidence(e.Findings[0], "signature_algorithm") == "" {
				t.Error("signature algorithm evidence missing")
			}
		})
		t.Run(tc.code+" on a self-issued CA is informational", func(t *testing.T) {
			der := testpki.Resign(t, ca.DER, nil, tc.alg, caKey)
			e := inspect(t, der, now)
			assertCodes(t, e.Findings, tc.code+":info")
			if e.Summary.SelfSigned != tc.selfSigned {
				t.Errorf("self-signed %s, want %s", e.Summary.SelfSigned, tc.selfSigned)
			}
		})
	}
}

func TestRSAKeySize(t *testing.T) {
	now := notBefore.AddDate(0, 0, 1)
	ca := testpki.Issue(t, caTemplate("CA"), testpki.ECDSAKey(t), nil)
	for bits, want := range map[int][]string{
		1024: {"key.rsa_under_2048:critical"},
		2048: nil,
	} {
		leaf := testpki.Issue(t, serverTemplate("rsa.example.test"), testpki.RSAKey(t, bits), ca)
		e := inspect(t, leaf.DER, now)
		assertCodes(t, e.Findings, want...)
		if bits == 1024 && evidence(e.Findings[0], "key_bits") != "1024" {
			t.Errorf("evidence %+v", e.Findings[0].Evidence)
		}
		if e.Summary.Key != "RSA "+map[int]string{1024: "1024", 2048: "2048"}[bits] {
			t.Errorf("key summary %q", e.Summary.Key)
		}
	}
}

func TestCommonNameOnly(t *testing.T) {
	now := notBefore.AddDate(0, 0, 1)
	ca := testpki.Issue(t, caTemplate("CA"), testpki.ECDSAKey(t), nil)

	cnOnly := serverTemplate("cn-only.example.test")
	cnOnly.DNSNames = nil
	e := inspect(t, testpki.Issue(t, cnOnly, testpki.ECDSAKey(t), ca).DER, now)
	assertCodes(t, e.Findings, "name.cn_only_no_san:warning")
	if !slices.Equal(e.Summary.Identifies, []string{"CN=cn-only.example.test"}) {
		t.Errorf("identifies %v", e.Summary.Identifies)
	}

	withSAN := inspect(t, testpki.Issue(t, serverTemplate("ok.example.test"), testpki.ECDSAKey(t), ca).DER, now)
	assertCodes(t, withSAN.Findings)
	if !slices.Equal(withSAN.Summary.Identifies, []string{"ok.example.test"}) {
		t.Errorf("identifies %v", withSAN.Summary.Identifies)
	}

	caOnlyCN := inspect(t, ca.DER, now)
	assertCodes(t, caOnlyCN.Findings) // a CA naming itself by CN is normal
}

func TestSummaryKinds(t *testing.T) {
	now := notBefore.AddDate(0, 0, 1)
	root := testpki.Issue(t, caTemplate("Root"), testpki.ECDSAKey(t), nil)
	inter := testpki.Issue(t, caTemplate("Intermediate"), testpki.ECDSAKey(t), root)

	withEKU := func(ekus ...x509.ExtKeyUsage) []byte {
		tpl := serverTemplate("svc.example.test")
		tpl.ExtKeyUsage = ekus
		return testpki.Issue(t, tpl, testpki.ECDSAKey(t), inter).DER
	}
	for _, tc := range []struct {
		der      []byte
		kind     string
		purposes []string
	}{
		{inter.DER, "CA certificate", []string{"ca"}},
		{withEKU(x509.ExtKeyUsageServerAuth), "TLS server certificate", []string{"tls_server"}},
		{withEKU(x509.ExtKeyUsageClientAuth), "TLS client certificate", []string{"tls_client"}},
		{withEKU(x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth), "TLS server and client certificate", []string{"tls_server", "tls_client"}},
		{withEKU(x509.ExtKeyUsageCodeSigning), "Code signing certificate", []string{"code_signing"}},
		{withEKU(), "Certificate with no extended key usage restriction", []string{}},
	} {
		e := inspect(t, tc.der, now)
		if e.Summary.Kind != tc.kind || !slices.Equal(e.Summary.Purposes, tc.purposes) {
			t.Errorf("kind %q purposes %v, want %q %v", e.Summary.Kind, e.Summary.Purposes, tc.kind, tc.purposes)
		}
		if e.Summary.Chain != interpret.ChainNotChecked {
			t.Errorf("chain %s: this version never claims a chain result", e.Summary.Chain)
		}
		if e.Summary.Issuer == "" {
			t.Error("issuer as stated in the certificate must be reported")
		}
	}
}

func TestKeyIdentityFindings(t *testing.T) {
	now := notBefore.AddDate(0, 0, 1)
	signer := testpki.ECDSAKey(t)
	base := testpki.Issue(t, serverTemplate("key.example.test"), testpki.ECDSAKey(t), nil)
	rsaKey := testpki.RSAKey(t, 2048)
	der := testpki.Resign(t, base.DER, testpki.RSASPKIWithoutNULL(t, &rsaKey.PublicKey), testpki.ECDSAWithSHA256, signer)

	e := inspect(t, der, now)
	if e.Summary != nil {
		t.Error("an unparseable certificate must not get a friendly summary")
	}
	assertCodes(t, e.Findings, "input.unparseable_certificate:critical", "key.noncanonical_spki:warning")
	for _, f := range e.Findings {
		if f.Code == findings.KeyNoncanonicalSPKI && (evidence(f, "x509-spki-sha256") == "" || evidence(f, "x509-spki-encoded-sha256") == "") {
			t.Errorf("both fingerprints must be evidence: %+v", f.Evidence)
		}
	}
}

func TestBlockProblems(t *testing.T) {
	now := notBefore
	for _, tc := range []struct {
		name  string
		block artifact.Block
		want  string
	}{
		{"malformed PEM", artifact.Block{Kind: artifact.KindMalformed, Label: "CERTIFICATE", Problem: artifact.ProblemMissingEnd}, "input.malformed_pem:critical"},
		{"malformed DER", artifact.Block{Kind: artifact.KindMalformed, Problem: artifact.ProblemBadEncoding}, "input.malformed_der:critical"},
		{"unsupported PEM label", artifact.Block{Kind: artifact.KindUnsupported, Label: "PRIVATE KEY"}, "input.unsupported_format:warning"},
		{"unsupported DER", artifact.Block{Kind: artifact.KindUnsupported}, "input.unsupported_format:warning"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := interpret.Block(tc.block, nil, interpret.Issuers{}, now, th)
			assertCatalogued(t, e.Findings)
			assertCodes(t, e.Findings, tc.want)
		})
	}

	e := interpret.Block(artifact.Block{Kind: artifact.KindUnsupported, Label: "PRIVATE KEY"}, nil, interpret.Issuers{}, now, th)
	if evidence(e.Findings[0], "pem_label") != "PRIVATE KEY" {
		t.Errorf("label evidence %+v", e.Findings[0].Evidence)
	}

	key := testpki.ECDSAKey(t)
	csr, err := x509.CreateCertificateRequest(nil, &x509.CertificateRequest{}, crypto.Signer(key))
	if err != nil {
		t.Fatal(err)
	}
	csrEntry := interpret.Block(artifact.Block{Kind: artifact.KindCertificate}, parsed(t, csr), interpret.Issuers{}, now, th)
	assertCodes(t, csrEntry.Findings, "input.unsupported_format:warning")
}

func TestInputFindings(t *testing.T) {
	for _, tc := range []struct {
		name         string
		decoded      artifact.Decoded
		certificates int
		want         []string
	}{
		{"empty", artifact.Decoded{Format: artifact.FormatEmpty}, 0, []string{"input.empty:critical"}},
		{"unknown", artifact.Decoded{Format: artifact.FormatUnknown}, 0, []string{"input.unsupported_format:critical"}},
		{"PEM with no certificates", artifact.Decoded{Format: artifact.FormatPEM, Blocks: []artifact.Block{{Kind: artifact.KindUnsupported}}}, 0, []string{"input.no_certificates:critical"}},
		{"PEM text around blocks", artifact.Decoded{Format: artifact.FormatPEM, Extraneous: []artifact.Span{{Offset: 0, Length: 5}}}, 1, []string{"input.trailing_data:info"}},
		{"DER trailing bytes", artifact.Decoded{Format: artifact.FormatDER, Extraneous: []artifact.Span{{Offset: 300, Length: 2}}}, 1, []string{"input.trailing_data:warning"}},
		{"clean", artifact.Decoded{Format: artifact.FormatPEM}, 2, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := interpret.Input(tc.decoded, tc.certificates)
			assertCatalogued(t, fs)
			assertCodes(t, fs, tc.want...)
			for _, f := range fs {
				if f.Entry != findings.WholeInput {
					t.Errorf("%s: input findings concern the whole input", f.Code)
				}
			}
		})
	}
}
