package issuance_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/issuance"
)

var now = time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC)

func newRoot(t *testing.T, mutate func(*issuance.RootRequest)) (*x509.Certificate, *issuance.RootRequest) {
	t.Helper()
	key, err := issuance.GenerateKey(rand.Reader, issuance.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	r := &issuance.RootRequest{CommonName: "Test Local CA", Organization: "Tests", Now: now,
		Validity: issuance.DefaultRootValidity, Key: key, Rand: rand.Reader}
	if mutate != nil {
		mutate(r)
	}
	der, err := issuance.Root(*r)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, r
}

func TestRootIsAnEndEntityOnlyCA(t *testing.T) {
	c, _ := newRoot(t, nil)
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Errorf("basic constraints: IsCA=%v valid=%v MaxPathLen=%d zero=%v; want a CA with path length 0", c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.MaxPathLenZero)
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage %v", c.KeyUsage)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Errorf("not self-signed: %v", err)
	}
	if !c.NotBefore.Equal(now.Add(-issuance.Backdate)) || !c.NotAfter.Equal(now.Add(issuance.DefaultRootValidity)) {
		t.Errorf("validity %s – %s", c.NotBefore, c.NotAfter)
	}
	if c.SerialNumber.Sign() <= 0 || len(c.SerialNumber.Bytes()) != 16 {
		t.Errorf("serial %x: want 16 positive octets", c.SerialNumber.Bytes())
	}
	if len(c.SubjectKeyId) != 20 {
		t.Errorf("subject key identifier %x", c.SubjectKeyId)
	}
	if len(c.PermittedDNSDomains) != 0 || len(c.PermittedIPRanges) != 0 {
		t.Error("unexpected name constraints")
	}
}

func TestRootNameConstraintsAreCritical(t *testing.T) {
	c, _ := newRoot(t, func(r *issuance.RootRequest) {
		r.PermittedDNS = []string{"example.internal"}
		r.PermittedIPs = []netip.Prefix{netip.MustParsePrefix("10.1.2.3/8")}
	})
	if !c.PermittedDNSDomainsCritical || len(c.PermittedDNSDomains) != 1 || c.PermittedDNSDomains[0] != "example.internal" {
		t.Errorf("DNS constraints %v critical=%v", c.PermittedDNSDomains, c.PermittedDNSDomainsCritical)
	}
	if len(c.PermittedIPRanges) != 1 || c.PermittedIPRanges[0].String() != "10.0.0.0/8" {
		t.Errorf("IP constraints %v; want the masked range 10.0.0.0/8", c.PermittedIPRanges)
	}
	if len(c.ExcludedIPRanges) != 0 {
		t.Errorf("excluded IP ranges %v", c.ExcludedIPRanges)
	}
}

// Constraining one name type closes the other: a DNS-only CA cannot certify
// an IP address and an IP-only CA cannot certify a DNS name. casvc's tests
// prove that validation agrees when such a certificate is signed anyway.
func TestNameConstraintsCloseTheOtherType(t *testing.T) {
	dnsOnly, dnsReq := newRoot(t, func(r *issuance.RootRequest) { r.PermittedDNS = []string{"example.internal"} })
	if len(dnsOnly.ExcludedIPRanges) != 2 {
		t.Errorf("DNS-only CA excludes %v; want every IPv4 and IPv6 address", dnsOnly.ExcludedIPRanges)
	}
	ipOnly, ipReq := newRoot(t, func(r *issuance.RootRequest) { r.PermittedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
	if len(ipOnly.PermittedDNSDomains) != 1 || ipOnly.PermittedDNSDomains[0] != "invalid" {
		t.Errorf("IP-only CA permits DNS %v", ipOnly.PermittedDNSDomains)
	}

	for name, tc := range map[string]struct {
		ca  *x509.Certificate
		req *issuance.RootRequest
		dns []string
		ips []netip.Addr
	}{
		"ip from a DNS-only CA":  {dnsOnly, dnsReq, nil, []netip.Addr{netip.MustParseAddr("10.1.2.3")}},
		"dns from an IP-only CA": {ipOnly, ipReq, []string{"app.example.internal"}, nil},
	} {
		r := leafRequest(t, tc.ca, tc.req)
		r.DNSNames, r.IPs = tc.dns, tc.ips
		if _, err := issuance.Leaf(r); !errors.Is(err, issuance.ErrRequest) {
			t.Errorf("%s: Leaf err %v, want a refusal", name, err)
		}
	}
}

func TestRootRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*issuance.RootRequest){
		"no name":           func(r *issuance.RootRequest) { r.CommonName = " " },
		"too long":          func(r *issuance.RootRequest) { r.Validity = issuance.MaxRootValidity + time.Hour },
		"too short":         func(r *issuance.RootRequest) { r.Validity = time.Minute },
		"bad permitted dns": func(r *issuance.RootRequest) { r.PermittedDNS = []string{"Example.internal"} },
	} {
		key, _ := issuance.GenerateKey(rand.Reader, issuance.KeyECDSAP256)
		r := issuance.RootRequest{CommonName: "CA", Now: now, Validity: issuance.DefaultRootValidity, Key: key, Rand: rand.Reader}
		mutate(&r)
		if _, err := issuance.Root(r); !errors.Is(err, issuance.ErrRequest) {
			t.Errorf("%s: err %v, want ErrRequest", name, err)
		}
	}
}

func leafRequest(t *testing.T, ca *x509.Certificate, caReq *issuance.RootRequest) issuance.LeafRequest {
	t.Helper()
	key, err := issuance.GenerateKey(rand.Reader, issuance.KeyECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	return issuance.LeafRequest{DNSNames: []string{"app.example.internal"}, IPs: []netip.Addr{netip.MustParseAddr("10.1.2.3")},
		Server: true, Now: now, Validity: issuance.DefaultLeafValidity,
		Key: key.Public(), CA: ca, CAKey: caReq.Key, Rand: rand.Reader}
}

func TestLeafProperties(t *testing.T) {
	ca, caReq := newRoot(t, nil)
	r := leafRequest(t, ca, caReq)
	r.Client = true
	der, err := issuance.Leaf(r)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSignatureFrom(ca); err != nil {
		t.Errorf("not signed by the CA: %v", err)
	}
	if c.IsCA || !c.BasicConstraintsValid {
		t.Error("a leaf must carry basicConstraints CA:FALSE")
	}
	if c.Subject.CommonName != "app.example.internal" || len(c.DNSNames) != 1 || len(c.IPAddresses) != 1 || c.IPAddresses[0].String() != "10.1.2.3" {
		t.Errorf("names: CN=%q DNS=%v IP=%v", c.Subject.CommonName, c.DNSNames, c.IPAddresses)
	}
	if len(c.ExtKeyUsage) != 2 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || c.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
		t.Errorf("EKU %v", c.ExtKeyUsage)
	}
	if c.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage %v", c.KeyUsage)
	}
	if string(c.AuthorityKeyId) != string(ca.SubjectKeyId) {
		t.Error("authority key identifier does not name the CA's key")
	}
}

func TestLeafRSAKeyAllowsKeyEncipherment(t *testing.T) {
	ca, caReq := newRoot(t, nil)
	r := leafRequest(t, ca, caReq)
	key, err := issuance.GenerateKey(rand.Reader, issuance.KeyRSA3072)
	if err != nil {
		t.Fatal(err)
	}
	r.Key = key.Public()
	der, err := issuance.Leaf(r)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	if c.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment {
		t.Errorf("key usage %v", c.KeyUsage)
	}
}

func TestLeafRefusals(t *testing.T) {
	ca, caReq := newRoot(t, func(r *issuance.RootRequest) {
		r.Validity = 200 * 24 * time.Hour
		r.PermittedDNS = []string{"example.internal"}
		r.PermittedIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	})
	for name, mutate := range map[string]func(*issuance.LeafRequest){
		"no names":           func(r *issuance.LeafRequest) { r.DNSNames, r.IPs = nil, nil },
		"no purpose":         func(r *issuance.LeafRequest) { r.Server = false },
		"outlives the CA":    func(r *issuance.LeafRequest) { r.Validity = 300 * 24 * time.Hour },
		"too long":           func(r *issuance.LeafRequest) { r.Validity = issuance.MaxLeafValidity + time.Hour },
		"outside dns":        func(r *issuance.LeafRequest) { r.DNSNames = []string{"example.com"} },
		"suffix not label":   func(r *issuance.LeafRequest) { r.DNSNames = []string{"badexample.internal"} },
		"outside ip":         func(r *issuance.LeafRequest) { r.IPs = []netip.Addr{netip.MustParseAddr("192.0.2.1")} },
		"upper case":         func(r *issuance.LeafRequest) { r.DNSNames = []string{"App.example.internal"} },
		"bare wildcard":      func(r *issuance.LeafRequest) { r.DNSNames = []string{"*.internal"} },
		"inner wildcard":     func(r *issuance.LeafRequest) { r.DNSNames = []string{"a.*.example.internal"} },
		"unicode":            func(r *issuance.LeafRequest) { r.DNSNames = []string{"bücher.example.internal"} },
		"before CA is valid": func(r *issuance.LeafRequest) { r.Now = now.Add(-time.Hour) },
	} {
		r := leafRequest(t, ca, caReq)
		mutate(&r)
		if _, err := issuance.Leaf(r); !errors.Is(err, issuance.ErrRequest) {
			t.Errorf("%s: err %v, want ErrRequest", name, err)
		}
	}
	r := leafRequest(t, ca, caReq)
	r.DNSNames = []string{"*.svc.example.internal", "example.internal"}
	if _, err := issuance.Leaf(r); err != nil {
		t.Errorf("wildcard and apex inside the constraint: %v", err)
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	ca, caReq := newRoot(t, nil)
	for _, kt := range issuance.KeyTypes() {
		key, err := issuance.GenerateKey(rand.Reader, kt)
		if err != nil {
			t.Fatal(err)
		}
		pemBytes, err := issuance.EncodePrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		back, err := issuance.DecodePrivateKey(pemBytes)
		if err != nil {
			t.Fatalf("%s: %v", kt, err)
		}
		if !back.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(key.Public()) {
			t.Errorf("%s: decoded key differs", kt)
		}
	}
	if !issuance.KeyMatches(ca, caReq.Key) {
		t.Error("the CA key does not match the CA certificate")
	}
	other, _ := issuance.GenerateKey(rand.Reader, issuance.KeyECDSAP256)
	if issuance.KeyMatches(ca, other) {
		t.Error("an unrelated key matches the CA certificate")
	}
	if _, err := issuance.DecodePrivateKey(issuance.EncodeCertificate(ca.Raw)); err == nil {
		t.Error("a certificate decoded as a private key")
	}
}

func TestParseKeyType(t *testing.T) {
	if k, err := issuance.ParseKeyType("ecdsa-p384"); err != nil || k != issuance.KeyECDSAP384 {
		t.Errorf("ecdsa-p384: %v %v", k, err)
	}
	for _, bad := range []string{"", "ECDSA-P256", "rsa-2048", "ed25519"} {
		if _, err := issuance.ParseKeyType(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
