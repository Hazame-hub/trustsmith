package artifact_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
)

// newCertDER creates a throwaway self-signed certificate. The decoder only
// cares about framing, so the bytes need not be deterministic.
func newCertDER(t testing.TB, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(label string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
}

func decode(t *testing.T, data []byte) artifact.Decoded {
	t.Helper()
	d, err := artifact.Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return d
}

type wantBlock struct {
	kind    artifact.Kind
	label   string
	der     []byte
	problem artifact.Problem
}

func assertBlocks(t *testing.T, d artifact.Decoded, want []wantBlock) {
	t.Helper()
	if len(d.Blocks) != len(want) {
		t.Fatalf("got %d blocks, want %d: %+v", len(d.Blocks), len(want), d.Blocks)
	}
	prevOffset := -1
	for i, w := range want {
		b := d.Blocks[i]
		if b.Entry != i {
			t.Errorf("block %d: Entry %d", i, b.Entry)
		}
		if b.Offset <= prevOffset {
			t.Errorf("block %d: offset %d does not increase (previous %d)", i, b.Offset, prevOffset)
		}
		prevOffset = b.Offset
		if b.Kind != w.kind || b.Label != w.label || b.Problem != w.problem {
			t.Errorf("block %d: got kind=%s label=%q problem=%q, want kind=%s label=%q problem=%q",
				i, b.Kind, b.Label, b.Problem, w.kind, w.label, w.problem)
		}
		if !bytes.Equal(b.DER, w.der) {
			t.Errorf("block %d: DER mismatch", i)
		}
	}
}

func TestSinglePEMCertificate(t *testing.T) {
	der := newCertDER(t, "a")
	d := decode(t, pemOf("CERTIFICATE", der))
	if d.Format != artifact.FormatPEM {
		t.Errorf("format %s", d.Format)
	}
	assertBlocks(t, d, []wantBlock{{kind: artifact.KindCertificate, label: "CERTIFICATE", der: der}})
	if len(d.Extraneous) != 0 {
		t.Errorf("unexpected extraneous data: %+v", d.Extraneous)
	}
}

func TestDERCertificate(t *testing.T) {
	der := newCertDER(t, "a")
	d := decode(t, der)
	if d.Format != artifact.FormatDER {
		t.Errorf("format %s", d.Format)
	}
	assertBlocks(t, d, []wantBlock{{kind: artifact.KindCertificate, der: der}})
}

func TestBundlePreservesOrder(t *testing.T) {
	a, b, c := newCertDER(t, "a"), newCertDER(t, "b"), newCertDER(t, "c")
	data := bytes.Join([][]byte{pemOf("CERTIFICATE", a), pemOf("CERTIFICATE", b), pemOf("CERTIFICATE", c)}, nil)
	assertBlocks(t, decode(t, data), []wantBlock{
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: a},
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: b},
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: c},
	})
}

// TestPEMFormattingDoesNotAffectIdentity proves CRLF line endings, blank
// lines, indentation-free rewrapping, PEM headers and a UTF-8 BOM all decode
// to the same DER, hence the same x509-cert-sha256.
func TestPEMFormattingDoesNotAffectIdentity(t *testing.T) {
	der := newCertDER(t, "a")
	want := fingerprint.CertFromDER(der)
	lf := string(pemOf("CERTIFICATE", der))
	body := strings.TrimSuffix(strings.TrimPrefix(lf, "-----BEGIN CERTIFICATE-----\n"), "-----END CERTIFICATE-----\n")

	variants := map[string]string{
		"LF":               lf,
		"CRLF":             strings.ReplaceAll(lf, "\n", "\r\n"),
		"no final newline": strings.TrimSuffix(lf, "\n"),
		"rewrapped": "-----BEGIN CERTIFICATE-----\n" + strings.Join(chunk(strings.ReplaceAll(body, "\n", ""), 40), "\n") +
			"\n-----END CERTIFICATE-----\n",
		"headers":                         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Source": "test"}, Bytes: der})),
		"BOM":                             "\xef\xbb\xbf" + lf,
		"trailing spaces on armour lines": "-----BEGIN CERTIFICATE-----  \n" + body + "-----END CERTIFICATE----- \t\n",
	}
	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			d := decode(t, []byte(v))
			if len(d.Blocks) != 1 || d.Blocks[0].Kind != artifact.KindCertificate {
				t.Fatalf("got %+v", d.Blocks)
			}
			if got := fingerprint.CertFromDER(d.Blocks[0].DER); got != want {
				t.Errorf("fingerprint changed: %s != %s", got, want)
			}
		})
	}
}

func chunk(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func TestMalformedBlockDoesNotStopUnrelatedBlocks(t *testing.T) {
	a, c := newCertDER(t, "a"), newCertDER(t, "c")
	bad := "-----BEGIN CERTIFICATE-----\nthis is !!! not base64\n-----END CERTIFICATE-----\n"
	data := string(pemOf("CERTIFICATE", a)) + bad + string(pemOf("CERTIFICATE", c))
	assertBlocks(t, decode(t, []byte(data)), []wantBlock{
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: a},
		{kind: artifact.KindMalformed, label: "CERTIFICATE", problem: artifact.ProblemBadEncoding},
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: c},
	})
}

func TestMissingEndThenValidBlock(t *testing.T) {
	c := newCertDER(t, "c")
	data := "-----BEGIN CERTIFICATE-----\nMIIB\n" + string(pemOf("CERTIFICATE", c))
	assertBlocks(t, decode(t, []byte(data)), []wantBlock{
		{kind: artifact.KindMalformed, label: "CERTIFICATE", problem: artifact.ProblemMissingEnd},
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: c},
	})
}

func TestMismatchedEndLabel(t *testing.T) {
	data := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END X509 CRL-----\n"
	assertBlocks(t, decode(t, []byte(data)), []wantBlock{
		{kind: artifact.KindMalformed, label: "CERTIFICATE", problem: artifact.ProblemMissingEnd},
	})
}

func TestMalformedArmour(t *testing.T) {
	data := "-----BEGIN CERTIFICATE\nMIIB\n-----END CERTIFICATE-----\n"
	d := decode(t, []byte(data))
	if len(d.Blocks) == 0 || d.Blocks[0].Kind != artifact.KindMalformed || d.Blocks[0].Problem != artifact.ProblemBadArmour {
		t.Fatalf("got %+v", d.Blocks)
	}
}

// TestUnsupportedBlocksAreNotDecoded proves non-certificate blocks — including
// private keys — are reported by label only and their contents never exposed.
func TestUnsupportedBlocksAreNotDecoded(t *testing.T) {
	a := newCertDER(t, "a")
	data := "-----BEGIN PRIVATE KEY-----\nsecret material that must not be decoded\n-----END PRIVATE KEY-----\n" +
		string(pemOf("CERTIFICATE", a)) +
		"-----BEGIN PKCS7-----\nnot base64 either\n-----END PKCS7-----\n"
	assertBlocks(t, decode(t, []byte(data)), []wantBlock{
		{kind: artifact.KindUnsupported, label: "PRIVATE KEY"},
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: a},
		{kind: artifact.KindUnsupported, label: "PKCS7"},
	})
}

// TestCertificateRequestBlocksAreDecoded proves both certificate signing
// request labels are framed as requests (ADR-0011), whatever their contents
// turn out to be, and that a corrupt request block is malformed, not skipped.
func TestCertificateRequestBlocksAreDecoded(t *testing.T) {
	a := newCertDER(t, "a")
	data := string(pemOf("CERTIFICATE REQUEST", a)) + string(pemOf("NEW CERTIFICATE REQUEST", a)) +
		"-----BEGIN CERTIFICATE REQUEST-----\nthis is !!! not base64\n-----END CERTIFICATE REQUEST-----\n" +
		string(pemOf("CERTIFICATE", a))
	assertBlocks(t, decode(t, []byte(data)), []wantBlock{
		{kind: artifact.KindCertificateRequest, label: "CERTIFICATE REQUEST", der: a},
		{kind: artifact.KindCertificateRequest, label: "NEW CERTIFICATE REQUEST", der: a},
		{kind: artifact.KindMalformed, label: "CERTIFICATE REQUEST", problem: artifact.ProblemBadEncoding},
		{kind: artifact.KindCertificate, label: "CERTIFICATE", der: a},
	})
}

func TestExtraneousTextAroundPEM(t *testing.T) {
	a := newCertDER(t, "a")
	lead := "subject=CN = a\nissuer=CN = a\n"
	trail := "\n\ntrailing notes\n"
	data := lead + string(pemOf("CERTIFICATE", a)) + trail
	d := decode(t, []byte(data))
	assertBlocks(t, d, []wantBlock{{kind: artifact.KindCertificate, label: "CERTIFICATE", der: a}})
	if len(d.Extraneous) != 2 {
		t.Fatalf("want 2 extraneous spans, got %+v", d.Extraneous)
	}
	if got := data[d.Extraneous[0].Offset : d.Extraneous[0].Offset+d.Extraneous[0].Length]; got != strings.TrimSpace(lead) {
		t.Errorf("leading span %q", got)
	}
	if got := data[d.Extraneous[1].Offset : d.Extraneous[1].Offset+d.Extraneous[1].Length]; got != "trailing notes" {
		t.Errorf("trailing span %q", got)
	}
}

func TestDERTrailingData(t *testing.T) {
	der := newCertDER(t, "a")
	data := append(bytes.Clone(der), 0xde, 0xad)
	d := decode(t, data)
	assertBlocks(t, d, []wantBlock{{kind: artifact.KindCertificate, der: der}})
	if len(d.Extraneous) != 1 || d.Extraneous[0].Offset != len(der) || d.Extraneous[0].Length != 2 {
		t.Errorf("extraneous %+v", d.Extraneous)
	}
}

func TestDERThatIsNotCertificateShaped(t *testing.T) {
	// PKCS#8-shaped: SEQUENCE { INTEGER 0, SEQUENCE {}, OCTET STRING } — never parsed further.
	pkcs8Shaped := []byte{0x30, 0x07, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04, 0x00}
	assertBlocks(t, decode(t, pkcs8Shaped), []wantBlock{{kind: artifact.KindUnsupported}})
}

func TestInvalidDER(t *testing.T) {
	assertBlocks(t, decode(t, []byte{0x30, 0x82, 0xff, 0xff, 0x01}), []wantBlock{
		{kind: artifact.KindMalformed, problem: artifact.ProblemBadEncoding},
	})
}

func TestUnknownAndEmptyInput(t *testing.T) {
	for name, tc := range map[string]struct {
		data   string
		format artifact.Format
	}{
		"empty":          {"", artifact.FormatEmpty},
		"whitespace":     {" \r\n\t\n", artifact.FormatEmpty},
		"plain text":     {"hello, this is not a certificate\n", artifact.FormatUnknown},
		"mid-line BEGIN": {"see -----BEGIN CERTIFICATE----- here\n", artifact.FormatUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			d := decode(t, []byte(tc.data))
			if d.Format != tc.format || len(d.Blocks) != 0 {
				t.Errorf("got format %s blocks %+v", d.Format, d.Blocks)
			}
		})
	}
}

func TestLimits(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		_, err := artifact.Decode(make([]byte, artifact.MaxInputBytes+1))
		if !errors.Is(err, artifact.ErrTooLarge) {
			t.Fatalf("want ErrTooLarge, got %v", err)
		}
		if _, err := artifact.Decode(bytes.Repeat([]byte{' '}, artifact.MaxInputBytes)); err != nil {
			t.Fatalf("exactly MaxInputBytes must be accepted: %v", err)
		}
	})
	t.Run("blocks", func(t *testing.T) {
		one := []byte("-----BEGIN X-----\n-----END X-----\n")
		_, err := artifact.Decode(bytes.Repeat(one, artifact.MaxBlocks+1))
		if !errors.Is(err, artifact.ErrTooManyBlocks) {
			t.Fatalf("want ErrTooManyBlocks, got %v", err)
		}
		d, err := artifact.Decode(bytes.Repeat(one, artifact.MaxBlocks))
		if err != nil || len(d.Blocks) != artifact.MaxBlocks {
			t.Fatalf("exactly MaxBlocks must be accepted: %d blocks, %v", len(d.Blocks), err)
		}
	})
}
