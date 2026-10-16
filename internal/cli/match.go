package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/Hazame-hub/trustsmith/internal/app/matchsvc"
	"github.com/Hazame-hub/trustsmith/internal/keyfacts"
)

// matchSchema versions the JSON contract of `trustsmith match`, under the
// same rules as trustsmith.inspect/v1.
const matchSchema = "trustsmith.match/v1"

func newMatchCommand(stdout io.Writer) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "match <certificate-file> <private-key-file>",
		Short: "Check whether a private key belongs to a certificate",
		Long: `Check whether a private key is the private half of a certificate's public key:
the question behind "key values mismatch" and similar server errors.

The certificate file may be a single certificate or a bundle; every
certificate in it is compared, and the answer names the one that matches. The
key file must hold exactly one unencrypted private key (PKCS #8, PKCS #1 or
SEC 1 PEM, or DER PKCS #8). Encrypted keys are refused: Trustsmith never asks
for a passphrase.

Keys are compared by their ADR-0002 x509-spki-sha256 identity. The private
key is used only to derive its public key; nothing about it except that public
identity is printed.

Exit codes: 0 the key belongs to a certificate in the file, 1 operational
error (unreadable file, encrypted key, no certificate), 2 usage error, 3 the
key belongs to none of them.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return usageError{fmt.Errorf("match takes a certificate file and a private key file, got %d argument(s)", len(args))}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return usageError{fmt.Errorf("invalid --output %q: want text or json", output)}
			}
			res, err := matchsvc.Match(args[0], args[1])
			if err != nil {
				return operationalError{err}
			}
			if output == "json" {
				err = renderMatchJSON(stdout, res)
			} else {
				err = renderMatchText(stdout, res)
			}
			if err != nil {
				return operationalError{err}
			}
			if res.Matched < 0 {
				return thresholdReached{}
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	return cmd
}

func keyDescription(k keyfacts.Key) string {
	d := k.Algorithm
	switch {
	case k.Detail != "":
		d += " " + k.Detail
	case k.Bits > 0:
		d += fmt.Sprintf(" %d", k.Bits)
	}
	return d
}

var keyFormatNames = map[keyfacts.Format]string{
	keyfacts.FormatPKCS8: "PKCS #8",
	keyfacts.FormatPKCS1: "PKCS #1",
	keyfacts.FormatSEC1:  "SEC 1",
}

func renderMatchText(w io.Writer, res matchsvc.Result) error {
	p := &printer{w: w}
	p.linef("Private key   %s (%s, %s, unencrypted)", res.KeyFile, keyDescription(res.Key), keyFormatNames[res.Key.Format])
	p.linef("Key identity  %s (x509-spki-sha256)", res.Key.KeyID)
	p.linef("")
	for _, c := range res.Certificates {
		var answer string
		switch c.State {
		case matchsvc.Matches:
			answer = "matches this key"
		case matchsvc.DoesNotMatch:
			answer = "does not match (certifies " + c.KeyID.String() + ")"
		default:
			answer = "cannot be compared: " + c.Detail
		}
		p.linef("[%d] %s", c.Entry, c.Subject)
		p.linef("    %s", answer)
	}
	p.linef("")
	if res.Matched >= 0 {
		p.linef("Result: the key belongs to entry %d of %s.", res.Matched, res.CertificateFile)
	} else {
		p.linef("Result: the key belongs to no certificate in %s.", res.CertificateFile)
		p.linef("Fix: find the key that was generated with this certificate's request, or issue a new")
		p.linef("certificate for this key. Never deploy a certificate with a key it does not certify.")
	}
	return p.err
}

type jsonMatch struct {
	Schema          string             `json:"schema"`
	CertificateFile string             `json:"certificate_file"`
	Key             jsonMatchKey       `json:"key"`
	Certificates    []jsonMatchSubject `json:"certificates"`
	// Matched is the entry of the first matching certificate; null when none
	// matches.
	Matched *int `json:"matched"`
}

type jsonMatchKey struct {
	File      string `json:"file"`
	Format    string `json:"format"` // pkcs8, pkcs1 or sec1
	Algorithm string `json:"algorithm"`
	Detail    string `json:"detail,omitempty"`
	Bits      int    `json:"bits,omitempty"`
	KeyID     string `json:"x509-spki-sha256"`
}

type jsonMatchSubject struct {
	Entry       int    `json:"entry"`
	Fingerprint string `json:"x509-cert-sha256"`
	Subject     string `json:"subject"`
	KeyID       string `json:"x509-spki-sha256,omitempty"`
	State       string `json:"state"` // matches, does_not_match or unverifiable
	Detail      string `json:"detail,omitempty"`
}

func renderMatchJSON(w io.Writer, res matchsvc.Result) error {
	doc := jsonMatch{
		Schema: matchSchema, CertificateFile: res.CertificateFile,
		Key: jsonMatchKey{File: res.KeyFile, Format: string(res.Key.Format), Algorithm: res.Key.Algorithm,
			Detail: res.Key.Detail, Bits: res.Key.Bits, KeyID: res.Key.KeyID.Hex()},
		Certificates: []jsonMatchSubject{},
	}
	for _, c := range res.Certificates {
		s := jsonMatchSubject{Entry: c.Entry, Fingerprint: c.Fingerprint.Hex(), Subject: c.Subject, State: string(c.State), Detail: c.Detail}
		if !c.KeyID.IsZero() {
			s.KeyID = c.KeyID.Hex()
		}
		doc.Certificates = append(doc.Certificates, s)
	}
	if res.Matched >= 0 {
		m := res.Matched
		doc.Matched = &m
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return errors.Join(errors.New("write JSON"), err)
	}
	return nil
}
