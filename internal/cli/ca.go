package cli

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Hazame-hub/trustsmith/internal/app/casvc"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/issuance"
)

const defaultCADir = "trustsmith-ca"

func newCACommand(stdout io.Writer, env Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Run a local private CA: create one, then issue certificates from it",
		Long: `Run a local private certification authority (ADR-0012).

'trustsmith ca init' creates a CA directory holding a root certificate (ca.pem)
and its private key (ca.key). 'trustsmith ca issue' creates a key and a
certificate signed by that CA, proves the certificate with the same checks as
'trustsmith inspect' (trusted by this CA, suitable for its purpose, identifying
every requested name), and only then writes them.

Trustsmith never overwrites a key or a certificate. Keys are written
unencrypted with owner-only permissions (0600) on Unix-like systems; protect
the CA directory as you would any private key.`,
	}
	cmd.AddCommand(newCAInitCommand(stdout, env), newCAIssueCommand(stdout, env))
	return cmd
}

func newCAInitCommand(stdout io.Writer, env Env) *cobra.Command {
	var (
		dir, name, org, keyType string
		days                    int
		permitDNS, permitIP     []string
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a local CA directory with a new root certificate and key",
		Long: `Create a local CA: a self-signed root certificate (ca.pem) and its private key
(ca.key) in --dir, which is created with owner-only permissions.

The root may sign end-entity certificates only (path length 0). With
--permit-dns or --permit-ip it carries critical name constraints, so a
certificate for any other name fails validation wherever name constraints are
enforced, even if the CA key is stolen. Without them the CA can certify any
name: trust it only where that is acceptable.

Exit codes: 0 created, 1 operational error (including an existing CA), 2 usage
error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			kt, err := issuance.ParseKeyType(keyType)
			if err != nil {
				return usageError{fmt.Errorf("invalid --key-type: %w", err)}
			}
			var prefixes []netip.Prefix
			for _, p := range permitIP {
				prefix, perr := netip.ParsePrefix(p)
				if perr != nil {
					return usageError{fmt.Errorf("invalid --permit-ip %q: want a CIDR range such as 10.0.0.0/8", p)}
				}
				prefixes = append(prefixes, prefix)
			}
			res, err := casvc.New(env.Now, env.Rand).Init(casvc.InitRequest{
				Dir: dir, CommonName: name, Organization: org, KeyType: kt,
				Validity: days24(days), PermittedDNS: permitDNS, PermittedIPs: prefixes,
			})
			if err != nil {
				return caError(err)
			}
			return renderCAInit(stdout, res, dir)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "dir", defaultCADir, "directory to create the CA in")
	f.StringVar(&name, "name", "Trustsmith Local CA", "the CA's common name, shown wherever it is trusted")
	f.StringVar(&org, "org", "", "the CA's organisation name")
	f.StringVar(&keyType, "key-type", string(issuance.KeyECDSAP256), "key algorithm: ecdsa-p256, ecdsa-p384 or rsa-3072")
	f.IntVar(&days, "days", int(issuance.DefaultRootValidity.Hours()/24), "validity in days")
	f.StringArrayVar(&permitDNS, "permit-dns", nil, "restrict the CA to this domain and its subdomains (repeatable)")
	f.StringArrayVar(&permitIP, "permit-ip", nil, "restrict the CA to this CIDR range (repeatable)")
	return cmd
}

func newCAIssueCommand(stdout io.Writer, env Env) *cobra.Command {
	var (
		dir, out, keyType, use string
		days                   int
		dns, ips               []string
	)
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a certificate and key from a local CA",
		Long: `Issue an end-entity certificate from the CA in --ca-dir, for the names given
with --dns and --ip, and write it to <out>.pem with its new private key in
<out>.key. --out defaults to the first name.

Before anything is written, the certificate is inspected exactly as
'trustsmith inspect <out>.pem --roots <ca-dir>/ca.pem --purpose <purpose>
--hostname <name>' would, for every requested name and purpose. If any check
fails, nothing is written.

Exit codes: 0 issued, 1 operational error (including an existing output file
or a refused request), 2 usage error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			kt, err := issuance.ParseKeyType(keyType)
			if err != nil {
				return usageError{fmt.Errorf("invalid --key-type: %w", err)}
			}
			var server, client bool
			switch use {
			case "server":
				server = true
			case "client":
				client = true
			case "both":
				server, client = true, true
			default:
				return usageError{fmt.Errorf("invalid --use %q: want server, client or both", use)}
			}
			if len(dns) == 0 && len(ips) == 0 {
				return usageError{errors.New("name the certificate with at least one --dns or --ip")}
			}
			var addrs []netip.Addr
			for _, s := range ips {
				a, perr := netip.ParseAddr(strings.Trim(s, "[]"))
				if perr != nil || a.Zone() != "" {
					return usageError{fmt.Errorf("invalid --ip %q", s)}
				}
				addrs = append(addrs, a.Unmap())
			}
			if out == "" {
				first := ""
				if len(dns) > 0 {
					first = dns[0]
				} else {
					first = addrs[0].String()
				}
				out = defaultOut(first)
			}
			res, err := casvc.New(env.Now, env.Rand).Issue(casvc.IssueRequest{
				Dir: dir, Out: out, DNSNames: dns, IPs: addrs,
				Server: server, Client: client, KeyType: kt, Validity: days24(days),
			})
			if err != nil {
				return caError(err)
			}
			return renderCAIssue(stdout, res, dir, use, dns, addrs)
		},
	}
	f := cmd.Flags()
	f.StringVar(&dir, "ca-dir", defaultCADir, "directory of the CA created by 'trustsmith ca init'")
	f.StringArrayVar(&dns, "dns", nil, "DNS name to certify, e.g. app.example.internal or *.example.internal (repeatable)")
	f.StringArrayVar(&ips, "ip", nil, "IP address to certify (repeatable)")
	f.StringVar(&use, "use", "server", "what the certificate is for: server, client or both")
	f.StringVar(&out, "out", "", "output path without extension (default: the first name)")
	f.StringVar(&keyType, "key-type", string(issuance.KeyECDSAP256), "key algorithm: ecdsa-p256, ecdsa-p384 or rsa-3072")
	f.IntVar(&days, "days", int(issuance.DefaultLeafValidity.Hours()/24), "validity in days (at most 397)")
	return cmd
}

func days24(days int) time.Duration { return time.Duration(days) * 24 * time.Hour }

// defaultOut turns a name into a file name: a wildcard becomes "_wildcard"
// and an IPv6 address's colons become dashes, so it is valid on every OS.
func defaultOut(name string) string {
	name = strings.Replace(name, "*", "_wildcard", 1)
	return strings.ReplaceAll(name, ":", "-")
}

// caError classifies a service error: every failure of a CA command that is
// not a flag problem is operational (exit 1), including a refused request,
// because it was refused after the invocation was understood.
func caError(err error) error { return operationalError{err} }

func renderCAInit(w io.Writer, res casvc.Init, dir string) error {
	c := res.Certificate
	constraints := "none: this CA can certify any name; trust it only where that is acceptable"
	var parts []string
	parts = append(parts, c.PermittedDNSDomains...)
	for _, n := range c.PermittedIPRanges {
		parts = append(parts, n.String())
	}
	if len(parts) > 0 {
		constraints = strings.Join(parts, ", ") + " (critical name constraints)"
	}
	p := &printer{w: w}
	p.linef("Created a local CA in %s", dir)
	p.linef("")
	p.linef("  Certificate   %s", res.CertPath)
	p.linef("  Private key   %s", res.KeyPath)
	p.linef("                keep it secret: whoever holds it can issue certificates that")
	p.linef("                every system trusting this CA will accept")
	p.linef("  Subject       %s", c.Subject.String())
	p.linef("  Valid until   %s", c.NotAfter.UTC().Format(humanTime))
	p.linef("  Names         %s", constraints)
	p.linef("  Certificate   %s", res.Fingerprint)
	p.linef("")
	p.linef("Next:")
	p.linef("  1. Trust %s on the machines and applications that should accept its certificates.", res.CertPath)
	p.linef("  2. trustsmith ca issue --ca-dir %s --dns app.example.internal", dir)
	return p.err
}

func renderCAIssue(w io.Writer, res casvc.Issued, dir, use string, dns []string, ips []netip.Addr) error {
	c := res.Certificate
	names := append([]string{}, dns...)
	for _, ip := range ips {
		names = append(names, ip.String())
	}
	p := &printer{w: w}
	p.linef("Issued a %s certificate for %s", useText(use), strings.Join(names, ", "))
	p.linef("")
	p.linef("  Certificate   %s", res.CertPath)
	p.linef("  Private key   %s", res.KeyPath)
	p.linef("  Issuer        %s", c.Issuer.String())
	p.linef("  Valid until   %s", c.NotAfter.UTC().Format(humanTime))
	p.linef("  Certificate   %s", fingerprint.CertFromDER(c.Raw))
	p.linef("")
	p.linef("Proven before writing, with the checks of 'trustsmith inspect':")
	p.linef("  - validates against %s as the only trust anchor", dir+"/"+casvc.CertFile)
	p.linef("  - its key usages permit %s use", useText(use))
	p.linef("  - it identifies every requested name")
	p.linef("")
	p.linef("Check it yourself: trustsmith inspect %s --roots %s/%s --hostname %s", res.CertPath, dir, casvc.CertFile, names[0])
	return p.err
}

func useText(use string) string {
	switch use {
	case "client":
		return "TLS client"
	case "both":
		return "TLS server and client"
	}
	return "TLS server"
}

// printer writes lines and keeps the first error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) linef(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
	}
}
