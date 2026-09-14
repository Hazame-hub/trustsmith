package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/endpoint"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
	"github.com/Hazame-hub/trustsmith/internal/probe"
	"github.com/Hazame-hub/trustsmith/internal/purpose"
)

func newInspectCommand(stdin io.Reader, stdout io.Writer, env Env) *cobra.Command {
	var (
		output      string
		failOn      string
		advanced    bool
		roots       []string
		purposes    string
		host        string
		probePolicy string
	)
	cmd := &cobra.Command{
		Use:   "inspect <file|host:port|tls://host:port|->",
		Short: "Explain a certificate file or the certificates a TLS endpoint presents",
		Long: `Explain what a certificate file contains and whether anything is wrong with it.

Accepts a PEM certificate, a DER certificate or a PEM bundle; "-" reads
standard input. Other PEM blocks (such as private keys) are reported by
label and never decoded.

A TLS endpoint is written host:port, [IPv6]:port or tls://host:port; without
a port, 443 is used. An existing file with the same name is always inspected
as a file. Trustsmith connects, completes one TLS handshake under the explicit
--probe-policy, keeps the certificates the server presented and closes the
connection: it sends no application data and speaks no HTTP. The handshake is
not authenticated, so completing it means only that certificates were
acquired, never that they are trusted, identify the host or suit a purpose.
Those are evaluated separately, exactly as for a file: an endpoint implies
--purpose tls-server and --hostname set to the endpoint's host, unless either
is given explicitly.

Trust is evaluated only against trust anchors you supply with --roots: a
certificate file or bundle, repeatable. Certificates in the inspected input,
self-signed or not, are never trust anchors, and no system trust store is
used. Without --roots, trust is not evaluated.

--purpose asks whether a certificate's own fields (extended key usage and key
usage) permit a purpose: any (the default for files: no specific application),
tls-server, tls-client, code-signing or email. With --roots, the chain is also
validated for that purpose. --purpose never checks host names.

--hostname asks whether a certificate's subject alternative names identify a
host name or IP address (bracketed IPv6 is accepted), using Go's crypto/x509
matching; the Common Name is never used. It does not imply any purpose. A
scheme, path or port is a usage error.

Exit codes: 0 no finding at or above --fail-on, 1 operational error (including
an endpoint from which no certificate was acquired), 2 usage error, 3 findings
reached --fail-on.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError{fmt.Errorf("inspect takes exactly one argument, got %d (usage: trustsmith inspect [flags] <file|host:port|tls://host:port|->)", len(args))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return usageError{fmt.Errorf("invalid --output %q: want text or json", output)}
			}
			threshold, err := parseFailOn(failOn)
			if err != nil {
				return usageError{err}
			}
			target := args[0]
			kind := resolveTarget(target, fileExists)

			policy, err := probe.PolicyByName(probePolicy)
			if err != nil {
				return usageError{fmt.Errorf("invalid --probe-policy: %w", err)}
			}
			if kind != targetEndpoint && cmd.Flags().Changed("probe-policy") {
				return usageError{errors.New("--probe-policy applies only when inspecting a TLS endpoint")}
			}
			var ep endpoint.Endpoint
			if kind == targetEndpoint {
				if ep, err = endpoint.Parse(target); err != nil {
					hint := ""
					if !strings.Contains(target, "://") {
						hint = fmt.Sprintf(" To inspect a file with this name, use ./%s.", target)
					}
					return usageError{fmt.Errorf("%w.%s", err, hint)}
				}
			}

			requested, err := purpose.Parse(purposes)
			if err != nil {
				return usageError{fmt.Errorf("invalid --purpose: %w", err)}
			}
			var opts []inspectsvc.Option
			// Only an explicit --purpose is passed on: an endpoint implies
			// tls-server otherwise, and a file defaults to any.
			if cmd.Flags().Changed("purpose") {
				opts = append(opts, inspectsvc.WithPurpose(requested))
			}
			if cmd.Flags().Changed("hostname") {
				request, hostErr := hostname.ParseRequest(host)
				if hostErr != nil {
					return usageError{fmt.Errorf("invalid --hostname: %w", hostErr)}
				}
				opts = append(opts, inspectsvc.WithHostname(request))
			}
			if len(roots) > 0 {
				for _, r := range roots {
					if strings.TrimSpace(r) == "" {
						return usageError{errors.New("--roots needs a certificate file name")}
					}
				}
				loaded, loadErr := inspectsvc.LoadRoots(roots)
				if loadErr != nil {
					return operationalError{loadErr}
				}
				opts = append(opts, inspectsvc.WithRoots(loaded))
			}

			var res inspectsvc.Result
			switch kind {
			case targetStdin:
				res, err = inspectsvc.New(env.Now, opts...).InspectReader(inspectsvc.Source{Kind: inspectsvc.SourceStdin, Locator: "-"}, stdin)
			case targetEndpoint:
				settings := inspectsvc.DefaultProbeSettings()
				settings.Policy, settings.Dial = policy, env.Dial
				opts = append(opts, inspectsvc.WithProbeSettings(settings))
				res = inspectsvc.New(env.Now, opts...).InspectEndpoint(cmd.Context(), ep)
			default:
				res, err = inspectsvc.New(env.Now, opts...).InspectFile(target)
			}
			if err != nil {
				return operationalError{err}
			}

			if output == "json" {
				err = renderJSON(stdout, res)
			} else {
				err = renderText(stdout, res, advanced)
			}
			if err != nil {
				return operationalError{err}
			}
			if p := res.Probe; p != nil && p.State == probe.StateFailed {
				return operationalError{fmt.Errorf("TLS probe of %s failed at the %s stage (%s); no peer certificate was acquired", res.Source.Locator, p.Stage, p.Reason)}
			}
			if threshold != "" && res.Highest != "" && res.Highest.AtLeast(threshold) {
				return thresholdReached{}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "text", "output format: text or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "exit 3 when a finding is at least this severe: info, warning, critical or never")
	cmd.Flags().BoolVar(&advanced, "advanced", false, "include technical details in text output")
	cmd.Flags().StringArrayVar(&roots, "roots", nil, "validate against the trust anchors in this certificate file (repeatable); without it, trust is not evaluated")
	cmd.Flags().StringVar(&host, "hostname", "", "check whether the certificate identifies this host name or IP address (no scheme, path or port); an endpoint implies its host")
	cmd.Flags().StringVar(&purposes, "purpose", string(purpose.Any), "evaluate suitability for a purpose: any, tls-server, tls-client, code-signing or email; an endpoint implies tls-server")
	cmd.Flags().StringVar(&probePolicy, "probe-policy", "modern", "TLS client policy for endpoint inspection: modern (TLS 1.2 with ECDHE and AEAD suites, and TLS 1.3)")
	return cmd
}

// parseFailOn returns the threshold severity, or "" for never.
func parseFailOn(v string) (findings.Severity, error) {
	if v == "never" {
		return "", nil
	}
	s, err := findings.ParseSeverity(v)
	if err != nil {
		return "", fmt.Errorf("invalid --fail-on %q: want info, warning, critical or never", v)
	}
	return s, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
