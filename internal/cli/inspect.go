package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/findings"
)

func newInspectCommand(stdin io.Reader, stdout io.Writer, env Env) *cobra.Command {
	var (
		output   string
		failOn   string
		advanced bool
	)
	cmd := &cobra.Command{
		Use:   "inspect <file|->",
		Short: "Explain a certificate, DER file or PEM bundle",
		Long: `Explain what a certificate file contains and whether anything is wrong with it.

Accepts a PEM certificate, a DER certificate or a PEM bundle; "-" reads
standard input. Other PEM blocks (such as private keys) are reported by
label and never decoded. Inspecting TLS endpoints is not supported yet.

Exit codes: 0 no finding at or above --fail-on, 1 operational error,
2 usage error, 3 findings reached --fail-on.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError{fmt.Errorf("inspect takes exactly one argument, got %d (usage: trustsmith inspect [flags] <file|->)", len(args))}
			}
			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return usageError{fmt.Errorf("invalid --output %q: want text or json", output)}
			}
			threshold, err := parseFailOn(failOn)
			if err != nil {
				return usageError{err}
			}

			svc := inspectsvc.New(env.Now)
			var res inspectsvc.Result
			target := args[0]
			switch resolveTarget(target, fileExists) {
			case targetStdin:
				res, err = svc.InspectReader(inspectsvc.Source{Kind: inspectsvc.SourceStdin, Locator: "-"}, stdin)
			case targetEndpoint:
				hint := ""
				if !strings.Contains(target, "://") {
					hint = fmt.Sprintf(" To inspect a file with this name, use ./%s.", target)
				}
				return usageError{fmt.Errorf("%q looks like a network endpoint; inspecting TLS endpoints is not supported in this version.%s", target, hint)}
			default:
				res, err = svc.InspectFile(target)
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
			if threshold != "" && res.Highest != "" && res.Highest.AtLeast(threshold) {
				return thresholdReached{}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "text", "output format: text or json")
	cmd.Flags().StringVar(&failOn, "fail-on", "critical", "exit 3 when a finding is at least this severe: info, warning, critical or never")
	cmd.Flags().BoolVar(&advanced, "advanced", false, "include technical details in text output")
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
