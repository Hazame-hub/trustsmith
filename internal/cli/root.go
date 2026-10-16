// Package cli is Trustsmith's command-line interface. It parses arguments,
// calls application services and renders their results. It contains no
// domain logic: everything it shows comes from the services.
package cli

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/Hazame-hub/trustsmith/internal/probe"
)

// Exit codes.
const (
	ExitOK       = 0 // success; no finding at or above the --fail-on threshold
	ExitError    = 1 // operational error, e.g. an unreadable file
	ExitUsage    = 2 // invalid invocation
	ExitFindings = 3 // inspection completed and findings reached the threshold
)

// Env is what the CLI needs from its environment.
type Env struct {
	Now     func() time.Time
	Version string
	// Dial replaces the TCP dialer of endpoint inspection; nil dials the
	// endpoint. Tests use it to reach in-process servers only.
	Dial probe.DialFunc
	// Rand is the randomness source for keys and serial numbers
	// (crypto/rand.Reader in cmd/trustsmith).
	Rand io.Reader
}

// operationalError marks failures that are not the user's invocation.
type operationalError struct{ error }

func (e operationalError) Unwrap() error { return e.error }

// usageError marks invalid invocations.
type usageError struct{ error }

func (e usageError) Unwrap() error { return e.error }

// thresholdReached reports ExitFindings; the output already explains why.
type thresholdReached struct{}

func (thresholdReached) Error() string { return "findings reached the --fail-on threshold" }

// Run executes the CLI and returns the process exit code. All error output is
// written here, in one place.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, env Env) int {
	root := newRoot(stdin, stdout, env)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.Execute()
	var (
		op        operationalError
		threshold thresholdReached
	)
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &threshold):
		return ExitFindings
	case errors.As(err, &op):
		_, _ = fmt.Fprintf(stderr, "trustsmith: error: %v\n", op.error)
		return ExitError
	default:
		// Flag, argument and unknown-command errors from cobra are usage
		// errors too; only operational errors are marked explicitly.
		_, _ = fmt.Fprintf(stderr, "trustsmith: %v\nRun 'trustsmith --help' for usage.\n", err)
		return ExitUsage
	}
}

func newRoot(stdin io.Reader, stdout io.Writer, env Env) *cobra.Command {
	root := &cobra.Command{
		Use:           "trustsmith",
		Short:         "Understand and manage certificates and private PKI, locally",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageError{err} })

	root.AddCommand(newInspectCommand(stdin, stdout, env))
	root.AddCommand(newCACommand(stdout, env))
	root.AddCommand(newMatchCommand(stdout))
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the Trustsmith version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(stdout, "trustsmith %s (%s %s/%s)\n", env.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			if err != nil {
				return operationalError{err}
			}
			return nil
		},
	})
	return root
}
