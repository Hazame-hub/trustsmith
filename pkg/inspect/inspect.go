// Package inspect explains one certificate source and returns a
// trustsmith.inspect/v1 document (ADR-0003, ADR-0015).
//
// The document is exactly what `trustsmith inspect --output json --fail-on
// never` prints, so the JSON contract and its compatibility rules are the
// whole promise: fields are only ever added within v1. Decode it with your
// own types and ignore properties you do not know
// (docs/integrations/sybil.md).
package inspect

import (
	"time"

	"github.com/Hazame-hub/trustsmith/pkg/internal/runcli"
)

// Schema is the value of the "schema" property of every document Target
// returns.
const Schema = "trustsmith.inspect/v1"

// Options configure an inspection. The zero value is the CLI's behaviour:
// no trust anchors, no purpose and no hostname evaluation.
type Options struct {
	// Now is the clock that validity is evaluated against; nil uses
	// time.Now.
	Now func() time.Time

	// Hostname, when set, is checked against the certificate's subject
	// alternative names, as --hostname does: a mismatch is the critical
	// finding name.hostname_mismatch. An endpoint implies its own host
	// otherwise.
	Hostname string

	// Purpose, when set, is evaluated as --purpose does: any, tls-server,
	// tls-client, code-signing or email. An endpoint implies tls-server
	// otherwise, and a file any.
	Purpose string
}

// Target inspects a file path or a TLS endpoint (host:port, [IPv6]:port or
// tls://host:port) with the modern probe policy, exactly as the CLI would.
// An endpoint is contacted over the network; a file is only read. Findings
// never make it fail; an error means the inspection could not run at all.
func Target(target string, opts Options) ([]byte, error) {
	args := []string{"inspect", "--output", "json", "--fail-on", "never"}
	// Only a set option becomes a flag: the CLI tells an explicit flag from
	// its default, and so does the document's "source".
	if opts.Hostname != "" {
		args = append(args, "--hostname", opts.Hostname)
	}
	if opts.Purpose != "" {
		args = append(args, "--purpose", opts.Purpose)
	}
	return runcli.JSON(opts.Now, append(args, "--", target)...)
}
