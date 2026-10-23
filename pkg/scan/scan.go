// Package scan finds the certificates under a directory and returns them as
// a trustsmith.scan/v1 document (ADR-0014, ADR-0015).
//
// The document is exactly what `trustsmith scan --output json --fail-on never`
// prints, so the JSON contract and its compatibility rules are the whole
// promise: fields are only ever added within v1. Decode it with your own
// types and ignore properties you do not know (docs/integrations/sybil.md).
package scan

import (
	"time"

	"github.com/Hazame-hub/trustsmith/pkg/internal/runcli"
)

// Schema is the value of the "schema" property of every document Directory
// returns.
const Schema = "trustsmith.scan/v1"

// Options configure a scan. The zero value is the CLI's behaviour.
type Options struct {
	// Now is the clock that validity is evaluated against; nil uses
	// time.Now.
	Now func() time.Time
}

// Directory scans path, a directory or a single file, under the same limits
// as the CLI: symbolic links are never followed, files over 8 MiB are
// skipped and the scan stops after 100,000 files, all of which the document
// reports. Nothing outside path is read and nothing is written. Findings never
// make it fail; an error means the scan could not run at all.
func Directory(path string, opts Options) ([]byte, error) {
	return runcli.JSON(opts.Now, "scan", "--output", "json", "--fail-on", "never", "--", path)
}
