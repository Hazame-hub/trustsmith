// Package runcli runs one Trustsmith command in process and returns its
// standard output. It is how the public packages under pkg/ reach the JSON
// contracts without exposing the internal packages that build them
// (ADR-0015).
package runcli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Hazame-hub/trustsmith/internal/cli"
)

// JSON runs args with the given clock and returns what the command wrote to
// standard output. Any exit other than ExitOK is an error carrying the
// command's own message; callers pass --fail-on never, so findings never
// cause one.
func JSON(now func() time.Time, args ...string) ([]byte, error) {
	if now == nil {
		now = time.Now
	}
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, bytes.NewReader(nil), &stdout, &stderr, cli.Env{Now: now, Version: "library"})
	if code != cli.ExitOK {
		msg := strings.TrimSpace(strings.TrimPrefix(stderr.String(), "trustsmith: "))
		if msg == "" {
			msg = fmt.Sprintf("exit code %d", code)
		}
		return nil, errors.New(msg)
	}
	return stdout.Bytes(), nil
}
