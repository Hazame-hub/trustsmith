package cli

import (
	"fmt"
	"io"
)

// printer writes lines and keeps the first error, so a renderer can write
// many lines and check once.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) linef(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
	}
}
