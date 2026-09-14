//go:build windows

package probe

import (
	"errors"
	"syscall"
)

// Windows reports socket failures with WSA error codes.
const (
	wsaeConnReset   = syscall.Errno(10054) // WSAECONNRESET
	wsaeConnRefused = syscall.Errno(10061) // WSAECONNREFUSED
)

func isRefused(err error) bool { return errors.Is(err, wsaeConnRefused) }

func isReset(err error) bool { return errors.Is(err, wsaeConnReset) }
