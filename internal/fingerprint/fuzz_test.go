package fingerprint_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
)

// FuzzCanonicalSPKI asserts that the canonicaliser never panics, only fails
// with ErrUnsupported or ErrMalformed, never yields a KeyID without a
// canonical form, and is idempotent.
func FuzzCanonicalSPKI(f *testing.F) {
	for _, pattern := range []string{
		filepath.Join("testdata", "vectors", "*", "spki.der"),
		filepath.Join("testdata", "unsupported", "*.der"),
	} {
		files, err := filepath.Glob(pattern)
		if err != nil {
			f.Fatal(err)
		}
		for _, name := range files {
			b, err := os.ReadFile(name)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(b)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, spki []byte) {
		canonical, err := fingerprint.CanonicalSPKI(spki)
		if err != nil {
			if !errors.Is(err, fingerprint.ErrUnsupported) && !errors.Is(err, fingerprint.ErrMalformed) {
				t.Fatalf("unexpected error class: %v", err)
			}
			if _, keyErr := fingerprint.KeyIDFromSPKI(spki); keyErr == nil {
				t.Fatal("a KeyID was produced for input with no canonical form")
			}
			return
		}
		again, err := fingerprint.CanonicalSPKI(canonical)
		if err != nil || !bytes.Equal(again, canonical) {
			t.Fatalf("canonical form is not a fixed point: %v", err)
		}
		fromInput, err1 := fingerprint.KeyIDFromSPKI(spki)
		fromCanonical, err2 := fingerprint.KeyIDFromSPKI(canonical)
		if err1 != nil || err2 != nil || fromInput != fromCanonical {
			t.Fatalf("KeyID differs between an encoding and its canonical form (%v, %v)", err1, err2)
		}
	})
}
