package artifact_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Hazame-hub/trustsmith/internal/artifact"
)

// FuzzDecode asserts the decoder never panics and its output is always
// internally consistent, whatever the input.
func FuzzDecode(f *testing.F) {
	der := newCertDER(f, "seed")
	for _, seed := range [][]byte{
		nil,
		[]byte("\xef\xbb\xbf"),
		der,
		pemOf("CERTIFICATE", der),
		append(pemOf("CERTIFICATE", der), pemOf("PRIVATE KEY", []byte{1})...),
		[]byte("-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\nMIIB\n"),
		[]byte("-----BEGIN -----\n-----END -----\n"),
		[]byte("-----BEGIN A-----\n-----BEGIN B-----\n-----END A-----\n-----END B-----\n"),
		{0x30, 0x80, 0x00, 0x00},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := artifact.Decode(data)
		if err != nil {
			if !errors.Is(err, artifact.ErrTooLarge) && !errors.Is(err, artifact.ErrTooManyBlocks) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		prev := -1
		for i, b := range d.Blocks {
			if b.Entry != i || b.Offset <= prev || b.Offset >= len(data) {
				t.Fatalf("block %d inconsistent: %+v (len %d)", i, b, len(data))
			}
			prev = b.Offset
			switch b.Kind {
			case artifact.KindCertificate:
				if len(b.DER) == 0 || b.Problem != "" {
					t.Fatalf("certificate block %d has no DER or has a problem", i)
				}
			case artifact.KindMalformed:
				if b.Problem == "" || b.DER != nil {
					t.Fatalf("malformed block %d without problem or with DER", i)
				}
			case artifact.KindUnsupported:
				if b.DER != nil {
					t.Fatalf("unsupported block %d exposes bytes", i)
				}
			default:
				t.Fatalf("block %d has unknown kind %q", i, b.Kind)
			}
		}
		for _, e := range d.Extraneous {
			if e.Offset < 0 || e.Length <= 0 || e.Offset+e.Length > len(data) {
				t.Fatalf("extraneous span out of range: %+v", e)
			}
			if len(bytes.TrimSpace(data[e.Offset:e.Offset+e.Length])) != e.Length {
				t.Fatalf("extraneous span is not trimmed: %+v", e)
			}
		}
	})
}
