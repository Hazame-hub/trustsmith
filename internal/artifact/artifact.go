// Package artifact frames untrusted input into ordered blocks — PEM blocks or
// one DER object — without deciding what the blocks mean or whether they are
// acceptable. Interpretation happens elsewhere.
//
// It does not use encoding/pem to find blocks: pem.Decode silently skips a
// corrupt block, which would turn "could not read this block" into "there was
// no block". Only the contents of CERTIFICATE blocks are decoded; blocks with
// any other label (including private keys) are reported by label alone.
package artifact

import (
	"bytes"
	"encoding/pem"
	"errors"
	"unicode"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// MaxInputBytes bounds the input Decode accepts.
	MaxInputBytes = 8 << 20
	// MaxBlocks bounds the number of PEM blocks Decode accepts.
	MaxBlocks = 10000
)

var (
	ErrTooLarge      = errors.New("input exceeds the maximum size")
	ErrTooManyBlocks = errors.New("input contains more PEM blocks than the maximum")
)

// Format is how the input as a whole was framed.
type Format string

const (
	FormatEmpty   Format = "empty"
	FormatPEM     Format = "pem"
	FormatDER     Format = "der"
	FormatUnknown Format = "unknown"
)

// Kind says what a block is, as far as framing can tell.
type Kind string

const (
	// KindCertificate: a PEM CERTIFICATE block, or DER shaped like a
	// certificate. Whether it actually parses is decided later.
	KindCertificate Kind = "certificate"
	// KindUnsupported: well-framed, but not something this version inspects.
	KindUnsupported Kind = "unsupported"
	// KindMalformed: could not be framed or decoded.
	KindMalformed Kind = "malformed"
)

// Problem says why a block is malformed.
type Problem string

const (
	ProblemBadArmour   Problem = "bad_armour"   // a BEGIN line that is not valid PEM armour
	ProblemMissingEnd  Problem = "missing_end"  // no matching END line before the next block or end of input
	ProblemBadEncoding Problem = "bad_encoding" // invalid base64/headers, or invalid DER
)

// Block is one framed unit of input, in input order.
type Block struct {
	Entry   int     // position among blocks, from 0
	Kind    Kind    //
	Label   string  // PEM label; empty for DER input
	Offset  int     // byte offset of the block in the input
	DER     []byte  // KindCertificate only
	Problem Problem // KindMalformed only
}

// Span locates non-whitespace input that belongs to no block.
type Span struct {
	Offset int
	Length int
}

// Decoded is the framing of an input.
type Decoded struct {
	Format     Format
	Blocks     []Block
	Extraneous []Span
}

const certificateLabel = "CERTIFICATE"

var (
	utf8BOM     = []byte{0xef, 0xbb, 0xbf}
	beginMarker = []byte("-----BEGIN ")
	armourEnd   = []byte("-----")
)

// Decode frames data. It returns an error only when a limit is exceeded;
// every other problem is reported per block.
func Decode(data []byte) (Decoded, error) {
	if len(data) > MaxInputBytes {
		return Decoded{}, ErrTooLarge
	}
	start := 0
	if bytes.HasPrefix(data, utf8BOM) {
		start = len(utf8BOM)
	}
	switch {
	case len(bytes.TrimSpace(data[start:])) == 0:
		return Decoded{Format: FormatEmpty}, nil
	case indexAtLineStart(data, start, start, beginMarker) >= 0:
		return decodePEM(data, start)
	case data[start] == 0x30:
		return decodeDER(data, start), nil
	default:
		return Decoded{Format: FormatUnknown}, nil
	}
}

func decodePEM(data []byte, start int) (Decoded, error) {
	d := Decoded{Format: FormatPEM}
	pos := start
	for {
		begin := indexAtLineStart(data, pos, start, beginMarker)
		if begin < 0 {
			d.addExtraneous(data, pos, len(data))
			return d, nil
		}
		d.addExtraneous(data, pos, begin)
		if len(d.Blocks) == MaxBlocks {
			return Decoded{}, ErrTooManyBlocks
		}

		headerEnd := lineEnd(data, begin)
		label, ok := armourLabel(data[begin:headerEnd])
		if !ok {
			d.add(Block{Kind: KindMalformed, Offset: begin, Problem: ProblemBadArmour})
			pos = headerEnd
			continue
		}

		end := indexAtLineStart(data, headerEnd, start, []byte("-----END "+label+"-----"))
		next := indexAtLineStart(data, headerEnd, start, beginMarker)
		if end < 0 || (next >= 0 && next < end) {
			d.add(Block{Kind: KindMalformed, Label: label, Offset: begin, Problem: ProblemMissingEnd})
			if next < 0 {
				pos = len(data)
			} else {
				pos = next
			}
			continue
		}

		stop := lineEnd(data, end)
		d.add(classifyPEM(label, begin, data[begin:stop]))
		pos = stop
	}
}

func classifyPEM(label string, offset int, raw []byte) Block {
	if label != certificateLabel {
		// Never decode other blocks: this version does not inspect them,
		// and some (private keys) must not be handled needlessly.
		return Block{Kind: KindUnsupported, Label: label, Offset: offset}
	}
	p, rest := pem.Decode(raw)
	if p == nil || p.Type != label || len(p.Bytes) == 0 || len(bytes.TrimSpace(rest)) != 0 {
		return Block{Kind: KindMalformed, Label: label, Offset: offset, Problem: ProblemBadEncoding}
	}
	return Block{Kind: KindCertificate, Label: label, Offset: offset, DER: p.Bytes}
}

func decodeDER(data []byte, start int) Decoded {
	d := Decoded{Format: FormatDER}
	input := cryptobyte.String(data[start:])
	var elem cryptobyte.String
	if !input.ReadASN1Element(&elem, cbasn1.SEQUENCE) {
		d.add(Block{Kind: KindMalformed, Offset: start, Problem: ProblemBadEncoding})
		return d
	}
	b := Block{Kind: KindUnsupported, Offset: start}
	if certificateShaped(elem) {
		b.Kind = KindCertificate
		b.DER = bytes.Clone(elem)
	}
	d.add(b)
	d.addExtraneous(data, start+len(elem), len(data))
	return d
}

// certificateShaped reports whether elem is SEQUENCE { SEQUENCE, SEQUENCE,
// BIT STRING } — the outer shape of an X.509 certificate (and of a CSR, which
// the caller tells apart by parsing).
func certificateShaped(elem cryptobyte.String) bool {
	var body, tbs, alg, sig cryptobyte.String
	return elem.ReadASN1(&body, cbasn1.SEQUENCE) &&
		body.ReadASN1(&tbs, cbasn1.SEQUENCE) &&
		body.ReadASN1(&alg, cbasn1.SEQUENCE) &&
		body.ReadASN1(&sig, cbasn1.BIT_STRING) &&
		body.Empty()
}

func (d *Decoded) add(b Block) {
	b.Entry = len(d.Blocks)
	d.Blocks = append(d.Blocks, b)
}

// addExtraneous records data[from:to] with surrounding whitespace removed, if
// anything remains.
func (d *Decoded) addExtraneous(data []byte, from, to int) {
	seg := data[from:to]
	left := bytes.TrimLeftFunc(seg, unicode.IsSpace)
	trimmed := bytes.TrimRightFunc(left, unicode.IsSpace)
	if len(trimmed) == 0 {
		return
	}
	d.Extraneous = append(d.Extraneous, Span{Offset: from + len(seg) - len(left), Length: len(trimmed)})
}

// indexAtLineStart finds marker at or after from, but only where it begins a
// line (at start, or right after '\n').
func indexAtLineStart(data []byte, from, start int, marker []byte) int {
	for from < len(data) {
		i := bytes.Index(data[from:], marker)
		if i < 0 {
			return -1
		}
		i += from
		if i == start || (i > 0 && data[i-1] == '\n') {
			return i
		}
		from = i + 1
	}
	return -1
}

// lineEnd returns the offset just past the '\n' ending the line at i, or
// len(data).
func lineEnd(data []byte, i int) int {
	if j := bytes.IndexByte(data[i:], '\n'); j >= 0 {
		return i + j + 1
	}
	return len(data)
}

// armourLabel extracts LABEL from a "-----BEGIN LABEL-----" line.
func armourLabel(line []byte) (string, bool) {
	line = bytes.TrimRight(line, " \t\r\n")
	if !bytes.HasPrefix(line, beginMarker) || !bytes.HasSuffix(line, armourEnd) ||
		len(line) < len(beginMarker)+len(armourEnd) {
		return "", false
	}
	label := line[len(beginMarker) : len(line)-len(armourEnd)]
	if len(label) == 0 || bytes.Contains(label, armourEnd) {
		return "", false
	}
	for _, c := range label {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(label), true
}
