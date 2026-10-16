// Package scansvc finds certificate files under a directory and inspects
// each one through inspectsvc (ADR-0014). It answers "which certificates are
// here, and which expire first?" for a directory the user names, and never
// looks anywhere else.
package scansvc

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/artifact"
)

// Limits bound a scan, so pointing it at / cannot run without end.
type Limits struct {
	MaxFiles int // regular files examined; the scan stops, and says so, after this many
}

// DefaultLimits are the CLI's limits.
func DefaultLimits() Limits { return Limits{MaxFiles: 100_000} }

// derExtensions are the extensions under which a file without PEM armour is
// still examined as possible DER. Any file with PEM certificate armour is
// examined whatever its name.
var derExtensions = []string{".der", ".cer", ".crt", ".cert"}

var pemCertificateMarker = []byte("-----BEGIN CERTIFICATE-----")

// File is one certificate file and its inspection.
type File struct {
	Path       string // as walked: the root joined with the relative path
	Inspection inspectsvc.Result
}

// FileError is a path that could not be examined.
type FileError struct {
	Path string
	Err  string
}

// Result is a complete scan.
type Result struct {
	Root            string
	FilesExamined   int // regular files read or considered
	Files           []File
	SkippedSymlinks int // symbolic links are never followed
	SkippedTooLarge int // files over artifact.MaxInputBytes
	Errors          []FileError
	LimitReached    bool
}

// Scan walks root and inspects every certificate file under it with svc.
// root may also be a single file.
func Scan(svc *inspectsvc.Service, root string, limits Limits) (Result, error) {
	res := Result{Root: root, Files: []File{}, Errors: []FileError{}}
	info, err := os.Lstat(root)
	if err != nil {
		return Result{}, err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		// The root the user named is followed once; links inside it are not.
		if info, err = os.Stat(root); err != nil {
			return Result{}, err
		}
	}
	if !info.IsDir() {
		res.FilesExamined = 1
		scanFile(svc, root, info.Size(), &res)
		return res, nil
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			res.Errors = append(res.Errors, FileError{Path: path, Err: errText(err)})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			res.SkippedSymlinks++
			return nil
		case d.IsDir() || !d.Type().IsRegular():
			return nil
		}
		if res.FilesExamined >= limits.MaxFiles {
			res.LimitReached = true
			return fs.SkipAll
		}
		res.FilesExamined++
		info, err := d.Info()
		if err != nil {
			res.Errors = append(res.Errors, FileError{Path: path, Err: errText(err)})
			return nil
		}
		scanFile(svc, path, info.Size(), &res)
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	slices.SortFunc(res.Errors, func(a, b FileError) int { return strings.Compare(a.Path, b.Path) })
	return res, nil
}

func scanFile(svc *inspectsvc.Service, path string, size int64, res *Result) {
	if size > artifact.MaxInputBytes {
		res.SkippedTooLarge++
		return
	}
	data, err := readFile(path)
	if err != nil {
		res.Errors = append(res.Errors, FileError{Path: path, Err: errText(err)})
		return
	}
	if !bytes.Contains(data, pemCertificateMarker) {
		if !slices.Contains(derExtensions, strings.ToLower(filepath.Ext(path))) {
			return
		}
		if d, err := artifact.Decode(data); err != nil || d.Format != artifact.FormatDER || len(d.Blocks) == 0 || d.Blocks[0].Kind != artifact.KindCertificate {
			return
		}
	}
	insp, err := svc.InspectBytes(inspectsvc.Source{Kind: inspectsvc.SourceFile, Locator: path}, data)
	if err != nil {
		res.Errors = append(res.Errors, FileError{Path: path, Err: errText(err)})
		return
	}
	res.Files = append(res.Files, File{Path: path, Inspection: insp})
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a file under the directory the user named
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, artifact.MaxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > artifact.MaxInputBytes {
		return nil, artifact.ErrTooLarge
	}
	return data, nil
}

// errText keeps the operating system's reason without repeating the path.
func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
