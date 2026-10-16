package cli

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Hazame-hub/trustsmith/internal/app/inspectsvc"
	"github.com/Hazame-hub/trustsmith/internal/app/scansvc"
	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/fingerprint"
	"github.com/Hazame-hub/trustsmith/internal/interpret"
)

// scanSchema versions the JSON contract of `trustsmith scan`, under the same
// rules as trustsmith.inspect/v1.
const scanSchema = "trustsmith.scan/v1"

func newScanCommand(stdout io.Writer, env Env) *cobra.Command {
	var (
		output, failOn string
		within         int
	)
	cmd := &cobra.Command{
		Use:   "scan <directory|file>",
		Short: "Find the certificates under a directory and list them by expiry",
		Long: `Find every certificate file under a directory, inspect each one exactly as
'trustsmith inspect <file>' would, and list the certificates soonest-expiring
first with the most severe finding for each (ADR-0014).

A file is examined when it contains PEM certificate armour, whatever its name,
or when it is named *.der, *.cer, *.crt or *.cert and holds a DER certificate.
Symbolic links inside the directory are never followed, files over 8 MiB are
skipped, and the scan stops after 100,000 files; the summary counts all three.
Nothing outside the named directory is read and nothing is written.

As with inspect, trust is not evaluated (no system trust store is used), so a
scan reports what each certificate contains and when it expires, not whether
anything trusts it.

--expiring-within N lists only certificates expired or expiring within N
days; findings and --fail-on still cover every certificate scanned.

Exit codes: 0 no finding at or above --fail-on, 1 operational error, 2 usage
error, 3 findings reached --fail-on.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageError{fmt.Errorf("scan takes exactly one directory or file, got %d", len(args))}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if output != "text" && output != "json" {
				return usageError{fmt.Errorf("invalid --output %q: want text or json", output)}
			}
			threshold, err := parseFailOn(failOn)
			if err != nil {
				return usageError{err}
			}
			if cmd.Flags().Changed("expiring-within") && within < 0 {
				return usageError{errors.New("--expiring-within must be zero or more days")}
			}
			svc := inspectsvc.New(env.Now)
			res, err := scansvc.Scan(svc, args[0], scansvc.DefaultLimits())
			if err != nil {
				return operationalError{err}
			}
			view := newScanView(res, env.Now().UTC())
			if cmd.Flags().Changed("expiring-within") {
				view.filter(within)
			}
			if output == "json" {
				err = renderScanJSON(stdout, view)
			} else {
				err = renderScanText(stdout, view)
			}
			if err != nil {
				return operationalError{err}
			}
			if threshold != "" && view.highest != "" && view.highest.AtLeast(threshold) {
				return thresholdReached{}
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&output, "output", "o", "text", "output format: text or json")
	f.StringVar(&failOn, "fail-on", "critical", "exit 3 when any finding is at least this severe: info, warning, critical or never")
	f.IntVar(&within, "expiring-within", 0, "list only certificates expired or expiring within this many days")
	return cmd
}

// scanRow is one certificate found by a scan.
type scanRow struct {
	file        string
	entry       int
	fingerprint fingerprint.Cert
	summary     *interpret.Summary
	findings    []findings.Finding // this entry's findings, most severe first
}

// scanProblem is a finding that belongs to no listed certificate: about a
// whole file, or about a block that is not a parseable certificate.
type scanProblem struct {
	file    string
	finding findings.Finding
}

type scanView struct {
	res        scansvc.Result
	scannedAt  time.Time
	rows       []scanRow
	problems   []scanProblem
	total      int // certificates found, before any filter
	distinct   int // distinct certificates by fingerprint
	highest    findings.Severity
	counts     map[findings.Severity]int
	filteredTo *int
}

func newScanView(res scansvc.Result, now time.Time) *scanView {
	v := &scanView{res: res, scannedAt: now, counts: map[findings.Severity]int{}}
	seen := map[fingerprint.Cert]bool{}
	for _, f := range res.Files {
		insp := f.Inspection
		listed := map[int]bool{}
		for _, a := range insp.Artifacts {
			if a.Summary == nil || a.Certificate == nil {
				continue
			}
			listed[a.Entry] = true
			row := scanRow{file: f.Path, entry: a.Entry, fingerprint: a.Certificate.Fingerprint, summary: a.Summary}
			for _, fd := range insp.Findings {
				if fd.Entry == a.Entry {
					row.findings = append(row.findings, fd)
				}
			}
			v.rows = append(v.rows, row)
			if !seen[row.fingerprint] {
				seen[row.fingerprint] = true
				v.distinct++
			}
		}
		for _, fd := range insp.Findings {
			v.counts[fd.Severity]++
			if v.highest == "" || !v.highest.AtLeast(fd.Severity) {
				v.highest = fd.Severity
			}
			if !listed[fd.Entry] {
				v.problems = append(v.problems, scanProblem{file: f.Path, finding: fd})
			}
		}
	}
	v.total = len(v.rows)
	slices.SortStableFunc(v.rows, func(a, b scanRow) int {
		return cmp.Or(a.summary.Validity.NotAfter.Compare(b.summary.Validity.NotAfter),
			strings.Compare(a.file, b.file), cmp.Compare(a.entry, b.entry))
	})
	return v
}

func (v *scanView) filter(days int) {
	v.filteredTo = &days
	v.rows = slices.DeleteFunc(v.rows, func(r scanRow) bool { return r.summary.Validity.DaysRemaining > days })
}

func (r scanRow) worst() (string, string) {
	if len(r.findings) == 0 {
		return "ok", ""
	}
	return string(r.findings[0].Severity), string(r.findings[0].Code)
}

func (r scanRow) names() string {
	names := []rune(strings.Join(r.summary.Identifies, ", "))
	if len(names) > 48 {
		return string(names[:45]) + "..."
	}
	return string(names)
}

func (r scanRow) locator() string {
	return fmt.Sprintf("%s#%d", r.file, r.entry)
}

func renderScanText(w io.Writer, v *scanView) error {
	res := v.res
	p := &printer{w: w}
	p.linef("Scanned %s at %s", res.Root, v.scannedAt.Format(humanTime))
	p.linef("  %d files examined, %d with certificates, %d certificates (%d distinct)",
		res.FilesExamined, len(res.Files), v.total, v.distinct)
	p.linef("  skipped: %d symbolic links (never followed), %d files over 8 MiB; %d unreadable",
		res.SkippedSymlinks, res.SkippedTooLarge, len(res.Errors))
	if res.LimitReached {
		p.linef("  the scan stopped after %d files; the list is incomplete", res.FilesExamined)
	}
	p.linef("  trust is not evaluated: certificates are listed by what they contain, not by who trusts them")
	if p.err != nil {
		return p.err
	}
	p.linef("")
	if v.filteredTo != nil {
		p.linef("Certificates expired or expiring within %d days (%d of %d)", *v.filteredTo, len(v.rows), v.total)
	} else {
		p.linef("Certificates, soonest expiry first (%d)", len(v.rows))
	}
	if len(v.rows) == 0 {
		p.linef("  none")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  EXPIRES\tDAYS\tWORST\tFINDING\tNAMES\tFILE")
		for _, r := range v.rows {
			sev, code := r.worst()
			_, _ = fmt.Fprintf(tw, "  %s\t%d\t%s\t%s\t%s\t%s\n", r.summary.Validity.NotAfter.Format(time.DateOnly),
				r.summary.Validity.DaysRemaining, sev, code, r.names(), r.locator())
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(v.problems) > 0 {
		p.linef("")
		p.linef("Other findings (%d)", len(v.problems))
		for _, pr := range v.problems {
			where := pr.file
			if pr.finding.Entry != findings.WholeInput {
				where = fmt.Sprintf("%s#%d", pr.file, pr.finding.Entry)
			}
			p.linef("  %-8s  %-30s  %s", strings.ToUpper(string(pr.finding.Severity)), pr.finding.Code, where)
		}
	}
	if len(res.Errors) > 0 {
		p.linef("")
		p.linef("Unreadable (%d)", len(res.Errors))
		for _, e := range res.Errors {
			p.linef("  %s: %s", e.Path, e.Err)
		}
	}
	p.linef("")
	p.linef("Findings: %d critical, %d warning, %d info. Explain one: trustsmith inspect <file>",
		v.counts[findings.SeverityCritical], v.counts[findings.SeverityWarning], v.counts[findings.SeverityInfo])
	return p.err
}

type jsonScan struct {
	Schema    string `json:"schema"`
	ScannedAt string `json:"scanned_at"`
	// Path is the directory or file the user asked to scan.
	Path     string           `json:"path"`
	Overview jsonScanOverview `json:"overview"`
	// ExpiringWithin is the --expiring-within filter applied to
	// certificates; null when none was.
	ExpiringWithin *int              `json:"expiring_within"`
	Certificates   []jsonScanCert    `json:"certificates"`
	Problems       []jsonScanProblem `json:"problems"`
	Errors         []jsonScanError   `json:"errors"`
}

type jsonScanOverview struct {
	FilesExamined        int    `json:"files_examined"`
	CertificateFiles     int    `json:"certificate_files"`
	Certificates         int    `json:"certificates"`
	DistinctCertificates int    `json:"distinct_certificates"`
	SkippedSymlinks      int    `json:"skipped_symlinks"`
	SkippedTooLarge      int    `json:"skipped_too_large"`
	LimitReached         bool   `json:"limit_reached"`
	Findings             int    `json:"findings"`
	HighestSeverity      string `json:"highest_severity"`
	Trust                string `json:"trust"` // always not_evaluated
}

type jsonScanCert struct {
	File        string            `json:"file"`
	Entry       int               `json:"entry"`
	Fingerprint string            `json:"x509-cert-sha256"`
	Kind        string            `json:"kind"`
	Identifies  []string          `json:"identifies"`
	Issuer      string            `json:"issuer_as_stated"`
	Validity    jsonValidity      `json:"validity"` // as summary.validity in trustsmith.inspect/v1
	Findings    []jsonScanFinding `json:"findings"`
}

type jsonScanFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
}

type jsonScanProblem struct {
	File     string `json:"file"`
	Entry    *int   `json:"entry"` // null when the finding concerns the whole file
	Code     string `json:"code"`
	Severity string `json:"severity"`
}

type jsonScanError struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

func renderScanJSON(w io.Writer, v *scanView) error {
	res := v.res
	doc := jsonScan{
		Schema: scanSchema, ScannedAt: stamp(v.scannedAt), Path: res.Root,
		Overview: jsonScanOverview{
			FilesExamined: res.FilesExamined, CertificateFiles: len(res.Files),
			Certificates: v.total, DistinctCertificates: v.distinct,
			SkippedSymlinks: res.SkippedSymlinks, SkippedTooLarge: res.SkippedTooLarge,
			LimitReached: res.LimitReached, HighestSeverity: string(v.highest), Trust: "not_evaluated",
			Findings: v.counts[findings.SeverityCritical] + v.counts[findings.SeverityWarning] + v.counts[findings.SeverityInfo],
		},
		ExpiringWithin: v.filteredTo,
		Certificates:   []jsonScanCert{}, Problems: []jsonScanProblem{}, Errors: []jsonScanError{},
	}
	if doc.Overview.HighestSeverity == "" {
		doc.Overview.HighestSeverity = "none"
	}
	for _, r := range v.rows {
		c := jsonScanCert{File: r.file, Entry: r.entry, Fingerprint: r.fingerprint.Hex(), Kind: r.summary.Kind,
			Identifies: r.summary.Identifies, Issuer: r.summary.Issuer,
			Validity: jsonValidity{State: string(r.summary.Validity.State), NotBefore: stamp(r.summary.Validity.NotBefore),
				NotAfter: stamp(r.summary.Validity.NotAfter), DaysRemaining: r.summary.Validity.DaysRemaining},
			Findings: []jsonScanFinding{}}
		if c.Identifies == nil {
			c.Identifies = []string{}
		}
		for _, fd := range r.findings {
			c.Findings = append(c.Findings, jsonScanFinding{Code: string(fd.Code), Severity: string(fd.Severity)})
		}
		doc.Certificates = append(doc.Certificates, c)
	}
	for _, pr := range v.problems {
		jp := jsonScanProblem{File: pr.file, Code: string(pr.finding.Code), Severity: string(pr.finding.Severity)}
		if pr.finding.Entry != findings.WholeInput {
			e := pr.finding.Entry
			jp.Entry = &e
		}
		doc.Problems = append(doc.Problems, jp)
	}
	for _, e := range res.Errors {
		doc.Errors = append(doc.Errors, jsonScanError{Path: e.Path, Error: e.Err})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
