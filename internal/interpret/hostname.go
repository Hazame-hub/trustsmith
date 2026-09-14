package interpret

import (
	"strings"

	"github.com/Hazame-hub/trustsmith/internal/findings"
	"github.com/Hazame-hub/trustsmith/internal/hostname"
)

// Hostname turns a host name identity result into findings: one finding when
// the certificate does not identify the requested name. A match is not a
// finding. The evidence names the request and the certificate's subject
// alternative names of the requested kind; Go's error text is never used.
func Hostname(entry int, r hostname.Request, res hostname.Result) []findings.Finding {
	if res.State != hostname.Mismatch {
		return nil
	}
	evidence := []findings.Evidence{
		ev("requested", r.Input),
		ev("normalized", r.Normalized),
		ev("kind", string(r.Kind)),
	}
	if r.Kind == hostname.KindIP {
		evidence = append(evidence, ev("certificate_ip_addresses", strings.Join(res.IPAddresses, ",")))
	} else {
		evidence = append(evidence, ev("certificate_dns_names", strings.Join(res.DNSNames, ",")))
	}
	if res.CommonNameIgnored {
		evidence = append(evidence, ev("common_name_ignored", "true"))
	}
	return []findings.Finding{finding(entry, findings.NameHostnameMismatch, findings.SeverityCritical, evidence...)}
}
