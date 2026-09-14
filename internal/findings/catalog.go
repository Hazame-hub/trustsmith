package findings

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"slices"
)

// Action is a suggested remediation, with a stable code and human text.
type Action struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

// Description is the human explanation of a code.
type Description struct {
	Title       string   `json:"title"`
	Explanation string   `json:"explanation"`
	Remediation []Action `json:"remediation"`
}

//go:embed catalog.json
var catalogJSON []byte

var catalog = loadCatalog()

// loadCatalog parses the embedded catalog. The catalog is compiled into the
// binary and validated by the package tests, so a failure here is a build
// defect, not bad input.
func loadCatalog() map[Code]Description {
	dec := json.NewDecoder(bytes.NewReader(catalogJSON))
	dec.DisallowUnknownFields()
	var m map[Code]Description
	if err := dec.Decode(&m); err != nil {
		panic("findings: embedded catalog.json is invalid: " + err.Error())
	}
	return m
}

// Describe returns the human text for a code.
func Describe(c Code) (Description, bool) {
	d, ok := catalog[c]
	return d, ok
}

// Codes returns every catalogued code, sorted.
func Codes() []Code {
	out := make([]Code, 0, len(catalog))
	for c := range catalog {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}
