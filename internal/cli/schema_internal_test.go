package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// The published JSON Schema of trustsmith.inspect/v1 is derived from the
// contract types in render_json.go, so it cannot drift from what the CLI
// emits. Integrations (Sybil among them) validate against the committed file.
var schemaPath = filepath.Join("..", "..", "docs", "schema", "trustsmith.inspect.v1.schema.json")

func TestInspectSchemaIsCurrent(t *testing.T) {
	got := inspectJSONSchema(t)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(schemaPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(schemaPath, got, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("missing %s (run with UPDATE_GOLDEN=1): %v", schemaPath, err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Errorf("%s is out of date with render_json.go (run with UPDATE_GOLDEN=1 to regenerate)", schemaPath)
	}
}

// Every JSON golden is real CLI output; each must validate against the
// committed schema. This catches a contract type whose runtime shape differs
// from its declaration (a nil slice rendered as null, for instance).
func TestJSONGoldensValidateAgainstSchema(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	goldens, err := filepath.Glob(filepath.Join("testdata", "golden", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(goldens) == 0 {
		t.Fatal("no JSON goldens found")
	}
	for _, path := range goldens {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		v := validator{defs: schema["$defs"].(map[string]any)}
		v.validate(schema, doc, "$")
		for _, e := range v.errs {
			t.Errorf("%s: %s", filepath.Base(path), e)
		}
	}
}

func inspectJSONSchema(t *testing.T) []byte {
	t.Helper()
	g := schemaGen{defs: map[string]any{}}
	root := g.object(reflect.TypeFor[jsonInspect]())
	doc := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://github.com/Hazame-hub/trustsmith/blob/main/docs/schema/trustsmith.inspect.v1.schema.json",
		"title":       "trustsmith.inspect/v1",
		"description": "Output of `trustsmith inspect --output json`. Generated from internal/cli/render_json.go; do not edit by hand. Fields may be added within v1, so consumers must ignore properties they do not know; renaming, removing or changing the meaning of one requires v2.",
	}
	for k, v := range root {
		doc[k] = v
	}
	doc["properties"].(map[string]any)["schema"] = map[string]any{"const": inspectSchema}
	doc["$defs"] = g.defs
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

type schemaGen struct{ defs map[string]any }

func defName(t reflect.Type) string {
	name := strings.TrimPrefix(t.Name(), "json")
	var b strings.Builder
	for i, r := range name {
		if unicode.IsUpper(r) {
			if i > 0 && !unicode.IsUpper(rune(name[i-1])) {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (g *schemaGen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	required := []string{}
	for f := range t.Fields() {
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		props[name] = g.of(f.Type)
		if !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   required,
	}
}

func (g *schemaGen) of(t reflect.Type) map[string]any {
	switch t.Kind() {
	case reflect.Pointer:
		inner := g.of(t.Elem())
		if typ, ok := inner["type"].(string); ok && len(inner) == 1 {
			return map[string]any{"type": []string{typ, "null"}}
		}
		return map[string]any{"anyOf": []any{inner, map[string]any{"type": "null"}}}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": g.of(t.Elem())}
	case reflect.Struct:
		name := defName(t)
		if _, ok := g.defs[name]; !ok {
			g.defs[name] = nil // reserve against recursion
			g.defs[name] = g.object(t)
		}
		return map[string]any{"$ref": "#/$defs/" + name}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint16, reflect.Uint8:
		return map[string]any{"type": "integer"}
	}
	panic(fmt.Sprintf("schema: unsupported kind %s in %s", t.Kind(), t))
}

// validator checks the subset of JSON Schema the generator emits. It is
// stricter than the published schema: a property the schema does not declare
// is an error here, because the CLI must never emit an undeclared field, while
// consumers are told to ignore fields added later within v1.
type validator struct {
	defs map[string]any
	errs []string
}

func (v *validator) fail(at, format string, args ...any) {
	v.errs = append(v.errs, at+": "+fmt.Sprintf(format, args...))
}

func (v *validator) validate(s map[string]any, val any, at string) {
	if ref, ok := s["$ref"].(string); ok {
		v.validate(v.defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any), val, at)
		return
	}
	if c, ok := s["const"]; ok && c != val {
		v.fail(at, "want %v, got %v", c, val)
	}
	if alts, ok := s["anyOf"].([]any); ok {
		for _, alt := range alts {
			sub := validator{defs: v.defs}
			sub.validate(alt.(map[string]any), val, at)
			if len(sub.errs) == 0 {
				return
			}
		}
		v.fail(at, "matches no alternative")
		return
	}
	if typ, ok := s["type"]; ok && !typeMatches(typ, val) {
		v.fail(at, "want type %v, got %T", typ, val)
		return
	}
	switch val := val.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		for _, r := range s["required"].([]any) {
			if _, ok := val[r.(string)]; !ok {
				v.fail(at, "missing required %q", r)
			}
		}
		for k, sub := range val {
			ps, ok := props[k]
			if !ok {
				v.fail(at, "unexpected property %q", k)
				continue
			}
			v.validate(ps.(map[string]any), sub, at+"."+k)
		}
	case []any:
		for i, item := range val {
			v.validate(s["items"].(map[string]any), item, fmt.Sprintf("%s[%d]", at, i))
		}
	}
}

func typeMatches(typ, val any) bool {
	var types []string
	switch t := typ.(type) {
	case string:
		types = []string{t}
	case []any:
		for _, x := range t {
			types = append(types, x.(string))
		}
	}
	var got string
	switch val := val.(type) {
	case nil:
		got = "null"
	case bool:
		got = "boolean"
	case string:
		got = "string"
	case float64:
		got = "number"
		if val == float64(int64(val)) && slices.Contains(types, "integer") {
			got = "integer"
		}
	case []any:
		got = "array"
	case map[string]any:
		got = "object"
	}
	return slices.Contains(types, got)
}

// The validator must reject what the schema forbids, or the golden check
// above proves nothing.
func TestSchemaValidatorRejects(t *testing.T) {
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"wrong schema":     `{"schema":"trustsmith.inspect/v2"}`,
		"extra property":   `{"unexpected":1}`,
		"wrong type":       `{"inspected_at":3}`,
		"missing required": `{}`,
	} {
		var val any
		if err := json.Unmarshal([]byte(doc), &val); err != nil {
			t.Fatal(err)
		}
		v := validator{defs: schema["$defs"].(map[string]any)}
		v.validate(schema, val, "$")
		if len(v.errs) == 0 {
			t.Errorf("%s: %s validated", name, doc)
		}
	}
}
