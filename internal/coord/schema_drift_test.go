package coord_test

// Schema drift guard (docs/schema.sql vs the embedded engine's persisted records).
//
// The PostgreSQL DDL in docs/schema.sql is the normative model; the embedded
// engine persists JSON records whose field names are the embedded layout. This
// test parses both sides statically (no package imports, so it cannot create a
// dependency on any of them) and fails when a persisted field has no matching
// column. Intentional divergences must be declared in one of the tables below,
// which makes every divergence reviewable instead of accidental:
//
//	renames    field is stored under a clearer SQL column name;
//	normalized field is stored in a child table (ACLs, tags, ring membership);
//	expand     field is a nested record that the relational model flattens.
//
// Adding a field to a record struct without touching docs/schema.sql now fails
// the coordinator test suite — the migration-pain guard the Lead asked for.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// goTypeToTable maps a persisted Go record type to its relational table.
var goTypeToTable = map[string]string{
	"Swarm":             "swarms",
	"Nexus":             "nexuses",
	"Node":              "nodes",
	"Agent":             "agents",
	"Ring":              "rings",
	"RedundancyClass":   "redundancy_classes",
	"Tenant":            "tenants",
	"AccessKey":         "access_keys",
	"Policy":            "iam_policies",
	"Bucket":            "buckets",
	"latestRecord":      "objects",
	"versionRecord":     "object_versions",
	"uploadRecord":      "uploads",
	"partRecord":        "upload_parts",
	"DeletionItem":      "deletion_queue",
	"shardStatusRecord": "shard_status",
}

// renames maps "<Type>.<json field>" to the SQL column that stores it.
var renames = map[string]string{
	"Tenant.key_seed":            "key_seed_wrapped",
	"AccessKey.secret":           "secret_wrapped",
	"Bucket.lifecycle":           "lifecycle_xml",
	"latestRecord.version_id":    "latest_version_id",
	"latestRecord.delete_marker": "is_delete_marker",
	"uploadRecord.created_at":    "initiated_at",
	"Ring.capacity":              "capacity_bytes",
	"Agent.last_seen":            "last_seen_at",
	"Agent.state_changed":        "state_changed_at",
	"Agent.secret_expires":       "secret_expires_at",
	"Retention.mode":             "retention_mode",
}

// normalized records fields stored in a child table by the relational model.
var normalized = map[string]string{
	"Bucket.acl":         "bucket_acls",
	"Agent.ring_ids":     "ring_agents",
	"versionRecord.tags": "object_tags",
	"versionRecord.acl":  "object_acls",
	"Ring.agent_ids":     "ring_agents",
}

// expand records nested records that the relational model flattens into the
// parent table. The synthetic type name in renames is "<Type><Field>".
var expand = map[string]string{
	"RedundancyClass.params":  "Params",
	"versionRecord.retention": "Retention",
	"uploadRecord.meta":       "CommitTemplate",
}

// scanDirs are the source directories that contain persisted record structs.
var scanDirs = []string{
	"meta",
	"membership",
	"auth",
	"../contract",
	"../ec",
}

// schemaPath is relative to internal/coord (the test's working directory).
const schemaPath = "../../docs/schema.sql"

// ---------------------------------------------------------------------------
// SQL parsing
// ---------------------------------------------------------------------------

var createTableRE = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+([a-z_][a-z0-9_]*)\s*\(`)

var skipColumnPrefixes = []string{
	"CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "EXCLUDE", "LIKE",
}

// parseSchema returns table -> set of columns.
func parseSchema(t *testing.T, ddl string) map[string]map[string]bool {
	t.Helper()
	// Strip line and inline comments; both would otherwise be parsed as column
	// definitions (the schema annotates many columns).
	var b strings.Builder
	for _, line := range strings.Split(ddl, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		b.WriteString(stripSQLComment(line))
		b.WriteString("\n")
	}
	clean := b.String()

	out := make(map[string]map[string]bool)
	for _, loc := range createTableRE.FindAllStringSubmatchIndex(clean, -1) {
		name := clean[loc[2]:loc[3]]
		open := loc[1] - 1 // index of '('
		body, end := parenBody(clean, open)
		if end < 0 {
			t.Fatalf("schema: unterminated CREATE TABLE %s", name)
		}
		cols := make(map[string]bool)
		for _, item := range splitTopLevel(body) {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			upper := strings.ToUpper(item)
			skip := false
			for _, p := range skipColumnPrefixes {
				if strings.HasPrefix(upper, p) {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			fields := strings.Fields(item)
			if len(fields) == 0 {
				continue
			}
			cols[strings.ToLower(fields[0])] = true
		}
		out[name] = cols
	}
	if len(out) < 20 {
		t.Fatalf("schema: parsed only %d tables from %s — parser or file shape broke", len(out), schemaPath)
	}
	return out
}

// stripSQLComment removes a trailing -- comment that is outside a quoted string.
func stripSQLComment(line string) string {
	inQuote := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			inQuote = !inQuote
		case '-':
			if !inQuote && i+1 < len(line) && line[i+1] == '-' {
				return line[:i]
			}
		}
	}
	return line
}

// parenBody returns the content between the paren at open and its match.
func parenBody(s string, open int) (string, int) {
	depth := 0
	inQuote := false
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				depth++
			}
		case ')':
			if !inQuote {
				depth--
				if depth == 0 {
					return s[open+1 : i], i
				}
			}
		}
	}
	return "", -1
}

// splitTopLevel splits on commas that are not inside parentheses or quotes.
func splitTopLevel(s string) []string {
	var out []string
	depth := 0
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			inQuote = !inQuote
		case '(':
			if !inQuote {
				depth++
			}
		case ')':
			if !inQuote {
				depth--
			}
		case ',':
			if depth == 0 && !inQuote {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// ---------------------------------------------------------------------------
// Go AST parsing
// ---------------------------------------------------------------------------

type goField struct {
	name     string
	jsonName string
	typ      string // resolved type name, or "" for non-struct
	embedded bool
}

// parseGoStructs returns struct name -> fields for every struct in scanDirs.
func parseGoStructs(t *testing.T) map[string][]goField {
	t.Helper()
	out := make(map[string][]goField)
	fset := token.NewFileSet()
	for _, dir := range scanDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("schema drift: read %s: %v", dir, err)
		}
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, ent.Name())
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("schema drift: parse %s: %v", path, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					return true
				}
				var fields []goField
				for _, f := range st.Fields.List {
					jsonName := jsonTag(f)
					typ := typeName(f.Type)
					if len(f.Names) == 0 {
						fields = append(fields, goField{embedded: true, typ: typ, jsonName: jsonName})
						continue
					}
					for _, name := range f.Names {
						fields = append(fields, goField{name: name.Name, jsonName: jsonName, typ: typ})
					}
				}
				out[ts.Name.Name] = fields
				return true
			})
		}
	}
	if len(out) < 20 {
		t.Fatalf("schema drift: parsed only %d structs", len(out))
	}
	return out
}

func jsonTag(f *ast.Field) string {
	if f.Tag == nil {
		return ""
	}
	tag := strings.Trim(f.Tag.Value, "`")
	const prefix = `json:"`
	i := strings.Index(tag, prefix)
	if i < 0 {
		return ""
	}
	rest := tag[i+len(prefix):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	spec := rest[:j]
	if spec == "" {
		return ""
	}
	if k := strings.IndexByte(spec, ','); k >= 0 {
		spec = spec[:k]
	}
	return spec
}

// typeName returns the bare struct type name for ident/selector/pointer types.
func typeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return typeName(x.X)
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.ArrayType, *ast.MapType, *ast.InterfaceType, *ast.FuncType:
		return ""
	}
	return ""
}

// ---------------------------------------------------------------------------
// The drift check
// ---------------------------------------------------------------------------

func TestSchemaMatchesEmbeddedRecords(t *testing.T) {
	ddl, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", schemaPath, err)
	}
	tables := parseSchema(t, string(ddl))
	structs := parseGoStructs(t)

	var problems []string
	for typ, table := range goTypeToTable {
		fields, ok := structs[typ]
		if !ok {
			problems = append(problems, "type "+typ+" not found in scanned sources")
			continue
		}
		cols, ok := tables[table]
		if !ok {
			problems = append(problems, "table "+table+" (for "+typ+") missing from schema")
			continue
		}
		checkStruct(t, typ, "", fields, structs, cols, &problems)
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Errorf("schema drift: %s", p)
	}
}

// checkStruct verifies that every persisted JSON field of typ has a column.
// contextPrefix is used for expanded nested types (e.g. "versionRecordRetention").
func checkStruct(t *testing.T, typ, contextPrefix string, fields []goField, structs map[string][]goField, cols map[string]bool, problems *[]string) {
	t.Helper()
	for _, f := range fields {
		if f.embedded {
			nested, ok := structs[f.typ]
			if !ok {
				*problems = append(*problems, typ+": cannot resolve embedded type "+f.typ)
				continue
			}
			checkStruct(t, typ, contextPrefix, nested, structs, cols, problems)
			continue
		}
		if f.jsonName == "" {
			*problems = append(*problems, typ+"."+f.name+": persisted field has no json tag")
			continue
		}
		if f.jsonName == "-" {
			continue
		}
		key := typ + "." + f.jsonName
		ctxKey := contextPrefix + typ + "." + f.jsonName
		if _, ok := normalized[key]; ok {
			continue
		}
		column := f.jsonName
		if renamed, ok := renames[key]; ok {
			column = renamed
		}
		// A nested record that the relational model flattens: recurse instead of
		// requiring a column for the container field.
		if nestedType, ok := expand[key]; ok {
			if !cols[column] {
				nested, ok := structs[nestedType]
				if !ok {
					*problems = append(*problems, ctxKey+": expand target "+nestedType+" not found")
					continue
				}
				checkStruct(t, nestedType, "", nested, structs, cols, problems)
				continue
			}
		}
		if !cols[column] {
			*problems = append(*problems, ctxKey+" (json "+f.jsonName+") has no column "+column)
		}
	}
}
