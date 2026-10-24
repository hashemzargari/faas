package sdp

import (
	"strings"
	"testing"
)

const docsExample = `[
  {"id":"video-to-cold","enabled":true,"inputStorageClass":"STANDARD",
   "conditions":{"operator":"AND","conditions":[
      {"field":"object.key","operator":"matches_regex","value":"\\.(mp4|avi|mov)$"},
      {"operator":"OR","conditions":[
         {"field":"object.size","operator":"gt","value":104857600},
         {"field":"object.content_type","operator":"equals","value":"video/mp4"}]}]},
   "action":{"type":"route","target":{"type":"fixed","redundancyClassId":"rc-cold"}}},
  {"id":"drop-secrets","enabled":true,
   "conditions":{"field":"object.key","operator":"starts_with","value":"private/"},
   "action":{"type":"drop"}},
  {"id":"tenant-acme","enabled":true,
   "conditions":{"field":"tenant.name","operator":"equals","value":"acme"},
   "action":{"type":"route","target":{"type":"fixed","redundancyClassId":"rc-acme"}}},
  {"id":"disabled","enabled":false,
   "conditions":{"field":"object.key","operator":"exists"},
   "action":{"type":"route","target":{"type":"fixed","redundancyClassId":"rc-never"}}}
]`

func TestEvaluateDocsExample(t *testing.T) {
	engine, err := Compile([]byte(docsExample))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if engine.Rules() != 4 {
		t.Fatalf("rules = %d", engine.Rules())
	}

	tests := []struct {
		name string
		meta ObjectMeta
		want Decision
	}{
		{
			name: "large video key routes (size)",
			meta: ObjectMeta{Key: "clips/a.mp4", Size: 200 << 20, ContentType: "application/octet-stream", StorageClass: "STANDARD"},
			want: Decision{Action: ActionRoute, RCID: "rc-cold", RuleID: "video-to-cold"},
		},
		{
			name: "small mp4 by content type routes",
			meta: ObjectMeta{Key: "clips/b.mov", Size: 10, ContentType: "video/mp4", StorageClass: "STANDARD"},
			want: Decision{Action: ActionRoute, RCID: "rc-cold", RuleID: "video-to-cold"},
		},
		{
			name: "non-video key does not match first rule",
			meta: ObjectMeta{Key: "notes.txt", Size: 200 << 20, ContentType: "text/plain", StorageClass: "STANDARD"},
			want: Decision{Action: ActionDefault},
		},
		{
			name: "storage class filter excludes the video rule",
			meta: ObjectMeta{Key: "clips/a.mp4", Size: 200 << 20, StorageClass: "HOT"},
			want: Decision{Action: ActionDefault},
		},
		{
			name: "drop action wins on prefix",
			meta: ObjectMeta{Key: "private/keys.pem", Size: 10, StorageClass: "STANDARD"},
			want: Decision{Action: ActionDrop, RuleID: "drop-secrets"},
		},
		{
			name: "tenant rule",
			meta: ObjectMeta{Key: "x", Size: 1, TenantName: "acme", StorageClass: "STANDARD"},
			want: Decision{Action: ActionRoute, RCID: "rc-acme", RuleID: "tenant-acme"},
		},
		{
			name: "disabled rule never matches",
			meta: ObjectMeta{Key: "anything", Size: 1, StorageClass: "STANDARD"},
			want: Decision{Action: ActionDefault},
		},
		{
			name: "nil engine defaults",
			meta: ObjectMeta{},
			want: Decision{Action: ActionDefault},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got Decision
			if tc.name == "nil engine defaults" {
				var nilEngine *Engine
				got = nilEngine.Evaluate(tc.meta)
			} else {
				got = engine.Evaluate(tc.meta)
			}
			if got != tc.want {
				t.Fatalf("decision = %+v, want %+v", got, tc.want)
			}
		})
	}
}

type leafCase struct {
	operator string
	value    any
	meta     ObjectMeta
	want     bool
}

func TestOperatorMatrix(t *testing.T) {
	tests := []leafCase{
		{"equals", "a.txt", ObjectMeta{Key: "a.txt"}, true},
		{"equals", "a.txt", ObjectMeta{Key: "b.txt"}, false},
		{"not_equals", "a.txt", ObjectMeta{Key: "b.txt"}, true},
		{"matches_regex", `\.txt$`, ObjectMeta{Key: "notes.txt"}, true},
		{"matches_regex", `\.txt$`, ObjectMeta{Key: "notes.md"}, false},
		{"not_matches_regex", `\.txt$`, ObjectMeta{Key: "notes.md"}, true},
		{"starts_with", "logs/", ObjectMeta{Key: "logs/2026/01.log"}, true},
		{"ends_with", ".log", ObjectMeta{Key: "logs/2026/01.log"}, true},
		{"contains", "2026", ObjectMeta{Key: "logs/2026/01.log"}, true},
		{"not_contains", "2025", ObjectMeta{Key: "logs/2026/01.log"}, true},
		{"gt", float64(100), ObjectMeta{Size: 101}, true},
		{"gt", float64(100), ObjectMeta{Size: 100}, false},
		{"lt", float64(100), ObjectMeta{Size: 99}, true},
		{"gte", float64(100), ObjectMeta{Size: 100}, true},
		{"lte", float64(100), ObjectMeta{Size: 100}, true},
		{"lte", float64(100), ObjectMeta{Size: 101}, false},
		{"in", []any{"STANDARD", "HOT"}, ObjectMeta{ContentType: "application/json"}, false},
		{"in", []any{"text/plain", "text/csv"}, ObjectMeta{ContentType: "text/csv"}, true},
		{"not_in", []any{"text/plain"}, ObjectMeta{ContentType: "text/csv"}, true},
		{"exists", nil, ObjectMeta{ContentType: "text/plain"}, true},
		{"exists", nil, ObjectMeta{ContentType: ""}, false},
		{"not_exists", nil, ObjectMeta{TenantName: ""}, true},
		{"not_exists", nil, ObjectMeta{ContentType: "text/plain"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.operator, func(t *testing.T) {
			rule := Rule{
				ID:         "r",
				Conditions: &Condition{Operator: tc.operator, Field: fieldFor(tc), Value: tc.value},
				Action:     ActionJSON{Type: ActionDrop},
			}
			engine, err := New([]Rule{rule})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got := engine.Evaluate(tc.meta).Action == ActionDrop
			if got != tc.want {
				t.Fatalf("%s(%v) on %+v = %v, want %v", tc.operator, tc.value, tc.meta, got, tc.want)
			}
		})
	}
}

// fieldFor picks the field the operator test is exercising.
func fieldFor(tc leafCase) string {
	switch {
	case tc.value == nil:
		if tc.meta.TenantName == "" && tc.meta.ContentType == "" && tc.meta.Key == "" {
			return FieldTenantName
		}
		return FieldContentType
	case isNumberValue(tc.value):
		return FieldSize
	case tc.operator == "in" || tc.operator == "not_in":
		return FieldContentType
	default:
		return FieldKey
	}
}

func isNumberValue(v any) bool {
	_, ok := v.(float64)
	return ok
}

func TestFirstMatchWins(t *testing.T) {
	engine, err := New([]Rule{
		{ID: "first", Conditions: &Condition{Field: FieldKey, Operator: OpStartsWith, Value: "a"}, Action: ActionJSON{Type: ActionRoute, Target: fixed("rc-1")}},
		{ID: "second", Conditions: &Condition{Field: FieldKey, Operator: OpStartsWith, Value: "a"}, Action: ActionJSON{Type: ActionRoute, Target: fixed("rc-2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Evaluate(ObjectMeta{Key: "abc", StorageClass: "STANDARD"})
	if got.RCID != "rc-1" || got.RuleID != "first" {
		t.Fatalf("decision = %+v", got)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty", ``, "empty policy"},
		{"bad json", `{`, "invalid policy"},
		{"missing id", `[{"enabled":true,"action":{"type":"drop"}}]`, "no id"},
		{"bad field", `[{"id":"r","conditions":{"field":"object.magic","operator":"equals","value":"x"},"action":{"type":"drop"}}]`, "unsupported field"},
		{"bad operator", `[{"id":"r","conditions":{"field":"object.key","operator":"about_equals","value":"x"},"action":{"type":"drop"}}]`, "unsupported operator"},
		{"bad regex", `[{"id":"r","conditions":{"field":"object.key","operator":"matches_regex","value":"("},"action":{"type":"drop"}}]`, "invalid regex"},
		{"numeric op on string", `[{"id":"r","conditions":{"field":"object.key","operator":"gt","value":5},"action":{"type":"drop"}}]`, "only valid on object.size"},
		{"in without array", `[{"id":"r","conditions":{"field":"object.key","operator":"in","value":"x"},"action":{"type":"drop"}}]`, "array value"},
		{"route without target", `[{"id":"r","action":{"type":"route"}}]`, "no target"},
		{"route without rc", `[{"id":"r","action":{"type":"route","target":{"type":"fixed"}}}]`, "no redundancyClassId"},
		{"bad target type", `[{"id":"r","action":{"type":"route","target":{"type":"ml","redundancyClassId":"x"}}}]`, "unsupported target type"},
		{"bad action", `[{"id":"r","action":{"type":"teleport"}}]`, "unsupported action type"},
		{"empty group", `[{"id":"r","conditions":{"operator":"AND","conditions":[]},"action":{"type":"drop"}}]`, "empty AND group"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile([]byte(tc.body))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func fixed(rc string) *struct {
	Type              string `json:"type"`
	RedundancyClassID string `json:"redundancyClassId"`
} {
	return &struct {
		Type              string `json:"type"`
		RedundancyClassID string `json:"redundancyClassId"`
	}{Type: "fixed", RedundancyClassID: rc}
}
