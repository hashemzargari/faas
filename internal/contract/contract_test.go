package contract

import (
	"encoding/json"
	"reflect"
	"regexp"
	"testing"
)

// wireTypes is every type that crosses a service boundary as JSON.
//
// The rule these tests enforce: the contract package IS the wire format
// (docs/07). A struct that crosses a boundary without a snake_case json tag
// silently serialises Go field names and breaks the other two services.
var wireTypes = []any{
	Principal{}, Resource{}, Decision{},
	BucketConfig{}, ACL{}, Grant{}, Retention{},
	Manifest{}, ChunkRef{}, Slot{}, EncryptionMeta{},
	PlacementRequest{}, Placement{},
	CommitRequest{}, CommitResult{},
	ListRequest{}, ListResult{}, ObjectEntry{},
	PartInfo{}, UploadInfo{},
	AnnounceRequest{}, AnnounceResult{}, Heartbeat{}, ShardStatus{},
	RepairJob{}, RepairResult{},
	ShardHeader{}, ShardInfo{},
}

var snakeCase = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)

func TestEveryWireFieldHasSnakeCaseJSONTag(t *testing.T) {
	for _, v := range wireTypes {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "" {
				t.Errorf("%s.%s has no json tag (would serialise as %q)",
					typ.Name(), f.Name, f.Name)
				continue
			}
			name := tag
			if i := indexByte(tag, ','); i >= 0 {
				name = tag[:i]
			}
			if name == "-" {
				continue
			}
			if !snakeCase.MatchString(name) {
				t.Errorf("%s.%s json tag %q is not snake_case", typ.Name(), f.Name, name)
			}
		}
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TestCommitRequestWireShape guards the single most important payload in the
// system: the one that makes an object visible.
func TestCommitRequestWireShape(t *testing.T) {
	req := CommitRequest{
		VersionID: "11111111-2222-3333-4444-555555555555",
		BucketID:  "bkt",
		Key:       "a/b.bin",
		Size:      1024,
		ETag:      "abc",
		ChunkSize: 16 << 20,
		Chunks:    []ChunkRef{},
		Tags:      map[string]string{"k": "v"},
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version_id", "bucket_id", "key", "size", "etag", "chunk_size", "chunks", "tags"} {
		if _, ok := got[want]; !ok {
			t.Errorf("CommitRequest JSON missing %q; got keys %v", want, keysOf(got))
		}
	}
	for _, forbidden := range []string{"VersionID", "BucketID", "ChunkSize"} {
		if _, ok := got[forbidden]; ok {
			t.Errorf("CommitRequest JSON leaked Go field name %q", forbidden)
		}
	}
}

// TestRoundTripThroughJSON asserts every wire type survives marshal/unmarshal.
func TestRoundTripThroughJSON(t *testing.T) {
	for _, v := range wireTypes {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Errorf("%T marshal: %v", v, err)
			continue
		}
		ptr := reflect.New(reflect.TypeOf(v))
		if err := json.Unmarshal(raw, ptr.Interface()); err != nil {
			t.Errorf("%T unmarshal: %v (payload %s)", v, err, raw)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCRNRoundTrip(t *testing.T) {
	cases := []Resource{
		{Region: "eu-west-1", Kind: "bucket", TenantID: "t-1", ProjectID: "p-1", Bucket: "my-bucket"},
		{Region: "eu-west-1", Kind: "object", TenantID: "t-1", ProjectID: "p-1", Bucket: "b", Key: "a/b/c.txt"},
		{Region: "us-east-1", Kind: "object", TenantID: "t-2", ProjectID: "p-2", Bucket: "b", Key: "plain"},
	}
	for _, want := range cases {
		crn := want.CRN()
		got, err := ParseCRN(crn)
		if err != nil {
			t.Fatalf("ParseCRN(%q): %v", crn, err)
		}
		if got != want {
			t.Errorf("round trip %q: got %+v want %+v", crn, got, want)
		}
	}
}

func TestCRNDefaultsRegion(t *testing.T) {
	r := Resource{Kind: "bucket", TenantID: "t", ProjectID: "p", Bucket: "b"}
	if got := r.CRN(); got != "crn:eu-west-1:s3:bucket:tenant_t/project_p/b" {
		t.Fatalf("unexpected CRN %q", got)
	}
}

func TestCRNRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "arn:aws:s3:::b", "crn:eu-west-1:s3:bucket", "crn:eu-west-1:s3:bucket:t-1",
		"crn:eu-west-1:s3:bucket:tenant_/project_",
	} {
		if _, err := ParseCRN(bad); err == nil {
			t.Errorf("ParseCRN(%q) should fail", bad)
		}
	}
}

func TestResourceMatches(t *testing.T) {
	r := Resource{Region: "eu-west-1", Kind: "object", TenantID: "t", ProjectID: "p", Bucket: "b", Key: "logs/2026/x.log"}
	cases := map[string]bool{
		"*": true,
		"crn:eu-west-1:s3:object:tenant_t/project_p/b/logs/*":          true,
		"crn:eu-west-1:s3:object:tenant_t/project_p/b/logs/2026/x.log": true, // exact
		"crn:eu-west-1:s3:object:tenant_t/project_p/other/*":           false,
	}
	for pattern, want := range cases {
		if got := r.Matches(pattern); got != want {
			t.Errorf("Matches(%q) = %v, want %v", pattern, got, want)
		}
	}
}
