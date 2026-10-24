package contract

import (
	"fmt"
	"strings"
)

// CRN (Cubbit Resource Name) grammar, as published in Cubbit's permission docs:
//
//	crn:<region>:s3:bucket:<tenant_uuid>/<project_uuid>/<bucket>
//	crn:<region>:s3:object:<tenant_uuid>/<project_uuid>/<bucket>/<key>
//
// Object keys may contain slashes, so the key is everything after the bucket.
func (r Resource) CRN() string {
	region := r.Region
	if region == "" {
		region = DefaultRegion
	}
	var b strings.Builder
	b.WriteString("crn:")
	b.WriteString(region)
	b.WriteString(":s3:")
	b.WriteString(r.Kind)
	b.WriteString(":tenant_")
	b.WriteString(string(r.TenantID))
	b.WriteString("/project_")
	b.WriteString(string(r.ProjectID))
	if r.Bucket != "" {
		b.WriteString("/")
		b.WriteString(r.Bucket)
	}
	if r.Key != "" {
		b.WriteString("/")
		b.WriteString(r.Key)
	}
	return b.String()
}

// DefaultRegion matches the region string Cubbit documents in every
// integration guide.
const DefaultRegion = "eu-west-1"

// ParseCRN is the inverse of CRN.
func ParseCRN(s string) (Resource, error) {
	parts := strings.SplitN(s, ":", 5)
	if len(parts) != 5 || parts[0] != "crn" || parts[2] != "s3" {
		return Resource{}, fmt.Errorf("contract: malformed CRN %q", s)
	}
	r := Resource{Region: parts[1], Kind: parts[3]}
	path := parts[4]

	// tenant_<uuid>/project_<uuid>[/bucket[/key...]]
	seg := strings.SplitN(path, "/", 3)
	if len(seg) < 2 {
		return Resource{}, fmt.Errorf("contract: CRN %q missing tenant/project", s)
	}
	if !strings.HasPrefix(seg[0], "tenant_") || !strings.HasPrefix(seg[1], "project_") {
		return Resource{}, fmt.Errorf("contract: CRN %q malformed tenant/project", s)
	}
	r.TenantID = TenantID(strings.TrimPrefix(seg[0], "tenant_"))
	r.ProjectID = ProjectID(strings.TrimPrefix(seg[1], "project_"))
	if len(seg) == 3 {
		rest := seg[2]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			r.Bucket = rest[:i]
			r.Key = rest[i+1:]
		} else {
			r.Bucket = rest
		}
	}
	return r, nil
}

// Matches reports whether a policy resource pattern matches the target. It
// supports the two wildcard forms the S3 policy language uses: a bare "*" and a
// trailing "*" prefix match.
func (r Resource) Matches(pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(r.CRN(), strings.TrimSuffix(pattern, "*"))
	}
	return r.CRN() == pattern
}
