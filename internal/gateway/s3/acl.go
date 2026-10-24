package s3

import (
	"encoding/xml"
	"net/http"
	"strings"

	"github.com/fass-storage/fass/internal/contract"
)

const (
	groupAllUsersURI         = "http://acs.amazonaws.com/groups/global/AllUsers"
	groupAuthenticatedURI    = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
	granteeTypeCanonicalUser = "CanonicalUser"
	granteeTypeGroup         = "Group"
	granteeTypeEmail         = "AmazonCustomerByEmail"
	permissionFullControl    = "FULL_CONTROL"
)

// aclToXML renders a stored ACL as an AccessControlPolicy document.
func aclToXML(acl contract.ACL, displayName string) accessControlPolicyXML {
	out := accessControlPolicyXML{
		Owner: xmlOwner{ID: acl.OwnerID, DisplayName: displayName},
	}
	for _, g := range acl.Grants {
		ge := granteeXML{}
		switch g.GranteeType {
		case granteeTypeGroup:
			ge.XMLNSXsi = "http://www.w3.org/2001/XMLSchema-instance"
			ge.XsiType = granteeTypeGroup
			ge.URI = groupURI(g.Grantee)
		case granteeTypeEmail:
			ge.XMLNSXsi = "http://www.w3.org/2001/XMLSchema-instance"
			ge.XsiType = granteeTypeEmail
			ge.EmailAddress = g.Grantee
		default:
			ge.XMLNSXsi = "http://www.w3.org/2001/XMLSchema-instance"
			ge.XsiType = granteeTypeCanonicalUser
			ge.ID = g.Grantee
			if g.Grantee == acl.OwnerID {
				ge.DisplayName = displayName
			}
		}
		out.ACL.Grants = append(out.ACL.Grants, grantXML{Grantee: ge, Permission: g.Permission})
	}
	return out
}

func groupURI(name string) string {
	switch name {
	case "AllUsers":
		return groupAllUsersURI
	case "AuthenticatedUsers":
		return groupAuthenticatedURI
	default:
		return name
	}
}

func groupName(uri string) string {
	switch uri {
	case groupAllUsersURI:
		return "AllUsers"
	case groupAuthenticatedURI:
		return "AuthenticatedUsers"
	default:
		return uri
	}
}

// defaultACL returns the private ACL for an owner.
func defaultACL(owner string) contract.ACL {
	return contract.ACL{
		OwnerID: owner,
		Grants: []contract.Grant{
			{Grantee: owner, GranteeType: granteeTypeCanonicalUser, Permission: permissionFullControl},
		},
	}
}

// aclFromRequest parses an AccessControlPolicy body or a canned-ACL header.
// bucketOwner is used for the bucket-owner-* canned ACLs.
func aclFromRequest(r *http.Request, owner, bucketOwner string) (contract.ACL, *APIError) {
	canned := r.Header.Get("x-amz-acl")
	if canned == "" && hasGrantHeaders(r) {
		return contract.ACL{}, ErrNotImplemented.withMessage("x-amz-grant-* headers are not implemented; use a canned ACL or an AccessControlPolicy body.")
	}
	if canned != "" {
		acl, ok := cannedACL(canned, owner, bucketOwner)
		if !ok {
			return contract.ACL{}, ErrInvalidArgument.withMessage("Unsupported canned ACL %q.", canned)
		}
		return acl, nil
	}

	body, err := readBody(r, 1<<20)
	if err != nil {
		return contract.ACL{}, err
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		// PUT without a body and without a canned header is an S3 error.
		return contract.ACL{}, ErrMalformedXML
	}
	var doc accessControlPolicyXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		return contract.ACL{}, ErrMalformedXML
	}
	acl := contract.ACL{OwnerID: owner}
	for _, g := range doc.ACL.Grants {
		grant := contract.Grant{Permission: strings.ToUpper(strings.TrimSpace(g.Permission))}
		switch grant.Permission {
		case "READ", "WRITE", "READ_ACP", "WRITE_ACP", permissionFullControl:
		default:
			return contract.ACL{}, ErrInvalidArgument.withMessage("Invalid ACL permission %q.", g.Permission)
		}
		switch {
		case g.Grantee.URI != "":
			grant.GranteeType = granteeTypeGroup
			grant.Grantee = groupName(strings.TrimSpace(g.Grantee.URI))
		case g.Grantee.EmailAddress != "":
			grant.GranteeType = granteeTypeEmail
			grant.Grantee = strings.TrimSpace(g.Grantee.EmailAddress)
		case g.Grantee.ID != "":
			grant.GranteeType = granteeTypeCanonicalUser
			grant.Grantee = strings.TrimSpace(g.Grantee.ID)
		default:
			return contract.ACL{}, ErrMalformedXML
		}
		acl.Grants = append(acl.Grants, grant)
	}
	if len(acl.Grants) == 0 {
		return contract.ACL{}, ErrMalformedXML
	}
	return acl, nil
}

// cannedACL expands the six documented canned ACLs (docs/05 §5.4).
func cannedACL(name, owner, bucketOwner string) (contract.ACL, bool) {
	acl := contract.ACL{OwnerID: owner}
	add := func(grantee, gtype, permission string) {
		for _, g := range acl.Grants {
			if g.Grantee == grantee && g.Permission == permission {
				return
			}
		}
		acl.Grants = append(acl.Grants, contract.Grant{Grantee: grantee, GranteeType: gtype, Permission: permission})
	}
	add(owner, granteeTypeCanonicalUser, permissionFullControl)

	switch strings.TrimSpace(name) {
	case "private":
		return acl, true
	case "public-read":
		add("AllUsers", granteeTypeGroup, "READ")
	case "public-read-write":
		add("AllUsers", granteeTypeGroup, "READ")
		add("AllUsers", granteeTypeGroup, "WRITE")
	case "authenticated-read":
		add("AuthenticatedUsers", granteeTypeGroup, "READ")
	case "bucket-owner-read":
		if bucketOwner != "" && bucketOwner != owner {
			add(bucketOwner, granteeTypeCanonicalUser, "READ")
		}
	case "bucket-owner-full-control":
		if bucketOwner != "" && bucketOwner != owner {
			add(bucketOwner, granteeTypeCanonicalUser, permissionFullControl)
		}
	default:
		return contract.ACL{}, false
	}
	return acl, true
}

func hasGrantHeaders(r *http.Request) bool {
	for k := range r.Header {
		switch strings.ToLower(k) {
		case "x-amz-grant-read", "x-amz-grant-write", "x-amz-grant-read-acp", "x-amz-grant-write-acp", "x-amz-grant-full-control":
			return true
		}
	}
	return false
}

// aclGrantsOthers reports whether an ACL grants access to anyone but the owner.
// Used to reject BucketOwnerEnforced when the bucket ACL is non-private.
func aclGrantsOthers(acl contract.ACL) bool {
	for _, g := range acl.Grants {
		if g.Grantee != acl.OwnerID {
			return true
		}
	}
	return false
}
