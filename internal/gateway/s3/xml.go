package s3

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// xmlNS is the S3 XML namespace used on every result document.
const xmlNS = "http://s3.amazonaws.com/doc/2006-03-01/"

// timeFormat is the timestamp format S3 uses in XML (millisecond precision).
const timeFormat = "2006-01-02T15:04:05.000Z"

func xmlTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeFormat)
}

// xmlOwner is the Owner element shared by several responses.
type xmlOwner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

type errorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestID string   `xml:"RequestId"`
	HostID    string   `xml:"HostId,omitempty"`
}

// ---------------------------------------------------------------------------
// Bucket operations
// ---------------------------------------------------------------------------

type listAllMyBucketsResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   xmlOwner `xml:"Owner"`
	Buckets struct {
		Bucket []bucketXML `xml:"Bucket"`
	} `xml:"Buckets"`
}

type bucketXML struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
	BucketRegion string `xml:"BucketRegion,omitempty"`
}

type locationConstraint struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LocationConstraint"`
	Value   string   `xml:",chardata"`
}

type versioningConfigurationXML struct {
	XMLName   xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ VersioningConfiguration"`
	Status    string   `xml:"Status,omitempty"`
	MFADelete string   `xml:"MfaDelete,omitempty"`
}

// ---------------------------------------------------------------------------
// ACLs
// ---------------------------------------------------------------------------

type accessControlPolicyXML struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy"`
	Owner   xmlOwner `xml:"Owner"`
	ACL     struct {
		Grants []grantXML `xml:"Grant"`
	} `xml:"AccessControlList"`
}

type grantXML struct {
	Grantee    granteeXML `xml:"Grantee"`
	Permission string     `xml:"Permission"`
}

type granteeXML struct {
	// Namespace declarations are emitted on the Grantee element, exactly as S3
	// does, so SDKs that switch on xsi:type can parse grantees.
	XMLNSXsi     string `xml:"xmlns:xsi,attr,omitempty"`
	XsiType      string `xml:"xsi:type,attr,omitempty"`
	ID           string `xml:"ID,omitempty"`
	DisplayName  string `xml:"DisplayName,omitempty"`
	URI          string `xml:"URI,omitempty"`
	EmailAddress string `xml:"EmailAddress,omitempty"`
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

type listObjectsV2Result struct {
	XMLName               xml.Name          `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string            `xml:"Name"`
	Prefix                string            `xml:"Prefix"`
	KeyCount              int               `xml:"KeyCount"`
	MaxKeys               int               `xml:"MaxKeys"`
	Delimiter             string            `xml:"Delimiter,omitempty"`
	IsTruncated           bool              `xml:"IsTruncated"`
	ContinuationToken     string            `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string            `xml:"NextContinuationToken,omitempty"`
	StartAfter            string            `xml:"StartAfter,omitempty"`
	EncodingType          string            `xml:"EncodingType,omitempty"`
	Contents              []objectXML       `xml:"Contents"`
	CommonPrefixes        []commonPrefixXML `xml:"CommonPrefixes"`
}

type listObjectsV1Result struct {
	XMLName        xml.Name          `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name           string            `xml:"Name"`
	Prefix         string            `xml:"Prefix"`
	Marker         string            `xml:"Marker"`
	NextMarker     string            `xml:"NextMarker,omitempty"`
	MaxKeys        int               `xml:"MaxKeys"`
	Delimiter      string            `xml:"Delimiter,omitempty"`
	IsTruncated    bool              `xml:"IsTruncated"`
	EncodingType   string            `xml:"EncodingType,omitempty"`
	Contents       []objectXML       `xml:"Contents"`
	CommonPrefixes []commonPrefixXML `xml:"CommonPrefixes"`
}

type objectXML struct {
	Key          string    `xml:"Key"`
	LastModified string    `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	Owner        *xmlOwner `xml:"Owner,omitempty"`
	StorageClass string    `xml:"StorageClass,omitempty"`
}

type commonPrefixXML struct {
	Prefix string `xml:"Prefix"`
}

type listVersionsResult struct {
	XMLName             xml.Name          `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListVersionsResult"`
	Name                string            `xml:"Name"`
	Prefix              string            `xml:"Prefix"`
	KeyMarker           string            `xml:"KeyMarker"`
	VersionIDMarker     string            `xml:"VersionIdMarker"`
	NextKeyMarker       string            `xml:"NextKeyMarker,omitempty"`
	NextVersionIDMarker string            `xml:"NextVersionIdMarker,omitempty"`
	MaxKeys             int               `xml:"MaxKeys"`
	Delimiter           string            `xml:"Delimiter,omitempty"`
	IsTruncated         bool              `xml:"IsTruncated"`
	EncodingType        string            `xml:"EncodingType,omitempty"`
	Versions            []versionXML      `xml:"Version"`
	DeleteMarkers       []deleteMarkerXML `xml:"DeleteMarker"`
	CommonPrefixes      []commonPrefixXML `xml:"CommonPrefixes"`
}

type versionXML struct {
	Key          string    `xml:"Key"`
	VersionID    string    `xml:"VersionId"`
	IsLatest     bool      `xml:"IsLatest"`
	LastModified string    `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	Owner        *xmlOwner `xml:"Owner,omitempty"`
	StorageClass string    `xml:"StorageClass,omitempty"`
}

type deleteMarkerXML struct {
	Key          string    `xml:"Key"`
	VersionID    string    `xml:"VersionId"`
	IsLatest     bool      `xml:"IsLatest"`
	LastModified string    `xml:"LastModified"`
	Owner        *xmlOwner `xml:"Owner,omitempty"`
}

// ---------------------------------------------------------------------------
// Object operations
// ---------------------------------------------------------------------------

type copyObjectResultXML struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyObjectResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

type copyPartResultXML struct {
	XMLName      xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CopyPartResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

type deleteObjectsRequest struct {
	XMLName xml.Name           `xml:"Delete"`
	Objects []objectIdentifier `xml:"Object"`
	Quiet   bool               `xml:"Quiet"`
}

type objectIdentifier struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
}

type deleteObjectsResult struct {
	XMLName xml.Name         `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult"`
	Deleted []deletedXML     `xml:"Deleted"`
	Errors  []deleteErrorXML `xml:"Error"`
}

type deletedXML struct {
	Key                   string `xml:"Key"`
	VersionID             string `xml:"VersionId,omitempty"`
	DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId,omitempty"`
}

type deleteErrorXML struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId,omitempty"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
}

// ---------------------------------------------------------------------------
// Tagging
// ---------------------------------------------------------------------------

type taggingXML struct {
	XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Tagging"`
	TagSet  tagSetXML `xml:"TagSet"`
}

type tagSetXML struct {
	Tags []tagXML `xml:"Tag"`
}

type tagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// ---------------------------------------------------------------------------
// Versioning / ownership / object lock
// ---------------------------------------------------------------------------

type ownershipControlsXML struct {
	XMLName xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ OwnershipControls"`
	Rules   []ownershipRule `xml:"Rule"`
}

type ownershipRule struct {
	ObjectOwnership string `xml:"ObjectOwnership"`
}

type objectLockConfigurationXML struct {
	XMLName           xml.Name        `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ObjectLockConfiguration"`
	ObjectLockEnabled string          `xml:"ObjectLockEnabled,omitempty"`
	Rule              *objectLockRule `xml:"Rule,omitempty"`
}

type objectLockRule struct {
	DefaultRetention *defaultRetentionXML `xml:"DefaultRetention,omitempty"`
}

type defaultRetentionXML struct {
	Mode  string `xml:"Mode,omitempty"`
	Days  int    `xml:"Days,omitempty"`
	Years int    `xml:"Years,omitempty"`
}

type retentionXML struct {
	XMLName         xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ Retention"`
	Mode            string   `xml:"Mode"`
	RetainUntilDate string   `xml:"RetainUntilDate"`
}

type legalHoldXML struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LegalHold"`
	Status  string   `xml:"Status"`
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

type initiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

type completeMultipartUploadRequest struct {
	XMLName xml.Name       `xml:"CompleteMultipartUpload"`
	Parts   []completePart `xml:"Part"`
}

type completePart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

type completeMultipartUploadResult struct {
	XMLName  xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

type listPartsResult struct {
	XMLName              xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListPartsResult"`
	Bucket               string    `xml:"Bucket"`
	Key                  string    `xml:"Key"`
	UploadID             string    `xml:"UploadId"`
	PartNumberMarker     int       `xml:"PartNumberMarker"`
	NextPartNumberMarker int       `xml:"NextPartNumberMarker"`
	MaxParts             int       `xml:"MaxParts"`
	IsTruncated          bool      `xml:"IsTruncated"`
	Parts                []partXML `xml:"Part"`
}

type partXML struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

type listMultipartUploadsResult struct {
	XMLName            xml.Name          `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListMultipartUploadsResult"`
	Bucket             string            `xml:"Bucket"`
	KeyMarker          string            `xml:"KeyMarker"`
	UploadIDMarker     string            `xml:"UploadIdMarker"`
	NextKeyMarker      string            `xml:"NextKeyMarker,omitempty"`
	NextUploadIDMarker string            `xml:"NextUploadIdMarker,omitempty"`
	Delimiter          string            `xml:"Delimiter,omitempty"`
	Prefix             string            `xml:"Prefix"`
	MaxUploads         int               `xml:"MaxUploads"`
	IsTruncated        bool              `xml:"IsTruncated"`
	Uploads            []uploadXML       `xml:"Upload"`
	CommonPrefixes     []commonPrefixXML `xml:"CommonPrefixes"`
}

type uploadXML struct {
	Key          string    `xml:"Key"`
	UploadID     string    `xml:"UploadId"`
	Initiator    *xmlOwner `xml:"Initiator,omitempty"`
	Owner        *xmlOwner `xml:"Owner,omitempty"`
	StorageClass string    `xml:"StorageClass"`
	Initiated    string    `xml:"Initiated"`
}

// ---------------------------------------------------------------------------
// Writing helpers
// ---------------------------------------------------------------------------

// writeXML marshals v with the XML declaration and the given status.
func writeXML(w http.ResponseWriter, status int, v any) {
	body, err := xml.Marshal(v)
	if err != nil {
		// Marshalling our own response types cannot fail; fall back to a plain
		// internal error rather than panicking on a request path.
		writeErrorResponse(w, nil, ErrInternalError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}

// writeRawXML writes pre-validated XML (used for opaque lifecycle documents).
func writeRawXML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeEmpty writes a bodyless response.
func writeEmpty(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

// writeErrorResponse renders the S3 error envelope. requestID may be empty when
// called before request state exists.
func writeErrorResponse(w http.ResponseWriter, r *http.Request, err error) {
	api := mapError(err)
	res := ""
	reqID := ""
	if r != nil {
		res = r.URL.Path
		reqID = requestIDFromRequest(r)
	}
	if api.Header != nil {
		for k, vs := range api.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(api.Status)
	body, merr := xml.Marshal(errorResponse{
		Code:      api.Code,
		Message:   api.Message,
		Resource:  res,
		RequestID: reqID,
	})
	if merr != nil {
		return
	}
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}

// quoteETag renders an ETag the way S3 does (always quoted).
func quoteETag(etag string) string {
	etag = strings.Trim(etag, `"`)
	return `"` + etag + `"`
}

// canonicalMetadataHeader maps a stored metadata key onto the response header
// name. Keys are stored lowercased exactly as received, so this is mostly a
// no-op on the wire format, but it keeps the intent explicit.
func canonicalMetadataHeader(k string) string {
	if strings.HasPrefix(k, "x-amz-meta-") {
		return k
	}
	if strings.HasPrefix(k, "x-amz-") {
		return k
	}
	return http.CanonicalHeaderKey(k)
}

// setManifestHeaders writes the headers shared by GET and HEAD object responses.
func setManifestHeaders(h http.Header, m manifestView, etag string) {
	h.Set("ETag", quoteETag(etag))
	h.Set("Last-Modified", m.createdAt.UTC().Format(http.TimeFormat))
	h.Set("Accept-Ranges", "bytes")
	if m.contentType != "" {
		h.Set("Content-Type", m.contentType)
	}
	if m.versionID != "" {
		h.Set("x-amz-version-id", m.versionID)
	}
	if m.storageClass != "" {
		h.Set("x-amz-storage-class", m.storageClass)
	}
	for k, v := range m.userMeta {
		h.Set(canonicalMetadataHeader(k), v)
	}
}

// manifestView is the subset of a committed manifest the S3 layer needs to build
// response headers.
type manifestView struct {
	createdAt    time.Time
	contentType  string
	versionID    string
	storageClass string
	userMeta     map[string]string
}

// splitTags parses the x-amz-tagging header (URL-encoded tag set).
func splitTags(raw string) (map[string]string, error) {
	tags := make(map[string]string)
	if raw == "" {
		return tags, nil
	}
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		key, err := urlQueryUnescape(k)
		if err != nil {
			return nil, fmt.Errorf("invalid tagging: %w", err)
		}
		val, err := urlQueryUnescape(v)
		if err != nil {
			return nil, fmt.Errorf("invalid tagging: %w", err)
		}
		tags[key] = val
	}
	return tags, nil
}

// ---------------------------------------------------------------------------
// Request bodies
//
// Response documents carry the S3 namespace; request documents from clients may
// or may not include it, so their XMLName fields are deliberately unqualified
// (a local-only XMLName matches any namespace).
// ---------------------------------------------------------------------------

type versioningConfigRequest struct {
	Status    string `xml:"Status"`
	MFADelete string `xml:"MfaDelete"`
}

type ownershipControlsRequest struct {
	Rules []ownershipRule `xml:"Rule"`
}

type objectLockConfigRequest struct {
	ObjectLockEnabled string          `xml:"ObjectLockEnabled"`
	Rule              *objectLockRule `xml:"Rule"`
}

type taggingRequest struct {
	TagSet tagSetXML `xml:"TagSet"`
}

type retentionRequest struct {
	Mode            string `xml:"Mode"`
	RetainUntilDate string `xml:"RetainUntilDate"`
}

type legalHoldRequest struct {
	Status string `xml:"Status"`
}

type accessControlPolicyRequest struct {
	Owner struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	} `xml:"Owner"`
	ACL struct {
		Grants []grantXML `xml:"Grant"`
	} `xml:"AccessControlList"`
}
