# 05 — S3 API Specification & Compatibility Matrix

The gateway's external contract. Cubbit publishes an explicit matrix (42 supported / 55 unsupported operations, counted row by row from their table); we reproduce it, then document exactly where we deliberately do better.

---

## 1. Endpoint, addressing, region

| Item | Cubbit (published/observed) | FASS |
|---|---|---|
| Endpoint | per-tenant "endpoint gateway" hostname, e.g. `s3.<tenant>.cubbit.eu`, shown without scheme | `s3.<tenant>.<deployment-domain>` or a customer CNAME |
| Addressing | path-style inferred (host is account-specific); virtual-hosted never documented | **both**: path-style always; virtual-hosted when `{bucket}.` matches `virtual_host_domain` |
| Region | `eu-west-1` in every integration guide and in CRNs | configurable; default `eu-west-1`; **any** region string accepted and ignored for signing/scope |
| TLS | expected, not mandated; self-hosted gateways can disable | TLS 1.3 on `:8443`; plaintext `:8080` allowed only when explicitly enabled |
| Request IDs | undocumented | `x-amz-request-id`, `x-amz-id-2` on every response |

---

## 2. Authentication

| Mechanism | Cubbit | FASS |
|---|---|---|
| SigV4 (`AWS4-HMAC-SHA256`) | yes | yes, incl. `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-cli chunked signing) and `UNSIGNED-PAYLOAD` |
| SigV2 (`AWS …:Signature=`) | yes ("version can be either 2 or 4") | yes (legacy tooling; e.g. old S3 browsers) |
| Presigned URLs | **undocumented** (no occurrence across 63 pages) | **yes** — query auth, `X-Amz-Expires` ≤ 7 d, signed headers honoured |
| Session tokens / STS | **not supported** ("no session token field is sent") | accepted-and-ignored, documented; no STS endpoint in v1 |
| Credentials | access key + secret bound to a project IAM user; secret shown once; unlimited keys | identical model (`access_keys` table, Argon2id secret hash) |
| Anonymous | public-read ACLs exist but "read and write operations are not yet supported in a public-read scenario" | supported for `GET` when ACL grants `AllUsers:READ` (we do not inherit the limitation) |

**CRN format** (both bucket and object scopes; used in policies):
```
crn:<region>:s3:bucket:<tenant_uuid>/<project_uuid>/<bucket>
crn:<region>:s3:object:<tenant_uuid>/<project_uuid>/<bucket>/<key>
```

**Authorisation chain** (mirrors Cubbit's documented four stages, in order):

```
access key ──▶ IAM policy        (explicit Deny wins)
           ──▶ bucket policy     (Deny wins; else fall through; managed out-of-band, no S3 API)
           ──▶ ACL               (cross-account must explicitly Allow)
           ──▶ object-lock/retention guard
```
Preset roles: `Owner`, `Admin`, `Member`, `ReadOnly`. Policy JSON uses `syntax_version: "2023-10-16"`, statements `{effect, actions[], resources[], conditions{}}`, condition keys `s3:prefix`, `s3:max-keys`, `s3:versionid`, `s3:x-amz-acl`, `s3:ExistingObjectTag/<k>`.

> Fidelity quirk retained: reading/writing S3 through the API requires the IAM permissions `iam:CreateKey`, `iam:ManageKey`, `iam:ListKeys` in addition to `s3:*` (Cubbit documents this explicitly). We keep it for drop-in policy compatibility, and ship a `--compat-loose-iam` flag for operators who find it surprising.

---

## 3. Operations compatibility matrix

**Supported (42)** — we implement all of them. (Earlier drafts of this document said 41; Cubbit's table has 42 `Yes` rows, and our supported set matches theirs exactly, operation for operation.)

| Family | Operations |
|---|---|
| Bucket | `CreateBucket`, `DeleteBucket`, `HeadBucket`, `ListBuckets`, `GetBucketLocation` |
| Object | `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `DeleteObjects`, `CopyObject` |
| Listing | `ListObjects`, `ListObjectsV2`, `ListObjectVersions`, `ListMultipartUploads`, `ListParts` |
| Multipart | `CreateMultipartUpload`, `UploadPart`, `UploadPartCopy`, `CompleteMultipartUpload`, `AbortMultipartUpload` |
| ACL | `GetBucketAcl`, `PutBucketAcl`, `GetObjectAcl`, `PutObjectAcl` |
| Versioning | `GetBucketVersioning`, `PutBucketVersioning` |
| Object lock | `GetObjectLockConfiguration`, `PutObjectLockConfiguration`, `GetObjectRetention`, `PutObjectRetention`, `GetObjectLegalHold`, `PutObjectLegalHold` |
| Tagging (object) | `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging` |
| Lifecycle | `GetBucketLifecycleConfiguration`, `PutBucketLifecycleConfiguration`, `DeleteBucketLifecycle` |
| Ownership | `GetBucketOwnershipControls`, `PutBucketOwnershipControls`, `DeleteBucketOwnershipControls` |

**Unsupported (55)** — we return `501 NotImplemented`, exactly like Cubbit.

| Family | Unsupported operations |
|---|---|
| Bucket policy | `PutBucketPolicy`, `GetBucketPolicy`, `DeleteBucketPolicy`, `GetBucketPolicyStatus` |
| Public access | `GetPublicAccessBlock`, `PutPublicAccessBlock`, `DeletePublicAccessBlock` |
| CORS | `PutBucketCors`, `GetBucketCors`, `DeleteBucketCors` |
| Website | `PutBucketWebsite`, `GetBucketWebsite`, `DeleteBucketWebsite` |
| Logging | `PutBucketLogging`, `GetBucketLogging` |
| Replication | `PutBucketReplication`, `GetBucketReplication`, `DeleteBucketReplication` |
| Notifications | `PutBucketNotification`, `GetBucketNotification`, `PutBucketNotificationConfiguration`, `GetBucketNotificationConfiguration` |
| Encryption | `PutBucketEncryption`, `GetBucketEncryption`, `DeleteBucketEncryption` |
| Analytics / Inventory / Metrics / IntelligentTiering | all `Put/Get/Delete/ListBucket*Configuration` (12 ops) |
| Request payment / accelerate | `GetBucketRequestPayment`, `PutBucketRequestPayment`, `GetBucketAccelerateConfiguration`, `PutBucketAccelerateConfiguration` |
| Bucket tagging | `GetBucketTagging`, `PutBucketTagging`, `DeleteBucketTagging` |
| Legacy lifecycle | `GetBucketLifecycle`, `PutBucketLifecycle` (only the `…Configuration` variants exist) |
| Object extras | `GetObjectAttributes`, `SelectObjectContent`, `RestoreObject`, `GetObjectTorrent`, `WriteGetObjectResponse` |

> Note the deliberate asymmetry: **bucket policies are evaluated but cannot be managed via the S3 API** (Cubbit: `PutBucketPolicy` = No). They are managed through the Coordinator API/console. We keep this because the alternative — full bucket-policy API — would be a *possible* extension, but silently differing from Cubbit's surface is worse than matching it. An extension flag can enable the APIs later.

---

## 4. Header evaluation matrix

| Header family | Evaluated by Cubbit | FASS |
|---|---|---|
| `Content-Type`, `Content-Disposition`, `Content-Encoding`, `Cache-Control`, `x-amz-meta-*` | yes (stored; CopyObject only with `metadata-directive: REPLACE`) | same |
| `Content-Language`, `Expires`, `x-amz-website-redirect-location` | no (not stored) | stored (harmless superset; documented) |
| `x-amz-acl`, `x-amz-grant-*`, `x-amz-object-ownership` | validated / stored, with limits | same, and public-read actually works |
| `x-amz-expected-bucket-owner` | **enforced** (`Access Denied` on mismatch) | same |
| `x-amz-source-expected-bucket-owner` | not evaluated | evaluated (improvement) |
| `x-amz-object-lock-*` | enforced | same |
| `x-amz-bypass-governance-retention` | enforced (needs `s3:BypassGovernanceRetention` **or** root) | same |
| `x-amz-storage-class` | validated; invalid rejected; object lands in `STANDARD` | validated, **and** drives Smart Data Placement routing |
| `Range` | honoured | honoured (+ multi-range → 206 single range, documented) |
| `x-amz-tagging`, `x-amz-tagging-directive` | ignored | **honoured** at upload (improvement) |
| `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, `x-amz-copy-source-if-*` | **ignored** ("no 412", copy unconditional; support "targeted for early 2027") | **implemented** (412/304, RFC 9110 semantics, `If-None-Match: *` = create-if-absent) |
| `x-amz-checksum-*`, `x-amz-sdk-checksum-algorithm`, `x-amz-checksum-mode`, `x-amz-trailer` | **ignored**, never verified | **verified** on write, returned on read (CRC32/CRC32C/SHA1/SHA256/CRC64NVME); trailer support |
| `Content-MD5` | never verified | verified against payload ⇒ `BadDigest` |
| SSE-S3 / SSE-KMS / SSE-C headers | accepted, inert | accepted; SSE-C **rejected with `NotImplemented`** (never silently ignored — a key you think you used is a security bug); SSE-KMS maps to our KMIP mode |
| `x-amz-request-payer` | ignored | ignored, documented |
| `x-amz-mfa` | settable/reported, never enforced | reported, not enforced (same) |
| `x-amz-optional-object-attributes` | ignored | ignored |

**Design rule:** a header is either *fully honoured* or *explicitly rejected*. We never accept-and-ignore anything a client might rely on for integrity or confidentiality (Cubbit's own docs warn users about exactly this: "do not rely on them to prevent overwrites, to verify integrity, or to encrypt objects with your own key"). This is the largest intentional divergence and it is one-directional: we are a strict superset.

---

## 5. Feature semantics (Cubbit-documented, adopted)

### 5.1 Versioning
* Bucket-level; `Enabled` / `Suspended`. Suspension affects future writes only.
* **Version ID = 128-bit UUIDv4** (not AWS's 32-char base62). Clients must treat it as opaque; we match this because some backup tools persist it.
* **Exception — suspended versioning uses the literal version id `null`**, per S3: a PUT into a suspended bucket replaces the existing null version and retains all non-null versions; a DELETE creates a `null` delete marker (replacing an existing null version or marker). Rationale: `null` is not cosmetic — tools use it to distinguish "unversioned write" from "a version", and the UUIDv4 rule describes Cubbit's *enabled*-versioning behaviour, which is what its docs describe. Both are opaque to well-behaved clients; we pick the one real clients depend on.
* Delete without `versionId` ⇒ delete marker, versions retained. Delete with `versionId` ⇒ permanent and irreversible.
* `DeleteBucket` requires the bucket empty of **objects and versions**.

### 5.2 Object Lock (WORM)
* Can only be enabled **at bucket creation**; cannot be disabled or converted later; auto-enables versioning.
* Modes: `GOVERNANCE`, `COMPLIANCE`, plus independent legal hold.
* Retention can only be **extended**, never shortened (COMPLIANCE: never; GOVERNANCE: only with bypass).
* Governance bypass requires `s3:BypassGovernanceRetention` or root principal **and** `x-amz-bypass-governance-retention: true`; it never bypasses a legal hold.
* Deleting a locked version ⇒ `403 AccessDenied`. Unversioned delete still creates a marker.
* Bucket default retention is **not retroactive**; `PutObjectRetention` overrides per object.
* `x-amz-bucket-object-lock-token` is not evaluated.

### 5.3 Ownership controls
* Default is **`ObjectWriter`** (AWS defaults to `BucketOwnerEnforced`) — the uploader owns the object.
* Under `BucketOwnerEnforced`, ACL writes fail with `AccessControlListNotSupported`; enabling it while the bucket ACL grants other accounts ⇒ `InvalidBucketAclWithObjectOwnership`.
* `x-amz-grant-write` on object ACLs is stored but never evaluated.

### 5.4 ACLs
Supported: `private`, `public-read`, `public-read-write`, `authenticated-read`, `bucket-owner-read`, `bucket-owner-full-control`. Groups limited to `AllUsers`, `AuthenticatedUsers`. Grantees: user by id or project email.

### 5.5 Tagging
Object tagging only (10 tags max, 256-char key/value). `GetObject` does not return `x-amz-tagging-count`; `CopyObject` preserves tags but cannot replace them; no bucket tagging.

**Inline tagging at upload (`x-amz-tagging`) is honoured** — an intentional superset of Cubbit, which accepts and ignores the header (see §9, divergence D8). Rationale: accepting a header and silently discarding its effect is a correctness trap, and every mainstream client that sets it expects the tags to exist. This reconciles the earlier contradiction between §4 and §5.5: §4 (honoured) is the normative behaviour, and `compat: cubbit-strict` must ignore it for parity testing.

### 5.6 Lifecycle (partial by design)
* Rules: `Expiration`, `NoncurrentVersionExpiration` and `ExpiredObjectDeleteMarker` only. (Transitions, `NoncurrentVersionTransition`, `AbortIncompleteMultipartUpload`, `Filter` and `Prefix` remain rejected.)
* **No** `Filter`, `Prefix`, `Transition`, `NoncurrentVersionTransition`, `AbortIncompleteMultipartUpload`.
* `Expiration.Date` must be **midnight UTC**; `ExpiredObjectDeleteMarker` cannot be combined with `Date`/`Days`.
* Expiry surfaces on `HEAD`/`GET` as `x-amz-expiration: expiry-date="…", rule-id="…"`.
* Lifecycle never deletes a version under retention/legal hold.
* `PutBucketLifecycle` (legacy, non-configuration) is unsupported — only the `…LifecycleConfiguration` family.

### 5.7 Storage classes
`HOT`, `STANDARD`, `COLD` are **routing labels**, not physical tiers: they select a Redundancy Class through Smart Data Placement. Unknown values ⇒ `InvalidStorageClass`. Objects "land in STANDARD" when no rule matches — in our case, in the gateway's `--default-redundancy-class`.

### 5.8 Smart Data Placement (gateway policy engine)
Evaluated **before** placement, first-match-wins over an ordered rule array:

```json
[{"id":"video-to-cold","enabled":true,"inputStorageClass":"STANDARD",
  "conditions":{"operator":"AND","conditions":[
     {"field":"object.key","operator":"matches_regex","value":"\\.(mp4|avi|mov)$"},
     {"operator":"OR","conditions":[
        {"field":"object.size","operator":"gt","value":104857600},
        {"field":"object.content_type","operator":"equals","value":"video/mp4"}]}]},
  "action":{"type":"route","target":{"type":"fixed","redundancyClassId":"<uuid>"}}}]
```
Fields: `object.key`, `object.size`, `object.content_type`, `tenant.name`. Operators: `equals, not_equals, matches_regex, not_matches_regex, starts_with, ends_with, contains, not_contains, gt, lt, gte, lte, in, not_in, exists, not_exists`. Groups `AND`/`OR`, recursable. Actions: `route → {fixed redundancyClassId}` or `drop` (reject upload with `403 AccessDenied`). No match ⇒ default RC.

---

## 6. Limits

| Limit | Value | Source |
|---|---|---|
| Max object size | 5 TiB | Cubbit-published |
| Max single PUT | 5 GiB | AWS parity (undocumented by Cubbit) |
| Multipart part size | 5 MiB – 5 GiB | Cubbit-published |
| Max parts | 10 000 (numbers 1–10 000 inclusive) | Cubbit-published |
| List page size | 1 000 | Cubbit-published |
| Max object key length | 1 024 B | AWS parity |
| Max user metadata | 2 KiB total for `x-amz-meta-*` | AWS parity |
| Max tags per object | 10 | AWS parity |
| Max buckets per project | 1 000 (soft, configurable) | our default |
| Min chargeable object | 256 KB | Cubbit-published (accounting) |
| Request timeout | 15 s header, 24 h body | our default |

---

## 7. Errors

Standard AWS XML envelope. Codes emitted by us:

`AccessDenied` · `InvalidAccessKeyId` · `SignatureDoesNotMatch` · `RequestTimeTooSkewed` · `NoSuchBucket` · `NoSuchKey` · `BucketAlreadyExists` · `BucketAlreadyOwnedByYou` · `BucketNotEmpty` · `InvalidBucketName` · `InvalidArgument` · `InvalidRequest` · `InvalidStorageClass` · `PreconditionFailed` · `NotModified` · `InvalidRange` · `EntityTooLarge` · `EntityTooSmall` · `BadDigest` · `InvalidPart` · `InvalidPartOrder` · `NoSuchUpload` · `AccessControlListNotSupported` · `InvalidBucketAclWithObjectOwnership` · `ObjectLockConfigurationNotFoundError` · `InvalidRetentionPeriod` · `NotImplemented` · `MethodNotAllowed` · `SlowDown` · `InternalError` · `ServiceUnavailable`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Resource>/bucket/key</Resource>
  <RequestId>1a2b3c4d</RequestId>
</Error>
```

Range/precondition precedence (documented because clients depend on it): auth → bucket/key existence → conditional headers → range validation → body.

---

## 8. Multipart implementation notes

* `UploadPart` streams into the normal chunk pipeline; each part gets its own shard sets and RC.
* `CompleteMultipartUpload` assembles a **manifest of part manifests** — no re-encoding, O(parts) metadata work, constant data movement.
* Part ETag = `md5(part bytes)`; object ETag = `md5(concat(part_md5s)) + "-" + len(parts)` (AWS formula). Cubbit warns ETags of large objects may differ between systems; we implement the AWS formula so migration tooling behaves predictably.
* `UploadPartCopy` supports `x-amz-copy-source-range`.
* Minimum part size 5 MiB enforced at complete time (except the last part).
* `AbortMultipartUpload` enqueues shard GC; abandoned sessions expire after 7 days.
* `ListParts` returns ≤ 1 000 parts, `PartNumberMarker` pagination.

---

## 9. Deliberate divergences (the honest list)

| # | Divergence | Why | Risk to clients |
|---|---|---|---|
| D1 | Checksums are **verified**, and `Content-MD5` is enforced | silent corruption is a durability bug; Cubbit's docs explicitly warn users not to rely on checksums | a client sending a wrong checksum now gets `BadDigest` instead of a silent success — *correct* but a behaviour change |
| D2 | Conditional requests (`If-Match`, `If-None-Match`, …) **work** | `If-None-Match: *` is the only race-free create-if-absent primitive; without it, concurrent writers corrupt data | clients get 412/304 where Cubbit would have ignored the header. Opt-out: `--disable-conditional-writes` |
| D3 | Presigned URLs **supported** | virtually every S3 client needs them; Cubbit simply doesn't document them | none |
| D4 | SSE-C **rejected** with `NotImplemented` instead of ignored | accepting an encryption header and not encrypting is a confidentiality bug | honest failure instead of silent plaintext |
| D5 | `Content-Language`/`Expires` **stored** | harmless, more AWS-compatible | none |
| D6 | Public-read ACLs **work** | Cubbit's limitation is a gap, not a feature | none |
| D7 | Bucket-policy S3 APIs remain unsupported (matching Cubbit) but a `--enable-bucket-policy-api` flag can turn them on | surface parity by default, escape hatch available | none |
| D8 | `x-amz-tagging` at upload is **honoured** rather than accepted-and-ignored, and `x-amz-tagging-directive` on copy is honoured | silently discarding a header whose effect clients assume exists is a correctness trap | tags may appear where Cubbit would have none; `cubbit-strict` disables it |

Everything in D1–D4 is guarded by a single config block so a strict-parity mode (`compat: cubbit-strict`) can reproduce Cubbit's behaviour exactly for conformance testing:
```yaml
compat:
  mode: fass            # fass | cubbit-strict
  verify_checksums: true
  conditional_writes: true
  reject_sse_c: true
  ignore_unknown_headers: true
```
`cubbit-strict` exists so our test suite can prove both "we match Cubbit" and "we are better than Cubbit" against the *same* request corpus.
