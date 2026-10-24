# Cubbit DS3 — Public Documentation Research (API reimplementation brief)

Source: https://docs.cubbit.io (English). All 63 sitemap URLs enumerated; 11 DS3 guide/getting-started pages plus integrations read. **No page 404'd.** `/guides/s3-api` needed raw-HTML retrieval; quotes verbatim. **INFERRED** = my deduction, not doc text.

## 1. Endpoint & auth model

- **Endpoint = per-account "endpoint gateway" hostname**, "configured at tenant level and assigned to your account, so it can differ for each tenant and account". Clients receive the **hostname without `https://`**. Shown in console Profile → Account → Endpoint gateway, editable per account when the row is visible; otherwise the console is bound to the tenant's gateway.
- **No fixed public hostname is published.** INFERRED: gateway is TLS at `https://<gateway-host>`; documented Cubbit hosts are only `console.cubbit.eu`, `console.<tenant>.cubbit.eu`, `s3bridge.cubbit.eu`, `cubbit-public.s3.cubbit.eu` (bucket URL), `installer.s3.cubbit.eu` — suggesting an `s3.cubbit.eu` domain.
- **Region:** `eu-west-1` everywhere (AWS CLI, Veeam, rclone "eu-west-1 (or leave empty)", Lucidlink, Nakivo, Elastic, Archiware). CRNs embed it (`crn:eu-west-1:s3:bucket:…`). Bridge: region "always mapped to Cubbit's eu-west region". INFERRED: other strings accepted/ignored.
- **Signature:** **SigV2 and SigV4 both accepted** — "the signature version can be either 2 or 4" (CloudBerry), "2 or 4" (Iperius), "v2 or v4" (QNAP), "Signature Version 4, with region: eu-west-1" (Archiware). SigV2 corroborated by: `Content-MD5` is "Only used as part of the Signature Version 2 (SigV2) signature".
- **Credentials:** access key + secret key bound to a project IAM user ("client API key"); generated in console, secret shown once, CSV download, unlimited keys.
- **Session tokens / STS:** **not documented/supported** — "temporary/STS credentials are not supported (no session token field is sent)". INFERRED: `X-Amz-Security-Token` ignored.
- **Presigned URLs:** **entirely undocumented** — zero hits for "presigned", `X-Amz-Signature`, `X-Amz-Credential` across all 63 pages. Auth chain covers "anonymous requests" and public-read ACLs exist "with limitations", so unauthenticated GET may work; presign support is unknown.
- **Addressing:** never stated. The only path-style discussion is DS3 Bridge's *source* knob (`use_path_style`), and its migrator "always addresses the source using path-style URLs". INFERRED: **path-style only** (gateway host is account-specific, not bucket-specific).
- **TLS:** client guides enable SSL, but no page says HTTPS is mandatory; self-hosted Composer gateways can disable TLS by flag. INFERRED: 443/HTTPS expected.

## 2. S3 API compatibility matrix

Docs publish an explicit **API Compatibility Table**: **41 Yes / 54 No**.

| Family | Status (exact names) |
|---|---|
| Bucket CRUD | `CreateBucket`, `DeleteBucket`, `HeadBucket`, `ListBuckets`, `GetBucketLocation` — **Yes**. Delete requires bucket empty of objects *and versions*. |
| Object CRUD | `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `DeleteObjects`, `CopyObject` — **Yes** ("fully supported"); `Range` honoured. |
| Listing | `ListObjects`, `ListObjectsV2`, `ListObjectVersions`, `ListMultipartUploads`, `ListParts` — **Yes**; page size 1000. |
| Multipart | `CreateMultipartUpload`, `UploadPart`, `UploadPartCopy`, `CompleteMultipartUpload`, `AbortMultipartUpload` — **Yes** ("fully supported"). |
| ACL | `GetBucketAcl`, `PutBucketAcl`, `GetObjectAcl`, `PutObjectAcl` — **Yes**. Groups only `AllUsers`, `AuthenticatedUsers`; canned ACLs `private`, `public-read`, `public-read-write`, `authenticated-read`, `bucket-owner-read`, `bucket-owner-full-control`. |
| Policy | `PutBucketPolicy`, `GetBucketPolicy`, `DeleteBucketPolicy`, `GetBucketPolicyStatus`, PublicAccessBlock — **No** (yet bucket policies *are* evaluated — §4). |
| Tagging | `Put/Get/DeleteObjectTagging` — **Yes** ("May not be available for some buckets"); `Put/Get/DeleteBucketTagging` — **No**. |
| Versioning | `PutBucketVersioning`, `GetBucketVersioning` — **Yes**. |
| Object lock | `Put/GetObjectLockConfiguration`, `Put/GetObjectRetention`, `Put/GetObjectLegalHold` — all **Yes** ("fully supported"). |
| Lifecycle | `Put/GetBucketLifecycleConfiguration`, `DeleteBucketLifecycle` — **Yes**; `Put/GetBucketLifecycle` — **No**. |
| Ownership controls | `Put/Get/DeleteBucketOwnershipControls` — **Yes**. |
| CORS | `Put/Get/DeleteBucketCors` — **No**. |
| Encryption | `Put/Get/DeleteBucketEncryption` — **No**; all SSE headers accepted but inert (§4). |
| Storage class | `x-amz-storage-class` "Validated; invalid storage classes are rejected"; no transition APIs; objects "land in the default STANDARD class". |
| Select / misc | `SelectObjectContent`, `GetObjectAttributes`, `RestoreObject`, `GetObjectTorrent`, `WriteGetObjectResponse` — **No**. |
| Also **No** | Website, Logging, Replication, Notification(+Configuration), RequestPayment, Accelerate, and all Analytics/Inventory/Metrics/IntelligentTiering config APIs. |

## 3. Limits and quotas (published only)

| Item | Value |
|---|---|
| Max object size | **5 TiB** |
| Max parts / part numbers | **10,000**; numbering **1–10,000 inclusive** |
| Part size | min **5 MiB**, max **5 GiB** |
| ListParts / ListMultipartUploads / list objects page | **1000** |
| Max single PUT | **undocumented** (AWS parity 5 GiB — INFERRED) |
| Max buckets/account, key length, metadata size, tags | **undocumented**; for `x-amz-meta-*` only "a total size limit applies", number unpublished. |
| Rate limits, request timeout, streaming | **undocumented**. INFERRED: payloads streamed (5 GiB parts), unverified. |
| Billing-only | min chargeable object **256 KB**; bandwidth = downloads per calendar month. |

## 4. Semantics diverging from AWS S3

1. **Headers are permissive-but-inert:** "A header marked `No` is accepted without error but is not evaluated". **Conditional requests are dead** — `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`, all `x-amz-copy-source-if-*` return "no 412 Precondition Failed…"; copy "is performed unconditionally". Docs warn "conditional writes, checksums, and client-side encryption keys are not enforced yet"; conditional support "targeted for early 2027". No `If-None-Match: *` create-if-absent.
2. **Checksums decorative:** every `x-amz-checksum-*`, `x-amz-sdk-checksum-algorithm`, `x-amz-checksum-mode` unverified/unreturned; `Content-MD5` "never verified against the payload"; `x-amz-trailer` "discarded".
3. **Encryption headers ignored:** SSE-S3/KMS "Not applied; objects are stored with the platform's default encryption"; SSE-C keys "never used". Platform does AES-256 file keys + Reed-Solomon shards + gateway-side encryption.
4. **Versioning:** version IDs are **"a 128-bit fixed-size UUIDv4"**, not AWS's 32-char tokens — treat as opaque. Delete w/o `versionId` adds a marker and keeps versions; with `versionId` is permanent and irreversible. Suspension only affects future behaviour; versioning is bucket-wide.
5. **Object Lock:** "You can only turn on object locking during bucket creation"; auto-enables versioning; cannot be disabled or converted. COMPLIANCE + GOVERNANCE + legal hold. Retention may only be **extended**. Governance bypass needs `s3:BypassGovernanceRetention` **or** ROOT **plus** `x-amz-bypass-governance-retention:true`; never affects legal hold. Deleting a locked version → **403 AccessDenied** (unversioned delete still creates a marker). Bucket defaults are **not retroactive**; `PutObjectRetention` overrides per object. `x-amz-bucket-object-lock-token` "Not evaluated".
6. **Ownership Controls default is `ObjectWriter`** (AWS defaults to `BucketOwnerEnforced`): "This setting is the default value for Cubbit." `BucketOwnerEnforced` → ACL writes fail with `AccessControlListNotSupported` (reads OK); conflicting bucket ACL → `InvalidBucketAclWithObjectOwnership`. `x-amz-grant-write` on object ACLs is "stored but never evaluated"; ignored entirely on PutObject/CopyObject/CreateMultipartUpload.
7. **Public access crippled:** "read and write operations are not yet supported in a public-read or public-read-write scenario"; group semantics "might slightly change in the future".
8. **Lifecycle contradiction:** s3-api says "A single configuration rule is allowed… NoncurrentVersionExpiration with no filters"; lifecycle page (newer) says `Expiration` **and** `NoncurrentVersionExpiration`, multiple rules. Both: no `Filter`, `Prefix`, `Transition`, `NoncurrentVersionTransition`, `AbortIncompleteMultipartUpload`. `Expiration.Date` must be **midnight UTC**; `ExpiredObjectDeleteMarker` supported but not combinable with Date/Days; expiry surfaces as `Expiration: expiry-date="…", rule-id="…"`. Lifecycle skips locked/unexpired versions.
9. **Tagging partial:** no inline tags (`x-amz-tagging`, `x-amz-tagging-directive` not applied), no `x-amz-tagging-count` in GetObject, CopyObject preserves but cannot overwrite tags; legacy buckets may lack tagging entirely.
10. **Authorization is a 4-stage proprietary chain:** key/secret → **IAM policy** (explicit deny wins) → **bucket policy** (deny wins, else falls through) → **ACL** (must explicitly allow). Bucket policies have **no S3 API** (`PutBucketPolicy` = No) — managed out-of-band. Policies use `syntax_version` `2023-10-16`, v2 CRNs (`crn:eu-west-1:s3:object:tenant_<uuid>/project_<uuid>/bucket/key`) and Cubbit actions incl. `ds3:MapBucketNamesAndIDs`. Presets Owner/Admin/Member/ReadOnly. Quirk: to use S3 you must grant `iam:CreateKey`, `iam:ManageKey`, `iam:ListKeys`.
11. **Service accounts** = project IAM users (not console users); credentials bound to that user; an invited-but-unused account "is automatically deleted" after **7 days** and its keys stop working.
12. **No metrics API.** "Resource metrics" is console/billing only: 256 KB minimum chargeable size, separate empty vs non-empty object counts (a proxy for delete markers), bandwidth = monthly downloads.
13. **DS3 Bridge is not S3.** Separate migration control plane: **JSON over HTTPS at `https://s3bridge.cubbit.eu`**, auth via proprietary `x-cbt-api-key`, `x-cbt-api-secret`, `x-cbt-tenant-id` (no SigV4). `POST /bridges` (201 `{id}`), `POST /bridges/start-migration` (204, idempotent), `GET /bridges` (status `ready|in-progress|completed`; per-bucket `migrated`/`failed`/`locked`, `locked` reserved, always 0), `DELETE /bridges` (204, tracking only). One bridge per project; bucket must never have had Object Lock; while migrating, CopyObject/UploadPartCopy are blocked and pending source MPUs are lost. Reads proxy to source until copied, then source copy is deleted; writes always hit Cubbit. ETags of large objects may differ, storage class forced STANDARD, SSE/Content-Language/Expires/website-redirect not carried over.
14. **Other inert features:** `x-amz-request-payer` (Requester Pays unsupported), `x-amz-mfa` (MFA Delete can be *set and reported* but "never enforced on delete operations"), `x-amz-website-redirect-location`, `Content-Language`, `Expires`, `x-amz-optional-object-attributes`, `x-amz-source-expected-bucket-owner`. `x-amz-expected-bucket-owner` *is* enforced ("A mismatch returns Access Denied"). Multipart ETags are not guaranteed stable across implementations.

## 5. Error codes and XML envelope

**No error reference page exists and no XML envelope is documented.** Error codes named in prose only:

| Code | Trigger | Page |
|---|---|---|
| `AccessControlListNotSupported` | ACL write / ACL-bearing upload under `BucketOwnerEnforced` | ownership-controls |
| `InvalidBucketAclWithObjectOwnership` | enabling `BucketOwnerEnforced` while bucket ACL grants other accounts | ownership-controls |
| `AccessDenied` 403 | delete of a version under retention/legal hold | object-lock |
| "Access Denied" | `x-amz-expected-bucket-owner` mismatch | s3-api |
| "Invalid source object" | `UploadPartCopy` from very old objects | multipart-upload |

Conditional codes are explicitly **absent** ("no 412 Precondition Failed or 304 Not Modified is returned"). INFERRED: assume standard `<Error><Code>…</Code><Message>…</Message><Resource>…</Resource><RequestId>…</RequestId></Error>`; unverified.

## 6. Quoted claims

- "The Cubbit S3 Gateway supports most of the AWS S3 RESTful APIs used by the AWS SDKs … and by all the S3 compatible clients." — https://docs.cubbit.io/guides/s3-api
- "A header marked `No` is accepted without error but is not evaluated: its effect is not applied by the gateway." — /guides/s3-api
- "conditional writes, checksums, and client-side encryption keys are not enforced yet … do not rely on them to prevent overwrites, to verify integrity, or to encrypt objects with your own key." — /guides/s3-api
- "A single configuration rule is allowed. The only configuration rule supported is the NoncurrentVersionExpiration with no filters." — /guides/s3-api
- "Currently, both NoncurrentVersionExpiration and Expiration rules are supported … Multiple rules per bucket are supported." — https://docs.cubbit.io/guides/lifecycle-configuration
- "Each new version generated has a unique version ID, which is a 128-bit fixed-size UUIDv4." — https://docs.cubbit.io/guides/bucket-and-object-versioning
- "With ObjectWriter, the original uploader remains the object owner … This setting is the default value for Cubbit." — https://docs.cubbit.io/guides/ownership-controls
- "You can only turn on object locking during bucket creation. A bucket created without Object Lock cannot be converted." — https://docs.cubbit.io/guides/object-lock
- "read and write operations are not yet supported in a public-read or public-read-write scenario" — /guides/s3-api
- "To operate over the S3, so in example create buckets, uploads objects, you need to grant at least iam:CreateKey, iam:ManageKey and iam:ListKeys to your users" — https://docs.cubbit.io/guides/permissions
- "Configure the client with the endpoint gateway assigned to your account and the region eu-west-1" — https://docs.cubbit.io/guides/service-accounts
- "If the row is not shown, your console is bound to the endpoint gateway configured for your tenant" — https://docs.cubbit.io/getting-started/quickstart
- "Cubbit enforces a minimum chargeable size. This size is 256KB." — https://docs.cubbit.io/guides/resource-metrics
- "temporary/STS credentials are not supported (no session token field is sent)" — https://docs.cubbit.io/guides/ds3-bridge
- "Maximum object size | 5 TiB … Minimum part size | 5 MiB … Maximum part size | 5 GiB … Maximum number of parts per upload | 10,000" — https://docs.cubbit.io/guides/multipart-upload
