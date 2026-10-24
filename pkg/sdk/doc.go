// Package sdk is the Go client SDK for FASS, the analogue of Cubbit's SDK.
//
// v1 scope: an S3 client with presigned-URL helpers, so the CLI and the e2e
// suite do not have to reimplement SigV4. Zero-knowledge client-side
// encryption (encrypt-before-upload, mirroring crypto.Envelope) is v1.1 and
// will live here too, because in zero-knowledge mode the client — not the
// gateway — owns the key material.
package sdk
