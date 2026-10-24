# Intellectual-property and provenance audit (limited)

This is a **bounded, evidence-based audit performed at the moment of the project's documentation
freeze**. It records what was checked, how, and what it does **not** establish.

**It is not a legal opinion, does not clear the project, and does not address patents.** Patent
freedom-to-operate, trademark clearance, and any definitive conclusion about infringement or
licence compatibility require qualified professional review. Nothing here should be read as a
guarantee of legal safety.

Scope of the checks: repository contents at the frozen commit, the dependency tree and vendored
licences, documentation provenance, and committed secrets. Out of scope: externally hosted
material, behaviour of third-party services, and the law of any jurisdiction.

| Status | Meaning |
|---|---|
| **VERIFIED** | Checked against evidence in this repository; the statement below is supportable. |
| **NEEDS HUMAN REVIEW** | A real question that this audit cannot settle. Decide before any commercial distribution. |
| **NO ISSUE FOUND IN THIS LIMITED AUDIT** | Looked, found nothing — not proof that nothing exists. |

---

## 1. Source-code provenance

| Finding | Evidence | Status |
|---|---|---|
| The implementation is original Go code, not copied from a third-party project. | The tree is our history: 61 commits authored in this repository, no file-level copying of an external codebase. The design documents record *behaviour* observed from public material and mark deductions `INFERRED`. | VERIFIED (as far as this repository's own history can show) |
| No proprietary binaries, decompiled code or leaked internal protocols were used. | Method statement in [01 §Method](01-reverse-engineering.md); only public web documentation is cited. | VERIFIED per that statement |
| The two-tier erasure-coding mathematics and the S3 API are public standards: Reed–Solomon over GF(2⁸), and the S3 HTTP/XML protocol. | Implemented with the MIT-licensed `klauspost/reedsolomon` library and hand-written S3 handlers. | NO ISSUE FOUND IN THIS LIMITED AUDIT |

## 2. Third-party documentation and diagrams

| Finding | Evidence | Status |
|---|---|---|
| No third-party documentation pages are redistributed. | The raw research snapshot (`cubbit/pages/`, `cubbit/pg.html`, `cubbit/extract.py`) is **untracked and gitignored**; `git ls-files cubbit/` lists only our own analysis file. | VERIFIED |
| The tracked research notes cite their sources and quote only short excerpts for analysis. | `docs/research/*.md` cite `docs.cubbit.io` page paths; [01 §7](01-reverse-engineering.md) is an evidence index mapping each claim to a public page. Quotations are short phrases used to characterise published behaviour. | VERIFIED (practice); **NEEDS HUMAN REVIEW** if the project is ever distributed commercially or the research notes are expanded |
| Diagrams are original. | All architecture diagrams in the docs are hand-written ASCII/Unicode art authored here. | VERIFIED |
| No claim of architectural identity or behavioural equivalence is made. | Root README states FASS is independently developed and that public observations are design input only; the S3 compatibility claims are scoped to the published operation matrix and are backed by tests. | VERIFIED |

**NEEDS HUMAN REVIEW — research notes.** If the project is published beyond a development
release, a human should confirm that short quotations in `docs/01` and `docs/research/*` are
acceptable in the intended jurisdictions (quotation/fair-use limits differ), and decide whether the
untracked scraped snapshot should be retained locally at all.

## 3. Dependencies and licence compatibility

The module declares MIT and vendors eight third-party modules. Every vendored module carries a
licence file:

| Module | Version | Licence file present | Licence |
|---|---|---|---|
| `github.com/jackc/pgx/v5` | v5.11.0 | yes | MIT |
| `github.com/jackc/puddle/v2` | v2.2.2 | yes | MIT |
| `github.com/jackc/pgpassfile` | v1.0.0 | yes | MIT |
| `github.com/jackc/pgservicefile` | v0.0.0-2024… | yes | MIT |
| `github.com/klauspost/reedsolomon` | v1.14.2 | yes | MIT |
| `github.com/klauspost/cpuid/v2` | v2.3.0 | yes | MIT |
| `golang.org/x/sync`, `x/sys`, `x/text` | v0.17.0 / v0.30.0 / v0.29.0 | yes (+`PATENTS`) | BSD-3-Clause |

| Finding | Status |
|---|---|
| MIT project code distributed with MIT and BSD-3-Clause dependencies: those licences are permissive and generally compatible with an MIT-licensed aggregate, provided copyright notices are retained. They are retained in `vendor/`. | VERIFIED (licence files present) |
| Whether any dependency has a **patent** clause implication for the user's jurisdiction. | **NEEDS HUMAN REVIEW** (`golang.org/x/*` includes a `PATENTS` file; others do not) |

Project licence file: [`LICENSE`](../LICENSE) (MIT). The README's licence section points to it, and
the file's copyright holder is "FASS contributors" — **NEEDS HUMAN REVIEW** if a specific legal
entity or person should be named instead.

## 4. Trademarks and naming

| Finding | Status |
|---|---|
| The product is named **FASS**; the GitHub repository is `faas` (a name collision of letters, not a reference to Function-as-a-Service). | VERIFIED |
| "Cubbit", "Cubbit DS3", "DS3 Composer" appear as **nominative, descriptive references** in research and technical-comparison documents, not as branding of this project. No logos or brand assets are used. | **NEEDS HUMAN REVIEW** — nominative use is generally defensible, but whether specific usage is acceptable is a legal judgement |
| The root README carries a non-affiliation notice (independence; no endorsement; third-party trademarks remain their owners' property). | VERIFIED (see [README §Repository](../README.md)) |
| Internal identifiers still contain a legacy name: the Go module path is `github.com/fass-storage/fass`, which does not match the repository URL. | VERIFIED as a **deliberate, documented** mismatch — changing it would rewrite every internal import for no functional gain; there are no published downstream consumers. Not a licence issue. |

## 5. Committed secrets and credentials

| Finding | Evidence | Status |
|---|---|---|
| No real credentials are committed. | Pattern scan over tracked files for private-key blocks and `AKIA…` access-key IDs. The only hit is AWS's own documented example key `AKIAIOSFODNN7EXAMPLE`, used as a SigV4 test fixture. | VERIFIED |
| The dev cluster ships fixed development credentials (`dev-access-key` / `dev-secret-key`) and a hex tenant key seed. | These are documented dev defaults in `--dev-bootstrap`, deliberately predictable and loudly marked dev-only; they are not production secrets. | VERIFIED (by design) — **NEEDS HUMAN REVIEW** only if someone treats the dev stack as production |

## 6. Claims made in documentation

| Finding | Status |
|---|---|
| Compatibility claims are scoped and test-backed: "42 supported operations" was verified by set-diff against a published compatibility table; performance figures are labelled as single-host order-of-magnitude measurements; the README's maturity banner says the release is **not production-validated**. | VERIFIED |
| No claim of full S3 conformance, of identity with any third-party product, or of durability guarantees is made without stated conditions. | VERIFIED |
| Whether a reader could still infer third-party equivalence from the research documents. | **NEEDS HUMAN REVIEW** — the documents are explicit about method and inference markers, but a reviewer may want to strengthen the wording |

---

## 7. What this audit does not establish

- That FASS is free of patent or trademark infringement.
- That short quotations in the research notes qualify as fair use / fair dealing in any jurisdiction.
- That the MIT/BSD dependency licences are compatible with every intended distribution channel
  (e.g. statically linked binaries, app stores, regulated environments).
- That no third-party code was copied — this audit can only report what the repository's history
  and content show.
- That the project is legally cleared for commercial use.

**Recommended before any commercial distribution:** a review by qualified counsel of (a) the
research notes and their quotations, (b) trademark use of third-party product names, (c) patent
questions in the erasure-coding and S3-protocol space, and (d) the copyright holder named in
`LICENSE`.
