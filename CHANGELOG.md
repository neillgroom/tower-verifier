# Changelog

All notable changes to the Tower Verifier are documented here. Each tagged release lists the SHA-256 of every vendored file at that release, so users running the verifier offline can confirm provenance by comparing the locally-installed files against the values here.

## [Unreleased] — 0.2.0

Green now means every piece of content the receipt shows is tied, link by link, to a Bitcoin block header that carries real work. Receipt formats: `docs/formats.md`.

### Changed (verification semantics)
- Five links, all required for green: content to `hash_text` (`A-plain`, `A-salted`, `A-envelope`, fixed by tier), `hash_text` + timestamp + identity to `hash_bound` (`B-hash` or `B-v3` only), Merkle path, OTS proof to the header's Merkle root, header is real.
- Check order: field formats, tier/marker consistency, every link the receipt carries data for (any failure red), and only then amber for missing pieces.
- Header floors pinned in the verifier (minimum height 940842, absolute target ceiling, minimum date), re-derived from `test-vectors/anchored-headers.json` by `scripts/derive-header-constants.js` in the test run. Previously a header with self-declared easy bits could pass.
- A stated `btc_block` must match a Bitcoin attestation; a pending-only proof under a stated block is red.
- OTS parser bounded: 4096-byte working message, 10000 ops, 256 nested forks.
- Public receipts with the identity withheld (every public receipt since The Tower's PR 45, Open included) are amber `A_IDENTITY_WITHHELD`; link 1 and links 3 to 5 are still checked.
- Entries 58 and 59 (binding never recorded) are pinned amber `A_BINDING_UNRECORDED`, never green.
- Hidden Sealed / Time Capsule with no plaintext: green `G_HIDDEN`, labelled "COMMITMENT ANCHORED — CONTENT HIDDEN", never plain "VERIFIED".
- Receipt version 1.3 / protocol 3 (`B-v3`, `A-salted`, `A-envelope`) accepted ahead of the server producing it.
- `B-v3` binds a per-carve secret `binding_nonce` (64 hex) first, so a public `hash_text` and timestamp cannot be used to search for the carver's identity. The nonce is on the owner's receipt only; a public receipt carrying it is red.
- Each result has a stable outcome code and a label, and names the link-1 and link-2 rules evaluated.

### Removed claims
- "Fully offline" no longer implies main-chain membership: offline green proves real launch-era work; confirm the block with the explorer link.

### UI
- Proven date is the block header's timestamp; the receipt's `created_at` is shown only as "stated by the receipt" when link 2 held. Unproven receipt text is labelled NOT proven.
- No in-page owner check: a hidden Sealed / Time Capsule result links The Tower's decrypt page for the owner. The core API still accepts owner plaintext and salt (covered by vectors); any owner input it cannot check is red.
- ZIP: the whole archive layout is walked before the ZIP library reads it (`src/verify-zip.js`, shared with the tests): one end record ending the file, at most 20 real central records, flat unique names only (no `./`, `../`, folders or case-only duplicates), local entries contiguous and matching their central records, no ZIP64, multi-disk or encryption. Closes a forged `envelope.json` showing VERIFIED through a duplicate or path-normalised name. Only the four files the verifier reads are inflated; empty ones are refused; per-file and cumulative inflated-size caps; inflated size must equal the declared size.
- Core: an `owner` argument that is not an object, or an empty owner string, is checked rather than ignored; only a public receipt whose content is still hidden may withhold `hash_text`; an `envelope.json` that cannot be checked is red; `btc_block` accepts 1 to 4294967295 in either form; a malformed test header policy throws.
- OpenTimestamps proofs are read by the strict grammar (no fork-of-fork, no repeated siblings, canonical varints, uint32 heights).
- `envelope.json` added to the ZIP allowlist; README.txt and ciphertext files are no longer read.
- No web font: the Google Fonts import is removed.

### CI
- GitHub Pages deploy runs only after the test job passes.

### Vendored
Unchanged: `vendor/jszip.min.js` jszip@3.10.1 `acc7e41455a80765b5fd9c7ee1b8078a6d160bbbca455aeae854de65c947d59e`.

## [0.1.0] — 2026-05-14

Initial release.

### Features
- Drag-and-drop receipt ZIP verification in the browser
- Full offline path for confirmed entries (no network calls when block header is bundled in ZIP)
- Inline OpenTimestamps file format parser — no third-party crypto library dependency
- Tower's hex-string Merkle convention locked and replicated bit-for-bit
- Multi-attestation OTS proof handling (selects the attestation matching the receipt's canonical block)
- Block hash cross-check against `receipt.bitcoin.block_hash`
- Fail-closed traffic-light state machine: hash check evaluates first; any failure short-circuits to RED
- ZIP-bomb defenses: 50 MB compressed cap, 25 MB per-file decompressed cap, 20 entries max, filename allowlist, no `innerHTML`
- CSP meta tag: `default-src 'none'; script-src 'self'; connect-src 'none'`

### Vendored at this release
| File | Version | SHA-256 |
|------|---------|---------|
| `vendor/jszip.min.js` | jszip@3.10.1 | `acc7e41455a80765b5fd9c7ee1b8078a6d160bbbca455aeae854de65c947d59e` |

### Notable design decisions
- We do NOT vendor `javascript-opentimestamps`. The npm package is CommonJS-only with deep Node.js stdlib usage. Bundling for browser requires polyfills and inflates the audit surface. We instead implement the OTS file format inline (`src/verify-core.js`, ~120 lines) — fully auditable, zero supply-chain risk.
- Tower's Merkle convention is hex-string concatenation (NOT Bitcoin's byte-concat). The verifier replicates this exactly. Migrating to byte-concat would break every existing receipt; this is locked.
- "Verified" requires a `BitcoinBlockHeaderAttestation` confirmed against a real block header. Calendar-only pending attestations render AMBER, never GREEN.
