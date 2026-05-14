# Changelog

All notable changes to the Tower Verifier are documented here. Each tagged release lists the SHA-256 of every vendored file at that release, so users running the verifier offline can confirm provenance by comparing the locally-installed files against the values here.

## [Unreleased]

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
