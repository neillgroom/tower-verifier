# Security Policy & Threat Model

This document describes the verifier's trust assumptions, the threats it defends against, the threats it does NOT defend against, and how to report vulnerabilities.

## Reporting

Open a private security advisory at <https://github.com/neillgroom/tower-verifier/security/advisories/new>. Do not file a public issue for security findings.

If GitHub is unavailable, email Neill Groom (security@thetower.one) with a description.

## Threat model

### Trusted

- The math: SHA-256, Bitcoin's proof-of-work, OpenTimestamps' file format.
- The browser's `SubtleCrypto` SHA-256 (we run a self-test at load to confirm).
- Bitcoin block headers bundled inside a confirmed receipt ZIP. These are 80 bytes of well-defined binary; we hash them locally to derive the block hash and don't trust any provider.

### Trusted-on-first-use (verifiable)

- Tower's `receipt.json`: we hash-check every claim. If a claim disagrees with the math, we render RED.
- The vendored `jszip.min.js`: provenance locked in `vendor/vendor-lock.json` with the upstream URL and SHA-256. Run `scripts/verify-vendor.sh` to re-verify.

### Not trusted

- Anything fetched at verification time. For confirmed entries, the verifier makes ZERO network calls — the bundled block header is sufficient.
- Block explorers (mempool.space, blockstream.info, etc.). The verifier does not consult them for confirmed entries. If a future amber-state verification needs explorer lookup, the verifier will say so explicitly.
- The Tower's API. The verifier never calls Tower.

## Threats this verifier defends against

| # | Threat | Mitigation |
|---|--------|------------|
| 1 | Forged receipt with tampered entry text | Step A re-hashes the text and compares to `hashes.hash_text`; any mismatch → RED |
| 2 | Forged Merkle proof leading to a fake root | Step C walks the proof using Tower's locked hex-concat convention; any mismatch → RED |
| 3 | Forged OTS proof claiming a Bitcoin attestation | Step D parses the OTS proof's binary tree, walks ops to derive the attestation's final hash, verifies the bundled block header's merkle_root field matches |
| 4 | Forged block header | The header is SHA-256d locally to derive the block hash; if `receipt.bitcoin.block_hash` is claimed, must match |
| 5 | Calendar-only OTS proof (Bitcoin confirmation not yet captured) | Renders AMBER, never GREEN. User instructed to re-download |
| 6 | Pre-batch receipt (no anchor yet) | Renders AMBER with clear remediation |
| 7 | ZIP-bomb DoS via crafted small ZIP | Hard caps: 50 MB compressed, 25 MB per file, 20 entries |
| 8 | Path-traversal / XSS via crafted filenames | Filename allowlist + safe-character regex; `textContent` only — no `innerHTML` |
| 9 | Malicious CDN serving a compromised script | All JS is vendored. No remote loads. CSP `default-src 'none'; script-src 'self'` |
| 10 | Compromised SubtleCrypto in the browser | Self-test on a known SHA-256 vector at load; abort on mismatch |

## Threats this verifier explicitly does NOT defend against

- **Compromised verifier repo.** If an attacker pushes a malicious commit to `neillgroom/tower-verifier`, anyone running the live `neillgroom.github.io/tower-verifier` version would run their code. Mitigation: every release lists vendor SHA-256s in `CHANGELOG.md`. Power users clone the repo at a known-good tag and run `scripts/verify-vendor.sh`.
- **Phishing a fake verifier URL.** A user who runs a copy of this code on `tower-verifier-totally-real.com` is trusting that site. Mitigation: the live UI displays its own `window.location.href` so users can confirm the URL matches the one printed in their receipt's `README.txt`. Always cross-check.
- **Decryption of sealed-tier plaintext.** The verifier proves a *hash* was anchored to Bitcoin. For Sealed/Tomb tier entries, decryption of the ciphertext requires the user's key — which The Tower never holds. The verifier proves the carve happened; it does not prove what was carved.
- **The block hash is for a real Bitcoin block.** The verifier confirms the bundled 80-byte header SHA-256d's to a specific hash. It does NOT confirm that hash exists in the longest Bitcoin chain. For complete certainty, look the block hash up in a block explorer or local Bitcoin node — the verifier's UI links you to mempool.space for GREEN results. (A fabricated header would still need to satisfy Bitcoin's proof-of-work difficulty, which is computationally infeasible for any attacker without an enormous mining budget — but if you want certainty, do the explorer cross-check.)

## Reproducible builds

The verifier ships as static HTML/CSS/JS — no build step. The source you see is the code that runs. Tagged releases include SHA-256s of every vendored file in `CHANGELOG.md`, so users can compare their local clone against the published values.

## Coordinated disclosure

We commit to:
- Acknowledging security reports within 72 hours
- Coordinating a fix and disclosure timeline with the reporter
- Crediting reporters in `CHANGELOG.md` unless they prefer anonymity

We do NOT commit to bug bounties.
