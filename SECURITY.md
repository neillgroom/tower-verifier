# Security Policy & Threat Model

This document describes the verifier's trust assumptions, the threats it defends against, the threats it does NOT defend against, and how to report vulnerabilities.

## Reporting

Open a private security advisory at <https://github.com/neillgroom/tower-verifier/security/advisories/new>. Do not file a public issue for security findings.

If GitHub is unavailable, email Neill Groom (security@thetower.one) with a description.

## Threat model

### Trusted

- The math: SHA-256, Bitcoin's proof-of-work, OpenTimestamps' file format.
- The browser's `SubtleCrypto` SHA-256 (we run a self-test at load to confirm).
- Bitcoin's proof of work, judged against floors pinned in the verifier (minimum height 940842, an absolute difficulty ceiling, a minimum date), never against values the receipt chooses. A bundled header itself is not trusted.

### Trusted-on-first-use (verifiable)

- Tower's `receipt.json`: every claim it carries data for is checked, and any failure is RED. A missing piece can only make the result AMBER after every available check has passed.
- The vendored `jszip.min.js`: provenance locked in `vendor/vendor-lock.json` with the upstream URL and SHA-256. Run `scripts/verify-vendor.sh` to re-verify.

### Not trusted

- Anything fetched at verification time. The verifier makes no network calls at all (CSP `connect-src 'none'`).
- Block explorers. The verifier never consults one; a green result links one for the main-chain check the verifier cannot do offline (see below).
- The Tower's API. The verifier never calls Tower.

## Threats this verifier defends against

Each row is pinned by vectors in `test-vectors/` (`expected.json` names the outcome code the verifier must return; `test/run.js` fails if any outcome code has no vector).

| # | Threat | Mitigation |
|---|--------|------------|
| 1 | Text swapped over a real anchor | Link 1: the text shown must hash to `hash_text` (`A-plain` / `A-salted`); link 2: `hash_text`, timestamp and identity (and under `B-v3` the owner-only binding nonce) must hash to `hash_bound`. Either failing is RED |
| 2 | A tier claim that skips the text check (e.g. "sealed" over visible text, "tomb" over ordinary text) | Tier and marker are checked first; the content rule is fixed by the tier, and a rule stated for the wrong tier is RED |
| 3 | A leaf the receipt cannot explain (bound over the text, `hash_bound == hash_text`, bound over the literal `[SEALED]`) | Only `B-hash` and `B-v3` are implemented; anything else is RED. Two pinned early entries whose binding was never recorded are AMBER, never green |
| 4 | Pipe or salt boundary shifts, a hash posing as text | Fields are format-checked before hashing (exact 64-hex, exact millisecond UTC timestamp, hex or decimal identity, no NUL); `B-v3` and `A-salted` inputs are NUL-separated and domain-labelled, so they cannot equal a `B-hash` input |
| 5 | Forged Merkle proof | Link 3 walks the path with Tower's hex-concat convention; mismatch is RED |
| 6 | Forged or mismatched OTS proof | Link 4 parses the proof inline, bounded (4096-byte message, 10000 ops, 256 forks), and requires the attestation at the receipt's stated height to end at the header's Merkle root. A stated block with a pending-only proof is RED |
| 7 | Forged block header (easy self-declared bits, early-chain or pre-launch header, bad nonce) | Link 5: pinned minimum height, absolute target ceiling and minimum date, then `sha256d(header)` at or below its own target; a stated `block_hash` must match |
| 8 | Incomplete receipt shown as proven | Not batched, OTS pending, no OTS or header, identity withheld, Treasure envelope missing: AMBER, never GREEN, and only after every available link has passed |
| 9 | Hidden carve presented as verified content | A Sealed / Time Capsule receipt showing only `[SEALED]` is labelled "commitment anchored, content hidden" and claims no content; the receipt's `created_at` is never shown as the block time |
| 10 | ZIP-bomb DoS | Hard caps: 50 MB compressed, 25 MB per file and 50 MB in all (enforced while inflating), 20 real central records |
| 10a | ZIP that shows different files to different readers (duplicate or `./`-style names, hidden local entries, trailing data) | `src/verify-zip.js` walks the whole layout before the ZIP library loads it and refuses any ambiguity; the library must then hold exactly the names walked |
| 11 | Path traversal / XSS via crafted filenames or receipt strings | Filename allowlist + safe-character regex; every receipt string is inserted with `textContent`, never as HTML |
| 12 | Malicious CDN or exfiltration | All JS vendored or local; CSP `default-src 'none'; script-src 'self'; connect-src 'none'`; the page takes no plaintext, salt or key file |
| 13 | Compromised SubtleCrypto | Self-test on a known SHA-256 vector; abort on mismatch |

## Threats this verifier explicitly does NOT defend against

- **Compromised verifier repo.** If an attacker pushes a malicious commit to `neillgroom/tower-verifier`, anyone running the live `neillgroom.github.io/tower-verifier` version would run their code. Mitigation: every release lists vendor SHA-256s in `CHANGELOG.md`. Power users clone the repo at a known-good tag and run `scripts/verify-vendor.sh`.
- **Phishing a fake verifier URL.** A user who runs a copy of this code on `tower-verifier-totally-real.com` is trusting that site. Mitigation: the live UI displays its own `window.location.href` so users can confirm the URL matches the one printed in their receipt's `README.txt`. Always cross-check.
- **The content of an unrevealed sealed carve.** For Sealed and Time Capsule entries the verifier proves a commitment was anchored. It does not prove what was carved; the page takes no plaintext or key, and the owner checks content on The Tower's decrypt page.
- **Main-chain membership.** Offline, a green result proves the bundled header carries real launch-era Bitcoin work: its target is at or below a ceiling pinned from the real blocks The Tower has anchored, its date is at or after The Tower's first anchor (and the height the timestamp proof states is too; the header does not prove its height), and its hash meets its own target. It does NOT prove the block is in the main Bitcoin chain. Confirm that with the explorer link on a green result, or your own node. Forging a header that passes would need mining a block at real Bitcoin difficulty.
- **Who carved a public receipt.** Public receipts withhold the carver's identity, so link 2 cannot be checked on them; they are AMBER. Only the owner's own receipt can be green.

## Reproducible builds

The verifier ships as static HTML/CSS/JS — no build step. The source you see is the code that runs. Tagged releases include SHA-256s of every vendored file in `CHANGELOG.md`, so users can compare their local clone against the published values.

## Coordinated disclosure

We commit to:
- Acknowledging security reports within 72 hours
- Coordinating a fix and disclosure timeline with the reporter
- Crediting reporters in `CHANGELOG.md` unless they prefer anonymity

We do NOT commit to bug bounties.
