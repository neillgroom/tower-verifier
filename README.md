# Tower Verifier

**Independent proof checker for [The Tower](https://thetower.one).** Drop a Tower receipt ZIP, get a cryptographically verified result. Works without The Tower being online.

> *If The Tower is gone, this still works.*

## What this is

The Tower is a Bitcoin-anchored idea-timestamping service. Every "carve" gets a SHA-256 hash → Merkle batch → OpenTimestamps stamp → Bitcoin block anchor. Users can download a self-contained **receipt ZIP** containing everything the verifier checks offline.

This repo is the receipt verifier. It's:

- **Independent of The Tower.** Separate repo, separate domain, separate maintainer pathway. Audit it without reading Tower's server code.
- **Static.** Pure HTML/CSS/JS. No build step. Open `index.html` in any modern browser, including from `file://`.
- **Auditable.** About 1,000 lines of verification logic in one file, `src/verify-core.js`, with no DOM. The OpenTimestamps file format is parsed inline — no third-party crypto library. The only vendored dependency is [JSZip](https://github.com/Stuk/jszip) (for reading the ZIP itself), with provenance locked in `vendor/vendor-lock.json`.
- **MIT licensed.**

## Usage

**Live verifier:** [neillgroom.github.io/tower-verifier](https://neillgroom.github.io/tower-verifier/)

**Offline:**
```bash
git clone https://github.com/neillgroom/tower-verifier.git
cd tower-verifier
# Open index.html in any modern browser — that's the whole install.
```

## What gets verified

**Green means every piece of content the receipt shows is tied, link by link, to a Bitcoin block header that carries real work.** The byte-level contract is [`docs/formats.md`](docs/formats.md).

0. **Self-test.** `SHA-256("The Tower")` must equal a known constant, or nothing else is trusted.
1. **Field formats and tier.** Hashes are exactly 64 lowercase hex, the timestamp is an exact millisecond ISO-8601 UTC string, the identity is a 64-hex phone hash or a decimal user id, and the shown text agrees with the tier (`[SEALED]` for a Time Capsule, `[TREASURE]` for a Treasure, never a marker on Open). Receipt version `1.2` (legacy) or `1.3` (protocol 3).
2. **Link 1, content to commitment.** The text shown hashes to `hash_text`: `A-plain` for Open and for every Sealed / Time Capsule carved before protocol 3, `A-salted` for Sealed / Time Capsule from protocol 3, `A-envelope` (the bytes of `envelope.json`) for Treasure. The rule is fixed by the tier; a rule stated for the wrong tier is red.
3. **Link 2, commitment to leaf.** `hash_text`, the timestamp and the identity hash to `hash_bound`, by exactly one of two formats: `B-hash` (every carve before protocol 3) or `B-v3` (domain-separated, from protocol 3). Nothing else is accepted.
4. **Link 3, leaf to root.** The Merkle path from `hash_bound` reaches `merkle_root` (Tower's hex-string concatenation convention).
5. **Link 4, root to header.** The OpenTimestamps proof, parsed inline with bounded size and operation count, ends at the Merkle root inside the bundled 80-byte header, at the height the receipt states.
6. **Link 5, the header is real.** Pinned minimum height (940842, Tower's first anchored block), pinned absolute difficulty ceiling, pinned minimum date, and `sha256d(header)` below its own target. None of these depend on a value the receipt chooses.

Any check that runs and fails is **RED**, even if something else is also missing. Only after every available link has passed may a missing piece make the result **AMBER**.

| Light | Meaning |
|---|---|
| **VERIFIED** (green) | The content shown (or the Treasure envelope) was anchored in this block |
| **COMMITMENT ANCHORED — CONTENT HIDDEN** (green) | A hidden Sealed / Time Capsule carve by this identity was anchored. No content is shown, so none is claimed |
| **NOT FULLY PROVEN** (amber) | Something is not proven, and the result says whether the Bitcoin anchor itself was checked: not yet batched, OTS pending, no OTS or header bundled, identity withheld (every public receipt), binding unrecorded (two pinned early entries), Treasure envelope not supplied |
| **FAILED** (red) | A claim in the receipt is false or malformed; the result names which |

The block time shown is the timestamp in the Bitcoin block header. A miner sets it, and Bitcoin only keeps it within about two hours of real time, so it dates the anchor approximately; it is not an exact proven moment. The block height comes from the timestamp proof and is not proven by the header; the explorer link goes by block hash. The receipt's `created_at` is shown only as "stated by the receipt", and only when link 2 held. Every result names the link-1 and link-2 rules it evaluated.

**Hidden content.** This page takes no plaintext, salt or key file. A hidden Sealed or Time Capsule entry shows "commitment anchored, content hidden"; its owner can decrypt and check the content with The Tower's decrypt page (https://thetower.one/decrypt.html), linked from the result. The page fetches nothing (CSP `connect-src 'none'`).

## What green does not prove

Offline, green proves the header carries real launch-era Bitcoin work and that the receipt's content leads to it. It does not prove the block is in the main Bitcoin chain: confirm that with the explorer link shown on a green result (or your own node). Forging a header that passes would need mining a block at real Bitcoin difficulty.

The verifier makes no network calls at all. The receipt ZIP carries everything it checks.

## Verifying the vendor

The only third-party code is `vendor/jszip.min.js`. Its provenance is locked in `vendor/vendor-lock.json` with the exact upstream URL and SHA-256. To verify yourself:

```bash
curl -sSL https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js | sha256sum
# Should match the sha256 in vendor/vendor-lock.json
```

Or run the included script:
```bash
bash scripts/verify-vendor.sh
```

## Threat model and limits

See [SECURITY.md](SECURITY.md) for the full threat model. In brief:

- **Trusted:** the math (SHA-256, Bitcoin's PoW) and the browser's SubtleCrypto (self-tested). A bundled header is not trusted: it must meet the pinned height, work and date floors.
- **Trusted-on-first-use:** Tower's `receipt.json` (we hash-check its claims), JSZip (vendored, locked).
- **Not trusted:** anything fetched at verification time. The verifier fetches nothing; if a receipt is unconfirmed or incomplete it says so (amber) rather than guess.

The verifier specifically does NOT:
- Check a hidden Sealed or Time Capsule entry's plaintext (that is done on The Tower's decrypt page; Tower never holds the key)
- Prove that the anchoring block is in the main chain (use the explorer link)
- Search Tower for receipts (you must already have the ZIP)
- Connect to The Tower's API (zero outbound calls)

## Why no `javascript-opentimestamps` library?

The npm package is CommonJS-only and depends deeply on Node.js stdlib + several heavy npm modules (request-promise, bitcore-lib). Bundling it for the browser requires polyfills and inflates the audit surface to ~250KB of vendored third-party code.

We instead implement the OpenTimestamps file format inline in `src/verify-core.js`. The format is well-documented at the [python-opentimestamps file-format spec](https://github.com/opentimestamps/python-opentimestamps/blob/master/doc/file-format.md), and the operations used by Bitcoin proofs are small: `append`, `prepend`, `sha256`, `fork`, plus the Bitcoin and pending-calendar attestation tags. The whole parser is about 150 lines.

This trades library convenience for audit transparency — a deliberate choice for an indestructibility tool.

## Layout

```
tower-verifier/
├── index.html              # Drag-and-drop UI
├── style.css
├── src/
│   ├── verify-core.js      # Crypto, OTS parser, top-level verifier (zero DOM)
│   ├── verify-zip.js       # Strict receipt-ZIP reader (layout walk, caps), shared with tests
│   └── verify-ui.js        # DOM rendering, drag-drop
├── vendor/
│   ├── jszip.min.js
│   ├── jszip.LICENSE
│   └── vendor-lock.json    # Upstream SHA-256s
├── docs/
│   └── formats.md          # Receipt byte layouts and outcome codes
├── scripts/
│   ├── verify-vendor.sh
│   ├── build-test-vectors.py      # Independent (Python) builder of every vector
│   └── derive-header-constants.js # Re-derives the pinned header floors
├── test-vectors/           # Genuine and forged receipt ZIPs + expected.json
├── test/
│   └── run.js              # Node-side test harness
├── README.md
├── SECURITY.md
├── CHANGELOG.md
└── LICENSE                 # MIT
```

## Contributing

Issues and PRs welcome at [github.com/neillgroom/tower-verifier](https://github.com/neillgroom/tower-verifier). Please open an issue before sending a PR for any verification-logic change — false positives are the single failure mode this tool exists to prevent.
