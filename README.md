# Tower Verifier

**Independent proof checker for [The Tower](https://thetower.one).** Drop a Tower receipt ZIP, get a cryptographically verified result. Works without The Tower being online.

> *If The Tower is gone, this still works.*

## What this is

The Tower is a Bitcoin-anchored idea-timestamping service. Every "carve" gets a SHA-256 hash → Merkle batch → OpenTimestamps stamp → Bitcoin block anchor. Users can download a self-contained **receipt ZIP** containing everything needed to prove the carve mathematically.

This repo is the receipt verifier. It's:

- **Independent of The Tower.** Separate repo, separate domain, separate maintainer pathway. Audit it without reading Tower's server code.
- **Static.** Pure HTML/CSS/JS. No build step. Open `index.html` in any modern browser, including from `file://`.
- **Auditable.** ~400 lines of verification logic in `src/verify-core.js`. The OpenTimestamps file format is parsed inline — no third-party crypto library. The only vendored dependency is [JSZip](https://github.com/Stuk/jszip) (for reading the ZIP itself), with provenance locked in `vendor/vendor-lock.json`.
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

The traffic-light result reflects this exact sequence (any failing step short-circuits to RED — there is no path to a false-positive GREEN):

1. **Self-test.** `SHA-256("The Tower")` must equal a known constant. If the browser's crypto is broken, abort.
2. **Receipt version.** Must equal `1.2` (the current ZIP-shape contract).
3. **Text hash.** `SHA-256(receipt.entry.text)` must equal `receipt.hashes.hash_text`.
4. **Merkle proof.** Walk `receipt.merkle.proof` from `hash_bound` to `merkle_root` using The Tower's locked hex-string concatenation convention (see `docs/MERKLE-CONVENTION.md`).
5. **OpenTimestamps proof.** Parse `merkle-root.ots` inline. Walk the operation tree. For each Bitcoin attestation, compute the final hash that would be the Bitcoin block's merkle_root.
6. **Bitcoin block header.** SHA-256d the bundled 80-byte block header to derive the block hash. The header's merkle_root field (bytes 36-67) must match the OTS attestation's final hash. If `receipt.bitcoin.block_hash` is provided, it must match our computed block hash exactly.

If all six pass: **GREEN.** The carve is mathematically anchored to a specific Bitcoin block.

States:
- **GREEN** — verified, anchored at a specific block.
- **AMBER** — carve is recorded but the Bitcoin confirmation is not yet captured in the ZIP. Re-download the receipt after the next OTS calendar upgrade (~1 hour after Bitcoin confirmation).
- **RED** — verification failed; the detail will say which step and why.

## The "fully offline" claim

The verifier makes **zero network calls** for confirmed entries. The 80-byte Bitcoin block header is bundled into the receipt ZIP at download time by Tower. The verifier hashes those 80 bytes locally to derive the block hash. The OTS proof's embedded Merkle path connects Tower's batch root to that block's merkle_root field.

This means the indestructibility claim works without The Tower, without GitHub Pages, without mempool.space, without any block explorer, without a Bitcoin node. The math is self-contained inside the ZIP. The verifier (this repo) is one tool that runs it; the standard `opentimestamps-client` CLI runs the same math via a different path. The ZIP's `README.txt` documents both.

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

- **Trusted:** the math (SHA-256, Bitcoin's PoW), the browser's SubtleCrypto, the Bitcoin block headers embedded in confirmed receipts.
- **Trusted-on-first-use:** Tower's `receipt.json` (we hash-check its claims), JSZip (vendored, locked).
- **Not trusted:** anything fetched at verification time. The verifier doesn't fetch anything for confirmed entries; if you supply an unconfirmed receipt, it'll tell you so rather than guess.

The verifier specifically does NOT:
- Validate Sealed-tier *plaintext* (Tower never holds the key; verifier proves the hash was anchored, not what was encrypted)
- Search Tower for receipts (you must already have the ZIP)
- Connect to The Tower's API (zero outbound calls)

## Why no `javascript-opentimestamps` library?

The npm package is CommonJS-only and depends deeply on Node.js stdlib + several heavy npm modules (request-promise, bitcore-lib). Bundling it for the browser requires polyfills and inflates the audit surface to ~250KB of vendored third-party code.

We instead implement the OpenTimestamps file format inline in `src/verify-core.js`. The format is well-documented at the [python-opentimestamps file-format spec](https://github.com/opentimestamps/python-opentimestamps/blob/master/doc/file-format.md), and the operations used by Bitcoin proofs are small: `append`, `prepend`, `sha256`, `fork`, plus the Bitcoin and pending-calendar attestation tags. The whole parser is ~120 lines.

This trades library convenience for audit transparency — a deliberate choice for an indestructibility tool.

## Layout

```
tower-verifier/
├── index.html              # Drag-and-drop UI
├── verify.js               # Entry point (~loads modules)
├── style.css
├── src/
│   ├── verify-core.js      # Crypto, OTS parser, top-level verifier (zero DOM)
│   └── verify-ui.js        # DOM rendering, drag-drop
├── vendor/
│   ├── jszip.min.js
│   ├── jszip.LICENSE
│   └── vendor-lock.json    # Upstream SHA-256s
├── scripts/
│   └── verify-vendor.sh
├── test-vectors/           # Real receipt ZIPs for CI tests
├── test/
│   └── run.js              # Node-side test harness
├── README.md
├── SECURITY.md
├── CHANGELOG.md
└── LICENSE                 # MIT
```

## Contributing

Issues and PRs welcome at [github.com/neillgroom/tower-verifier](https://github.com/neillgroom/tower-verifier). Please open an issue before sending a PR for any verification-logic change — false positives are the single failure mode this tool exists to prevent.
