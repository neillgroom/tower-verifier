// verify-core.js — pure verification functions. Zero DOM. Node-testable.
//
// Implements the math behind The Tower's receipt verification. No
// external dependencies; the OpenTimestamps proof format is parsed
// in-line below (see parseOtsProof). This is intentional: an
// indestructibility tool that depends on a third-party crypto library
// inherits that library's supply-chain risk and audit complexity. The
// entire verification path fits in one file you can read end-to-end.
//
// References:
//   - The Tower receipt format: ../../docs/step2-verifier-plan.md §4.5-§4.8
//   - OpenTimestamps file format: https://github.com/opentimestamps/python-opentimestamps/blob/master/doc/file-format.md
//   - Bitcoin block header format: 80 bytes
//       0..3      version (LE int32)
//       4..35     prev_block_hash (32 bytes, LE)
//       36..67    merkle_root (32 bytes, LE)
//       68..71    timestamp (LE uint32)
//       72..75    bits (LE uint32)
//       76..79    nonce (LE uint32)
//   - Block hash = SHA-256(SHA-256(header_bytes)), little-endian byte
//     order. Displayed reversed (big-endian) in explorers.

const TOWER_RECEIPT_VERSION = '1.2';
const OTS_MAGIC = new Uint8Array([
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
    0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
    0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const ATTESTATION_TAG_BITCOIN = '0588960d73d71901';
const ATTESTATION_TAG_PENDING = '83dfe30d2ef90c8e';
const ATTESTATION_MARKER = 0x00;
const OP_FORK = 0xff;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const OP_SHA256 = 0x08;
const OP_RIPEMD160 = 0x02;

// =====================================================================
// Hash + encoding helpers (browser SubtleCrypto; Node fallback exposed
// via global.crypto in modern runtimes).
// =====================================================================

function getSubtle() {
    if (typeof crypto !== 'undefined' && crypto.subtle) return crypto.subtle;
    throw new Error('SubtleCrypto unavailable — verifier requires a modern browser or Node 20+ with globalThis.crypto');
}

async function sha256Bytes(bytes) {
    const buf = await getSubtle().digest('SHA-256', bytes);
    return new Uint8Array(buf);
}

async function sha256Hex(input) {
    const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    const out = await sha256Bytes(bytes);
    return bytesToHex(out);
}

function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
        s += bytes[i].toString(16).padStart(2, '0');
    }
    return s;
}

function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
        throw new Error('invalid hex string');
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
        if (Number.isNaN(out[i])) throw new Error('invalid hex character');
    }
    return out;
}

function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

// =====================================================================
// Browser self-test — Step 0 of the verifier state machine. If
// SubtleCrypto's SHA-256 disagrees with the known answer for "The Tower",
// fail the entire verification immediately. The verifier is useless if
// the host crypto is broken.
// =====================================================================

const SELFTEST_INPUT = 'The Tower';
const SELFTEST_EXPECTED = '699c520b932dd7b7cd109500bf8231cda667a94dd70da850b8fef1f5e94a1136';

async function selfTest() {
    const got = await sha256Hex(SELFTEST_INPUT);
    return got === SELFTEST_EXPECTED;
}

// =====================================================================
// Step A — text hash. SHA-256 of receipt.entry.text must equal
// receipt.hashes.hash_text.
// =====================================================================

async function verifyTextHash(receipt) {
    if (typeof receipt?.entry?.text !== 'string') {
        return { status: 'fail', detail: 'receipt.entry.text missing or not a string' };
    }
    if (typeof receipt?.hashes?.hash_text !== 'string') {
        return { status: 'fail', detail: 'receipt.hashes.hash_text missing' };
    }
    const expected = receipt.hashes.hash_text.toLowerCase();
    const got = await sha256Hex(receipt.entry.text);
    if (got !== expected) {
        return { status: 'fail', detail: `text hash mismatch: computed ${got.slice(0, 16)}…, claimed ${expected.slice(0, 16)}…` };
    }
    return { status: 'pass', detail: `text hash matches (${expected.slice(0, 12)}…)` };
}

// =====================================================================
// Step C — Merkle proof walk. Tower's Merkle convention is locked at
// hex-string concatenation (NOT raw-byte concat per Bitcoin convention).
// See docs/step2-verifier-plan.md §4.5. The verifier MUST replicate
// this byte-for-byte.
//
//   node(left, right) = hex(sha256(ascii(left + right)))
//
// Where left and right are 64-char lowercase hex strings.
// =====================================================================

async function merkleStep(currentHex, siblingHex, siblingPosition) {
    if (siblingPosition !== 'left' && siblingPosition !== 'right') {
        throw new Error(`invalid sibling position: ${siblingPosition}`);
    }
    const combined = siblingPosition === 'right' ? currentHex + siblingHex : siblingHex + currentHex;
    return await sha256Hex(combined);
}

async function verifyMerkleProof(receipt) {
    const merkleObj = receipt?.merkle;
    if (!merkleObj) {
        return { status: 'fail', detail: 'receipt.merkle missing' };
    }
    // Pre-batch entries have merkle.proof === null and merkle_root === null.
    // That's an amber state, not red — the carve is recorded but not yet
    // anchored.
    if (merkleObj.proof === null && merkleObj.merkle_root === null) {
        return { status: 'amber', detail: 'entry not yet batched; anchor pending — re-download after the next batch confirms' };
    }
    if (!Array.isArray(merkleObj.proof)) {
        return { status: 'fail', detail: 'receipt.merkle.proof must be an array (or null for pre-batch)' };
    }
    if (typeof merkleObj.merkle_root !== 'string' || !/^[0-9a-f]{64}$/i.test(merkleObj.merkle_root)) {
        return { status: 'fail', detail: 'receipt.merkle.merkle_root must be a 64-char hex string' };
    }
    const startHex = receipt?.hashes?.hash_bound;
    if (typeof startHex !== 'string' || !/^[0-9a-f]{64}$/i.test(startHex)) {
        return { status: 'fail', detail: 'receipt.hashes.hash_bound must be a 64-char hex string' };
    }
    let current = startHex.toLowerCase();
    for (const step of merkleObj.proof) {
        if (typeof step?.hash !== 'string' || !/^[0-9a-f]{64}$/i.test(step.hash)) {
            return { status: 'fail', detail: 'merkle proof step has invalid sibling hash' };
        }
        current = await merkleStep(current, step.hash.toLowerCase(), step.position);
    }
    const expectedRoot = merkleObj.merkle_root.toLowerCase();
    if (current !== expectedRoot) {
        return { status: 'fail', detail: `merkle proof does not reach root (got ${current.slice(0, 12)}…, expected ${expectedRoot.slice(0, 12)}…)` };
    }
    return { status: 'pass', detail: `merkle proof valid (root ${expectedRoot.slice(0, 12)}…)` };
}

// =====================================================================
// OpenTimestamps proof parser.
//
// The OTS file format encodes a proof as a tree of operations starting
// from an initial hash and ending at one or more attestations. Each
// path from root to attestation corresponds to one timestamp source
// (a Bitcoin block, a Litecoin block, or a still-pending calendar).
//
// We collect every attestation reached and the hash that was the input
// to that attestation. For Bitcoin attestations, the input hash is the
// Bitcoin block's merkle_root field (bytes 36-67 of the 80-byte header).
//
// Operations:
//   0xf0 + varint len + bytes   append bytes to current hash
//   0xf1 + varint len + bytes   prepend bytes to current hash
//   0x08                        SHA-256(current hash)
//   0x02                        RIPEMD160(current hash) — RARE; not in
//                               Bitcoin chain. We support it via async
//                               WebCrypto fallback (failure = unknown).
//   0xff                        Fork (binary branch). Process left
//                               subtree, then right subtree, both
//                               starting from the same current hash.
//   0x00 + 8-byte-tag + varint-len + payload   Attestation (leaf)
// =====================================================================

class OtsReader {
    constructor(bytes) {
        this.bytes = bytes;
        this.pos = 0;
    }
    readByte() {
        if (this.pos >= this.bytes.length) throw new Error('OTS read past end');
        return this.bytes[this.pos++];
    }
    readBytes(n) {
        if (this.pos + n > this.bytes.length) throw new Error('OTS read past end');
        const out = this.bytes.subarray(this.pos, this.pos + n);
        this.pos += n;
        return out;
    }
    readVarint() {
        let value = 0;
        let shift = 0;
        for (let i = 0; i < 10; i++) {
            const b = this.readByte();
            value |= (b & 0x7f) << shift;
            if ((b & 0x80) === 0) return value >>> 0;
            shift += 7;
        }
        throw new Error('varint too long');
    }
    eof() {
        return this.pos >= this.bytes.length;
    }
}

async function applyOp(reader, opCode, currentHash) {
    if (opCode === OP_APPEND) {
        const n = reader.readVarint();
        const data = reader.readBytes(n);
        const out = new Uint8Array(currentHash.length + data.length);
        out.set(currentHash, 0);
        out.set(data, currentHash.length);
        return out;
    }
    if (opCode === OP_PREPEND) {
        const n = reader.readVarint();
        const data = reader.readBytes(n);
        const out = new Uint8Array(data.length + currentHash.length);
        out.set(data, 0);
        out.set(currentHash, data.length);
        return out;
    }
    if (opCode === OP_SHA256) {
        return await sha256Bytes(currentHash);
    }
    if (opCode === OP_RIPEMD160) {
        throw new Error('RIPEMD160 operation in proof — not supported by this verifier (uncommon for Bitcoin OTS proofs)');
    }
    throw new Error(`unknown op code 0x${opCode.toString(16)}`);
}

// Recursively walk the OTS timestamp tree. Returns an array of
// { tag, height, finalHash } attestation records.
async function walkOtsTree(reader, currentHash, attestations) {
    while (!reader.eof()) {
        const tag = reader.readByte();
        if (tag === OP_FORK) {
            // Binary branch. The current hash is the starting point for
            // BOTH the left and the right subtree. Walk the left subtree
            // first (it consumes its own bytes from the stream), then
            // continue with the right subtree using the SAME currentHash.
            // The format encodes this by simply running another timestamp
            // tree inline after the fork marker; the outer loop will
            // continue processing what's after.
            //
            // Per the OTS spec, fork means: parse one full subtree (a
            // timestamp) right here, then continue the current timestamp
            // from the same currentHash. We accomplish this by recursing
            // on the same reader+hash; recursion returns when its
            // subtree hits an attestation. After return, the outer
            // loop continues processing additional ops from the same
            // starting hash.
            await walkOtsTree(reader, currentHash, attestations);
            // After the fork's sub-timestamp terminates, the outer loop
            // resumes from the SAME current hash to process the right
            // branch in-line.
            continue;
        }
        if (tag === ATTESTATION_MARKER) {
            const tagBytes = reader.readBytes(8);
            const tagHex = bytesToHex(tagBytes);
            const payloadLen = reader.readVarint();
            const payload = reader.readBytes(payloadLen);
            if (tagHex === ATTESTATION_TAG_BITCOIN) {
                // payload = varint block_height
                const subReader = new OtsReader(payload);
                const height = subReader.readVarint();
                attestations.push({
                    type: 'bitcoin',
                    blockHeight: height,
                    finalHash: new Uint8Array(currentHash),
                });
            } else if (tagHex === ATTESTATION_TAG_PENDING) {
                // payload = varint url-len + url
                const subReader = new OtsReader(payload);
                const urlLen = subReader.readVarint();
                const urlBytes = subReader.readBytes(urlLen);
                const url = new TextDecoder().decode(urlBytes);
                attestations.push({ type: 'pending', url, finalHash: new Uint8Array(currentHash) });
            } else {
                attestations.push({ type: 'unknown', tagHex, finalHash: new Uint8Array(currentHash) });
            }
            // Attestation terminates this leaf path. Return to outer
            // frame, which may continue processing if we're inside a
            // fork.
            return;
        }
        // Op tag; apply and continue.
        currentHash = await applyOp(reader, tag, currentHash);
    }
}

async function parseOtsProof(otsBytes, initialHashHex) {
    // Verify magic.
    if (otsBytes.length < OTS_MAGIC.length + 2) {
        throw new Error('OTS file too short');
    }
    for (let i = 0; i < OTS_MAGIC.length; i++) {
        if (otsBytes[i] !== OTS_MAGIC[i]) {
            throw new Error(`OTS magic mismatch at byte ${i}`);
        }
    }
    const reader = new OtsReader(otsBytes);
    reader.pos = OTS_MAGIC.length;
    const version = reader.readByte();
    if (version !== 0x01) {
        throw new Error(`OTS version ${version} not supported (expected 1)`);
    }
    // File hash op: must be SHA-256 (0x08) + 32 bytes. The 32 bytes are
    // the hash OTS calls "file hash" — for Tower, that's the SHA-256 of
    // the ASCII bytes of the merkle_root hex string (because anchor.js
    // writes merkle_root to a file and then calls `ots stamp <file>`).
    const fileHashOp = reader.readByte();
    if (fileHashOp !== OP_SHA256) {
        throw new Error(`OTS file hash op 0x${fileHashOp.toString(16)} not SHA-256`);
    }
    const fileHash = reader.readBytes(32);
    // Verify the file hash matches what we expect (SHA-256 of the ASCII
    // hex of Tower's merkle_root).
    const expectedFileHash = await sha256Bytes(new TextEncoder().encode(initialHashHex));
    if (!bytesEqual(fileHash, expectedFileHash)) {
        throw new Error(`OTS file hash mismatch: expected ${bytesToHex(expectedFileHash).slice(0, 16)}…, got ${bytesToHex(fileHash).slice(0, 16)}…`);
    }
    // Walk the timestamp tree from the file hash.
    const attestations = [];
    await walkOtsTree(reader, new Uint8Array(fileHash), attestations);
    return attestations;
}

// =====================================================================
// Step D — Bitcoin block header verification.
//
// The OTS attestation tells us a Bitcoin block height + an expected
// merkle_root for that block. If the receipt ZIP includes the 80-byte
// block header, we can verify fully offline:
//   - SHA-256d the header bytes; the result is the block hash
//   - Check that the merkle_root field (bytes 36-67) matches the
//     hash that OTS walked to (just before the attestation)
//   - If receipt.bitcoin.block_hash is supplied, double-check it
//     matches our computed block hash (reversed for display)
//
// If the receipt has no header, we fall back to fetching one from a
// block explorer (see verify-fetch.js) — but the strong-claim path is
// the bundled-header check.
// =====================================================================

async function verifyBitcoinHeader(receipt, otsBytes) {
    const merkleRoot = receipt?.merkle?.merkle_root;
    if (typeof merkleRoot !== 'string' || !/^[0-9a-f]{64}$/i.test(merkleRoot)) {
        return { status: 'fail', detail: 'receipt.merkle.merkle_root missing or invalid' };
    }
    if (!otsBytes) {
        return { status: 'amber', detail: 'no OTS proof in receipt ZIP — cannot verify Bitcoin anchor' };
    }
    let attestations;
    try {
        attestations = await parseOtsProof(otsBytes, merkleRoot.toLowerCase());
    } catch (err) {
        return { status: 'fail', detail: `OTS parse failed: ${err.message}` };
    }
    const btcAttestations = attestations.filter((a) => a.type === 'bitcoin');
    if (btcAttestations.length === 0) {
        const pending = attestations.filter((a) => a.type === 'pending');
        if (pending.length > 0) {
            return {
                status: 'amber',
                detail: `OTS proof has ${pending.length} pending calendar attestation(s); Bitcoin confirmation not yet captured — re-download the receipt after the calendar upgrades the proof`,
            };
        }
        return { status: 'fail', detail: 'OTS proof has no Bitcoin or pending attestation' };
    }

    // A single OTS proof can carry MULTIPLE Bitcoin attestations from
    // different calendars at slightly different blocks (e.g., batch #2
    // attests 941015, 941022, and 941032 — all valid timestamps). The
    // receipt's btc_block is the CANONICAL block (lowest, per anchor.js).
    // To verify offline, we need the attestation whose blockHeight
    // matches the bundled block header. Pick that one — not blindly the
    // first.
    const expectedBlock = receipt?.bitcoin?.btc_block;
    let chosen = null;
    if (expectedBlock) {
        chosen = btcAttestations.find((a) => String(a.blockHeight) === String(expectedBlock));
    }
    if (!chosen) {
        // Fall back to lowest height — matches anchor.js convention.
        chosen = btcAttestations.reduce(
            (lo, a) => (lo === null || a.blockHeight < lo.blockHeight ? a : lo),
            null
        );
    }
    const headerHex = receipt?.bitcoin?.block_header_hex;
    if (typeof headerHex !== 'string' || !/^[0-9a-f]{160}$/i.test(headerHex)) {
        return {
            status: 'amber',
            detail: `OTS attests Bitcoin block ${chosen.blockHeight}, but receipt has no bundled block header to verify offline — fall back to a block explorer (handled by the fetch path)`,
            attestations: btcAttestations,
        };
    }
    const header = hexToBytes(headerHex);
    if (header.length !== 80) {
        return { status: 'fail', detail: 'block header is not 80 bytes' };
    }
    // Block hash = SHA-256d(header), then reverse for display.
    const hash1 = await sha256Bytes(header);
    const hash2 = await sha256Bytes(hash1);
    const blockHashLE = hash2;
    const blockHashBE = new Uint8Array(blockHashLE.length);
    for (let i = 0; i < blockHashLE.length; i++) blockHashBE[i] = blockHashLE[blockHashLE.length - 1 - i];
    const blockHashHex = bytesToHex(blockHashBE);
    // merkle_root field is bytes 36..67 of the header, little-endian.
    const headerMerkleRootLE = header.subarray(36, 68);
    const headerMerkleRootBE = new Uint8Array(32);
    for (let i = 0; i < 32; i++) headerMerkleRootBE[i] = headerMerkleRootLE[31 - i];
    const headerMerkleRootHexBE = bytesToHex(headerMerkleRootBE);
    // The OTS attestation's "final hash" is what we walked the proof to
    // produce — that should equal the Bitcoin block's merkle_root
    // (typically displayed big-endian).
    const otsFinalHashHex = bytesToHex(chosen.finalHash);
    if (otsFinalHashHex !== headerMerkleRootHexBE && otsFinalHashHex !== bytesToHex(headerMerkleRootLE)) {
        return {
            status: 'fail',
            detail: `OTS proof's final hash for block ${chosen.blockHeight} (${otsFinalHashHex.slice(0, 16)}…) does not match the block header's merkle_root (${headerMerkleRootHexBE.slice(0, 16)}…). All attestation heights found: ${btcAttestations.map((a) => a.blockHeight).join(', ')}.`,
        };
    }
    // Optionally cross-check the receipt's block_hash claim.
    if (receipt?.bitcoin?.block_hash && receipt.bitcoin.block_hash.toLowerCase() !== blockHashHex) {
        return {
            status: 'fail',
            detail: `receipt claims block hash ${receipt.bitcoin.block_hash.slice(0, 16)}…, computed ${blockHashHex.slice(0, 16)}…`,
        };
    }
    return {
        status: 'pass',
        detail: `anchored at Bitcoin block ${chosen.blockHeight} (${blockHashHex.slice(0, 16)}…) — verified offline against bundled 80-byte header (${btcAttestations.length} attestation${btcAttestations.length === 1 ? '' : 's'} in proof)`,
        blockHeight: chosen.blockHeight,
        blockHashHex,
    };
}

// =====================================================================
// Top-level verify function. Returns the traffic-light result.
// Evaluation order per docs/step2-verifier-plan.md §4.6.
// =====================================================================

async function verifyReceiptArtifacts({ receipt, otsBytes }) {
    const steps = [];
    const log = (name, result) => steps.push({ name, ...result });
    // Step 0 — self-test.
    if (!(await selfTest())) {
        return {
            overall: 'red',
            summary: 'Browser SHA-256 self-test failed. The host crypto is broken; do not trust any green result.',
            steps,
        };
    }
    log('self-test', { status: 'pass', detail: 'SubtleCrypto SHA-256 verified against known vector' });
    // Step Pre — receipt version.
    if (!receipt || receipt.version !== TOWER_RECEIPT_VERSION) {
        log('receipt-version', { status: 'fail', detail: `expected receipt version ${TOWER_RECEIPT_VERSION}, got ${receipt?.version ?? '(missing)'}` });
        return { overall: 'red', summary: 'Receipt version mismatch.', steps };
    }
    log('receipt-version', { status: 'pass', detail: `receipt v${TOWER_RECEIPT_VERSION}` });
    // Step A — text hash.
    const a = await verifyTextHash(receipt);
    log('text-hash', a);
    if (a.status === 'fail') {
        return { overall: 'red', summary: 'Text hash does not match.', steps };
    }
    // Step C — Merkle proof.
    const c = await verifyMerkleProof(receipt);
    log('merkle-proof', c);
    if (c.status === 'fail') {
        return { overall: 'red', summary: 'Merkle proof does not reach root.', steps };
    }
    if (c.status === 'amber') {
        return {
            overall: 'amber',
            summary: 'Carve recorded but anchor pending — re-download after the next batch confirms.',
            steps,
        };
    }
    // Step D — Bitcoin header + OTS walk.
    const d = await verifyBitcoinHeader(receipt, otsBytes);
    log('bitcoin-anchor', d);
    if (d.status === 'fail') {
        return { overall: 'red', summary: d.detail, steps };
    }
    if (d.status === 'amber') {
        return { overall: 'amber', summary: d.detail, steps };
    }
    return {
        overall: 'green',
        summary: `Verified — anchored at Bitcoin block ${d.blockHeight}`,
        blockHeight: d.blockHeight,
        blockHashHex: d.blockHashHex,
        steps,
    };
}

// Exports for browser (script global) and Node (CommonJS) — works in both.
const api = {
    TOWER_RECEIPT_VERSION,
    sha256Hex,
    sha256Bytes,
    bytesToHex,
    hexToBytes,
    selfTest,
    verifyTextHash,
    verifyMerkleProof,
    parseOtsProof,
    verifyBitcoinHeader,
    verifyReceiptArtifacts,
};
if (typeof module !== 'undefined' && module.exports) module.exports = api;
if (typeof window !== 'undefined') window.TowerVerifyCore = api;
