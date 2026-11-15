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
//   - The Tower receipt formats and outcome codes: ../docs/formats.md
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
const OP_SHA1 = 0x02;
const OP_RIPEMD160 = 0x03;

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
// The one rule (docs/formats.md is the byte-level contract).
//
// GREEN means every piece of content the receipt shows is tied, link by
// link, to a Bitcoin block header that carries real work:
//   link 1  content          -> hash_text   (A-plain | A-salted | A-envelope)
//   link 2  hash_text + timestamp + identity -> hash_bound   (B-hash | B-v3;
//           B-v3 also binds the secret binding nonce, tier and content rule)
//   link 3  Merkle path      -> merkle_root
//   link 4  OTS proof        -> header merkle root
//   link 5  header is real   (pinned height, work and date floors)
// AMBER means something shown or implied is not proven; the result says
// what, and whether the anchor itself was checked. RED means a claim in the receipt is
// false or malformed.
//
// Order, so an amber can never mask a false claim: field formats; tier and
// marker consistency; rule-for-tier; then EVERY link the receipt carries
// data for is checked and any failure is red; only then may a missing piece
// make the result amber.
// =====================================================================

// Every outcome the verifier can return, with its colour. test/run.js fails
// if any of these has no vector.
const OUTCOME_CODES = Object.freeze({
    G_CONTENT: 'green', //          the content shown was anchored
    G_HIDDEN: 'green', //           commitment anchored, content hidden
    G_OWNER_CONTENT: 'green', //    owner-supplied content was anchored
    G_ENVELOPE: 'green', //         this Treasure envelope was anchored
    A_NOT_BATCHED: 'amber',
    A_OTS_PENDING: 'amber',
    A_NO_OTS: 'amber',
    A_NO_HEADER: 'amber',
    A_IDENTITY_WITHHELD: 'amber',
    A_BINDING_UNRECORDED: 'amber',
    A_TREASURE_NO_ENVELOPE: 'amber',
    R_SELFTEST: 'red',
    R_VERSION: 'red',
    R_FIELD_FORMAT: 'red',
    R_UNKNOWN_RULE: 'red',
    R_RULE_TIER: 'red',
    R_TIER_MARKER: 'red',
    R_CONTENT_MISMATCH: 'red',
    R_SALT_MISSING: 'red',
    R_BINDING_MISMATCH: 'red',
    R_MERKLE: 'red',
    R_OTS: 'red',
    R_HEADER: 'red',
    R_HEADER_HEIGHT: 'red',
    R_HEADER_WORK: 'red',
    R_HEADER_TIME: 'red',
    R_HEADER_POW: 'red',
});

// The traffic-light label for each colour. The hidden-commitment green has
// its own label and is never shown as plain "VERIFIED": it claims no content.
const OUTCOME_LABELS = Object.freeze({
    G_HIDDEN: 'COMMITMENT ANCHORED — CONTENT HIDDEN',
    green: 'VERIFIED',
    amber: 'NOT FULLY PROVEN',
    red: 'FAILED',
});
function outcomeLabel(code) {
    if (Object.prototype.hasOwnProperty.call(OUTCOME_LABELS, code)) return OUTCOME_LABELS[code];
    return OUTCOME_LABELS[OUTCOME_CODES[code]] || 'UNKNOWN';
}

// When several things are missing, the result's code is the first of these
// that applies; result.ambers lists all of them.
const AMBER_PRIORITY = [
    'A_NOT_BATCHED',
    'A_OTS_PENDING',
    'A_NO_OTS',
    'A_NO_HEADER',
    'A_IDENTITY_WITHHELD',
    'A_BINDING_UNRECORDED',
    'A_TREASURE_NO_ENVELOPE',
];

const LEGACY_RECEIPT_VERSION = '1.2';
const V3_RECEIPT_VERSION = '1.3';
const SEALED_MARKER = '[SEALED]';
const TREASURE_MARKER = '[TREASURE]';
const TIERS = ['open', 'sealed', 'tomb', 'treasure'];
const CONTENT_RULE_FOR_V3_TIER = { open: 'A-plain', sealed: 'A-salted', tomb: 'A-salted', treasure: 'A-envelope' };
const CONTENT_RULES = ['A-plain', 'A-salted', 'A-envelope'];

const HEX64 = /^[0-9a-f]{64}$/;
const HEX160 = /^[0-9a-f]{160}$/;
const ISO_MS_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const USER_ID = /^(0|[1-9][0-9]{0,14})$/;
const BLOCK_HEIGHT = /^[1-9][0-9]{0,9}$/;
const MAX_BLOCK_HEIGHT = 0xffffffff; // OTS stores heights as uint32

// Two manual inserts (entries 58 and 59) whose binding was never recorded.
// Their leaves are anchored, but no formula reproduces them: amber, never
// green, and only for legacy receipts.
const PINNED_UNRECORDED_BINDINGS = Object.freeze([
    '50593140802f2c4d2652c0fa34220b21b167039caf6777b4096ac78a908150d5',
    '6313be4d0d3958910e557005fb4df7228c7ee0e1682523641a69b098adbf88d8',
]);

// ---------------------------------------------------------------------
// Header constants. Derived from the twelve real headers Tower has anchored
// (test-vectors/anchored-headers.json); scripts/derive-header-constants.js
// recomputes them and test/run.js fails if they drift.
//   MIN_ANCHOR_HEIGHT  Tower's first anchored block. No carve is older.
//   MAX_TARGET         4 x the easiest target among the anchored headers
//                      (bits 0x17021ff0 at 949320/949407): 0x21ff0 * 4 =
//                      0x87fc0, shifted 8 * (0x17 - 3) = 160 bits. Four is
//                      the most Bitcoin's difficulty can ease in one
//                      retarget. Same ceiling for every height; it does not
//                      depend on the bits or height the receipt chooses.
//   MIN_HEADER_TIME    earliest anchored header time (block 940842,
//                      1773628353 = 2026-03-16T02:32:33Z) minus 2 hours of
//                      timestamp slack between neighbouring blocks.
// ---------------------------------------------------------------------
const MIN_ANCHOR_HEIGHT = 940842;
const MAX_TARGET = 0x87fc0n << 160n;
const MIN_HEADER_TIME = 1773621153;
const PINNED_HEADER_POLICY = Object.freeze({
    minHeight: MIN_ANCHOR_HEIGHT,
    maxTarget: MAX_TARGET,
    minTime: MIN_HEADER_TIME,
});

// =====================================================================
// Rule implementations (docs/formats.md). All inputs are pre-validated
// ASCII except plaintext, which is UTF-8 without NUL.
// =====================================================================

const utf8 = (s) => new TextEncoder().encode(s);

function joinWithNul(parts) {
    const enc = parts.map((p) => (typeof p === 'string' ? utf8(p) : p));
    const len = enc.reduce((n, p) => n + p.length, 0) + enc.length - 1;
    const out = new Uint8Array(len);
    let off = 0;
    enc.forEach((p, i) => {
        if (i > 0) out[off++] = 0x00;
        out.set(p, off);
        off += p.length;
    });
    return out;
}

// B-hash: sha256(hash_text | created_at | identity). Legacy carves.
async function bindHash(hashText, createdAt, identity) {
    return sha256Hex(hashText + '|' + createdAt + '|' + identity);
}

// B-v3: sha256("tower" 00 "bound" 00 "v4" 00 nonce 00 tier 00 content_rule 00
//              hash_text 00 created_at 00 identity).
// nonce is a per-carve secret (64 lowercase hex, server CSPRNG) carried only
// on the owner's receipt. Without it, a public hash_text and timestamp would
// let anyone search the small identity space against hash_bound. Label "v4":
// the unshipped nonce-less layout used "v3".
function bindV3Input(nonce, tier, contentRule, hashText, createdAt, identity) {
    return joinWithNul(['tower', 'bound', 'v4', nonce, tier, contentRule, hashText, createdAt, identity]);
}
async function bindV3(nonce, tier, contentRule, hashText, createdAt, identity) {
    return sha256Hex(bindV3Input(nonce, tier, contentRule, hashText, createdAt, identity));
}

// A-salted: sha256("tower" 00 "commit" 00 "v1" 00 salt 00 utf8(plaintext)).
function commitSaltedInput(salt, plaintext) {
    return joinWithNul(['tower', 'commit', 'v1', salt, plaintext]);
}
async function commitSalted(salt, plaintext) {
    return sha256Hex(commitSaltedInput(salt, plaintext));
}

// =====================================================================
// Step 1 — field formats and rule statements. Nothing is hashed until the
// receipt parses. Returns { ok: true, r } or { ok: false, code, detail }.
// =====================================================================

const bad = (code, detail) => ({ ok: false, code, detail });
const isObj = (o) => o !== null && typeof o === 'object' && !Array.isArray(o);
const absent = (v) => v === undefined || v === null;

function isIsoMsUtc(s) {
    if (typeof s !== 'string' || !ISO_MS_UTC.test(s)) return false;
    const d = new Date(s);
    return !Number.isNaN(d.getTime()) && d.toISOString() === s;
}

// One range for every form a height arrives in: 1 to 2^32-1, the same bound
// the OTS walker applies to attested heights.
function parseHeight(v) {
    let n = NaN;
    if (typeof v === 'number' && Number.isSafeInteger(v)) n = v;
    else if (typeof v === 'string' && BLOCK_HEIGHT.test(v)) n = Number(v);
    return n >= 1 && n <= MAX_BLOCK_HEIGHT ? n : NaN;
}

function parseReceipt(receipt, owner, envelopeBytes) {
    if (!isObj(receipt)) return bad('R_FIELD_FORMAT', 'receipt.json is not a JSON object');

    // Version and protocol.
    const legacy = receipt.version === LEGACY_RECEIPT_VERSION;
    if (!legacy && receipt.version !== V3_RECEIPT_VERSION) {
        return bad('R_VERSION', `receipt version ${JSON.stringify(receipt.version ?? null)} is not ${LEGACY_RECEIPT_VERSION} or ${V3_RECEIPT_VERSION}`);
    }
    const pv = receipt.protocol_version;
    if (legacy && !(absent(pv) || pv === 1 || pv === 2)) {
        return bad('R_UNKNOWN_RULE', `receipt v${LEGACY_RECEIPT_VERSION} must have protocol_version 1 or 2 (got ${JSON.stringify(pv)})`);
    }
    if (!legacy && pv !== 3) {
        return bad('R_UNKNOWN_RULE', `receipt v${V3_RECEIPT_VERSION} must have protocol_version 3 (got ${JSON.stringify(pv)})`);
    }
    const hashes = receipt.hashes;
    if (!isObj(hashes)) return bad('R_FIELD_FORMAT', 'receipt.hashes missing');

    // Rule statements: a v3 receipt states its rules and only those are
    // tried; a legacy receipt may state B-hash / A-plain and nothing else.
    let boundRule;
    let statedContentRule = null;
    if (legacy) {
        if (!absent(hashes.bound_rule) && hashes.bound_rule !== 'B-hash') {
            return bad('R_UNKNOWN_RULE', `legacy receipt states bound_rule ${JSON.stringify(hashes.bound_rule)}; only B-hash exists before protocol 3`);
        }
        if (!absent(hashes.content_rule) && hashes.content_rule !== 'A-plain') {
            return bad('R_UNKNOWN_RULE', `legacy receipt states content_rule ${JSON.stringify(hashes.content_rule)}; only A-plain exists before protocol 3`);
        }
        boundRule = 'B-hash';
        if (!absent(hashes.binding_nonce)) {
            return bad('R_FIELD_FORMAT', 'a protocol 1/2 receipt never carries binding_nonce');
        }
    } else {
        if (hashes.bound_rule !== 'B-v3') {
            return bad('R_UNKNOWN_RULE', `protocol 3 receipt must state bound_rule "B-v3" (got ${JSON.stringify(hashes.bound_rule ?? null)})`);
        }
        if (!CONTENT_RULES.includes(hashes.content_rule)) {
            return bad('R_UNKNOWN_RULE', `protocol 3 receipt states unknown content_rule ${JSON.stringify(hashes.content_rule ?? null)}`);
        }
        boundRule = 'B-v3';
        statedContentRule = hashes.content_rule;
    }

    // Entry: text, tier, timestamp.
    const entry = receipt.entry;
    if (!isObj(entry)) return bad('R_FIELD_FORMAT', 'receipt.entry missing');
    if (!(typeof entry.id === 'number' && Number.isSafeInteger(entry.id) && entry.id > 0)) {
        return bad('R_FIELD_FORMAT', 'entry.id is not a positive integer');
    }
    if (typeof entry.text !== 'string') return bad('R_FIELD_FORMAT', 'entry.text missing or not a string');
    if (entry.text.includes('\u0000')) return bad('R_FIELD_FORMAT', 'entry.text contains a NUL character');
    let tier = entry.tier;
    if (absent(tier) && legacy) {
        tier = entry.text === SEALED_MARKER ? 'sealed' : 'open';
    } else if (!TIERS.includes(tier)) {
        return bad('R_FIELD_FORMAT', `entry.tier ${JSON.stringify(tier ?? null)} is not one of ${TIERS.join(', ')}`);
    }
    if (!isIsoMsUtc(entry.created_at)) {
        return bad('R_FIELD_FORMAT', `entry.created_at ${JSON.stringify(entry.created_at ?? null)} is not an exact millisecond ISO-8601 UTC timestamp`);
    }

    // Identity: present (64-hex phone hash or decimal user id), or withheld.
    const ident = receipt.identity;
    if (!isObj(ident)) return bad('R_FIELD_FORMAT', 'receipt.identity missing');
    let identity = null;
    if (ident.redacted === true) {
        if (!absent(ident.binding_identity)) return bad('R_FIELD_FORMAT', 'identity is marked redacted but carries binding_identity');
    } else {
        identity = ident.binding_identity;
        const isPhone = typeof identity === 'string' && HEX64.test(identity);
        const isUser = typeof identity === 'string' && USER_ID.test(identity);
        if (!isPhone && !isUser) {
            return bad('R_FIELD_FORMAT', 'identity.binding_identity is not a 64-hex phone hash or a decimal user id');
        }
        const field = ident.binding_field;
        if (!absent(field) && !((field === 'phone_hash' && isPhone) || (field === 'user_id' && isUser))) {
            return bad('R_FIELD_FORMAT', `identity.binding_field ${JSON.stringify(field)} does not match the identity's form`);
        }
    }

    // Hashes.
    if (typeof hashes.hash_bound !== 'string' || !HEX64.test(hashes.hash_bound)) {
        return bad('R_FIELD_FORMAT', 'hashes.hash_bound is not 64 lowercase hex characters');
    }
    let hashText = hashes.hash_text;
    if (absent(hashText)) {
        // Only a public receipt whose content is still hidden may withhold
        // hash_text; once text is shown, link 1 must be checkable.
        const contentHidden = entry.text === SEALED_MARKER || entry.text === TREASURE_MARKER;
        if (!(identity === null && tier !== 'open' && contentHidden)) {
            return bad('R_FIELD_FORMAT', 'hashes.hash_text is missing; only a public receipt whose content is still hidden may withhold it');
        }
        hashText = null;
    } else if (typeof hashText !== 'string' || !HEX64.test(hashText)) {
        return bad('R_FIELD_FORMAT', 'hashes.hash_text is not 64 lowercase hex characters');
    }
    let commitSalt = hashes.commit_salt;
    if (absent(commitSalt)) commitSalt = null;
    else if (typeof commitSalt !== 'string' || !HEX64.test(commitSalt)) {
        return bad('R_FIELD_FORMAT', 'hashes.commit_salt is not 64 lowercase hex characters');
    }
    // B-v3 binding nonce: on the owner's receipt (identity present) and only
    // there. A public receipt that carries it is leaking a secret: red.
    let bindingNonce = null;
    if (!legacy) {
        const n = hashes.binding_nonce;
        if (identity === null) {
            if (!absent(n)) return bad('R_FIELD_FORMAT', 'a public receipt (identity withheld) must not carry binding_nonce');
        } else if (typeof n !== 'string' || !HEX64.test(n)) {
            return bad('R_FIELD_FORMAT', 'hashes.binding_nonce is missing or not 64 lowercase hex characters (an owner receipt carries it)');
        } else {
            bindingNonce = n;
        }
    }

    // Merkle.
    const m = receipt.merkle;
    if (!isObj(m)) return bad('R_FIELD_FORMAT', 'receipt.merkle missing');
    let merkle;
    if (m.proof === null && m.merkle_root === null) {
        merkle = null;
    } else {
        if (!Array.isArray(m.proof)) return bad('R_FIELD_FORMAT', 'merkle.proof must be an array (or null before batching)');
        if (typeof m.merkle_root !== 'string' || !HEX64.test(m.merkle_root)) {
            return bad('R_FIELD_FORMAT', 'merkle.merkle_root is not 64 lowercase hex characters');
        }
        if (m.proof.length > 64) return bad('R_FIELD_FORMAT', 'merkle.proof is longer than 64 steps');
        for (const step of m.proof) {
            if (!isObj(step) || typeof step.hash !== 'string' || !HEX64.test(step.hash) ||
                (step.position !== 'left' && step.position !== 'right')) {
                return bad('R_FIELD_FORMAT', 'a merkle.proof step is not { hash: 64 lowercase hex, position: left|right }');
            }
        }
        merkle = { root: m.merkle_root, proof: m.proof };
    }

    // Bitcoin.
    if (!absent(receipt.bitcoin) && !isObj(receipt.bitcoin)) return bad('R_FIELD_FORMAT', 'receipt.bitcoin is not a JSON object');
    const b = absent(receipt.bitcoin) ? {} : receipt.bitcoin;
    let btcBlock = null;
    if (!absent(b.btc_block)) {
        btcBlock = parseHeight(b.btc_block);
        if (Number.isNaN(btcBlock)) return bad('R_FIELD_FORMAT', `bitcoin.btc_block ${JSON.stringify(b.btc_block)} is not a positive integer`);
    }
    let blockHash = null;
    if (!absent(b.block_hash)) {
        if (typeof b.block_hash !== 'string' || !HEX64.test(b.block_hash)) return bad('R_FIELD_FORMAT', 'bitcoin.block_hash is not 64 lowercase hex characters');
        blockHash = b.block_hash;
    }
    let headerHex = null;
    if (!absent(b.block_header_hex)) {
        if (typeof b.block_header_hex !== 'string' || !HEX160.test(b.block_header_hex)) {
            return bad('R_FIELD_FORMAT', 'bitcoin.block_header_hex is not 160 lowercase hex characters');
        }
        headerHex = b.block_header_hex;
        if (btcBlock === null) return bad('R_FIELD_FORMAT', 'receipt bundles a block header but no btc_block — refusing to guess which attestation it belongs to');
    }

    // Owner-supplied secret (never from the receipt).
    let ownerPlaintext = null;
    let ownerSalt = null;
    // Owner input that is present in any form is validated and checked:
    // a non-object, or an empty string, is never silently ignored.
    if (!absent(owner)) {
        if (!isObj(owner)) return bad('R_FIELD_FORMAT', 'the owner input is not an object of { plaintext, salt }');
        if (!absent(owner.plaintext)) {
            if (typeof owner.plaintext !== 'string' || owner.plaintext.includes('\u0000')) {
                return bad('R_FIELD_FORMAT', 'the supplied plaintext is not text without NUL characters');
            }
            ownerPlaintext = owner.plaintext;
        }
        if (!absent(owner.salt)) {
            if (typeof owner.salt !== 'string' || !HEX64.test(owner.salt)) {
                return bad('R_FIELD_FORMAT', 'the supplied salt is not 64 lowercase hex characters');
            }
            ownerSalt = owner.salt;
        }
    }
    if (merkle === null && (btcBlock !== null || blockHash !== null || headerHex !== null)) {
        return bad('R_FIELD_FORMAT', 'the receipt says the entry is not batched but carries Bitcoin anchor fields');
    }
    if (!absent(envelopeBytes) && !(envelopeBytes instanceof Uint8Array)) {
        return bad('R_FIELD_FORMAT', 'envelope.json could not be read as bytes');
    }

    return {
        ok: true,
        r: {
            entryId: entry.id, legacy, boundRule, statedContentRule, tier, text: entry.text, createdAt: entry.created_at,
            identity, hashText, hashBound: hashes.hash_bound, commitSalt, merkle, btcBlock, blockHash,
            headerHex, ownerPlaintext, ownerSalt, envelopeBytes: envelopeBytes || null, bindingNonce,
        },
    };
}

// =====================================================================
// Step 2 — tier and marker consistency. A tier claim can never skip a
// check: the marker a tier requires is enforced here.
// =====================================================================

function checkTierMarker(r) {
    const t = r.text;
    if (r.tier === 'tomb' && t !== SEALED_MARKER) return `tier tomb must show exactly ${SEALED_MARKER}`;
    if (r.tier === 'treasure' && t !== TREASURE_MARKER) return `tier treasure must show exactly ${TREASURE_MARKER}`;
    if (r.tier === 'open' && (t === SEALED_MARKER || t === TREASURE_MARKER)) return `tier open may not show the ${t} marker`;
    if (r.tier === 'sealed' && t === TREASURE_MARKER) return `tier sealed may not show ${TREASURE_MARKER}`;
    return null;
}

// Step 3 — the content rule is tied to the tier, never chosen by the
// receipt alone.
function contentRuleFor(r) {
    if (r.legacy) {
        if (r.tier === 'treasure') return { error: 'Treasure exists only under protocol 3; no accepted rule explains a legacy Treasure leaf' };
        if (r.commitSalt !== null) return { error: 'commit_salt on a legacy receipt; legacy content is A-plain and has no salt' };
        return { rule: 'A-plain' };
    }
    const want = CONTENT_RULE_FOR_V3_TIER[r.tier];
    if (r.statedContentRule !== want) {
        return { error: `content_rule ${r.statedContentRule} stated for tier ${r.tier}; that tier requires ${want}` };
    }
    if (r.commitSalt !== null && want !== 'A-salted') return { error: `commit_salt on a ${want} receipt` };
    return { rule: want };
}

// =====================================================================
// Link 3 — Merkle proof walk. Tower's Merkle convention is hex-string
// concatenation (NOT raw-byte concat per Bitcoin convention):
//   node(left, right) = hex(sha256(ascii(left + right)))
// =====================================================================

async function merkleStep(currentHex, siblingHex, siblingPosition) {
    if (siblingPosition !== 'left' && siblingPosition !== 'right') {
        throw new Error(`invalid sibling position: ${siblingPosition}`);
    }
    const combined = siblingPosition === 'right' ? currentHex + siblingHex : siblingHex + currentHex;
    return await sha256Hex(combined);
}

async function walkMerkle(leafHex, proof) {
    let current = leafHex;
    for (const step of proof) current = await merkleStep(current, step.hash, step.position);
    return current;
}

// =====================================================================
// OpenTimestamps proof parser.
//
// The OTS file format encodes a proof as a tree of operations starting
// from an initial hash and ending at one or more attestations. We collect
// every attestation reached and the message that was its input. For a
// Bitcoin attestation that message is the block's merkle_root field
// (header bytes 36-67).
//
// Operations:
//   0xf0 + varint len + bytes   append bytes to current message
//   0xf1 + varint len + bytes   prepend bytes to current message
//   0x08                        SHA-256(current message)
//   0xff                        fork: parse one sub-timestamp here, then
//                               continue from the same message
//   0x00 + 8-byte tag + varint len + payload   attestation (leaf)
//
// Bounds, so a crafted file cannot hang the tab: the working message never
// exceeds 4096 bytes (OpenTimestamps' own cap; checked before any copy), an
// op argument never exceeds 4096 bytes, at most 10000 ops and 256 nested
// forks per file.
// =====================================================================

const OTS_MAX_MSG = 4096;
const OTS_MAX_OPS = 10000;
const OTS_MAX_DEPTH = 256;

class OtsReader {
    constructor(bytes) {
        this.bytes = bytes;
        this.pos = 0;
        this.ops = 0;
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
        // LEB128 with float arithmetic: JS bitwise ops are signed-32.
        let value = 0;
        let shift = 0;
        for (let i = 0; i < 10; i++) {
            const b = this.readByte();
            value += (b & 0x7f) * Math.pow(2, shift);
            if ((b & 0x80) === 0) {
                if (b === 0 && i > 0) throw new Error('non-canonical varint (redundant trailing byte)');
                if (!Number.isSafeInteger(value)) throw new Error('varint exceeds safe integer range');
                return value;
            }
            shift += 7;
        }
        throw new Error('varint too long');
    }
    eof() {
        return this.pos >= this.bytes.length;
    }
}

async function applyOp(reader, opCode, currentHash) {
    if (++reader.ops > OTS_MAX_OPS) throw new Error(`OTS proof has more than ${OTS_MAX_OPS} operations`);
    if (opCode === OP_APPEND || opCode === OP_PREPEND) {
        const n = reader.readVarint();
        if (n < 1 || n > OTS_MAX_MSG) throw new Error(`OTS ${opCode === OP_APPEND ? 'append' : 'prepend'} argument of ${n} bytes is outside 1..${OTS_MAX_MSG}`);
        if (currentHash.length + n > OTS_MAX_MSG) throw new Error(`OTS message would exceed ${OTS_MAX_MSG} bytes`);
        const data = reader.readBytes(n);
        const out = new Uint8Array(currentHash.length + n);
        if (opCode === OP_APPEND) {
            out.set(currentHash, 0);
            out.set(data, currentHash.length);
        } else {
            out.set(data, 0);
            out.set(currentHash, n);
        }
        return out;
    }
    if (opCode === OP_SHA256) return await sha256Bytes(currentHash);
    // SHA-1 (0x02) and RIPEMD160 (0x03) are valid OpenTimestamps ops but are
    // not used on Tower's proofs (calendar paths are SHA-256 only). Rejecting
    // them keeps the verifier's hash surface to SHA-256 alone.
    if (opCode === OP_SHA1) throw new Error('SHA-1 operation in proof — not supported by this verifier');
    if (opCode === OP_RIPEMD160) throw new Error('RIPEMD160 operation in proof — not supported by this verifier');
    throw new Error(`unknown op code 0x${opCode.toString(16)}`);
}

// OpenTimestamps serialization, read strictly:
//   timestamp := ( 0xff item )* item        every item but the last is
//                                           preceded by one fork marker
//   item      := 0x00 attestation           a leaf
//              | op [argument] timestamp    an operation and what follows it
// An item never starts with 0xff, and no two sibling items of one timestamp
// may be identical (same attestation, or same op with the same argument).
// A trailing op chain is walked in a loop, so only forks nest.
function readAttestation(reader, currentHash, attestations, seen) {
    const start = reader.pos;
    const tagHex = bytesToHex(reader.readBytes(8));
    const payloadLen = reader.readVarint();
    if (payloadLen > 8192) throw new Error('OTS attestation payload too large');
    const payload = reader.readBytes(payloadLen);
    const key = '00' + bytesToHex(reader.bytes.subarray(start, reader.pos));
    if (seen.has(key)) throw new Error('OTS proof repeats an attestation on the same message');
    seen.add(key);
    if (tagHex === ATTESTATION_TAG_BITCOIN) {
        const sub = new OtsReader(payload);
        const height = sub.readVarint();
        if (!sub.eof()) throw new Error('OTS Bitcoin attestation payload has trailing bytes');
        if (height > 0xffffffff) throw new Error(`OTS Bitcoin attestation height ${height} is above 4294967295`);
        attestations.push({ type: 'bitcoin', blockHeight: height, finalHash: new Uint8Array(currentHash) });
    } else if (tagHex === ATTESTATION_TAG_PENDING) {
        const sub = new OtsReader(payload);
        const url = new TextDecoder().decode(sub.readBytes(sub.readVarint()));
        if (!sub.eof()) throw new Error('OTS pending attestation payload has trailing bytes');
        attestations.push({ type: 'pending', url, finalHash: new Uint8Array(currentHash) });
    } else {
        attestations.push({ type: 'unknown', tagHex, finalHash: new Uint8Array(currentHash) });
    }
}

// Apply one op item's operation; returns the new message. The op byte and
// its argument form the sibling key.
async function readOp(reader, opCode, currentHash, seen) {
    const start = reader.pos;
    const out = await applyOp(reader, opCode, currentHash);
    const key = opCode.toString(16).padStart(2, '0') + bytesToHex(reader.bytes.subarray(start, reader.pos));
    if (seen.has(key)) throw new Error('OTS proof repeats an operation on the same message');
    seen.add(key);
    return out;
}

async function walkOtsTree(reader, currentHash, attestations, depth) {
    if (depth > OTS_MAX_DEPTH) throw new Error(`OTS proof nests more than ${OTS_MAX_DEPTH} forks`);
    let seen = new Set();
    for (;;) {
        const tag = reader.readByte();
        if (tag === OP_FORK) {
            if (++reader.ops > OTS_MAX_OPS) throw new Error(`OTS proof has more than ${OTS_MAX_OPS} operations`);
            const first = reader.readByte();
            if (first === OP_FORK) throw new Error('OTS item starts with a fork marker');
            if (first === ATTESTATION_MARKER) {
                readAttestation(reader, currentHash, attestations, seen);
            } else {
                const next = await readOp(reader, first, currentHash, seen);
                await walkOtsTree(reader, next, attestations, depth + 1);
            }
            continue;
        }
        // The last item of this timestamp.
        if (tag === ATTESTATION_MARKER) {
            readAttestation(reader, currentHash, attestations, seen);
            return;
        }
        currentHash = await readOp(reader, tag, currentHash, seen);
        seen = new Set(); // the op's own timestamp starts here
    }
}

async function parseOtsProof(otsBytes, initialHashHex) {
    if (otsBytes.length < OTS_MAGIC.length + 2) throw new Error('OTS file too short');
    for (let i = 0; i < OTS_MAGIC.length; i++) {
        if (otsBytes[i] !== OTS_MAGIC[i]) throw new Error(`OTS magic mismatch at byte ${i}`);
    }
    const reader = new OtsReader(otsBytes);
    reader.pos = OTS_MAGIC.length;
    const version = reader.readByte();
    if (version !== 0x01) throw new Error(`OTS version ${version} not supported (expected 1)`);
    // File hash: SHA-256 of the ASCII hex of Tower's merkle_root (anchor.js
    // writes merkle_root to a file and stamps the file).
    const fileHashOp = reader.readByte();
    if (fileHashOp !== OP_SHA256) throw new Error(`OTS file hash op 0x${fileHashOp.toString(16)} not SHA-256`);
    const fileHash = reader.readBytes(32);
    const expectedFileHash = await sha256Bytes(new TextEncoder().encode(initialHashHex));
    if (!bytesEqual(fileHash, expectedFileHash)) {
        throw new Error(`OTS file hash mismatch: expected ${bytesToHex(expectedFileHash).slice(0, 16)}…, got ${bytesToHex(fileHash).slice(0, 16)}…`);
    }
    const attestations = [];
    await walkOtsTree(reader, new Uint8Array(fileHash), attestations, 0);
    if (!reader.eof()) throw new Error(`OTS proof has ${otsBytes.length - reader.pos} trailing bytes after the timestamp`);
    return attestations;
}

// =====================================================================
// Link 5 — the header is real. Bitcoin block header (80 bytes):
//   0..3 version, 4..35 prev hash, 36..67 merkle_root, 68..71 time (LE),
//   72..75 bits (LE), 76..79 nonce. Block hash = SHA-256d(header), shown
//   byte-reversed on explorers.
//
// Nothing here depends on a value the receipt chooses: the height floor,
// the absolute target ceiling and the time floor are pinned above.
// =====================================================================

// Decode compact `bits` into the 256-bit target. Negative or zero targets
// decode to 0n, which no hash can meet.
function targetFromBits(bits) {
    const exponent = bits >>> 24;
    const mantissa = bits & 0x007fffff;
    if (bits & 0x00800000) return 0n;
    if (exponent <= 3) return BigInt(mantissa >>> (8 * (3 - exponent)));
    return BigInt(mantissa) << BigInt(8 * (exponent - 3));
}

function leUint32(bytes, off) {
    return (bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | (bytes[off + 3] << 24)) >>> 0;
}

function leBigInt(bytes) {
    let v = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(bytes[i]);
    return v;
}

// claimedHeight may be null when the height is not yet known.
async function checkHeaderIsReal(header, claimedHeight, policy = PINNED_HEADER_POLICY) {
    if (!(header instanceof Uint8Array) || header.length !== 80) {
        return { ok: false, code: 'R_HEADER', reason: 'block header is not 80 bytes' };
    }
    if (claimedHeight !== null && claimedHeight < policy.minHeight) {
        return { ok: false, code: 'R_HEADER_HEIGHT', reason: `claimed height ${claimedHeight} is below Tower's first anchored block ${policy.minHeight}` };
    }
    const bits = leUint32(header, 72);
    const target = targetFromBits(bits);
    if (target === 0n || target > policy.maxTarget) {
        return {
            ok: false,
            code: 'R_HEADER_WORK',
            reason: `header target (bits 0x${bits.toString(16).padStart(8, '0')}) is easier than the pinned ceiling — it does not carry launch-era Bitcoin work, whatever its bits say`,
        };
    }
    const time = leUint32(header, 68);
    if (time < policy.minTime) {
        return { ok: false, code: 'R_HEADER_TIME', reason: `header time ${new Date(time * 1000).toISOString()} is before Tower's first anchor` };
    }
    const hashLE = await sha256Bytes(await sha256Bytes(header));
    if (leBigInt(hashLE) > target) {
        return { ok: false, code: 'R_HEADER_POW', reason: 'header hash is above its own target (proof of work invalid)' };
    }
    const hashBE = new Uint8Array(32);
    for (let i = 0; i < 32; i++) hashBE[i] = hashLE[31 - i];
    return { ok: true, blockHashHex: bytesToHex(hashBE), time, bits };
}

// =====================================================================
// Top-level verify. Input:
//   receipt           parsed receipt.json
//   otsBytes          merkle-root.ots (Uint8Array) or null
//   blockHeaderBytes  btc-block-header.bin (Uint8Array) or null
//   envelopeBytes     envelope.json (Uint8Array) or null — Treasure
//   owner             { plaintext, salt } typed by the owner, or null
// options.testHeaderPolicy replaces the pinned header floors; ONLY the test
// suite passes it (synthetic leaves cannot sit in real blocks). The UI never
// does, and a result produced under it says so in summary and testPolicy.
// =====================================================================

const SUMMARIES = {
    G_CONTENT: 'Verified — the content shown was anchored in a Bitcoin block.',
    G_HIDDEN: 'Commitment anchored, content hidden. A hidden carve by this identity was anchored in a Bitcoin block; no content is shown, so none is claimed.',
    G_OWNER_CONTENT: 'Verified — the content you supplied is the content anchored in a Bitcoin block.',
    G_ENVELOPE: 'Verified — this Treasure envelope was anchored in a Bitcoin block.',
    A_NOT_BATCHED: 'Not yet anchored — the entry is not in a batch yet. Re-download after the next batch confirms.',
    A_OTS_PENDING: 'Anchor pending — the timestamp proof has no Bitcoin confirmation yet. Re-download the receipt later.',
    A_NO_OTS: 'Anchor not checked — this receipt carries no OpenTimestamps proof (public receipts do not). Download the proof ZIP to check the Bitcoin anchor.',
    A_NO_HEADER: 'Anchor not checked offline — no Bitcoin block header is bundled. Confirm the block on a public explorer.',
    A_IDENTITY_WITHHELD: 'Identity withheld. Who carved it, and the tie from the content to the anchor, are shown only on the owner\'s receipt.',
    A_BINDING_UNRECORDED: 'How this leaf was bound was not recorded. The text cannot be tied to the anchor.',
    A_TREASURE_NO_ENVELOPE: 'The Treasure envelope (envelope.json) was not supplied, so its content is not checked.',
};

async function verifyReceiptArtifacts(input, options) {
    const { receipt, otsBytes = null, blockHeaderBytes = null, envelopeBytes = null, owner = null } = input || {};
    const testPolicy = !!(options && options.testHeaderPolicy);
    if (testPolicy) {
        // A malformed test policy must never quietly switch the floors off.
        const p = options.testHeaderPolicy;
        if (!isObj(p) || !Number.isSafeInteger(p.minHeight) || !Number.isSafeInteger(p.minTime) || typeof p.maxTarget !== 'bigint') {
            throw new TypeError('testHeaderPolicy must be { minHeight: integer, maxTarget: bigint, minTime: integer }');
        }
    }
    const policy = testPolicy ? options.testHeaderPolicy : PINNED_HEADER_POLICY;
    const steps = [];
    const log = (name, status, detail) => steps.push({ name, status, detail });
    const state = { link1Rule: 'not evaluated', link2Rule: 'not evaluated', entryId: null };
    const finish = (code, summary, extra = {}) => ({
        overall: OUTCOME_CODES[code],
        code,
        label: outcomeLabel(code),
        summary: (testPolicy ? '[TEST HEADER POLICY] ' : '') + summary,
        link1Rule: state.link1Rule,
        link2Rule: state.link2Rule,
        entryId: state.entryId,
        testPolicy,
        steps,
        ...extra,
    });
    const red = (code, name, detail) => {
        log(name, 'fail', detail);
        return finish(code, detail);
    };

    // Step 0 — the host's SHA-256 must be sane, or nothing below means anything.
    if (!(await selfTest())) {
        return finish('R_SELFTEST', 'Browser SHA-256 self-test failed. The host crypto is broken; do not trust any result.');
    }
    log('self-test', 'pass', 'SubtleCrypto SHA-256 verified against known vector');

    // Step 1 — formats and rule statements.
    const parsed = parseReceipt(receipt, owner, envelopeBytes);
    if (!parsed.ok) return red(parsed.code, 'formats', parsed.detail);
    const r = parsed.r;
    state.entryId = r.entryId;
    log('formats', 'pass', `receipt v${r.legacy ? LEGACY_RECEIPT_VERSION : V3_RECEIPT_VERSION}, tier ${r.tier}, binding rule ${r.boundRule}${r.identity === null ? ', identity withheld' : ''}`);

    // Step 2 — tier and marker.
    const markerError = checkTierMarker(r);
    if (markerError) return red('R_TIER_MARKER', 'tier-marker', `the receipt claims a tier its text contradicts: ${markerError}`);
    const hidden = r.text === SEALED_MARKER || r.text === TREASURE_MARKER;
    log('tier-marker', 'pass', hidden ? `tier ${r.tier}, content hidden behind ${r.text}` : `tier ${r.tier}, content shown`);

    // Step 3 — content rule for this tier.
    const cr = contentRuleFor(r);
    if (cr.error) return red('R_RULE_TIER', 'content-rule', cr.error);
    const contentRule = cr.rule;

    const ambers = [];
    let provenContent = null; // what the page may print as proven

    // Owner input that is supplied but cannot be checked is red, never
    // silently skipped.
    const ownerGiven = r.ownerPlaintext !== null || r.ownerSalt !== null;
    if (ownerGiven && contentRule === 'A-envelope') {
        return red('R_CONTENT_MISMATCH', 'link-1 content', 'a plaintext or salt was supplied, but a Treasure entry is checked by its envelope.json only');
    }
    if (ownerGiven && r.hashText === null) {
        return red('R_CONTENT_MISMATCH', 'link-1 content', 'a plaintext or salt was supplied, but this receipt withholds hash_text, so it cannot be checked');
    }
    if (hidden && r.ownerSalt !== null && r.ownerPlaintext === null) {
        return red('R_CONTENT_MISMATCH', 'link-1 content', 'a salt was supplied without the plaintext, so it cannot be checked');
    }

    // Link 1 — content to commitment.
    if (contentRule === 'A-envelope') {
        if (!r.envelopeBytes) {
            ambers.push('A_TREASURE_NO_ENVELOPE');
            log('link-1 content', 'amber', 'envelope.json not supplied; Treasure content not checked');
        } else if (r.hashText === null) {
            // Supplied but uncheckable is red, never a silent skip.
            return red('R_CONTENT_MISMATCH', 'link-1 content', 'envelope.json was supplied, but this receipt withholds hash_text, so the envelope cannot be checked');
        } else {
            state.link1Rule = 'A-envelope';
            const got = await sha256Hex(r.envelopeBytes);
            if (got !== r.hashText) return red('R_CONTENT_MISMATCH', 'link-1 content', 'envelope.json is not the envelope anchored (A-envelope mismatch)');
            log('link-1 content', 'pass', 'sha256(envelope.json) = hash_text (A-envelope)');
        }
    } else {
        let subject = null;
        let fromOwner = false;
        if (!hidden && r.ownerPlaintext !== null && r.ownerPlaintext !== r.text) {
            return red('R_CONTENT_MISMATCH', 'link-1 content', 'the supplied plaintext is not the text this receipt shows');
        }
        if (r.ownerSalt !== null && contentRule === 'A-plain') {
            return red('R_CONTENT_MISMATCH', 'link-1 content', 'a salt was supplied, but this entry is A-plain and has no salt');
        }
        if (r.ownerSalt !== null && r.commitSalt !== null && r.ownerSalt !== r.commitSalt) {
            return red('R_CONTENT_MISMATCH', 'link-1 content', 'the supplied salt is not the salt this receipt carries');
        }
        if (!hidden) subject = r.text;
        else if (r.ownerPlaintext !== null) {
            subject = r.ownerPlaintext;
            fromOwner = true;
        }
        if (subject === null) {
            log('link-1 content', 'skip', 'content hidden and no plaintext supplied; no content is claimed');
        } else if (r.hashText === null) {
            log('link-1 content', 'skip', 'hash_text withheld on this public receipt; the content cannot be checked here');
        } else if (contentRule === 'A-plain') {
            state.link1Rule = 'A-plain';
            if ((await sha256Hex(subject)) !== r.hashText) {
                return red('R_CONTENT_MISMATCH', 'link-1 content', `${fromOwner ? 'the supplied plaintext' : 'the text shown'} is not the content anchored (sha256 does not match hash_text)`);
            }
            log('link-1 content', 'pass', 'sha256(text) = hash_text (A-plain)');
            provenContent = subject;
        } else {
            // A shown (revealed) text is judged by the receipt's own salt only.
            const salt = fromOwner ? (r.ownerSalt || r.commitSalt) : r.commitSalt;
            if (salt === null) {
                return red('R_SALT_MISSING', 'link-1 content', fromOwner
                    ? 'this entry is salted (A-salted); supply the salt (or the key file) with the plaintext'
                    : 'the text shown cannot be tied to the anchor: this salted receipt carries no salt (A-salted)');
            }
            state.link1Rule = 'A-salted';
            if ((await commitSalted(salt, subject)) !== r.hashText) {
                return red('R_CONTENT_MISMATCH', 'link-1 content', `${fromOwner ? 'the supplied plaintext and salt are' : 'the text shown is'} not the content anchored (A-salted mismatch)`);
            }
            log('link-1 content', 'pass', 'salted commitment matches hash_text (A-salted)');
            provenContent = subject;
        }
    }

    // Link 2 — commitment to leaf.
    let link2Held = false;
    if (r.hashText !== null && r.hashBound === r.hashText) {
        return red('R_BINDING_MISMATCH', 'link-2 binding', 'hash_bound equals hash_text; no accepted rule produces that leaf');
    }
    if (r.legacy && PINNED_UNRECORDED_BINDINGS.includes(r.hashBound)) {
        ambers.push('A_BINDING_UNRECORDED');
        log('link-2 binding', 'amber', 'pinned exception: this leaf is anchored; how it was bound was not recorded');
    } else if (r.identity === null || r.hashText === null) {
        ambers.push('A_IDENTITY_WITHHELD');
        log('link-2 binding', 'amber', 'identity withheld on this public receipt; binding checked only on the owner\'s receipt');
    } else {
        state.link2Rule = r.boundRule;
        const want = r.boundRule === 'B-v3'
            ? await bindV3(r.bindingNonce, r.tier, contentRule, r.hashText, r.createdAt, r.identity)
            : await bindHash(r.hashText, r.createdAt, r.identity);
        if (want !== r.hashBound) {
            return red('R_BINDING_MISMATCH', 'link-2 binding', `the leaf is not the hash of what the receipt states (${r.boundRule} gives ${want.slice(0, 12)}…, hash_bound is ${r.hashBound.slice(0, 12)}…)`);
        }
        link2Held = true;
        log('link-2 binding', 'pass', `${r.boundRule} reproduces hash_bound`);
    }

    // Links 3–5 — leaf to root, root to header, header is real.
    let anchor = null;
    if (r.merkle === null && (otsBytes || blockHeaderBytes !== null)) {
        return red('R_FIELD_FORMAT', 'formats', 'the receipt says the entry is not batched but the ZIP carries an OpenTimestamps proof or a block header');
    }
    if (r.merkle === null) {
        ambers.push('A_NOT_BATCHED');
        log('link-3 merkle', 'amber', 'entry not yet batched; anchor pending');
    } else {
        const root = await walkMerkle(r.hashBound, r.merkle.proof);
        if (root !== r.merkle.root) {
            return red('R_MERKLE', 'link-3 merkle', `Merkle path does not reach the root (got ${root.slice(0, 12)}…, expected ${r.merkle.root.slice(0, 12)}…)`);
        }
        log('link-3 merkle', 'pass', `Merkle path reaches root ${r.merkle.root.slice(0, 12)}…`);

        if (r.btcBlock !== null && r.btcBlock < policy.minHeight) {
            return red('R_HEADER_HEIGHT', 'link-5 header', `claimed height ${r.btcBlock} is below Tower's first anchored block ${policy.minHeight}`);
        }

        let header = null;
        if (blockHeaderBytes !== null && !(blockHeaderBytes instanceof Uint8Array && blockHeaderBytes.length === 80)) {
            return red('R_HEADER', 'link-5 header', 'btc-block-header.bin is not exactly 80 bytes');
        }
        if (r.headerHex !== null) {
            header = hexToBytes(r.headerHex);
            if (blockHeaderBytes !== null && !bytesEqual(header, blockHeaderBytes)) {
                return red('R_HEADER', 'link-5 header', 'btc-block-header.bin disagrees with receipt.bitcoin.block_header_hex');
            }
        } else if (blockHeaderBytes !== null) {
            return red('R_FIELD_FORMAT', 'formats', 'btc-block-header.bin is bundled but the receipt carries no block_header_hex / btc_block for it');
        }
        let real = null;
        if (header) {
            real = await checkHeaderIsReal(header, r.btcBlock, policy);
            if (!real.ok) return red(real.code, 'link-5 header', real.reason);
            if (r.blockHash !== null && r.blockHash !== real.blockHashHex) {
                return red('R_HEADER', 'link-5 header', `receipt claims block hash ${r.blockHash.slice(0, 16)}…, the header hashes to ${real.blockHashHex.slice(0, 16)}…`);
            }
        }

        if (!otsBytes) {
            ambers.push('A_NO_OTS');
            log('link-4 ots', 'amber', 'no OpenTimestamps proof supplied');
            if (!header) ambers.push('A_NO_HEADER');
            else log('link-5 header', 'pass', `bundled header carries real launch-era work (not tied to the root without the OTS proof)`);
        } else {
            let attestations;
            try {
                attestations = await parseOtsProof(otsBytes, r.merkle.root);
            } catch (err) {
                return red('R_OTS', 'link-4 ots', `OTS proof rejected: ${err.message}`);
            }
            const btc = attestations.filter((a) => a.type === 'bitcoin');
            if (btc.length === 0) {
                if (!attestations.some((a) => a.type === 'pending')) {
                    return red('R_OTS', 'link-4 ots', 'OTS proof has no Bitcoin or pending attestation');
                }
                if (r.btcBlock !== null) {
                    return red('R_OTS', 'link-4 ots', `receipt claims block ${r.btcBlock} but the OTS proof has no Bitcoin attestation (pending only)`);
                }
                if (r.blockHash !== null) {
                    return red('R_OTS', 'link-4 ots', 'receipt claims a block hash but the OTS proof has no Bitcoin attestation (pending only)');
                }
                ambers.push('A_OTS_PENDING');
                log('link-4 ots', 'amber', 'only pending calendar attestations; no Bitcoin confirmation yet');
            } else {
                let chosen;
                if (r.btcBlock !== null) {
                    const atHeight = btc.filter((a) => a.blockHeight === r.btcBlock);
                    chosen = (header && atHeight.find((a) => bytesEqual(a.finalHash, header.subarray(36, 68)))) || atHeight[0];
                    if (!chosen) {
                        return red('R_OTS', 'link-4 ots', `receipt claims block ${r.btcBlock} but the OTS proof attests ${btc.map((a) => a.blockHeight).join(', ')}`);
                    }
                } else {
                    chosen = btc.reduce((lo, a) => (lo === null || a.blockHeight < lo.blockHeight ? a : lo), null);
                }
                if (chosen.blockHeight < policy.minHeight) {
                    return red('R_HEADER_HEIGHT', 'link-5 header', `attested height ${chosen.blockHeight} is below Tower's first anchored block ${policy.minHeight}`);
                }
                if (!header) {
                    ambers.push('A_NO_HEADER');
                    log('link-4 ots', 'amber', `OTS attests Bitcoin block ${chosen.blockHeight}, but no header is bundled to check offline`);
                } else {
                    if (!bytesEqual(chosen.finalHash, header.subarray(36, 68))) {
                        return red('R_OTS', 'link-4 ots', `the OTS proof for block ${chosen.blockHeight} does not end at the header's merkle root`);
                    }
                    log('link-4 ots', 'pass', `OTS proof ends at the merkle root of block ${chosen.blockHeight}`);
                    log('link-5 header', 'pass', `header carries real launch-era Bitcoin work (bits 0x${real.bits.toString(16).padStart(8, '0')}, at or under the pinned ceiling; header time ${new Date(real.time * 1000).toISOString()}, set by its miner and kept by Bitcoin within about two hours)`);
                    anchor = { blockHeight: chosen.blockHeight, blockHashHex: real.blockHashHex, blockTime: new Date(real.time * 1000).toISOString() };
                }
            }
        }
    }

    const anchorExtra = anchor || {};
    const stated = link2Held ? { statedCreatedAt: r.createdAt } : {};
    if (ambers.length > 0) {
        const code = AMBER_PRIORITY.find((c) => ambers.includes(c));
        const others = ambers.filter((c) => c !== code).map((c) => SUMMARIES[c]);
        const anchorLine = anchor
            ? ` The anchor is proven: the leaf reaches the block ${anchor.blockHashHex} (height ${anchor.blockHeight} as stated by the timestamp proof), whose header carries real launch-era work.`
            : ' The Bitcoin anchor was not fully checked.';
        return finish(code, SUMMARIES[code] + (others.length ? ' Also: ' + others.join(' ') : '') + anchorLine, { ambers, ...anchorExtra, ...stated });
    }

    // Green needs all five links. Pick which green.
    let code;
    if (contentRule === 'A-envelope') code = 'G_ENVELOPE';
    else if (!hidden) code = 'G_CONTENT';
    else if (provenContent !== null) code = 'G_OWNER_CONTENT';
    else code = 'G_HIDDEN';
    if (!anchor || !link2Held || (code === 'G_CONTENT' && provenContent === null) || (code === 'G_ENVELOPE' && state.link1Rule !== 'A-envelope')) {
        // Unreachable by construction; refuse rather than show green.
        return red('R_FIELD_FORMAT', 'internal', 'internal: a link was not proven but no amber was recorded');
    }
    const residual = ` Proven: the content commitment, binding (${state.link2Rule}), Merkle path and OpenTimestamps proof lead to a header carrying real launch-era Bitcoin work: block ${anchor.blockHashHex} (height ${anchor.blockHeight} as stated by the timestamp proof; the header does not prove its height), block time ${anchor.blockTime} (set by its miner, kept by Bitcoin within about two hours). Not proven offline: that this block is in the main chain — confirm it on the linked explorer. Forging this would need mining a block at real Bitcoin difficulty.`;
    return finish(code, SUMMARIES[code] + residual, { ambers: [], provenContent, ...anchorExtra, ...stated });
}

// Exports for browser (script global) and Node (CommonJS) — works in both.
const api = {
    LEGACY_RECEIPT_VERSION,
    V3_RECEIPT_VERSION,
    OUTCOME_CODES,
    outcomeLabel,
    MIN_ANCHOR_HEIGHT,
    MAX_TARGET,
    MIN_HEADER_TIME,
    PINNED_UNRECORDED_BINDINGS,
    SEALED_MARKER,
    TREASURE_MARKER,
    sha256Hex,
    sha256Bytes,
    bytesToHex,
    hexToBytes,
    selfTest,
    bindHash,
    bindV3,
    bindV3Input,
    commitSalted,
    commitSaltedInput,
    parseOtsProof,
    targetFromBits,
    checkHeaderIsReal,
    verifyReceiptArtifacts,
};
if (typeof module !== 'undefined' && module.exports) module.exports = api;
if (typeof window !== 'undefined') window.TowerVerifyCore = api;
