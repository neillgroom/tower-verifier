// Test harness — runs verify-core.js against every vector in test-vectors/.
//
// The expected outcome of each vector lives in test-vectors/expected.json,
// written by scripts/build-test-vectors.py next to the ZIP it describes. The
// test asserts what the verifier RETURNED (overall colour + stable outcome
// code, and the rule ids where the manifest names them), never a file name.
//
// Also checked here:
//   - pinned byte layouts (test-vectors/formats-vectors.json) match the
//     verifier's own B-hash / B-v3 / A-salted implementations;
//   - the pinned header constants match the anchored headers;
//   - completeness: every code in core.OUTCOME_CODES has at least one vector;
//   - no genuine production receipt is red;
//   - the browser self-test failing returns R_SELFTEST.
//
// Every vector ZIP is read through src/verify-zip.js, the same strict reader
// the page uses; test/zip-attacks.js covers the archive-layout attacks. No
// test framework dependency.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');


const core = require('../src/verify-core');
const zipReader = require('../src/verify-zip');
const JSZip = require('../vendor/jszip.min.js');

const VECTOR_DIR = path.join(__dirname, '..', 'test-vectors');

let passed = 0;
const failures = [];

function check(cond, msg) {
    if (cond) {
        passed++;
        console.log('PASS: ' + msg);
    } else {
        failures.push(msg);
        console.log('FAIL: ' + msg);
    }
}

// Every vector ZIP goes through the same strict reader the page uses.
function readZip(zipPath) {
    return zipReader.extractReceiptZip(new Uint8Array(fs.readFileSync(zipPath)), JSZip);
}

// Only for vectors the strict reader refuses: reads every file as-is so the
// core's own verdict on that input is still asserted.
async function readZipLenient(zipPath) {
    const zip = await JSZip.loadAsync(fs.readFileSync(zipPath));
    const out = {};
    for (const name of Object.keys(zip.files)) out[name] = await zip.files[name].async('uint8array');
    return out;
}

// Same shape the browser UI hands to the core.
function inputsFromZip(files, owner) {
    const receipt = JSON.parse(new TextDecoder().decode(files['receipt.json']));
    return {
        receipt,
        otsBytes: files['merkle-root.ots'] || null,
        blockHeaderBytes: files['btc-block-header.bin'] || null,
        envelopeBytes: files['envelope.json'] || null,
        owner: owner || null,
    };
}

// Test-only header policy for synthetic chains (a synthetic leaf cannot sit
// in a real block). Every other link is real. Rows opt in with testPolicy.
const TEST_HEADER_POLICY = { minHeight: 1, maxTarget: (1n << 256n) - 1n, minTime: 0 };

async function runVector(row) {
    const zipPath = path.join(VECTOR_DIR, row.name + '.zip');
    let files;
    try {
        files = await readZip(zipPath);
    } catch (err) {
        // The page shows a refused ZIP as red, so a refusal may only ever
        // stand in for a vector that expects red. The core's own answer is
        // still checked below on the leniently read files.
        check(row.overall === 'red', `${row.name}: strict ZIP reader refuses it and the vector expects red (${err.message})`);
        files = await readZipLenient(zipPath);
    }
    const input = inputsFromZip(files, row.owner);
    const t0 = Date.now();
    const result = row.testPolicy
        ? await core.verifyReceiptArtifacts(input, { testHeaderPolicy: TEST_HEADER_POLICY })
        : await core.verifyReceiptArtifacts(input);
    const ms = Date.now() - t0;
    const got = `${result.overall}/${result.code}`;
    const want = `${row.overall}/${row.code}`;
    let ok = got === want;
    const extra = [];
    if (row.ambersInclude) {
        for (const a of row.ambersInclude) {
            if (!(result.ambers || []).includes(a)) {
                ok = false;
                extra.push(`missing amber ${a}`);
            }
        }
    }
    if (row.link1 && result.link1Rule !== row.link1) {
        ok = false;
        extra.push(`link1Rule ${result.link1Rule} != ${row.link1}`);
    }
    if (row.link2 && result.link2Rule !== row.link2) {
        ok = false;
        extra.push(`link2Rule ${result.link2Rule} != ${row.link2}`);
    }
    if (row.maxMs && ms > row.maxMs) {
        ok = false;
        extra.push(`took ${ms} ms > ${row.maxMs}`);
    }
    if (typeof result.link1Rule !== 'string' || typeof result.link2Rule !== 'string') {
        ok = false;
        extra.push('result does not name link1Rule/link2Rule');
    }
    if (!ok) {
        console.log(`  summary="${result.summary}"`);
        for (const step of result.steps || []) console.log(`    [${step.status}] ${step.name}: ${step.detail}`);
    }
    check(ok, `${row.name}: want ${want}, got ${got}${extra.length ? ' (' + extra.join('; ') + ')' : ''} — ${row.desc}`);
    return result;
}

async function main() {
    check(await core.selfTest(), 'self-test (SubtleCrypto sha256 known vector)');

    const manifest = JSON.parse(fs.readFileSync(path.join(VECTOR_DIR, 'expected.json'), 'utf8'));
    const seenCodes = new Set();
    for (const row of manifest) {
        const result = await runVector(row);
        seenCodes.add(row.code);
        if (result.overall === 'amber') {
            const claims = /anchor (is )?proven/i.test(result.summary);
            check(claims === (typeof result.blockHeight === 'number'),
                `${row.name}: amber summary claims the anchor only when it was verified (claims=${claims}, verified=${typeof result.blockHeight === 'number'})`);
        }
        check(result.label === core.outcomeLabel(result.code), `${row.name}: result.label is the label for ${result.code}`);
        if (result.code === 'G_HIDDEN') {
            check(!/verified/i.test(result.label) && !/^verified/i.test(result.summary),
                `${row.name}: hidden-commitment green is never labelled plain "VERIFIED" (label "${result.label}")`);
        }
        if (row.genuine) {
            check(result.overall !== 'red', `genuine ${row.name} is not red`);
        }
    }

    // Core input rules that no vector ZIP carries (b3 P2s 7215dd47f30a,
    // a44cf7eeddcd). Each starts from a genuine vector and changes one thing.
    const vin = async (name, mutate, owner) => {
        const input = inputsFromZip(await readZip(path.join(VECTOR_DIR, name + '.zip')), owner);
        if (mutate) mutate(input);
        return core.verifyReceiptArtifacts(input, { testHeaderPolicy: TEST_HEADER_POLICY });
    };
    const want = (res, overall, code, label) =>
        check(res.overall === overall && res.code === code, `${label}: want ${overall}/${code}, got ${res.overall}/${res.code}`);
    for (const [label, owner] of [
        ['owner is a string', 'secret'],
        ['owner is an array', []],
        ['owner is a number', 7],
    ]) {
        want(await vin('v3-sealed-hidden', null, owner), 'red', 'R_FIELD_FORMAT', `hidden sealed + ${label}`);
        want(await vin('v3-treasure-envelope', null, owner), 'red', 'R_FIELD_FORMAT', `treasure + ${label}`);
    }
    want(await vin('v3-sealed-hidden', null, { plaintext: '' }), 'red', 'R_SALT_MISSING', 'hidden salted sealed + empty plaintext is checked, not ignored');
    want(await vin('legacy-sealed-owner', null, { plaintext: '' }), 'red', 'R_CONTENT_MISMATCH', 'hidden A-plain sealed + empty plaintext is checked, not ignored');
    want(await vin('v3-sealed-hidden', null, { plaintext: 'x', salt: '' }), 'red', 'R_FIELD_FORMAT', 'hidden sealed + empty salt is checked, not ignored');
    want(await vin('v3-treasure-envelope', null, { plaintext: '' }), 'red', 'R_CONTENT_MISMATCH', 'treasure + empty plaintext');
    want(await vin('v3-treasure-envelope', null, { salt: '' }), 'red', 'R_FIELD_FORMAT', 'treasure + empty salt');
    want(await vin('v3-sealed-revealed', (i) => {
        i.receipt.identity = { redacted: true };
        delete i.receipt.hashes.hash_text;
    }), 'red', 'R_FIELD_FORMAT', 'public revealed sealed receipt may not withhold hash_text');
    want(await vin('v3-treasure-envelope', (i) => {
        i.receipt.identity = { redacted: true };
        delete i.receipt.hashes.hash_text;
    }), 'red', 'R_CONTENT_MISMATCH', 'envelope.json with a receipt that withholds hash_text is red, not skipped');
    const noEnv = await vin('v3-treasure-envelope', (i) => {
        i.receipt.identity = { redacted: true };
        delete i.receipt.hashes.hash_text;
        i.envelopeBytes = null;
    });
    check(noEnv.overall === 'amber' && (noEnv.ambers || []).includes('A_TREASURE_NO_ENVELOPE'),
        `public treasure withholding hash_text and no envelope stays amber, envelope unchecked (got ${noEnv.overall}/${noEnv.code} ${JSON.stringify(noEnv.ambers)})`);

    // ZIP layout attacks against the reader the page uses.
    await require('./zip-attacks')(check);

    // Pinned byte layouts: the Python builder and the verifier agree.
    const fv = JSON.parse(fs.readFileSync(path.join(VECTOR_DIR, 'formats-vectors.json'), 'utf8'));
    check(
        (await core.bindHash(fv['b-hash'].hash_text, fv['b-hash'].created_at, fv['b-hash'].identity)) === fv['b-hash'].hash_bound,
        'B-hash layout matches formats-vectors.json'
    );
    const v = fv['b-v3'];
    check(core.bytesToHex(core.bindV3Input(v.tier, v.content_rule, v.hash_text, v.created_at, v.identity)) === v.input_hex,
        'B-v3 input bytes match formats-vectors.json');
    check((await core.bindV3(v.tier, v.content_rule, v.hash_text, v.created_at, v.identity)) === v.hash_bound,
        'B-v3 hash matches formats-vectors.json');
    const s = fv['a-salted'];
    check(core.bytesToHex(core.commitSaltedInput(s.salt, s.plaintext)) === s.input_hex,
        'A-salted input bytes match formats-vectors.json');
    check((await core.commitSalted(s.salt, s.plaintext)) === s.hash_text, 'A-salted hash matches formats-vectors.json');

    // Pinned header constants match the anchored headers, and every real
    // anchored header passes the production header check.
    execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'derive-header-constants.js')], { stdio: 'pipe' });
    passed++;
    console.log('PASS: pinned header constants re-derive from test-vectors/anchored-headers.json');
    const anchored = JSON.parse(fs.readFileSync(path.join(VECTOR_DIR, 'anchored-headers.json'), 'utf8'));
    for (const [h, { header_hex }] of Object.entries(anchored)) {
        const r = await core.checkHeaderIsReal(core.hexToBytes(header_hex), Number(h));
        check(r.ok, `real anchored header ${h} passes the header check (${r.ok ? 'ok' : r.code + ': ' + r.reason})`);
    }

    // Self-test failure path: break SubtleCrypto and confirm R_SELFTEST.
    const realCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', {
        configurable: true,
        value: { subtle: { digest: async () => new ArrayBuffer(32) } },
    });
    let st;
    try {
        st = await core.verifyReceiptArtifacts({ receipt: {} });
    } finally {
        Object.defineProperty(globalThis, 'crypto', realCrypto);
    }
    check(st.overall === 'red' && st.code === 'R_SELFTEST', `broken SubtleCrypto -> red/R_SELFTEST (got ${st.overall}/${st.code})`);
    seenCodes.add('R_SELFTEST');

    // btc_block: one range, 1 to 2^32-1, whether a JSON number or a string
    // (b3 P3s ba1a9a7d7b5b, 6335439e058f).
    const withBlock = async (v) => {
        const input = inputsFromZip(await readZip(path.join(VECTOR_DIR, 'captured-entry-2.zip')));
        input.receipt.bitcoin.btc_block = v;
        return core.verifyReceiptArtifacts(input);
    };
    for (const v of [4294967296, '4294967296', 0, '0', '01', -5, 1.5, '12345678901']) {
        const res = await withBlock(v);
        check(res.code === 'R_FIELD_FORMAT', `btc_block ${JSON.stringify(v)} is out of range or malformed (got ${res.code})`);
    }
    for (const v of [4294967295, '4294967295', '1234567890']) {
        const res = await withBlock(v);
        check(res.code !== 'R_FIELD_FORMAT' && res.overall === 'red', `btc_block ${JSON.stringify(v)} parses (then fails the anchor, got ${res.overall}/${res.code})`);
    }

    // A malformed test header policy throws; it never switches the floors off (b3 P3 50978a79b45d).
    const genuine = inputsFromZip(await readZip(path.join(VECTOR_DIR, 'captured-entry-2.zip')));
    for (const bad of [true, 1, 'yes', {}, { minHeight: 1, minTime: 0 }, { minHeight: '1', maxTarget: 1n, minTime: 0 }, { minHeight: 1, maxTarget: 1, minTime: 0 }]) {
        let threw = false;
        try {
            await core.verifyReceiptArtifacts(genuine, { testHeaderPolicy: bad });
        } catch (e) {
            threw = e instanceof TypeError;
        }
        check(threw, `malformed testHeaderPolicy ${typeof bad === 'object' ? JSON.stringify(bad, (k, x) => (typeof x === 'bigint' ? x + 'n' : x)) : JSON.stringify(bad)} throws`);
    }

    // Labels: every code has one; only the content-bearing greens say VERIFIED.
    for (const [code, colour] of Object.entries(core.OUTCOME_CODES)) {
        const label = core.outcomeLabel(code);
        check(typeof label === 'string' && label !== 'UNKNOWN', `outcome code ${code} has a traffic-light label`);
        check((label === 'VERIFIED') === (colour === 'green' && code !== 'G_HIDDEN'),
            `outcome code ${code} is labelled VERIFIED only if it is a content-bearing green (label "${label}")`);
    }

    // Completeness: every outcome code the verifier can return has a vector.
    const codes = core.OUTCOME_CODES ? Object.keys(core.OUTCOME_CODES) : [];
    check(codes.length > 0, 'core exports OUTCOME_CODES');
    for (const code of codes) {
        check(seenCodes.has(code), `outcome code ${code} has at least one vector`);
    }
    for (const code of seenCodes) {
        check(codes.includes(code), `manifest code ${code} is a declared outcome code`);
    }

    console.log('');
    console.log(`${passed} passed, ${failures.length} failed`);
    if (failures.length) {
        for (const f of failures) console.log('  FAILED: ' + f);
        process.exit(1);
    }
}

main().catch((err) => {
    console.error('FAIL: ' + (err.stack || err.message));
    process.exit(1);
});
