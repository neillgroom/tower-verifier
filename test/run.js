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
// Uses the `unzip` CLI via execFileSync (no shell) as before; no test
// framework dependency.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const os = require('os');

const core = require('../src/verify-core');

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

function readZip(zipPath) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tower-verify-'));
    try {
        execFileSync('unzip', ['-o', '-q', zipPath, '-d', tmp], { stdio: 'pipe' });
        const out = {};
        for (const name of fs.readdirSync(tmp)) {
            out[name] = new Uint8Array(fs.readFileSync(path.join(tmp, name)));
        }
        return out;
    } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
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
    const files = readZip(path.join(VECTOR_DIR, row.name + '.zip'));
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
