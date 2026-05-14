// Test harness — runs verify-core.js against real receipt ZIPs.
//
// Vectors:
//   - real-entry-3.zip       : Open-tier, batch confirmed. Expects GREEN.
//   - sealed-entry-4.zip     : Sealed-tier, batch confirmed. Step A skipped
//                              for the sentinel; Merkle + Bitcoin still
//                              verify. Expects GREEN.
//
// Uses Node's built-in unzip via execFileSync (no shell injection surface).

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const os = require('os');

const core = require('../src/verify-core');

const VECTOR_DIR = path.join(__dirname, '..', 'test-vectors');

function fail(msg) {
    console.error('FAIL: ' + msg);
    process.exit(1);
}

function pass(msg) {
    console.log('PASS: ' + msg);
}

function unzipToDir(zipPath, outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    execFileSync('unzip', ['-o', zipPath, '-d', outDir], { stdio: 'pipe' });
}

async function testVector(zipPath, expected) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tower-verify-'));
    try {
        unzipToDir(zipPath, tmp);
        const receipt = JSON.parse(fs.readFileSync(path.join(tmp, 'receipt.json'), 'utf8'));
        let otsBytes = null;
        const otsPath = path.join(tmp, 'merkle-root.ots');
        if (fs.existsSync(otsPath)) {
            otsBytes = new Uint8Array(fs.readFileSync(otsPath));
        }
        let blockHeaderBytes = null;
        const headerPath = path.join(tmp, 'btc-block-header.bin');
        if (fs.existsSync(headerPath)) {
            blockHeaderBytes = new Uint8Array(fs.readFileSync(headerPath));
        }
        const result = await core.verifyReceiptArtifacts({ receipt, otsBytes, blockHeaderBytes });
        console.log(`  overall=${result.overall} summary="${result.summary}"`);
        for (const step of result.steps) {
            console.log(`    [${step.status}] ${step.name}: ${step.detail}`);
        }
        if (result.overall !== expected) {
            fail(`expected ${expected}, got ${result.overall} for ${path.basename(zipPath)}`);
        }
        pass(`${path.basename(zipPath)} → ${expected}`);
    } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
    }
}

async function main() {
    const ok = await core.selfTest();
    if (!ok) fail('self-test (SubtleCrypto sha256) did not match known vector');
    pass('self-test (SubtleCrypto sha256 known vector)');

    // Positive vectors — real Tower receipts that MUST verify GREEN.
    const positives = [
        ['real-entry-3.zip', 'Open-tier, fully anchored. All 5 steps pass.'],
        ['sealed-entry-4.zip', 'Sealed-tier in same batch. Step A skips for the sentinel; Merkle + Bitcoin still verify.'],
    ];
    for (const [name, _desc] of positives) {
        const p = path.join(VECTOR_DIR, name);
        if (fs.existsSync(p)) await testVector(p, 'green');
        else console.log(`  SKIP: ${p} not present`);
    }

    // Negative vectors (built by scripts/build-test-vectors.py) — must
    // fail closed. Any path that lets one of these render GREEN is a
    // false-positive bug.
    const reds = [
        ['tampered-hash.zip', 'hash_text mutated; Step A must catch.'],
        ['tampered-merkle.zip', 'proof[0].hash zeroed; Step C must catch.'],
    ];
    for (const [name, _desc] of reds) {
        const p = path.join(VECTOR_DIR, name);
        if (fs.existsSync(p)) await testVector(p, 'red');
        else console.log(`  SKIP: ${p} not present`);
    }

    // Amber vectors — legitimate but not yet anchored. Must NOT render
    // GREEN (would be a "verified" claim with no Bitcoin block behind it)
    // and must NOT render RED (carve was recorded, just not anchored yet).
    const ambers = [
        ['pre-batch.zip', 'merkle nulled; Step C must amber, no fall-through to green.'],
    ];
    for (const [name, _desc] of ambers) {
        const p = path.join(VECTOR_DIR, name);
        if (fs.existsSync(p)) await testVector(p, 'amber');
        else console.log(`  SKIP: ${p} not present`);
    }
}

main().catch((err) => fail(err.stack || err.message));
