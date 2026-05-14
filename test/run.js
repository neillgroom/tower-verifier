// Test harness — runs verify-core.js against real receipt ZIPs.
//
// Usage: node test/run.js
//
// Uses Node's built-in unzip via execFileSync (no shell injection
// surface — args are passed as an array). Test vectors live under
// ../test-vectors/.

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
        const result = await core.verifyReceiptArtifacts({ receipt, otsBytes });
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
    // Self-test: SubtleCrypto SHA-256 known answer.
    const ok = await core.selfTest();
    if (!ok) fail('self-test (SubtleCrypto sha256) did not match known vector');
    pass('self-test (SubtleCrypto sha256 known vector)');

    // Real-world test: a confirmed Tower receipt ZIP.
    const realZip = path.join(VECTOR_DIR, 'real-entry-3.zip');
    if (fs.existsSync(realZip)) {
        await testVector(realZip, 'green');
    } else {
        console.log(`  SKIP: ${realZip} not present (drop a real receipt here to test)`);
    }
}

main().catch((err) => fail(err.stack || err.message));
