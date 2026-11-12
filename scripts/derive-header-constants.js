#!/usr/bin/env node
// derive-header-constants.js — reproduces the pinned header constants in
// src/verify-core.js from the real Bitcoin headers Tower has anchored.
//
// Input: test-vectors/anchored-headers.json — the 80-byte header of every
// block Tower anchored a batch in (12 batches, heights 940842..975496),
// captured 2026-11-12 from https://mempool.space/api/block-height/<h> then
// /api/block/<hash>/header, and cross-checked against the
// block_header_hex carried by public Tower receipts for 941015 and 949407.
//
// Output: MIN_ANCHOR_HEIGHT, MAX_TARGET (4x the easiest target among those
// headers) and MIN_HEADER_TIME (earliest header time minus 2 hours, the
// slack Bitcoin's own timestamp rules allow between neighbouring blocks).
//
// Usage: node scripts/derive-header-constants.js   (exits 1 if the values
// pinned in verify-core.js differ from what this derives)

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const core = require('../src/verify-core');

const headers = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'test-vectors', 'anchored-headers.json'), 'utf8'));

let minHeight = Infinity;
let maxTarget = 0n;
let minTime = Infinity;
for (const [h, { block_hash, header_hex }] of Object.entries(headers)) {
    const hdr = Buffer.from(header_hex, 'hex');
    if (hdr.length !== 80) throw new Error(`header ${h} is not 80 bytes`);
    const hash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(hdr).digest()).digest();
    const display = Buffer.from(hash).reverse().toString('hex');
    if (display !== block_hash) throw new Error(`header ${h} hashes to ${display}, explorer said ${block_hash}`);
    const target = core.targetFromBits(hdr.readUInt32LE(72));
    const time = hdr.readUInt32LE(68);
    console.log(`${h}  bits=0x${hdr.readUInt32LE(72).toString(16)}  time=${new Date(time * 1000).toISOString()}  target=0x${target.toString(16)}`);
    if (Number(h) < minHeight) minHeight = Number(h);
    if (target > maxTarget) maxTarget = target;
    if (time < minTime) minTime = time;
}

const derived = {
    MIN_ANCHOR_HEIGHT: minHeight,
    MAX_TARGET: maxTarget * 4n,
    MIN_HEADER_TIME: minTime - 7200,
};
console.log('');
console.log(`MIN_ANCHOR_HEIGHT = ${derived.MIN_ANCHOR_HEIGHT}`);
console.log(`MAX_TARGET        = 0x${derived.MAX_TARGET.toString(16)}  (4 x easiest anchored target 0x${maxTarget.toString(16)})`);
console.log(`MIN_HEADER_TIME   = ${derived.MIN_HEADER_TIME}  (${new Date(derived.MIN_HEADER_TIME * 1000).toISOString()})`);

let ok = true;
if (core.MIN_ANCHOR_HEIGHT !== derived.MIN_ANCHOR_HEIGHT) { console.error('MISMATCH MIN_ANCHOR_HEIGHT'); ok = false; }
if (core.MAX_TARGET !== derived.MAX_TARGET) { console.error('MISMATCH MAX_TARGET'); ok = false; }
if (core.MIN_HEADER_TIME !== derived.MIN_HEADER_TIME) { console.error('MISMATCH MIN_HEADER_TIME'); ok = false; }
if (!ok) process.exit(1);
console.log('pinned constants in src/verify-core.js match.');
