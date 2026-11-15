// ZIP layout attacks against the strict receipt reader (src/verify-zip.js).
//
// Every archive here is built byte by byte so each one differs from a
// genuine receipt ZIP in exactly one way. Genuine controls built by the same
// writer must be accepted, so a refusal is never just the writer's fault.
//
// Exported as one async function taking the harness's check().

const zlib = require('zlib');
const zipReader = require('../src/verify-zip');
const JSZip = require('../vendor/jszip.min.js');

const CRC_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c >>> 0;
    }
    return t;
})();
function crc32(buf) {
    let c = 0xffffffff;
    for (const x of buf) c = CRC_TABLE[(c ^ x) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}

function u16(n) {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n);
    return b;
}
function u32(n) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
}

// files: [{ name, data, deflate?, descriptor?: 'sig'|'nosig', localName?,
//           flags?, declaredSize? }]
// opts:  { prefix, between: {index, bytes}, beforeCd, afterEocd, total,
//          cdOffset, disk, zip64Locator, extraEocd }
function buildZip(files, opts = {}) {
    const parts = [];
    let offset = 0;
    const push = (b) => {
        parts.push(b);
        offset += b.length;
    };
    if (opts.prefix) push(opts.prefix);
    const central = [];
    files.forEach((f, i) => {
        if (opts.between && opts.between.index === i) push(opts.between.bytes);
        const data = Buffer.from(f.data);
        const body = f.deflate ? zlib.deflateRawSync(data) : data;
        const method = f.deflate ? 8 : 0;
        const crc = crc32(data);
        let flags = f.flags || 0;
        if (f.descriptor) flags |= 0x0008;
        const name = Buffer.from(f.name, 'latin1');
        const localName = Buffer.from(f.localName !== undefined ? f.localName : f.name, 'latin1');
        const size = f.declaredSize !== undefined ? f.declaredSize : data.length;
        const localAt = offset;
        push(Buffer.concat([
            u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0),
            u32(f.descriptor ? 0 : crc), u32(f.descriptor ? 0 : body.length), u32(f.descriptor ? 0 : size),
            u16(localName.length), u16(0), localName,
        ]));
        push(body);
        if (f.descriptor === 'sig') push(Buffer.concat([u32(0x08074b50), u32(crc), u32(body.length), u32(size)]));
        if (f.descriptor === 'nosig') push(Buffer.concat([u32(crc), u32(body.length), u32(size)]));
        central.push(Buffer.concat([
            u32(0x02014b50), u16(20), u16(20), u16(flags), u16(method), u16(0), u16(0),
            u32(crc), u32(body.length), u32(size),
            u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0), u32(localAt), name,
        ]));
    });
    if (opts.beforeCd) push(opts.beforeCd);
    const cdAt = offset;
    const cd = Buffer.concat(central);
    push(cd);
    if (opts.zip64Locator) push(Buffer.concat([u32(0x07064b50), u32(0), u32(0), u32(0), u32(1)]).subarray(0, 20));
    const eocd = (comment) => Buffer.concat([
        u32(0x06054b50), u16(opts.disk || 0), u16(0),
        u16(opts.total !== undefined ? opts.total : files.length),
        u16(opts.total !== undefined ? opts.total : files.length),
        u32(cd.length), u32(opts.cdOffset !== undefined ? opts.cdOffset : cdAt),
        u16(comment.length), comment,
    ]);
    if (opts.extraEocd) {
        // A second, complete EOCD hidden in the first one's comment.
        const inner = eocd(Buffer.alloc(0));
        push(eocd(inner));
    } else {
        push(eocd(Buffer.alloc(0)));
    }
    if (opts.afterEocd) push(opts.afterEocd);
    return new Uint8Array(Buffer.concat(parts));
}

const RECEIPT = '{"version":"1.2","entry":{"id":1}}';
const GENUINE_ENV = '{"envelope":"genuine"}';
const FORGED_ENV = '{"envelope":"forged"}';
const base = () => [
    { name: 'receipt.json', data: RECEIPT },
    { name: 'merkle-root.ots', data: 'ots-bytes' },
    { name: 'btc-block-header.bin', data: Buffer.alloc(80, 1) },
];

async function outcome(bytes) {
    try {
        const files = await zipReader.extractReceiptZip(bytes, JSZip);
        return { ok: true, files };
    } catch (err) {
        return { ok: false, err: err.message };
    }
}

module.exports = async function zipAttacks(check) {
    const text = (u8) => Buffer.from(u8).toString('utf8');

    // ---- Genuine controls: accepted, bytes exact.
    const controls = [
        ['stored', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV }])],
        ['deflated', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV, deflate: true }].map((f) => ({ ...f, deflate: true })))],
        ['data descriptor with signature (archiver-style)', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV }].map((f) => ({ ...f, deflate: true, descriptor: 'sig' })))],
        ['data descriptor without signature', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV }].map((f) => ({ ...f, descriptor: 'nosig' })))],
        ['Treasure kit with extra flat files', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV }, { name: 'reference.js', data: 'x' }, { name: 'spec.md', data: 'x' }, { name: 'README.txt', data: 'x' }])],
    ];
    for (const [label, bytes] of controls) {
        const r = await outcome(bytes);
        check(r.ok && text(r.files['envelope.json']) === GENUINE_ENV && text(r.files['receipt.json']) === RECEIPT,
            `zip: genuine control accepted with exact bytes — ${label}${r.ok ? '' : ' (' + r.err + ')'}`);
        if (r.ok) check(!('README.txt' in r.files) && !('reference.js' in r.files), `zip: only the four verifier files are returned — ${label}`);
    }

    // ---- Attacks: every one refused. (P1 689d99226242 and P2s 5d343e868151, a885eb9aec65.)
    const env = (name, data = FORGED_ENV) => ({ name, data });
    const attacks = [
        ['duplicate envelope.json, forged first (P1)', buildZip([...base(), env('envelope.json'), env('envelope.json', GENUINE_ENV)])],
        ['duplicate envelope.json, genuine first', buildZip([...base(), env('envelope.json', GENUINE_ENV), env('envelope.json')])],
        ['case-only duplicate Envelope.json', buildZip([...base(), env('Envelope.json'), env('envelope.json', GENUINE_ENV)])],
        ['./envelope.json after a forged envelope.json (P1)', buildZip([...base(), env('envelope.json'), env('./envelope.json', GENUINE_ENV)])],
        ['a/../envelope.json after a forged envelope.json (P1)', buildZip([...base(), env('envelope.json'), env('a/../envelope.json', GENUINE_ENV)])],
        ['envelope.json inside a folder', buildZip([...base(), env('kit/envelope.json', GENUINE_ENV)])],
        ['backslash path', buildZip([...base(), env('kit\\envelope.json', GENUINE_ENV)])],
        ['absolute path', buildZip([...base(), env('/envelope.json', GENUINE_ENV)])],
        ['directory entry', buildZip([...base(), { name: 'kit/', data: '' }])],
        ['name starting with a dot', buildZip([...base(), env('.envelope.json', GENUINE_ENV)])],
        ['non-ASCII name', buildZip([...base(), env('envelopeé.json', GENUINE_ENV)])],
        ['EOCD total=1 over 4 real records (P2 a885eb9aec65)', buildZip([...base(), env('envelope.json', GENUINE_ENV)], { total: 1 })],
        ['21 records, honestly declared', buildZip([...base(), ...Array.from({ length: 18 }, (_, i) => ({ name: `pad${i}.txt`, data: 'x' }))])],
        ['EOCD total 0xffff (ZIP64 sentinel)', buildZip(base(), { total: 0xffff })],
        ['EOCD cdOffset 0xffffffff (ZIP64 sentinel)', buildZip(base(), { cdOffset: 0xffffffff })],
        ['ZIP64 locator before the EOCD', buildZip(base(), { zip64Locator: true })],
        ['multi-disk EOCD', buildZip(base(), { disk: 1 })],
        ['trailing bytes after the EOCD', buildZip(base(), { afterEocd: Buffer.from('trailing') })],
        ['second EOCD hidden in the comment', buildZip(base(), { extraEocd: true })],
        ['bytes before the first entry', buildZip(base(), { prefix: Buffer.from('prefix-bytes') })],
        ['smuggled local entry between entries', buildZip([...base(), env('envelope.json', GENUINE_ENV)], {
            between: { index: 3, bytes: buildZip([env('envelope.json')]).subarray(0, 30 + 13 + FORGED_ENV.length) },
        })],
        ['bytes between the last entry and the central directory', buildZip(base(), { beforeCd: Buffer.from('gap') })],
        ['local name differs from central name', buildZip([...base(), { name: 'envelope.json', localName: 'envelopX.json', data: GENUINE_ENV }])],
        ['encrypted entry', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV, flags: 1 }])],
        ['empty envelope.json', buildZip([...base(), env('envelope.json', '')])],
        ['empty btc-block-header.bin', buildZip([{ name: 'receipt.json', data: RECEIPT }, { name: 'btc-block-header.bin', data: '' }])],
        ['declared size above the per-file cap', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV, declaredSize: zipReader.MAX_FILE_BYTES + 1 }])],
        ['declared size smaller than the inflated size', buildZip([...base(), { name: 'envelope.json', data: GENUINE_ENV, declaredSize: 3 }])],
        ['not a ZIP', new Uint8Array(Buffer.from('this is not a zip file at all, just text'))],
        ['trailing-dot name that Windows maps onto envelope.json', buildZip([...base(), env('envelope.json.'), env('envelope.json', GENUINE_ENV)])],
        ['local header name length runs past the file', (() => {
            const z = buildZip(base());
            Buffer.from(z.buffer, z.byteOffset).writeUInt16LE(0xfff0, 26); // first local header's name length
            return z;
        })()],
        ['data descriptor followed by four stray bytes', buildZip([...base().map((f) => ({ ...f, descriptor: 'nosig' })), env('envelope.json', GENUINE_ENV)], {
            between: { index: 3, bytes: Buffer.from('XXXX') },
        })],
    ];
    for (const [label, bytes] of attacks) {
        const r = await outcome(bytes);
        check(!r.ok, `zip: refused — ${label}${r.ok ? ' (ACCEPTED; envelope=' + (r.files['envelope.json'] ? text(r.files['envelope.json']) : 'none') + ')' : ''}`);
    }

    // ---- Inflation caps, enforced while streaming.
    const big = Buffer.alloc(zipReader.MAX_FILE_BYTES + 1024, 0x30);
    const lyingBomb = buildZip([...base(), { name: 'envelope.json', data: big, deflate: true, declaredSize: 100 }]);
    let r = await outcome(lyingBomb);
    check(!r.ok, `zip: refused — deflate bomb that declares 100 bytes and inflates past the per-file cap${r.ok ? '' : ' (' + r.err + ')'}`);

    const third = Buffer.alloc(Math.floor(zipReader.MAX_TOTAL_BYTES / 3) + 1024, 0x31);
    const overBudget = buildZip([
        { name: 'receipt.json', data: RECEIPT },
        { name: 'merkle-root.ots', data: third, deflate: true },
        { name: 'btc-block-header.bin', data: third, deflate: true },
        { name: 'envelope.json', data: third, deflate: true },
    ]);
    r = await outcome(overBudget);
    check(!r.ok && /size cap/.test(r.err), `zip: refused — three files each under the per-file cap but together past the total cap${r.ok ? '' : ' (' + r.err + ')'}`);
};
