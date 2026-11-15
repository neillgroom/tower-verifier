// verify-zip.js — strict receipt-ZIP reader shared by the page and the tests.
//
// The verifier says VERIFIED about the bytes it reads from a ZIP, so those
// must be the same bytes any other ZIP tool would show the user. JSZip on its
// own is not enough: it normalises entry names ("./envelope.json" and
// "a/../envelope.json" both become "envelope.json") and a later entry with
// the same name silently replaces an earlier one, while other readers keep
// the first. So before JSZip sees the archive, this file walks the whole
// layout itself and refuses anything a receipt ZIP never contains:
//
//   - exactly one End Of Central Directory, ending the file (comment and all);
//   - no ZIP64, no multi-disk, no encryption;
//   - the central directory holds exactly the records the EOCD declares
//     (counted from the real headers, at most MAX_ENTRIES);
//   - every name is a plain flat file name (letters, digits, ".", "_", "-";
//     no path, no directory, no "." or ".." segment) and no two names match,
//     case ignored;
//   - local entries start at byte 0, follow one another with no gap or
//     overlap (a data descriptor is the only thing allowed between them),
//     carry the same name as their central record, and end exactly where the
//     central directory begins. So a streaming reader and a central-directory
//     reader see the same entries.
//
// After JSZip loads, the names it holds must equal the names walked here.
// Only the four files the verifier reads are inflated, each against a
// per-file cap and a shared budget enforced while streaming.

(function (root) {
    const MAX_ZIP_BYTES = 50 * 1024 * 1024; //   compressed archive
    const MAX_FILE_BYTES = 25 * 1024 * 1024; //  one inflated file
    const MAX_TOTAL_BYTES = 50 * 1024 * 1024; // all inflated files together
    const MAX_ENTRIES = 20; //                   every record
    const ALLOWED_FILES = ['receipt.json', 'merkle-root.ots', 'btc-block-header.bin', 'envelope.json'];
    // No trailing dot: Windows strips it on extraction, so "envelope.json."
    // would land on top of "envelope.json".
    const SAFE_NAME = /^[A-Za-z0-9_-](?:[A-Za-z0-9._-]*[A-Za-z0-9_-])?$/;

    const SIG_LOCAL = 0x04034b50;
    const SIG_CENTRAL = 0x02014b50;
    const SIG_EOCD = 0x06054b50;
    const SIG_ZIP64_LOCATOR = 0x07064b50;
    const SIG_ZIP64_EOCD = 0x06064b50;
    // General-purpose flag bits a receipt ZIP may use: deflate options
    // (bits 1-2), data descriptor (bit 3), UTF-8 names (bit 11).
    const ALLOWED_FLAGS = 0x0002 | 0x0004 | 0x0008 | 0x0800;
    const SIG_DESCRIPTOR = 0x08074b50;

    function fail(msg) {
        throw new Error('Refused ZIP: ' + msg);
    }

    function u16(b, i) {
        return b[i] | (b[i + 1] << 8);
    }
    function u32(b, i) {
        return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)) + b[i + 3] * 0x1000000;
    }
    function need(b, i, n, what) {
        if (i < 0 || i + n > b.length) fail(what + ' runs past the end of the file');
    }

    let crcTable = null;
    function crc32(bytes) {
        if (!crcTable) {
            crcTable = new Uint32Array(256);
            for (let n = 0; n < 256; n++) {
                let c = n;
                for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
                crcTable[n] = c >>> 0;
            }
        }
        let c = 0xffffffff;
        for (let k = 0; k < bytes.length; k++) c = crcTable[(c ^ bytes[k]) & 0xff] ^ (c >>> 8);
        return (c ^ 0xffffffff) >>> 0;
    }

    function sameBytes(b, i, j, n) {
        for (let k = 0; k < n; k++) if (b[i + k] !== b[j + k]) return false;
        return true;
    }

    // Extra fields must tile their area exactly, and none may change how an
    // entry is named or sized: 0x7075 (Info-ZIP Unicode Path) renames an
    // entry in readers that honour it, 0x0001 is ZIP64.
    const FORBIDDEN_EXTRA = { 0x7075: 'a Unicode Path extra field (it can rename the entry)', 0x0001: 'a ZIP64 extra field' };
    function checkExtra(b, at, len, name, where) {
        let q = at;
        const end = at + len;
        while (q < end) {
            if (q + 4 > end) fail(`the ${where} extra field of "${name}" is malformed`);
            const id = u16(b, q);
            const size = u16(b, q + 2);
            if (q + 4 + size > end) fail(`the ${where} extra field of "${name}" is malformed`);
            if (FORBIDDEN_EXTRA[id]) fail(`"${name}" carries ${FORBIDDEN_EXTRA[id]} in its ${where} header`);
            q += 4 + size;
        }
    }

    // Walk the archive. Returns [{ name, crc, compressedSize,
    // uncompressedSize }] in central-directory order, or throws.
    function scanZip(input) {
        const b = input instanceof Uint8Array ? input : new Uint8Array(input);
        if (b.length > MAX_ZIP_BYTES) fail(`too large (${b.length} bytes; max ${MAX_ZIP_BYTES})`);
        if (b.length < 22) fail('not a ZIP file (too short)');

        // The EOCD must end the file exactly: its comment runs to the last
        // byte. Exactly one position may satisfy that.
        let eocd = -1;
        const lowest = Math.max(0, b.length - 22 - 0xffff);
        for (let i = b.length - 22; i >= lowest; i--) {
            if (u32(b, i) === SIG_EOCD && i + 22 + u16(b, i + 20) === b.length) {
                if (eocd !== -1) fail('more than one end-of-central-directory record');
                eocd = i;
            }
        }
        if (eocd === -1) fail('not a ZIP file (no end-of-central-directory record at the end)');
        // Readers that search backward for the last end record (JSZip, unzip)
        // must land on this one. So no record signature may start anywhere
        // after its own four signature bytes (one could straddle the
        // comment-length field and the comment), and the comment may hold no
        // "PK" pair at all. The second rule is deliberately stricter: plain
        // text "PK" in a comment is refused too.
        for (let k = eocd + 1; k + 4 <= b.length; k++) {
            const s = u32(b, k);
            if (s === SIG_EOCD || s === SIG_CENTRAL || s === SIG_LOCAL || s === SIG_ZIP64_LOCATOR || s === SIG_ZIP64_EOCD) {
                fail('a ZIP record signature appears after the end record');
            }
        }
        for (let k = eocd + 22; k + 1 < b.length; k++) {
            if (b[k] === 0x50 && b[k + 1] === 0x4b) fail('the ZIP comment contains "PK", which could hide a second archive');
        }

        const disk = u16(b, eocd + 4);
        const cdDisk = u16(b, eocd + 6);
        const onDisk = u16(b, eocd + 8);
        const total = u16(b, eocd + 10);
        const cdSize = u32(b, eocd + 12);
        const cdOffset = u32(b, eocd + 16);
        if (onDisk === 0xffff || total === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
            fail('ZIP64 archives are not accepted');
        }
        if (eocd >= 20 && u32(b, eocd - 20) === SIG_ZIP64_LOCATOR) fail('ZIP64 archives are not accepted');
        if (disk !== 0 || cdDisk !== 0 || onDisk !== total) fail('multi-disk archives are not accepted');
        if (total === 0) fail('the ZIP is empty');
        if (total > MAX_ENTRIES) fail(`too many entries (${total}; max ${MAX_ENTRIES})`);
        if (cdOffset + cdSize !== eocd) fail('central directory does not end where the end record begins');

        // Central directory: count the real headers, never trust `total`.
        const entries = [];
        const seen = new Set();
        let p = cdOffset;
        while (p < eocd) {
            if (entries.length >= MAX_ENTRIES) fail(`too many entries (more than ${MAX_ENTRIES})`);
            need(b, p, 46, 'central record');
            if (u32(b, p) !== SIG_CENTRAL) fail('bad central directory record');
            const flags = u16(b, p + 8);
            const method = u16(b, p + 10);
            const crc = u32(b, p + 16);
            const compressedSize = u32(b, p + 20);
            const uncompressedSize = u32(b, p + 24);
            const nameLen = u16(b, p + 28);
            const extraLen = u16(b, p + 30);
            const commentLen = u16(b, p + 32);
            const diskStart = u16(b, p + 34);
            const externalAttr = u32(b, p + 38);
            const localOffset = u32(b, p + 42);
            need(b, p + 46, nameLen + extraLen + commentLen, 'central record');
            if (flags & 0x0001) fail('encrypted entries are not accepted');
            if (flags & ~ALLOWED_FLAGS) fail('an entry uses ZIP flags a receipt never needs');
            const unixType = (externalAttr >>> 16) & 0xf000;
            if ((externalAttr & 0x18) !== 0 || (unixType !== 0 && unixType !== 0x8000)) {
                fail('an entry is marked as a directory, link or other non-file');
            }
            if (method !== 0 && method !== 8) fail('only stored or deflated entries are accepted');
            if (diskStart !== 0) fail('multi-disk archives are not accepted');
            if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
                fail('ZIP64 entries are not accepted');
            }
            let name = '';
            for (let k = 0; k < nameLen; k++) {
                const c = b[p + 46 + k];
                if (c < 0x21 || c > 0x7e) fail('an entry name is not plain ASCII');
                name += String.fromCharCode(c);
            }
            if (!SAFE_NAME.test(name)) fail(`entry name "${name}" is not a plain file name`);
            const key = name.toLowerCase();
            if (seen.has(key)) fail(`two entries are named "${name}"`);
            seen.add(key);
            checkExtra(b, p + 46 + nameLen, extraLen, name, 'central');
            entries.push({
                name,
                flags,
                method,
                crc,
                compressedSize,
                uncompressedSize,
                localOffset,
                cdNameAt: p + 46,
                nameLen,
            });
            p += 46 + nameLen + extraLen + commentLen;
        }
        if (p !== eocd) fail('central directory overruns the end record');
        if (entries.length !== total) fail(`end record declares ${total} entries, central directory holds ${entries.length}`);

        // Local entries: contiguous from byte 0 to the central directory, in
        // the same order, each with the same name as its central record.
        let expect = 0;
        for (let i = 0; i < entries.length; i++) {
            const e = entries[i];
            if (e.localOffset !== expect) fail(`entry "${e.name}" is not where the previous one ends`);
            need(b, e.localOffset, 30, 'local header');
            if (u32(b, e.localOffset) !== SIG_LOCAL) fail(`bad local header for "${e.name}"`);
            const lFlags = u16(b, e.localOffset + 6);
            const lMethod = u16(b, e.localOffset + 8);
            const lNameLen = u16(b, e.localOffset + 26);
            const lExtraLen = u16(b, e.localOffset + 28);
            need(b, e.localOffset + 30, lNameLen + lExtraLen, 'local header');
            if (lFlags & 0x0001) fail('encrypted entries are not accepted');
            if (lMethod !== e.method) fail(`local and central records disagree on "${e.name}"`);
            if (lNameLen !== e.nameLen || !sameBytes(b, e.localOffset + 30, e.cdNameAt, e.nameLen)) {
                fail(`local and central names disagree on "${e.name}"`);
            }
            if (lFlags !== e.flags) fail(`local and central flags disagree on "${e.name}"`);
            checkExtra(b, e.localOffset + 30 + lNameLen, lExtraLen, e.name, 'local');
            // A streaming reader trusts the local header (or the data
            // descriptor), not the central record: they must agree.
            const same = (crc, cs, us) => crc === e.crc && cs === e.compressedSize && us === e.uncompressedSize;
            let end = e.localOffset + 30 + lNameLen + lExtraLen + e.compressedSize;
            if (end > cdOffset) fail(`entry "${e.name}" runs into the central directory`);
            if (e.flags & 0x0008) {
                // Data descriptor: 12 bytes, or 16 when it carries its optional
                // signature. Judged by where the next entry (or the central
                // directory) actually starts, never by sniffing alone.
                const next = i + 1 < entries.length ? entries[i + 1].localOffset : cdOffset;
                const gap = next - end;
                if (!(gap === 12 || (gap === 16 && u32(b, end) === SIG_DESCRIPTOR))) {
                    fail(`entry "${e.name}" has a malformed data descriptor`);
                }
                const d = gap === 16 ? end + 4 : end;
                if (!same(u32(b, d), u32(b, d + 4), u32(b, d + 8))) {
                    fail(`the data descriptor of "${e.name}" disagrees with its central record`);
                }
                // A reader that ignores bit 3 reads the local header's sizes.
                const lc = u32(b, e.localOffset + 14);
                const lcs = u32(b, e.localOffset + 18);
                const lus = u32(b, e.localOffset + 22);
                if (!((lc === 0 && lcs === 0 && lus === 0) || same(lc, lcs, lus))) {
                    fail(`local sizes of "${e.name}" are neither zero nor its central record`);
                }
                end = next;
            } else if (!same(u32(b, e.localOffset + 14), u32(b, e.localOffset + 18), u32(b, e.localOffset + 22))) {
                fail(`local and central sizes or checksum disagree on "${e.name}"`);
            }
            expect = end;
        }
        if (expect !== cdOffset) fail('there are bytes between the last entry and the central directory');

        return entries.map((e) => ({
            name: e.name,
            crc: e.crc,
            compressedSize: e.compressedSize,
            uncompressedSize: e.uncompressedSize,
        }));
    }

    // Inflate one entry against a shared byte budget, stopping as soon as
    // the output passes either the per-file cap or what is left of the
    // budget for all files.
    function inflateCapped(entry, name, budget) {
        return new Promise((resolve, reject) => {
            const chunks = [];
            let total = 0;
            let done = false;
            const stop = (err) => {
                if (done) return;
                done = true;
                reject(err);
            };
            const stream = entry.internalStream('uint8array');
            stream
                .on('data', (chunk) => {
                    if (done) return;
                    total += chunk.length;
                    if (total > MAX_FILE_BYTES || total > budget.left) {
                        stream.pause();
                        stop(new Error(`${name} inflates past the size cap (${MAX_FILE_BYTES} bytes per file, ${MAX_TOTAL_BYTES} in all)`));
                        return;
                    }
                    chunks.push(chunk);
                })
                .on('error', stop)
                .on('end', () => {
                    if (done) return;
                    done = true;
                    budget.left -= total;
                    const out = new Uint8Array(total);
                    let off = 0;
                    for (const c of chunks) {
                        out.set(c, off);
                        off += c.length;
                    }
                    resolve(out);
                })
                .resume();
        });
    }

    // Returns { 'receipt.json': Uint8Array, ... } holding only the allowed
    // files that are present, or throws.
    async function extractReceiptZip(input, JSZip) {
        const b = input instanceof Uint8Array ? input : new Uint8Array(input);
        const entries = scanZip(b);
        const wanted = entries.filter((e) => ALLOWED_FILES.includes(e.name));
        for (const e of wanted) {
            if (e.uncompressedSize === 0) fail(`${e.name} is empty; a receipt ZIP never carries an empty ${e.name}`);
            if (e.uncompressedSize > MAX_FILE_BYTES) {
                fail(`${e.name} declares ${e.uncompressedSize} bytes uncompressed (cap ${MAX_FILE_BYTES})`);
            }
        }

        const zip = await JSZip.loadAsync(b);
        const loaded = Object.keys(zip.files);
        const walked = entries.map((e) => e.name);
        if (loaded.length !== walked.length || walked.some((n) => !Object.prototype.hasOwnProperty.call(zip.files, n))) {
            fail('the ZIP library read different entries than the archive declares');
        }
        for (const n of walked) {
            const f = zip.files[n];
            if (f.dir || (f.unsafeOriginalName !== undefined && f.unsafeOriginalName !== n)) {
                fail(`entry "${n}" was renamed while loading`);
            }
        }

        const budget = { left: MAX_TOTAL_BYTES };
        const result = {};
        for (const e of wanted) {
            // Raw bytes: an envelope is hashed exactly as it sits in the ZIP.
            const bytes = await inflateCapped(zip.files[e.name], e.name, budget);
            if (bytes.length !== e.uncompressedSize) fail(`${e.name} inflates to a different size than declared`);
            if (crc32(bytes) !== e.crc) fail(`${e.name} does not match its CRC-32`);
            result[e.name] = bytes;
        }
        return result;
    }

    const api = {
        MAX_ZIP_BYTES,
        MAX_FILE_BYTES,
        MAX_TOTAL_BYTES,
        MAX_ENTRIES,
        ALLOWED_FILES,
        scanZip,
        extractReceiptZip,
    };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.TowerVerifyZip = api;
})(typeof window !== 'undefined' ? window : null);
