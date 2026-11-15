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

    function sameBytes(b, i, j, n) {
        for (let k = 0; k < n; k++) if (b[i + k] !== b[j + k]) return false;
        return true;
    }

    // Walk the archive. Returns [{ name, flags, method, compressedSize,
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
            const compressedSize = u32(b, p + 20);
            const uncompressedSize = u32(b, p + 24);
            const nameLen = u16(b, p + 28);
            const extraLen = u16(b, p + 30);
            const commentLen = u16(b, p + 32);
            const diskStart = u16(b, p + 34);
            const localOffset = u32(b, p + 42);
            need(b, p + 46, nameLen + extraLen + commentLen, 'central record');
            if (flags & 0x0001) fail('encrypted entries are not accepted');
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
            entries.push({
                name,
                flags,
                method,
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
                end = next;
            }
            expect = end;
        }
        if (expect !== cdOffset) fail('there are bytes between the last entry and the central directory');

        return entries.map((e) => ({
            name: e.name,
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
