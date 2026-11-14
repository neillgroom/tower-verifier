// verify-ui.js — drag-and-drop UI and result rendering. DOM-heavy.
//
// Imports verify-core via window.TowerVerifyCore. Uses vendored JSZip
// via window.JSZip. Both are loaded by index.html.
//
// Nothing typed or loaded here leaves the page: the CSP sets
// connect-src 'none', and this file makes no network call.

(function () {
    const core = window.TowerVerifyCore;
    const JSZip = window.JSZip;
    if (!core || !JSZip) {
        document.body.replaceChildren();
        const p = document.createElement('p');
        p.style.cssText = 'color:#ff5555;font-family:monospace;padding:1rem';
        p.textContent =
            'Verifier failed to load core modules. Refresh, or clone the repo and open index.html directly.';
        document.body.appendChild(p);
        return;
    }

    const $ = (id) => document.getElementById(id);
    const el = (tag, cls, text) => {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text !== undefined) e.textContent = text;
        return e;
    };

    // The receipt currently loaded, so the owner panel can re-verify it.
    let current = null;

    // The label text comes from the core (result.label), so the
    // hidden-commitment green can never be shown as plain "VERIFIED".
    function renderTrafficLight(overall, text) {
        const colors = { green: '#3cd982', amber: '#d4af37', red: '#ff5555' };
        const dot = $('lightDot');
        const label = $('lightLabel');
        dot.style.background = colors[overall] || '#888';
        dot.style.boxShadow = `0 0 16px ${colors[overall] || '#888'}`;
        label.textContent = text || core.outcomeLabel(overall);
        label.style.color = colors[overall] || '#888';
    }

    function addRow(box, label, value) {
        const p = el('p', 'fact');
        p.appendChild(el('span', 'fact-label', label + ': '));
        p.appendChild(el('span', 'fact-value', value));
        box.appendChild(p);
    }

    function renderResult(result, receipt) {
        const out = $('result');
        out.replaceChildren();
        const light = el('div', 'traffic-light');
        light.appendChild(Object.assign(el('span', 'dot'), { id: 'lightDot' }));
        light.appendChild(Object.assign(el('span', 'label'), { id: 'lightLabel' }));
        out.appendChild(light);
        renderTrafficLight(result.overall, result.label);

        out.appendChild(el('p', 'summary', result.summary));

        const facts = el('div', 'facts');
        addRow(facts, 'Outcome', result.code);
        addRow(facts, 'Content rule (link 1)', result.link1Rule);
        addRow(facts, 'Binding rule (link 2)', result.link2Rule);
        if (result.blockTime) {
            addRow(facts, 'Proven date', `${result.blockTime} — the Bitcoin block's own timestamp (block ${result.blockHeight})`);
        }
        if (result.statedCreatedAt) {
            addRow(facts, 'Carve time stated by the receipt', `${result.statedCreatedAt} (bound into the leaf; the block date above is the proof)`);
        }
        out.appendChild(facts);

        if (result.blockHashHex) {
            const link = el('p', 'subtle');
            const a = document.createElement('a');
            a.href = `https://mempool.space/block/${result.blockHashHex}`;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.textContent = `mempool.space → block ${result.blockHeight}`;
            link.appendChild(document.createTextNode('Confirm the block is in the Bitcoin main chain: '));
            link.appendChild(a);
            out.appendChild(link);
        }

        // Steps detail.
        const stepsBox = el('div', 'steps');
        stepsBox.appendChild(el('h4', null, 'Verification steps'));
        const stepIcons = { pass: '✓', fail: '✗', amber: '⚠', skip: '—' };
        const stepColors = { pass: '#3cd982', fail: '#ff5555', amber: '#d4af37', skip: '#888' };
        for (const step of result.steps) {
            const row = el('div', 'step');
            const icon = el('span', 'step-icon', stepIcons[step.status] || '?');
            icon.style.color = stepColors[step.status] || '#888';
            row.appendChild(icon);
            row.appendChild(el('span', 'step-name', step.name));
            row.appendChild(el('span', 'step-detail', step.detail));
            stepsBox.appendChild(row);
        }
        out.appendChild(stepsBox);

        // Content. Only content the verifier proved is presented as proven.
        const entryId = receipt && receipt.entry ? receipt.entry.id : '?';
        if (result.overall === 'green' && typeof result.provenContent === 'string') {
            const box = el('div', 'entry-text');
            box.appendChild(el('h4', null, `Entry #${entryId} — proven content`));
            box.appendChild(el('pre', null, result.provenContent));
            out.appendChild(box);
        } else if (result.code === 'G_HIDDEN') {
            const box = el('div', 'entry-text');
            box.appendChild(el('h4', null, `Entry #${entryId} — content hidden`));
            box.appendChild(el('p', 'subtle', 'No content is shown, so none is claimed. The owner can check their plaintext below; it never leaves this page.'));
            out.appendChild(box);
        } else if (receipt && receipt.entry && typeof receipt.entry.text === 'string') {
            const box = el('div', 'entry-text unproven');
            box.appendChild(el('h4', null, `Entry #${entryId} — text in the receipt (NOT proven)`));
            box.appendChild(el('pre', null, receipt.entry.text));
            out.appendChild(box);
        }

        renderOwnerPanel(receipt);
    }

    // Owner panel: for sealed / tomb receipts, the owner may type the
    // plaintext and salt (or load the tower-sealed-key-v1 key file) to check
    // link 1 locally.
    function renderOwnerPanel(receipt) {
        const panel = $('ownerBox');
        if (!panel) return;
        const tier = receipt && receipt.entry && receipt.entry.tier;
        const hiddenText = receipt && receipt.entry && receipt.entry.text === core.SEALED_MARKER;
        panel.hidden = !(hiddenText || tier === 'sealed' || tier === 'tomb');
    }

    function renderError(message) {
        const out = $('result');
        out.replaceChildren();
        const light = el('div', 'traffic-light');
        light.appendChild(Object.assign(el('span', 'dot'), { id: 'lightDot' }));
        light.appendChild(Object.assign(el('span', 'label'), { id: 'lightLabel' }));
        out.appendChild(light);
        renderTrafficLight('red');
        out.appendChild(el('p', 'summary', message));
    }

    // Defensive ZIP extraction. Hard caps prevent ZIP-bomb DoS in the
    // browser. Filename allowlist prevents path-traversal / XSS via
    // crafted filenames.
    const MAX_ZIP_BYTES = 50 * 1024 * 1024;
    const MAX_FILE_BYTES = 25 * 1024 * 1024;
    const MAX_ENTRIES = 20;
    const ALLOWED_FILES = new Set([
        'receipt.json',
        'merkle-root.ots',
        'btc-block-header.bin',
        'envelope.json',
        'ciphertext.bin',
        'ciphertext-meta.json',
        'README.txt',
    ]);
    const TEXT_FILES = new Set(['receipt.json', 'README.txt', 'ciphertext-meta.json']);
    const SAFE_NAME = /^[a-zA-Z0-9._-]+$/;

    async function extractZip(file) {
        if (file.size > MAX_ZIP_BYTES) {
            throw new Error(`ZIP too large (${file.size} bytes; max ${MAX_ZIP_BYTES})`);
        }
        const buf = await file.arrayBuffer();
        const zip = await JSZip.loadAsync(buf);
        const fileNames = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
        if (fileNames.length > MAX_ENTRIES) {
            throw new Error(`Too many files in ZIP (${fileNames.length}; max ${MAX_ENTRIES})`);
        }

        // Pre-decompression size check from JSZip's entry metadata, before
        // any inflation. Absent metadata is treated as 0 and re-checked
        // after decompression below.
        let totalUncompressed = 0;
        for (const name of fileNames) {
            const meta = zip.files[name]?._data;
            const size = (meta && Number(meta.uncompressedSize)) || 0;
            if (size > MAX_FILE_BYTES) {
                throw new Error(`${name} declares ${size} bytes uncompressed (cap ${MAX_FILE_BYTES})`);
            }
            totalUncompressed += size;
        }
        if (totalUncompressed > MAX_ZIP_BYTES) {
            throw new Error(`Total uncompressed size ${totalUncompressed} exceeds ${MAX_ZIP_BYTES}`);
        }

        const result = {};
        for (const name of fileNames) {
            if (!SAFE_NAME.test(name)) continue;
            if (!ALLOWED_FILES.has(name)) continue;
            const entry = zip.files[name];
            // envelope.json is read as raw bytes: A-envelope hashes the
            // exact bytes in the ZIP, never a re-serialisation.
            const bytes = await entry.async('uint8array');
            if (bytes.length > MAX_FILE_BYTES) {
                throw new Error(`${name} exceeded ${MAX_FILE_BYTES} bytes after decompression`);
            }
            result[name] = TEXT_FILES.has(name) ? new TextDecoder().decode(bytes) : bytes;
        }
        return result;
    }

    async function runVerify(owner) {
        const { receipt, contents } = current;
        const result = await core.verifyReceiptArtifacts({
            receipt,
            otsBytes: contents['merkle-root.ots'] || null,
            blockHeaderBytes: contents['btc-block-header.bin'] || null,
            envelopeBytes: contents['envelope.json'] || null,
            owner: owner || null,
        });
        renderResult(result, receipt);
    }

    async function handleZipFile(file) {
        try {
            renderError('Extracting…');
            const contents = await extractZip(file);
            if (!contents['receipt.json']) {
                throw new Error('ZIP does not contain receipt.json');
            }
            const receipt = JSON.parse(contents['receipt.json']);
            current = { receipt, contents };
            clearOwnerInputs();
            await runVerify(null);
        } catch (err) {
            console.error(err);
            current = null;
            renderError(`Verification error: ${err.message}`);
        }
    }

    // ---- owner inputs ------------------------------------------------

    function clearOwnerInputs() {
        if ($('ownerPlaintext')) $('ownerPlaintext').value = '';
        if ($('ownerSalt')) $('ownerSalt').value = '';
        if ($('ownerKey')) $('ownerKey').value = '';
        if ($('ownerNote')) $('ownerNote').textContent = '';
    }

    function hexToBytesStrict(hex) {
        if (!/^(?:[0-9a-fA-F]{2})+$/.test(hex)) throw new Error('not hex');
        return core.hexToBytes(hex.toLowerCase());
    }

    // AES-256-GCM, 12-byte IV, no AAD — the inverse of the carve page's
    // encryption. Runs locally; used only to recover the owner's plaintext
    // from ciphertext.bin when the key file is supplied.
    async function decryptCiphertext(keyHex, contents) {
        const ctText = contents['ciphertext.bin'];
        const meta = contents['ciphertext-meta.json'] ? JSON.parse(contents['ciphertext-meta.json']) : null;
        if (!ctText || !meta || typeof meta.iv !== 'string') return null;
        const ct = hexToBytesStrict(new TextDecoder().decode(ctText).trim());
        const iv = hexToBytesStrict(meta.iv.trim());
        const key = await crypto.subtle.importKey('raw', hexToBytesStrict(keyHex), 'AES-GCM', false, ['decrypt']);
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
        return new TextDecoder().decode(plain);
    }

    async function readKeyFile(file) {
        if (file.size > 64 * 1024) throw new Error('that file is too large to be a key file');
        const parsed = JSON.parse(await file.text());
        if (!parsed || parsed.format !== 'tower-sealed-key-v1') throw new Error('that file is not a tower-sealed-key-v1 key file');
        return parsed;
    }

    async function handleOwnerCheck() {
        if (!current) return;
        const note = $('ownerNote');
        note.textContent = '';
        let plaintext = $('ownerPlaintext').value;
        let salt = $('ownerSalt').value.trim().toLowerCase();
        const keyInput = $('ownerKey');
        try {
            if (keyInput.files && keyInput.files[0]) {
                const kf = await readKeyFile(keyInput.files[0]);
                if (!salt && typeof kf.commit_salt === 'string') salt = kf.commit_salt.trim().toLowerCase();
                if (!plaintext && typeof kf.key_hex === 'string') {
                    const dec = await decryptCiphertext(kf.key_hex.trim(), current.contents).catch(() => {
                        throw new Error('the key file does not open the ciphertext in this ZIP');
                    });
                    if (dec === null) note.textContent = 'This ZIP carries no ciphertext; type the plaintext instead.';
                    else plaintext = dec;
                }
            }
        } catch (err) {
            note.textContent = `Key file: ${err.message}`;
            return;
        }
        await runVerify({ plaintext, salt });
    }

    // ---- wiring -------------------------------------------------------

    const drop = $('drop');
    const fileInput = $('fileInput');
    drop.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files[0]) handleZipFile(fileInput.files[0]);
    });
    drop.addEventListener('dragover', (e) => {
        e.preventDefault();
        drop.classList.add('dragover');
    });
    drop.addEventListener('dragleave', () => drop.classList.remove('dragover'));
    drop.addEventListener('drop', (e) => {
        e.preventDefault();
        drop.classList.remove('dragover');
        const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
        if (file) handleZipFile(file);
    });
    if ($('ownerCheck')) $('ownerCheck').addEventListener('click', () => {
        handleOwnerCheck().catch((err) => {
            console.error(err);
            renderError(`Verification error: ${err.message}`);
        });
    });

    // Display the verifier's own URL so users can confirm they're on
    // the right page (mitigates README-phishing per spec R13).
    const urlDisplay = $('selfUrl');
    if (urlDisplay) urlDisplay.textContent = window.location.href;
})();
