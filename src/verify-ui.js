// verify-ui.js — drag-and-drop UI and result rendering. DOM-heavy.
//
// Imports verify-core via window.TowerVerifyCore. Uses vendored JSZip
// via window.JSZip. Both are loaded by index.html.

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

    function renderTrafficLight(overall) {
        const colors = { green: '#3cd982', amber: '#d4af37', red: '#ff5555' };
        const labels = { green: 'VERIFIED', amber: 'PENDING', red: 'FAILED' };
        const dot = $('lightDot');
        const label = $('lightLabel');
        dot.style.background = colors[overall] || '#888';
        dot.style.boxShadow = `0 0 16px ${colors[overall] || '#888'}`;
        label.textContent = labels[overall] || 'UNKNOWN';
        label.style.color = colors[overall] || '#888';
    }

    function renderResult(result, receipt) {
        const out = $('result');
        out.replaceChildren();
        renderTrafficLight(result.overall);
        const summary = document.createElement('p');
        summary.className = 'summary';
        summary.textContent = result.summary;
        out.appendChild(summary);

        if (result.overall === 'green') {
            const link = document.createElement('p');
            link.className = 'subtle';
            const a = document.createElement('a');
            a.href = `https://mempool.space/block/${result.blockHashHex}`;
            a.target = '_blank';
            a.rel = 'noopener';
            a.textContent = `mempool.space → block ${result.blockHeight}`;
            link.appendChild(document.createTextNode('Confirm on a block explorer: '));
            link.appendChild(a);
            out.appendChild(link);
        }

        // Steps detail.
        const stepsBox = document.createElement('div');
        stepsBox.className = 'steps';
        const stepsHeader = document.createElement('h4');
        stepsHeader.textContent = 'Verification steps';
        stepsBox.appendChild(stepsHeader);
        const stepIcons = { pass: '✓', fail: '✗', amber: '⚠', skip: '—' };
        const stepColors = { pass: '#3cd982', fail: '#ff5555', amber: '#d4af37', skip: '#888' };
        for (const step of result.steps) {
            const row = document.createElement('div');
            row.className = 'step';
            const icon = document.createElement('span');
            icon.className = 'step-icon';
            icon.textContent = stepIcons[step.status] || '?';
            icon.style.color = stepColors[step.status] || '#888';
            const name = document.createElement('span');
            name.className = 'step-name';
            name.textContent = step.name;
            const detail = document.createElement('span');
            detail.className = 'step-detail';
            detail.textContent = step.detail;
            row.appendChild(icon);
            row.appendChild(name);
            row.appendChild(detail);
            stepsBox.appendChild(row);
        }
        out.appendChild(stepsBox);

        // Entry text (read from receipt — single source of truth).
        if (receipt && receipt.entry && typeof receipt.entry.text === 'string') {
            const entryBox = document.createElement('div');
            entryBox.className = 'entry-text';
            const entryHeader = document.createElement('h4');
            entryHeader.textContent = `Entry #${receipt.entry.id} — carved ${receipt.entry.created_at}`;
            entryBox.appendChild(entryHeader);
            const pre = document.createElement('pre');
            pre.textContent = receipt.entry.text;
            entryBox.appendChild(pre);
            out.appendChild(entryBox);
        }
    }

    function renderError(message) {
        const out = $('result');
        out.replaceChildren();
        renderTrafficLight('red');
        const p = document.createElement('p');
        p.className = 'summary';
        p.textContent = message;
        out.appendChild(p);
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
        'ciphertext.bin',
        'ciphertext-meta.json',
        'README.txt',
    ]);
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

        // Pre-decompression size check via JSZip's internal entry metadata.
        // We previously checked after `async()` decompressed the entry — too
        // late to defend against a ZIP bomb (the inflated bytes already in
        // memory). Now we read the uncompressed-size field from the local
        // header before any decompression starts. (Audit R2 finding —
        // Codex P1-6 + CodeRabbit Warning-1.) JSZip 3 exposes this on
        // `_data.uncompressedSize`; we treat any absence defensively.
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
            if (name === 'receipt.json' || name === 'README.txt' || name === 'ciphertext-meta.json') {
                const text = await entry.async('string');
                if (new Blob([text]).size > MAX_FILE_BYTES) {
                    throw new Error(`${name} exceeded ${MAX_FILE_BYTES} bytes after decompression`);
                }
                result[name] = text;
            } else {
                const bytes = await entry.async('uint8array');
                if (bytes.length > MAX_FILE_BYTES) {
                    throw new Error(`${name} exceeded ${MAX_FILE_BYTES} bytes after decompression`);
                }
                result[name] = bytes;
            }
        }
        return result;
    }

    async function handleZipFile(file) {
        try {
            renderError('Extracting…');
            const contents = await extractZip(file);
            if (!contents['receipt.json']) {
                throw new Error('ZIP does not contain receipt.json');
            }
            const receipt = JSON.parse(contents['receipt.json']);
            const otsBytes = contents['merkle-root.ots'] || null;
            const blockHeaderBytes = contents['btc-block-header.bin'] || null;
            const result = await core.verifyReceiptArtifacts({ receipt, otsBytes, blockHeaderBytes });
            renderResult(result, receipt);
        } catch (err) {
            console.error(err);
            renderError(`Verification error: ${err.message}`);
        }
    }

    // Drag-and-drop wiring.
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

    // Display the verifier's own URL so users can confirm they're on
    // the right page (mitigates README-phishing per spec R13).
    const urlDisplay = $('selfUrl');
    if (urlDisplay) urlDisplay.textContent = window.location.href;
})();
