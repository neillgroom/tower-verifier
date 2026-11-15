// verify-ui.js — drag-and-drop UI and result rendering. DOM-heavy.
//
// Imports verify-core via window.TowerVerifyCore. Uses vendored JSZip
// via window.JSZip. Both are loaded by index.html.
//
// Nothing loaded here leaves the page: the CSP sets connect-src 'none', and
// this file makes no network call. The page takes no owner input (plaintext,
// salt or key file); hidden content is checked on The Tower's decrypt page.
// The only link to it is an ordinary <a href>; nothing is fetched.

(function () {
    const core = window.TowerVerifyCore;
    const JSZip = window.JSZip;
    const zipReader = window.TowerVerifyZip;
    if (!core || !JSZip || !zipReader) {
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

    const DECRYPT_PAGE = 'https://thetower.one/decrypt.html';
    // Every ZIP selection takes a new generation; a run that finishes after
    // a newer one started is discarded, success or error alike.
    let generation = 0;
    const isStale = (gen) => gen !== generation;

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
            addRow(facts, 'Carve time stated by the receipt', result.blockTime
                ? `${result.statedCreatedAt} (bound into the leaf; the block date above is the proof)`
                : `${result.statedCreatedAt} (bound into the leaf; the anchor date is not yet proven)`);
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
        // The entry id is shown only when the core validated it as a
        // positive integer.
        const entryLabel = Number.isSafeInteger(result.entryId) && result.entryId > 0 ? `Entry #${result.entryId}` : 'Entry';
        if (result.code === 'G_ENVELOPE') {
            const box = el('div', 'entry-text');
            box.appendChild(el('h4', null, `${entryLabel} — Treasure envelope proven`));
            box.appendChild(el('p', 'subtle', 'The envelope.json in this ZIP is the envelope anchored. Its contents stay sealed; nothing beyond the envelope bytes is claimed.'));
            out.appendChild(box);
        } else if (result.overall === 'green' && typeof result.provenContent === 'string') {
            const box = el('div', 'entry-text');
            box.appendChild(el('h4', null, `${entryLabel} — proven content`));
            box.appendChild(el('pre', null, result.provenContent));
            out.appendChild(box);
        } else if (result.code === 'G_HIDDEN') {
            const box = el('div', 'entry-text');
            box.appendChild(el('h4', null, `${entryLabel} — content hidden`));
            box.appendChild(el('p', 'subtle', 'No content is shown, so none is claimed.'));
            const p = el('p', 'subtle', 'The owner can decrypt and check the content with The Tower\'s decrypt page: ');
            const a = document.createElement('a');
            a.href = DECRYPT_PAGE;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.textContent = DECRYPT_PAGE;
            p.appendChild(a);
            box.appendChild(p);
            out.appendChild(box);
        } else if (receipt && receipt.entry && typeof receipt.entry.text === 'string'
            && receipt.entry.text !== core.SEALED_MARKER && receipt.entry.text !== core.TREASURE_MARKER) {
            const box = el('div', 'entry-text unproven');
            box.appendChild(el('h4', null, `${entryLabel} — text in the receipt (NOT proven)`));
            box.appendChild(el('pre', null, receipt.entry.text));
            out.appendChild(box);
        }
    }

    function renderMessage(overall, label, message) {
        const out = $('result');
        out.replaceChildren();
        const light = el('div', 'traffic-light');
        light.appendChild(Object.assign(el('span', 'dot'), { id: 'lightDot' }));
        light.appendChild(Object.assign(el('span', 'label'), { id: 'lightLabel' }));
        out.appendChild(light);
        renderTrafficLight(overall, label);
        out.appendChild(el('p', 'summary', message));
    }
    const renderError = (message) => renderMessage('red', undefined, message);
    // Neutral grey while working: a red light is kept for a real refusal.
    const renderWorking = (message) => renderMessage('working', 'CHECKING', message);

    // ZIP reading lives in verify-zip.js, shared with the tests, so the
    // tests exercise the same layout checks and caps the page runs.
    async function extractZip(file) {
        if (file.size > zipReader.MAX_ZIP_BYTES) {
            throw new Error(`ZIP too large (${file.size} bytes; max ${zipReader.MAX_ZIP_BYTES})`);
        }
        const files = await zipReader.extractReceiptZip(await file.arrayBuffer(), JSZip);
        if (files['receipt.json']) files['receipt.json'] = new TextDecoder().decode(files['receipt.json']);
        return files;
    }

    // The page never passes owner input to the core: hidden content is
    // checked on The Tower's decrypt page, not here.
    async function runVerify(receipt, contents, gen) {
        const result = await core.verifyReceiptArtifacts({
            receipt,
            otsBytes: contents['merkle-root.ots'] || null,
            blockHeaderBytes: contents['btc-block-header.bin'] || null,
            envelopeBytes: contents['envelope.json'] || null,
        });
        if (isStale(gen)) return;
        renderResult(result, receipt);
    }

    async function handleZipFile(file) {
        const gen = ++generation;
        try {
            renderWorking('Reading the ZIP and checking the receipt…');
            const contents = await extractZip(file);
            if (isStale(gen)) return;
            if (!contents['receipt.json']) {
                throw new Error('ZIP does not contain receipt.json');
            }
            const receipt = JSON.parse(contents['receipt.json']);
            await runVerify(receipt, contents, gen);
        } catch (err) {
            if (isStale(gen)) return;
            console.error(err);
            renderError(`Verification error: ${err.message}`);
        }
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

    // Display the verifier's own URL so users can confirm they're on
    // the right page (mitigates README-phishing per spec R13).
    const urlDisplay = $('selfUrl');
    if (urlDisplay) urlDisplay.textContent = window.location.href;
})();
