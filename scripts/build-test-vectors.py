#!/usr/bin/env python3
"""Build negative + edge-case test vectors from the real Open-tier receipt.

Reproducible: anyone auditing the test suite can run `python3
scripts/build-test-vectors.py` and get the same bytes.

Outputs:
    test-vectors/tampered-hash.zip   — hash_text mutated; expects RED in Step A
    test-vectors/tampered-merkle.zip — proof[0].hash zeroed; expects RED in Step C
    test-vectors/pre-batch.zip       — merkle nulled; expects AMBER in Step C
"""

import io
import json
import os
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
VECTORS = HERE / 'test-vectors'
REAL = VECTORS / 'real-entry-3.zip'

if not REAL.exists():
    print(f'FAIL: {REAL} not present', file=sys.stderr)
    sys.exit(1)


def load_real() -> dict[str, bytes]:
    """Read the real receipt ZIP into a name->bytes dict."""
    out: dict[str, bytes] = {}
    with zipfile.ZipFile(REAL, 'r') as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            out[info.filename] = zf.read(info.filename)
    return out


def write_zip(path: Path, files: dict[str, bytes]) -> None:
    """Write a deterministic ZIP (sorted entries, fixed timestamp)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(2026, 5, 14, 0, 0, 0))
            zf.writestr(info, files[name])
    path.write_bytes(buf.getvalue())


def patch_receipt_json(files: dict[str, bytes], fn) -> dict[str, bytes]:
    """Return a copy of files with receipt.json transformed by fn."""
    r = json.loads(files['receipt.json'])
    fn(r)
    out = dict(files)
    out['receipt.json'] = json.dumps(r, separators=(',', ':')).encode('utf-8')
    return out


def tampered_hash(r: dict) -> None:
    orig = r['hashes']['hash_text']
    swap = 'f' if orig[0] != 'f' else '0'
    r['hashes']['hash_text'] = swap + orig[1:]
    print(f'  tampered-hash: {orig[:8]}... -> {(swap + orig[1:])[:8]}...')


def tampered_merkle(r: dict) -> None:
    if not r['merkle']['proof']:
        raise SystemExit(
            'SKIP: merkle proof empty (single-leaf batch?); '
            'tampered-merkle vector requires non-empty proof'
        )
    orig = r['merkle']['proof'][0]['hash']
    r['merkle']['proof'][0]['hash'] = '0' * 64
    print(f'  tampered-merkle: proof[0].hash {orig[:8]}... -> 00000000...')


def pre_batch(r: dict) -> None:
    r['merkle']['batch_id'] = None
    r['merkle']['merkle_root'] = None
    r['merkle']['proof'] = None
    r['bitcoin']['anchored'] = False
    r['bitcoin']['btc_block'] = None
    r['bitcoin']['block_hash'] = None
    r['bitcoin']['block_header_hex'] = None
    r['bitcoin']['anchored_at'] = None
    r['bitcoin']['status'] = 'not_batched'
    print('  pre-batch: merkle and bitcoin fields nulled')


real_files = load_real()

write_zip(
    VECTORS / 'tampered-hash.zip',
    patch_receipt_json(real_files, tampered_hash),
)

write_zip(
    VECTORS / 'tampered-merkle.zip',
    patch_receipt_json(real_files, tampered_merkle),
)

# Pre-batch entries would never carry OTS or block-header artifacts —
# strip them. The verifier should detect AMBER from null merkle alone.
pre_batch_files = patch_receipt_json(real_files, pre_batch)
pre_batch_files.pop('merkle-root.ots', None)
pre_batch_files.pop('btc-block-header.bin', None)
write_zip(VECTORS / 'pre-batch.zip', pre_batch_files)

print('Built:')
for name in ('tampered-hash.zip', 'tampered-merkle.zip', 'pre-batch.zip'):
    path = VECTORS / name
    print(f'  {path}  ({path.stat().st_size} bytes)')
