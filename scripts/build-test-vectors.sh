#!/bin/bash
# build-test-vectors.sh — synthesize negative + edge-case test vectors
# from the real Open-tier receipt (real-entry-3.zip). Reproducible: anyone
# auditing the test suite can run this script and get the same bytes.
#
# Outputs:
#   test-vectors/tampered-hash.zip   — receipt.json mutated; expects RED
#   test-vectors/tampered-merkle.zip — merkle proof sibling zeroed; expects RED
#   test-vectors/pre-batch.zip       — receipt fabricated with null proof/root; expects AMBER

set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
VECTORS="$HERE/test-vectors"
REAL="$VECTORS/real-entry-3.zip"

if [ ! -f "$REAL" ]; then
    echo "FAIL: $REAL not present"
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

unzip -o -q "$REAL" -d "$WORK/src"

# Vector: tampered-hash — flip first nibble of hash_text. Verifier should
# recompute hash and surface mismatch in Step A.
mkdir -p "$WORK/tampered-hash"
cp -r "$WORK/src/." "$WORK/tampered-hash/"
python3 - "$WORK/tampered-hash/receipt.json" <<'PY'
import json, sys
p = sys.argv[1]
with open(p) as f: r = json.load(f)
orig = r['hashes']['hash_text']
first = orig[0]
swap = ('f' if first != 'f' else '0')
r['hashes']['hash_text'] = swap + orig[1:]
with open(p, 'w') as f: json.dump(r, f, separators=(',',':'))
print(f"tampered-hash: {orig[:8]}... -> {(swap+orig[1:])[:8]}...")
PY
( cd "$WORK/tampered-hash" && zip -q -r "$VECTORS/tampered-hash.zip" . )

# Vector: tampered-merkle — zero the FIRST sibling hash in merkle.proof.
# Verifier should walk to a different root and surface mismatch in Step C.
mkdir -p "$WORK/tampered-merkle"
cp -r "$WORK/src/." "$WORK/tampered-merkle/"
python3 - "$WORK/tampered-merkle/receipt.json" <<'PY'
import json, sys
p = sys.argv[1]
with open(p) as f: r = json.load(f)
if not r['merkle']['proof']:
    print("SKIP: merkle proof empty (single-leaf batch?); tampered-merkle vector requires non-empty proof")
    sys.exit(0)
orig = r['merkle']['proof'][0]['hash']
r['merkle']['proof'][0]['hash'] = '0' * 64
with open(p, 'w') as f: json.dump(r, f, separators=(',',':'))
print(f"tampered-merkle: proof[0].hash {orig[:8]}... -> 00000000...")
PY
( cd "$WORK/tampered-merkle" && zip -q -r "$VECTORS/tampered-merkle.zip" . )

# Vector: pre-batch — fabricate a receipt for an entry whose batch hasn't
# been built yet. merkle.proof=null, merkle.merkle_root=null. Verifier
# should render AMBER ("anchor pending") in Step C, never falling through
# to GREEN.
#
# We take the real receipt as a template and null out the relevant
# fields. Bitcoin block fields stay nulled too (no anchor possible without
# a batch).
mkdir -p "$WORK/pre-batch"
cp -r "$WORK/src/." "$WORK/pre-batch/"
python3 - "$WORK/pre-batch/receipt.json" <<'PY'
import json, sys
p = sys.argv[1]
with open(p) as f: r = json.load(f)
r['merkle']['batch_id'] = None
r['merkle']['merkle_root'] = None
r['merkle']['proof'] = None
r['bitcoin']['anchored'] = False
r['bitcoin']['btc_block'] = None
r['bitcoin']['block_hash'] = None
r['bitcoin']['block_header_hex'] = None
r['bitcoin']['anchored_at'] = None
r['bitcoin']['status'] = 'not_batched'
with open(p, 'w') as f: json.dump(r, f, separators=(',',':'))
print("pre-batch: merkle and bitcoin nulled")
PY
# Pre-batch ZIPs would never carry an OTS or header in practice — strip them.
rm -f "$WORK/pre-batch/merkle-root.ots" "$WORK/pre-batch/btc-block-header.bin"
( cd "$WORK/pre-batch" && zip -q -r "$VECTORS/pre-batch.zip" . )

echo "Built:"
ls -la "$VECTORS"/tampered-hash.zip "$VECTORS"/tampered-merkle.zip "$VECTORS"/pre-batch.zip
