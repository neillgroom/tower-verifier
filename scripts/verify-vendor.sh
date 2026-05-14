#!/bin/bash
# verify-vendor.sh — re-fetch each vendored dependency and compare SHA-256
# against the locked value in vendor/vendor-lock.json.
#
# Usage: bash scripts/verify-vendor.sh
# Exits non-zero on any mismatch. CI runs this on every push.

set -eu

VENDOR_DIR="$(cd "$(dirname "$0")/.." && pwd)/vendor"
LOCK="$VENDOR_DIR/vendor-lock.json"

if [ ! -f "$LOCK" ]; then
    echo "FAIL: $LOCK not found"
    exit 1
fi

PYTHON=python3
command -v $PYTHON >/dev/null 2>&1 || PYTHON=python

count=$($PYTHON -c "import json,sys;print(len(json.load(open('$LOCK'))['packages']))")
echo "Checking $count vendored package(s)..."

fail=0
for i in $(seq 0 $((count-1))); do
    name=$($PYTHON -c "import json;print(json.load(open('$LOCK'))['packages'][$i]['name'])")
    url=$($PYTHON -c "import json;print(json.load(open('$LOCK'))['packages'][$i]['fetched_from'])")
    expected=$($PYTHON -c "import json;print(json.load(open('$LOCK'))['packages'][$i]['sha256'])")
    file=$($PYTHON -c "import json;print(json.load(open('$LOCK'))['packages'][$i]['file'])")
    local_path="$(cd "$(dirname "$0")/.." && pwd)/$file"

    if [ ! -f "$local_path" ]; then
        echo "FAIL: $name — local file $file missing"
        fail=1
        continue
    fi

    local_hash=$(sha256sum "$local_path" | awk '{print $1}')
    if [ "$local_hash" != "$expected" ]; then
        echo "FAIL: $name — local $file SHA-256 mismatch"
        echo "       expected: $expected"
        echo "       got:      $local_hash"
        fail=1
        continue
    fi

    # Re-fetch and compare too.
    remote_hash=$(curl -sSL "$url" | sha256sum | awk '{print $1}')
    if [ "$remote_hash" != "$expected" ]; then
        echo "FAIL: $name — upstream $url SHA-256 mismatch"
        echo "       expected: $expected"
        echo "       got:      $remote_hash"
        echo "       (upstream may have been tampered with, or vendor-lock.json is out of date — investigate before updating)"
        fail=1
        continue
    fi

    echo "OK:   $name v$($PYTHON -c "import json;print(json.load(open('$LOCK'))['packages'][$i].get('version',''))") — $local_hash"
done

if [ $fail -ne 0 ]; then
    echo
    echo "VENDOR VERIFICATION FAILED"
    exit 1
fi

echo
echo "All vendored packages verified."
