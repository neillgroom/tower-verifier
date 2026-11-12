#!/usr/bin/env python3
"""Build every test vector in test-vectors/ and the manifest test/run.js reads.

Reproducible: `python3 scripts/build-test-vectors.py` rewrites the same bytes
(ZIPs are written with sorted entries and a fixed timestamp; the only
randomness is a fixed-seed PRNG).

This is deliberately a SEPARATE implementation of the formats in
docs/formats.md (Python here, JavaScript in src/verify-core.js). The B-v3 and
A-salted byte layouts are written out again below from the document, so a
mismatch between the document and the verifier shows up as failing vectors.

Inputs (all committed):
  test-vectors/real-entry-3.zip      genuine Open receipt + batch 2 OTS + header
  test-vectors/sealed-entry-4.zip    genuine Sealed owner receipt, same batch
  test-vectors/captured/entry-*.json genuine public receipts (see README.md)
  test-vectors/anchored-headers.json real headers of every anchored block
  test-vectors/block-1-header.hex    real Bitcoin block 1 header

Outputs:
  test-vectors/*.zip                 one ZIP per vector
  test-vectors/expected.json         name -> expected overall + code (+ inputs)
  test-vectors/formats-vectors.json  pinned B-v3 / A-salted / B-hash bytes
"""

import hashlib
import io
import json
import random
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
VECTORS = HERE / 'test-vectors'
CAPTURED = VECTORS / 'captured'

rng = random.Random(20261112)


# ---------------------------------------------------------------- helpers

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def read_zip(path: Path) -> dict:
    out = {}
    with zipfile.ZipFile(path, 'r') as zf:
        for info in zf.infolist():
            if not info.is_dir():
                out[info.filename] = zf.read(info.filename)
    return out


def write_zip(name: str, files: dict) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as zf:
        for fname in sorted(files):
            info = zipfile.ZipInfo(fname, date_time=(2026, 5, 14, 0, 0, 0))
            data = files[fname]
            if isinstance(data, str):
                data = data.encode('utf-8')
            zf.writestr(info, data)
    (VECTORS / (name + '.zip')).write_bytes(buf.getvalue())


def dump(r: dict) -> bytes:
    return json.dumps(r, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def clone(o):
    return json.loads(json.dumps(o))


# ---------------------------------------------------------------- formats (docs/formats.md)

def b_hash(hash_text: str, created_at: str, identity: str) -> str:
    return sha256_hex((hash_text + '|' + created_at + '|' + identity).encode('utf-8'))


def b_v3(tier: str, content_rule: str, hash_text: str, created_at: str, identity: str) -> str:
    parts = [b'tower', b'bound', b'v3', tier.encode(), content_rule.encode(),
             hash_text.encode(), created_at.encode(), identity.encode()]
    return sha256_hex(b'\x00'.join(parts))


def a_plain(text: str) -> str:
    return sha256_hex(text.encode('utf-8'))


def a_salted(salt: str, plaintext: str) -> str:
    return sha256_hex(b'tower\x00commit\x00v1\x00' + salt.encode() + b'\x00' + plaintext.encode('utf-8'))


# ---------------------------------------------------------------- merkle (Tower convention)

def mnode(left: str, right: str) -> str:
    return sha256_hex((left + right).encode('ascii'))


def walk(leaf: str, proof: list) -> str:
    cur = leaf
    for step in proof:
        cur = mnode(cur, step['hash']) if step['position'] == 'right' else mnode(step['hash'], cur)
    return cur


# ---------------------------------------------------------------- OTS

OTS_MAGIC = bytes([
    0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
    0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf,
    0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
])
TAG_BTC = bytes.fromhex('0588960d73d71901')
TAG_PENDING = bytes.fromhex('83dfe30d2ef90c8e')


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def ots_header(merkle_root_hex: str) -> bytes:
    return OTS_MAGIC + b'\x01' + b'\x08' + hashlib.sha256(merkle_root_hex.encode('ascii')).digest()


def ots_btc_direct(merkle_root_hex: str, height: int) -> tuple:
    """OTS whose Bitcoin attestation sits directly on the file hash.
    Returns (ots_bytes, attested_message)."""
    payload = varint(height)
    body = ots_header(merkle_root_hex) + b'\x00' + TAG_BTC + varint(len(payload)) + payload
    return body, hashlib.sha256(merkle_root_hex.encode('ascii')).digest()


def ots_pending(merkle_root_hex: str) -> bytes:
    url = b'https://alice.btc.calendar.opentimestamps.org'
    payload = varint(len(url)) + url
    return ots_header(merkle_root_hex) + b'\x00' + TAG_PENDING + varint(len(payload)) + payload


# ---------------------------------------------------------------- headers

def bits_target(bits: int) -> int:
    exp = bits >> 24
    mant = bits & 0x007fffff
    return mant << (8 * (exp - 3)) if exp >= 3 else mant >> (8 * (3 - exp))


def mine(header: bytearray, max_tries: int = 1 << 22) -> bytearray:
    bits = struct.unpack_from('<I', header, 72)[0]
    target = bits_target(bits)
    for nonce in range(max_tries):
        struct.pack_into('<I', header, 76, nonce)
        if int.from_bytes(sha256d(bytes(header)), 'little') <= target:
            return header
    raise SystemExit('could not mine header')


def block_hash_display(header: bytes) -> str:
    return sha256d(header)[::-1].hex()


def make_header(merkle_root_le: bytes, time: int, bits: int) -> bytes:
    h = bytearray(80)
    struct.pack_into('<I', h, 0, 0x20000000)
    h[4:36] = bytes(rng.getrandbits(8) for _ in range(32))
    h[36:68] = merkle_root_le
    struct.pack_into('<I', h, 68, time)
    struct.pack_into('<I', h, 72, bits)
    return bytes(mine(h))


# ---------------------------------------------------------------- manifest

manifest = []


def add(name, files, overall, code, desc, owner=None, test_policy=False, genuine=False,
        ambers_include=None, link1=None, link2=None, fast=False):
    write_zip(name, files)
    row = {'name': name, 'overall': overall, 'code': code, 'desc': desc}
    if owner is not None:
        row['owner'] = owner
    if test_policy:
        row['testPolicy'] = True
    if genuine:
        row['genuine'] = True
    if ambers_include:
        row['ambersInclude'] = ambers_include
    if link1:
        row['link1'] = link1
    if link2:
        row['link2'] = link2
    if fast:
        row['maxMs'] = 2000
    manifest.append(row)


# ---------------------------------------------------------------- genuine bases

REAL3 = read_zip(VECTORS / 'real-entry-3.zip')
SEAL4 = read_zip(VECTORS / 'sealed-entry-4.zip')
R3 = json.loads(REAL3['receipt.json'])
BATCH2_OTS = REAL3['merkle-root.ots']
assert SEAL4['merkle-root.ots'] == BATCH2_OTS


def real3_with(fn, drop=()):
    r = clone(R3)
    fn(r)
    files = dict(REAL3)
    files['receipt.json'] = dump(r)
    for d in drop:
        files.pop(d, None)
    return files, r


def set_header(files, r, header: bytes):
    r['bitcoin']['block_header_hex'] = header.hex()
    r['bitcoin']['block_hash'] = block_hash_display(header)
    files['receipt.json'] = dump(r)
    files['btc-block-header.bin'] = header


# Existing genuine ZIPs (re-asserted, not rewritten).
manifest.append({'name': 'real-entry-3', 'overall': 'green', 'code': 'G_CONTENT', 'genuine': True,
                 'link1': 'A-plain', 'link2': 'B-hash',
                 'desc': 'Genuine Open owner ZIP, phone identity, batch 2 at 941015'})
manifest.append({'name': 'sealed-entry-4', 'overall': 'green', 'code': 'G_HIDDEN', 'genuine': True,
                 'link2': 'B-hash',
                 'desc': 'Genuine Sealed owner ZIP: commitment anchored, content hidden'})

# Captured public receipts (genuine bytes; see test-vectors/README.md).
for path in sorted(CAPTURED.glob('entry-*.json'), key=lambda p: int(p.stem.split('-')[1])):
    raw = path.read_bytes()
    r = json.loads(raw)
    eid = r['entry']['id']
    files = {'receipt.json': raw}
    hdr = r['bitcoin'].get('block_header_hex')
    if hdr:
        files['btc-block-header.bin'] = bytes.fromhex(hdr)
    batch2 = r['merkle']['batch_id'] == 2
    if batch2:
        files['merkle-root.ots'] = BATCH2_OTS
    redacted = (r.get('identity') or {}).get('redacted') is True
    pinned = r['hashes']['hash_bound'] in (
        '50593140802f2c4d2652c0fa34220b21b167039caf6777b4096ac78a908150d5',
        '6313be4d0d3958910e557005fb4df7228c7ee0e1682523641a69b098adbf88d8')
    if batch2 and not redacted:
        exp = ('green', 'G_CONTENT', None)
    elif batch2 and redacted:
        exp = ('amber', 'A_IDENTITY_WITHHELD', None)
    else:
        inc = ['A_NO_OTS']
        if redacted:
            inc.append('A_IDENTITY_WITHHELD')
        if pinned:
            inc.append('A_BINDING_UNRECORDED')
        exp = ('amber', 'A_NO_OTS', inc)
    add(f'captured-entry-{eid}', files, exp[0], exp[1],
        f"Genuine public receipt entry {eid} ({r['entry'].get('tier')}, "
        f"{'identity withheld' if redacted else (r['identity'].get('binding_field'))}, batch {r['merkle']['batch_id']})"
        + (' + batch 2 OTS from real-entry-3.zip' if batch2 else ' (public JSON carries no OTS)'),
        genuine=True, ambers_include=exp[2])

# ---------------------------------------------------------------- legacy vectors (production policy)

files, _ = real3_with(lambda r: r['hashes'].__setitem__('hash_text', 'f' + R3['hashes']['hash_text'][1:]))
add('tampered-hash', files, 'red', 'R_CONTENT_MISMATCH', 'hash_text mutated; link 1 fails')


def t_merkle(r):
    r['merkle']['proof'][0]['hash'] = '0' * 64


files, _ = real3_with(t_merkle)
add('tampered-merkle', files, 'red', 'R_MERKLE', 'proof[0].hash zeroed; link 3 fails')


def t_prebatch(r):
    r['merkle'].update(batch_id=None, merkle_root=None, proof=None)
    r['bitcoin'].update(anchored=False, btc_block=None, block_hash=None, block_header_hex=None,
                        anchored_at=None, status='not_batched')


files, _ = real3_with(t_prebatch, drop=('merkle-root.ots', 'btc-block-header.bin'))
add('pre-batch', files, 'amber', 'A_NOT_BATCHED', 'not yet batched: amber, never green')

# F1 swapped text over a real anchor (hash_text recomputed so link 1 holds).
SWAP = 'I, Mallory, conceived Synthetic Dialectic first.'
files, _ = real3_with(lambda r: (r['entry'].__setitem__('text', SWAP),
                                 r['hashes'].__setitem__('hash_text', a_plain(SWAP))))
add('forged-text-swap', files, 'red', 'R_BINDING_MISMATCH',
    'Swapped text + its own hash_text over a real anchored hash_bound')

# F5 tier claim that used to skip the text check.
files, _ = real3_with(lambda r: (r['entry'].__setitem__('tier', 'sealed'),
                                 r['entry'].__setitem__('text', SWAP)))
add('forged-sealed-visible-text', files, 'red', 'R_CONTENT_MISMATCH',
    'Claims tier sealed while showing other text (hash_text kept): old code skipped link 1')
files, _ = real3_with(lambda r: (r['entry'].__setitem__('tier', 'sealed'),
                                 r['entry'].__setitem__('text', SWAP),
                                 r['hashes'].__setitem__('hash_text', a_plain(SWAP))))
add('forged-sealed-visible-text-rehashed', files, 'red', 'R_BINDING_MISMATCH',
    'Claims tier sealed, shows other text with recomputed hash_text')

# Tier / marker violations.
for nm, tier, text in [('tomb-plain-text', 'tomb', 'hello'), ('treasure-plain-text', 'treasure', 'hello'),
                       ('open-shows-sealed', 'open', '[SEALED]'), ('open-shows-treasure', 'open', '[TREASURE]'),
                       ('sealed-shows-treasure', 'sealed', '[TREASURE]'), ('tomb-shows-treasure', 'tomb', '[TREASURE]')]:
    files, _ = real3_with(lambda r, tier=tier, text=text: (r['entry'].__setitem__('tier', tier),
                                                            r['entry'].__setitem__('text', text)))
    add('forged-marker-' + nm, files, 'red', 'R_TIER_MARKER', f'tier {tier} with text {text!r}')

# F4 pipe-boundary shift: fake earlier date into created_at, the real
# remainder pushed into identity.
REAL_TS = R3['entry']['created_at']
PHONE = R3['identity']['binding_identity']
files, _ = real3_with(lambda r: (r['entry'].__setitem__('created_at', '2025-01-01T00:00:00.000Z'),
                                 r['identity'].__setitem__('binding_identity', REAL_TS + '|' + PHONE)))
add('forged-pipe-shift-identity', files, 'red', 'R_FIELD_FORMAT',
    'Earlier date in created_at, real timestamp|phone pushed into identity')
files, _ = real3_with(lambda r: r['entry'].__setitem__('created_at', '2025-01-01T00:00:00.000Z|' + REAL_TS))
add('forged-pipe-shift-timestamp', files, 'red', 'R_FIELD_FORMAT',
    'Earlier date with the real one appended after a pipe in created_at')

# Malformed fields.
malformed = [
    ('ts-no-millis', lambda r: r['entry'].__setitem__('created_at', REAL_TS[:19] + 'Z')),
    ('ts-offset', lambda r: r['entry'].__setitem__('created_at', REAL_TS[:-1] + '+00:00')),
    ('ts-impossible-date', lambda r: r['entry'].__setitem__('created_at', '2026-02-30T11:37:02.653Z')),
    ('identity-upper', lambda r: r['identity'].__setitem__('binding_identity', PHONE.upper())),
    ('identity-short', lambda r: r['identity'].__setitem__('binding_identity', PHONE[:63])),
    ('identity-leading-zero', lambda r: r['identity'].__setitem__('binding_identity', '0042')),
    ('identity-field-mismatch', lambda r: r['identity'].__setitem__('binding_field', 'user_id')),
    ('hash-text-upper', lambda r: r['hashes'].__setitem__('hash_text', R3['hashes']['hash_text'].upper())),
    ('hash-bound-short', lambda r: r['hashes'].__setitem__('hash_bound', R3['hashes']['hash_bound'][:63])),
    ('hash-text-missing-open', lambda r: r['hashes'].pop('hash_text')),
    ('text-nul', lambda r: r['entry'].__setitem__('text', R3['entry']['text'] + '\u0000')),
    ('tier-unknown', lambda r: r['entry'].__setitem__('tier', 'gold')),
    ('btc-block-not-int', lambda r: r['bitcoin'].__setitem__('btc_block', '941015.0')),
]
for nm, fn in malformed:
    files, _ = real3_with(fn)
    add('forged-malformed-' + nm, files, 'red', 'R_FIELD_FORMAT', 'malformed field: ' + nm)

files, _ = real3_with(lambda r: r.__setitem__('version', '1.1'))
add('forged-version', files, 'red', 'R_VERSION', 'unknown receipt version')

# Hash posing as text, both forms.
H = R3['hashes']['hash_text']
files, _ = real3_with(lambda r: (r['entry'].__setitem__('text', H),
                                 r['hashes'].__setitem__('hash_text', a_plain(H))))
add('forged-hash-as-text-rehashed', files, 'red', 'R_BINDING_MISMATCH',
    'text := original hash_text, hash_text recomputed')
files, _ = real3_with(lambda r: r['entry'].__setitem__('text', H))
add('forged-hash-as-text-unchanged', files, 'red', 'R_CONTENT_MISMATCH',
    'text := original hash_text, hash_text left unchanged')

# Leaf equals hash_text without being v3 treasure.
files, _ = real3_with(lambda r: r['hashes'].__setitem__('hash_bound', r['hashes']['hash_text']))
add('forged-leaf-equals-hash-text', files, 'red', 'R_BINDING_MISMATCH',
    'hash_bound := hash_text on a legacy Open receipt')

# Unknown / misplaced rule statements.
files, _ = real3_with(lambda r: r['hashes'].__setitem__('bound_rule', 'B-text'))
add('forged-rule-b-text', files, 'red', 'R_UNKNOWN_RULE', 'legacy receipt states B-text')
files, _ = real3_with(lambda r: r['hashes'].__setitem__('bound_rule', 'B-v3'))
add('forged-legacy-states-b-v3', files, 'red', 'R_UNKNOWN_RULE', 'protocol 1 receipt states B-v3')
files, _ = real3_with(lambda r: (r['hashes'].__setitem__('bound_rule', 'B-hash'),
                                 r['hashes'].__setitem__('content_rule', 'A-plain')))
add('legacy-states-b-hash', files, 'green', 'G_CONTENT',
    'legacy receipt stating its rules explicitly (what c3 buildReceipt will emit)',
    link1='A-plain', link2='B-hash')
files, _ = real3_with(lambda r: r['hashes'].__setitem__('commit_salt', 'ab' * 32))
add('forged-legacy-salt', files, 'red', 'R_RULE_TIER', 'commit_salt on a legacy A-plain receipt')

# v3 relabel of a genuine B-hash receipt (B-hash input judged as B-v3).
def relabel_v3(r):
    r['version'] = '1.3'
    r['protocol_version'] = 3
    r['entry']['tier'] = 'open'
    r['hashes']['bound_rule'] = 'B-v3'
    r['hashes']['content_rule'] = 'A-plain'


files, _ = real3_with(relabel_v3)
add('forged-b-hash-relabelled-v3', files, 'red', 'R_BINDING_MISMATCH',
    'genuine B-hash leaf presented as a v3 receipt')

# Anchor-state ambers on the genuine receipt.
files, _ = real3_with(lambda r: None, drop=('merkle-root.ots',))
add('real3-no-ots', files, 'amber', 'A_NO_OTS', 'genuine receipt without its OTS file')
files, _ = real3_with(lambda r: r['bitcoin'].__setitem__('block_header_hex', None), drop=('btc-block-header.bin',))
add('real3-no-header', files, 'amber', 'A_NO_HEADER', 'genuine receipt without a bundled header')
files, _ = real3_with(lambda r: None)
files['merkle-root.ots'] = ots_pending(R3['merkle']['merkle_root'])
add('real3-ots-pending', files, 'amber', 'A_OTS_PENDING', 'OTS with only a pending calendar attestation')
files, _ = real3_with(lambda r: r['bitcoin'].__setitem__('btc_block', '941022'))
add('forged-btc-block-not-attested', files, 'red', 'R_OTS', 'btc_block names a height the OTS does not attest')

# Crafted OTS: long run of 1-byte appends (message would grow past 4096).
big = bytearray(ots_header(R3['merkle']['merkle_root']))
for _ in range(200000):
    big += b'\xf0\x01\x41'
files, _ = real3_with(lambda r: None)
files['merkle-root.ots'] = bytes(big)
add('forged-ots-long-appends', files, 'red', 'R_OTS', '200k one-byte appends; rejected without quadratic copying', fast=True)
big = bytearray(ots_header(R3['merkle']['merkle_root']))
big += b'\x08' * 200000
files, _ = real3_with(lambda r: None)
files['merkle-root.ots'] = bytes(big)
add('forged-ots-op-flood', files, 'red', 'R_OTS', '200k sha256 ops; op cap rejects quickly', fast=True)

# Headers (production policy).
REAL_HDR = bytes.fromhex(R3['bitcoin']['block_header_hex'])

h = bytearray(REAL_HDR)
struct.pack_into('<I', h, 72, 0x207fffff)
h = bytes(mine(h))
files, r = real3_with(lambda r: None)
set_header(files, r, h)
add('forged-header-easy-bits', files, 'red', 'R_HEADER_WORK',
    'real header with self-declared bits 0x207fffff, nonce mined in milliseconds')

BLOCK1 = bytes.fromhex((VECTORS / 'block-1-header.hex').read_text().strip())
files, r = real3_with(lambda r: r['bitcoin'].__setitem__('btc_block', '1'))
set_header(files, r, BLOCK1)
add('forged-header-block-1', files, 'red', 'R_HEADER_HEIGHT',
    'real early-chain header (block 1, bits 0x1d00ffff) claimed at height 1')

h = bytearray(REAL_HDR)
struct.pack_into('<I', h, 72, 0x1d00ffff)
files, r = real3_with(lambda r: r['bitcoin'].__setitem__('btc_block', '940842'))
set_header(files, r, bytes(h))
add('forged-header-genesis-work-at-min-height', files, 'red', 'R_HEADER_WORK',
    'claims the pinned minimum height and a post-launch timestamp, carries bits 0x1d00ffff')

h = bytearray(REAL_HDR)
struct.pack_into('<I', h, 68, 1700000000)
files, r = real3_with(lambda r: None)
set_header(files, r, bytes(h))
add('forged-header-before-launch', files, 'red', 'R_HEADER_TIME', 'header dated 2023, before the pinned minimum')

files, _ = real3_with(lambda r: r['bitcoin'].__setitem__('btc_block', '940000'))
add('forged-claimed-height-below-min', files, 'red', 'R_HEADER_HEIGHT', 'btc_block below the pinned minimum height')

h = bytearray(REAL_HDR)
struct.pack_into('<I', h, 76, (struct.unpack_from('<I', h, 76)[0] + 1) & 0xffffffff)
files, r = real3_with(lambda r: None)
set_header(files, r, bytes(h))
add('forged-header-bad-nonce', files, 'red', 'R_HEADER_POW', 'real header with nonce+1: hash above its own target')

files, _ = real3_with(lambda r: r['bitcoin'].__setitem__('block_hash', '00' * 32))
add('forged-block-hash-claim', files, 'red', 'R_HEADER', 'block_hash claim disagrees with the header')

# ---------------------------------------------------------------- synthetic chains (test header policy)
#
# A synthetic leaf cannot be anchored in a real Bitcoin block, so these
# vectors are judged under the test-only header policy (minimum height 1, any
# target, any time) with a header mined at easy difficulty. Every other link
# is real. test/run.js passes the policy only for rows marked testPolicy.

SYN_HEIGHT = 990000
SYN_TIME = 1800000000


def anchored(r: dict, extra=None, with_header=True):
    leaf = r['hashes']['hash_bound']
    sib = sha256_hex(b'synthetic sibling ' + leaf.encode())
    proof = [{'hash': sib, 'position': 'right'}]
    root = walk(leaf, proof)
    ots, msg = ots_btc_direct(root, SYN_HEIGHT)
    header = make_header(msg, SYN_TIME, 0x207fffff)
    r['merkle'] = {'batch_id': 99, 'merkle_root': root, 'proof': proof}
    r['bitcoin'] = {'anchored': True, 'btc_block': str(SYN_HEIGHT), 'block_hash': block_hash_display(header),
                    'block_header_hex': header.hex(), 'anchored_at': '2027-01-15T08:00:00.000Z',
                    'status': 'confirmed'}
    files = {'receipt.json': dump(r), 'merkle-root.ots': ots, 'btc-block-header.bin': header}
    if extra:
        files.update(extra)
    return files


USER_ID = '4242'
TS = '2026-11-12T09:30:00.000Z'


def v3_receipt(tier, text, content_rule, hash_text, identity=USER_ID, salt_in_receipt=None):
    r = {
        'tower': 'THE TOWER — Proof Receipt',
        'version': '1.3',
        'protocol_version': 3,
        'entry': {'id': 1000, 'text': text, 'tier': tier, 'category': 'test', 'tags': None,
                  'created_at': TS, 'source': 'web'},
        'identity': {'alias': None, 'binding_identity': identity, 'binding_field': 'user_id'},
        'hashes': {'hash_text': hash_text,
                   'hash_bound': b_v3(tier, content_rule, hash_text, TS, identity),
                   'bound_rule': 'B-v3', 'content_rule': content_rule},
    }
    if salt_in_receipt:
        r['hashes']['commit_salt'] = salt_in_receipt
    return r


PLAIN = 'Synthetic v3 entry: the verifier must tie this text to the anchor.'
SECRET = 'A sealed thought nobody else may read until reveal.'
SALT = ''.join(rng.choice('0123456789abcdef') for _ in range(64))
ENVELOPE = json.dumps({'format': 'tower-treasure-envelope-test', 'ciphertext': 'deadbeef'}, indent=2).encode()

# v3 positives.
add('v3-open', anchored(v3_receipt('open', PLAIN, 'A-plain', a_plain(PLAIN))),
    'green', 'G_CONTENT', 'v3 Open, A-plain + B-v3', test_policy=True, link1='A-plain', link2='B-v3')
SEALED_HT = a_salted(SALT, SECRET)
add('v3-sealed-hidden', anchored(v3_receipt('sealed', '[SEALED]', 'A-salted', SEALED_HT)),
    'green', 'G_HIDDEN', 'v3 Sealed unrevealed, owner receipt: commitment anchored, content hidden',
    test_policy=True, link2='B-v3')
add('v3-sealed-owner', anchored(v3_receipt('sealed', '[SEALED]', 'A-salted', SEALED_HT)),
    'green', 'G_OWNER_CONTENT', 'v3 Sealed unrevealed + owner-supplied plaintext and salt',
    owner={'plaintext': SECRET, 'salt': SALT}, test_policy=True, link1='A-salted', link2='B-v3')
add('v3-sealed-owner-wrong-salt', anchored(v3_receipt('sealed', '[SEALED]', 'A-salted', SEALED_HT)),
    'red', 'R_CONTENT_MISMATCH', 'owner-supplied salt is wrong',
    owner={'plaintext': SECRET, 'salt': SALT[::-1]}, test_policy=True)
add('v3-sealed-owner-no-salt', anchored(v3_receipt('sealed', '[SEALED]', 'A-salted', SEALED_HT)),
    'red', 'R_SALT_MISSING', 'owner supplies plaintext but no salt for an A-salted entry',
    owner={'plaintext': SECRET}, test_policy=True)
add('v3-sealed-owner-short-salt', anchored(v3_receipt('sealed', '[SEALED]', 'A-salted', SEALED_HT)),
    'red', 'R_FIELD_FORMAT', 'owner-supplied salt is 63 hex characters',
    owner={'plaintext': SECRET, 'salt': SALT[:63]}, test_policy=True)
add('v3-sealed-revealed', anchored(v3_receipt('sealed', SECRET, 'A-salted', SEALED_HT, salt_in_receipt=SALT)),
    'green', 'G_CONTENT', 'v3 Sealed revealed, salt carried in the receipt',
    test_policy=True, link1='A-salted', link2='B-v3')
add('v3-sealed-revealed-no-salt', anchored(v3_receipt('sealed', SECRET, 'A-salted', SEALED_HT)),
    'red', 'R_SALT_MISSING', 'revealed salted receipt carries no salt', test_policy=True)
add('v3-sealed-revealed-salt-short', anchored(v3_receipt('sealed', SECRET, 'A-salted', SEALED_HT,
                                                          salt_in_receipt=SALT[:63])),
    'red', 'R_FIELD_FORMAT', 'commit_salt of the wrong width', test_policy=True)
# Salt-boundary shift: last salt char moved to the front of the text, a
# zero padded onto the salt so it stays 64 hex.
add('v3-sealed-revealed-salt-shift',
    anchored(v3_receipt('sealed', SALT[63] + SECRET, 'A-salted', SEALED_HT, salt_in_receipt='0' + SALT[:63])),
    'red', 'R_CONTENT_MISMATCH', 'salt-boundary shift between salt and text', test_policy=True)
TOMB_HT = a_salted(SALT, SECRET + ' (tomb)')
add('v3-tomb-hidden', anchored(v3_receipt('tomb', '[SEALED]', 'A-salted', TOMB_HT)),
    'green', 'G_HIDDEN', 'v3 Time Capsule, owner receipt', test_policy=True, link2='B-v3')
TREAS_HT = sha256_hex(ENVELOPE)
add('v3-treasure-envelope', anchored(v3_receipt('treasure', '[TREASURE]', 'A-envelope', TREAS_HT),
                                     extra={'envelope.json': ENVELOPE}),
    'green', 'G_ENVELOPE', 'v3 Treasure with envelope.json', test_policy=True, link1='A-envelope', link2='B-v3')
add('v3-treasure-wrong-envelope', anchored(v3_receipt('treasure', '[TREASURE]', 'A-envelope', TREAS_HT),
                                           extra={'envelope.json': ENVELOPE + b' '}),
    'red', 'R_CONTENT_MISMATCH', 'envelope.json is not the anchored envelope', test_policy=True)
add('v3-treasure-no-envelope', anchored(v3_receipt('treasure', '[TREASURE]', 'A-envelope', TREAS_HT)),
    'amber', 'A_TREASURE_NO_ENVELOPE', 'Treasure ZIP without envelope.json', test_policy=True)

# v3 public hidden receipt: identity and hash_text withheld.
pub = v3_receipt('sealed', '[SEALED]', 'A-salted', SEALED_HT)
pub['identity'] = {'redacted': True, 'note': 'withheld'}
pub_files = anchored(pub)
pub = json.loads(pub_files['receipt.json'])
pub['hashes'].pop('hash_text')
pub_files['receipt.json'] = dump(pub)
add('v3-sealed-public', pub_files, 'amber', 'A_IDENTITY_WITHHELD',
    'public v3 Sealed receipt: identity and hash_text withheld', test_policy=True)

# v3 negatives.
add('v3-open-states-salted', anchored(v3_receipt('open', PLAIN, 'A-salted', a_salted(SALT, PLAIN))),
    'red', 'R_RULE_TIER', 'v3 Open stating A-salted', test_policy=True)
add('v3-sealed-states-plain', anchored(v3_receipt('sealed', '[SEALED]', 'A-plain', a_plain(SECRET))),
    'red', 'R_RULE_TIER', 'v3 Sealed stating A-plain', test_policy=True)
add('v3-treasure-states-plain', anchored(v3_receipt('treasure', '[TREASURE]', 'A-plain', TREAS_HT)),
    'red', 'R_RULE_TIER', 'v3 Treasure stating A-plain', test_policy=True)
r = v3_receipt('open', PLAIN, 'A-plain', a_plain(PLAIN))
r['hashes'].pop('content_rule')
add('v3-missing-content-rule', anchored(r), 'red', 'R_UNKNOWN_RULE', 'v3 receipt without content_rule', test_policy=True)
r = v3_receipt('open', PLAIN, 'A-plain', a_plain(PLAIN))
r['hashes']['bound_rule'] = 'B-hash'
add('v3-states-b-hash', anchored(r), 'red', 'R_UNKNOWN_RULE', 'protocol 3 receipt stating B-hash', test_policy=True)
# A v3 leaf presented as legacy (rule statements stripped): B-hash recompute fails.
r = v3_receipt('open', PLAIN, 'A-plain', a_plain(PLAIN))
f = anchored(r)
r = json.loads(f['receipt.json'])
r['version'] = '1.2'
r['protocol_version'] = 2
del r['hashes']['bound_rule']
del r['hashes']['content_rule']
f['receipt.json'] = dump(r)
add('forged-v3-presented-as-legacy', f, 'red', 'R_BINDING_MISMATCH',
    'B-v3 leaf with its rule statements stripped is judged by B-hash and fails', test_policy=True)
# A tier swap on a v3 leaf (tier is bound in B-v3).
r = v3_receipt('open', PLAIN, 'A-plain', a_plain(PLAIN))
f = anchored(r)
r = json.loads(f['receipt.json'])
r['entry']['tier'] = 'sealed'
r['hashes']['content_rule'] = 'A-salted'
r['hashes']['commit_salt'] = SALT
f['receipt.json'] = dump(r)
add('forged-v3-tier-swap', f, 'red', 'R_CONTENT_MISMATCH',
    'v3 Open leaf relabelled sealed with a salt: link 1 fails before link 2', test_policy=True)
# v3 text-bound leaf (anchored, but only a text-bound formula explains it).
r = v3_receipt('open', PLAIN, 'A-plain', a_plain(PLAIN))
r['hashes']['hash_bound'] = sha256_hex((PLAIN + '|' + TS + '|' + USER_ID).encode())
add('forged-text-bound-leaf', anchored(r), 'red', 'R_BINDING_MISMATCH',
    'anchored leaf = sha256(text|ts|id); no accepted rule explains it', test_policy=True)
r = json.loads(json.dumps(R3))
r['hashes']['hash_bound'] = sha256_hex((R3['entry']['text'] + '|' + REAL_TS + '|' + PHONE).encode())
f = anchored(r)
r = json.loads(f['receipt.json'])
r['bitcoin']['block_header_hex'] = None
f2 = {'receipt.json': dump(r)}  # drop OTS and header: amber must not mask red
add('forged-text-bound-leaf-unanchored', f2, 'red', 'R_BINDING_MISMATCH',
    'legacy text-bound leaf with no OTS: link 2 red is not masked by the missing-OTS amber')

# Legacy synthetic: legacy treasure (as the pre-c3 server builds it) and the
# pinned exception under a synthetic anchor.
LEG_TS = '2026-06-01T12:00:00.000Z'
leg = {'tower': 'THE TOWER — Proof Receipt', 'version': '1.2', 'protocol_version': 2,
       'entry': {'id': 2000, 'text': '[TREASURE]', 'tier': 'treasure', 'created_at': LEG_TS, 'source': 'web'},
       'identity': {'binding_identity': USER_ID, 'binding_field': 'user_id'},
       'hashes': {'hash_text': TREAS_HT, 'hash_bound': TREAS_HT}}
add('legacy-treasure', anchored(leg, extra={'envelope.json': ENVELOPE}), 'red', 'R_RULE_TIER',
    'pre-c3 Treasure (leaf == hash_text): Treasure exists only under protocol 3', test_policy=True)

leg = {'tower': 'THE TOWER — Proof Receipt', 'version': '1.2', 'protocol_version': 2,
       'entry': {'id': 2001, 'text': '[SEALED]', 'tier': 'sealed', 'created_at': LEG_TS, 'source': 'web'},
       'identity': {'binding_identity': USER_ID, 'binding_field': 'user_id'},
       'hashes': {'hash_text': a_plain(SECRET), 'hash_bound': b_hash(a_plain(SECRET), LEG_TS, USER_ID)}}
add('legacy-sealed-owner', anchored(clone(leg)), 'green', 'G_OWNER_CONTENT',
    'legacy Sealed + owner plaintext (A-plain)', owner={'plaintext': SECRET}, test_policy=True,
    link1='A-plain', link2='B-hash')
add('legacy-sealed-owner-wrong', anchored(clone(leg)), 'red', 'R_CONTENT_MISMATCH',
    'legacy Sealed + wrong owner plaintext', owner={'plaintext': SECRET + '!'}, test_policy=True)
legt = clone(leg)
legt['entry']['tier'] = 'tomb'
legt['hashes']['hash_bound'] = b_hash(legt['hashes']['hash_text'], LEG_TS, USER_ID)
add('legacy-tomb-hidden', anchored(legt), 'green', 'G_HIDDEN',
    'legacy Time Capsule shape (user id, [SEALED]); stands in for the uncaptured production capsule',
    test_policy=True)

c58 = json.loads((CAPTURED / 'entry-58.json').read_bytes())
add('pinned-58-anchored', anchored(c58), 'amber', 'A_BINDING_UNRECORDED',
    'entry 58 (pinned exception) under a synthetic anchor: amber, never green', test_policy=True)
c58b = json.loads((CAPTURED / 'entry-58.json').read_bytes())
c58b['entry']['text'] = SWAP
add('pinned-58-text-swap', anchored(c58b), 'red', 'R_CONTENT_MISMATCH',
    'pinned exception still checks link 1', test_policy=True)

# ---------------------------------------------------------------- pinned format vectors

fv = {
    'b-hash': {'hash_text': H, 'created_at': REAL_TS, 'identity': PHONE,
               'hash_bound': b_hash(H, REAL_TS, PHONE)},
    'b-v3': {'tier': 'open', 'content_rule': 'A-plain', 'hash_text': H, 'created_at': TS, 'identity': '42',
             'input_hex': b'\x00'.join([b'tower', b'bound', b'v3', b'open', b'A-plain', H.encode(),
                                        TS.encode(), b'42']).hex(),
             'hash_bound': b_v3('open', 'A-plain', H, TS, '42')},
    'a-salted': {'salt': 'ab' * 32, 'plaintext': 'hello, tower',
                 'input_hex': (b'tower\x00commit\x00v1\x00' + ('ab' * 32).encode() + b'\x00hello, tower').hex(),
                 'hash_text': a_salted('ab' * 32, 'hello, tower')},
}
(VECTORS / 'formats-vectors.json').write_text(json.dumps(fv, indent=1) + '\n')
(VECTORS / 'expected.json').write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + '\n', encoding='utf-8')
print(f'built {len(manifest)} vectors')
