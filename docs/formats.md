# Tower receipt formats the verifier accepts

This is the contract between The Tower's server (which builds receipts) and
this verifier (which judges them). The server implements the same bytes from
this document. Every rule below is pinned by test vectors in
`test-vectors/` built by `scripts/build-test-vectors.py`, an implementation
written separately from `src/verify-core.js`; the two must agree byte for byte.

Notation: `"abc"` is the ASCII bytes of abc, `00` is one zero byte (NUL),
`||` is byte concatenation, `sha256_hex(x)` is the SHA-256 of the bytes `x`
written as 64 lowercase hex characters. All hashes in receipts are lowercase hex.

## The one rule

GREEN means every piece of content the receipt shows is tied, link by link, to
a Bitcoin block header that carries real work:

1. content -> `hash_text` (a content rule, `A-*`)
2. `hash_text` + timestamp + identity -> `hash_bound` (a binding rule, `B-*`)
3. Merkle path -> `merkle_root`
4. OpenTimestamps proof -> the header's Merkle root
5. the header is real (pinned height, work and date floors; see below)

AMBER means the anchor checks out but something shown or implied is not
proven, and the result says what. RED means a claim in the receipt is false or
malformed.

## Field formats (checked before anything is hashed)

| Field | Format |
|---|---|
| `hashes.hash_text`, `hashes.hash_bound`, `hashes.commit_salt`, a Merkle sibling, `merkle.merkle_root`, `bitcoin.block_hash` | exactly 64 characters `[0-9a-f]` |
| `entry.created_at` | exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` (millisecond ISO-8601, UTC), and a real calendar instant (it round-trips through `Date.prototype.toISOString`) |
| `identity.binding_identity` | 64 characters `[0-9a-f]` (phone hash) or a decimal user id `0` or `[1-9][0-9]*` (at most 15 digits). If `identity.binding_field` is present it must be `phone_hash` for the first form and `user_id` for the second |
| `entry.tier` | one of `open`, `sealed`, `tomb`, `treasure`. A legacy receipt (protocol 1 or 2) may omit it; the verifier then reads `[SEALED]` text as `sealed` and anything else as `open` |
| `entry.id` | a positive integer (JSON number) |
| `entry.text` | a string containing no NUL (U+0000) |
| `bitcoin.btc_block` | a positive integer, as a JSON number or a string of decimal digits |
| `bitcoin.block_header_hex` | exactly 160 characters `[0-9a-f]` (80 bytes) |

A **withheld identity** (`identity.redacted === true` and no
`binding_identity`) is allowed; it is not malformed. Since The Tower's PR 45
every PUBLIC receipt, Open included, withholds the identity, so link 2 cannot
be checked on it: the result is at best AMBER `A_IDENTITY_WITHHELD`. Link 1
(when `text` and `hash_text` are present) and links 3 to 5 are still checked,
and a failure there is red. A **withheld
`hash_text`** (absent or `null`) is allowed only when the identity is also
withheld and the tier is `sealed`, `tomb` or `treasure`.

None of these fields can contain `|` or NUL, so the three-field `|` join of
B-hash has exactly one split, and no B-hash input contains the NUL that every
B-v3 and A-salted input carries.

## Which rules a receipt is judged by

| Receipt | Must carry | Binding rule tried | Content rule by tier |
|---|---|---|---|
| Legacy | `version: "1.2"`, `protocol_version` 1, 2 or absent. May state `hashes.bound_rule: "B-hash"` and `hashes.content_rule: "A-plain"`; nothing else may be stated | B-hash only | open, sealed, tomb: A-plain. treasure: none (red) |
| v3 | `version: "1.3"`, `protocol_version: 3`, `hashes.bound_rule: "B-v3"`, `hashes.content_rule` | B-v3 only | open: A-plain. sealed, tomb: A-salted. treasure: A-envelope |

- A stated rule id the verifier does not know, a v3 receipt missing a rule
  statement, or a legacy receipt stating `B-v3`, is red (`R_UNKNOWN_RULE`).
- A content rule stated for the wrong tier is red (`R_RULE_TIER`). A
  `commit_salt` on a receipt whose content rule is not A-salted is red too.
- Not implemented, on purpose: a binding over the text itself, a leaf equal
  to `hash_text` (`hash_bound == hash_text` is always red), and a binding over
  the literal `[SEALED]`. A receipt only those could explain is red.

## B-hash (every carve before protocol 3)

```
hash_bound = sha256_hex( "<hash_text>|<created_at>|<identity>" )
```

UTF-8 (all ASCII) of the three fields joined by `|` (0x7c), where
`identity` is `identity.binding_identity` (64-hex phone hash, or the decimal
user id) and `created_at` is `entry.created_at` exactly as serialized.

## B-v3 (every carve from protocol 3 on)

```
hash_bound = sha256_hex(
    "tower" 00 "bound" 00 "v3" 00
    tier 00 content_rule 00 hash_text 00 created_at 00 identity
)
```

- `tier`: `open` | `sealed` | `tomb` | `treasure` (ASCII).
- `content_rule`: `A-plain` | `A-salted` | `A-envelope` (ASCII; must be the one
  the tier requires).
- `hash_text`: 64 lowercase hex ASCII characters.
- `created_at`: the millisecond ISO-8601 UTC string, ASCII.
- `identity`: 64 lowercase hex or decimal digits, ASCII.
- No trailing NUL. No field may contain NUL (all are validated to formats that
  cannot).

Test vector (`b-v3` in `test-vectors/formats-vectors.json`):

```
tier         = "open"
content_rule = "A-plain"
hash_text    = "2f0f68faea86dd6eaa64a9e531d310703804bdc399c14cb5009e7535be6c1a92"
created_at   = "2026-11-12T09:30:00.000Z"
identity     = "42"
hash_bound   = see formats-vectors.json (pinned; both implementations must produce it)
```

## A-plain

```
hash_text = sha256_hex( utf8(text) )
```

## A-salted (protocol 3; tiers sealed and tomb)

```
hash_text = sha256_hex( "tower" 00 "commit" 00 "v1" 00 salt 00 utf8(plaintext) )
```

- `salt`: exactly 64 lowercase hex characters, written as those 64 ASCII
  bytes (not decoded). Generated in the browser at carve time and saved in the
  owner's key file.
- `plaintext`: the entry text, UTF-8, containing no NUL.
- The salt reaches the verifier either in the receipt as
  `hashes.commit_salt` (after reveal, when the text is shown) or from the
  owner (typed, or the `commit_salt` field of the `tower-sealed-key-v1` key
  file, which c3 adds next to `key_hex`).
- A revealed salted receipt (tier sealed/tomb, ordinary text shown) with no
  salt is red (`R_SALT_MISSING`): the text shown cannot be tied to the anchor.

## A-envelope (protocol 3; tier treasure)

```
hash_text = sha256_hex( bytes of envelope.json, exactly as in the ZIP )
```

The proof ZIP carries `envelope.json`. Shown text is exactly `[TREASURE]`.

## Tier and marker consistency (red when violated, `R_TIER_MARKER`)

| Tier | Shown text |
|---|---|
| open | not `[SEALED]`, not `[TREASURE]` |
| sealed | `[SEALED]` (hidden) or ordinary text (revealed); never `[TREASURE]` |
| tomb | exactly `[SEALED]` |
| treasure | exactly `[TREASURE]` |

## Pinned exceptions

Two manual inserts whose binding was never recorded. When `hash_bound` is one
of these (legacy receipts only), link 2 is not evaluated and the result is at
best AMBER `A_BINDING_UNRECORDED`, "this leaf is anchored; how it was bound
was not recorded". Every other link is still checked.

```
50593140802f2c4d2652c0fa34220b21b167039caf6777b4096ac78a908150d5   (entry 58)
6313be4d0d3958910e557005fb4df7228c7ee0e1682523641a69b098adbf88d8   (entry 59)
```

## Link 3: Merkle (unchanged)

`node(left, right) = sha256_hex( ascii(left_hex || right_hex) )`, walking
`merkle.proof` from `hash_bound`; each step's `position` says where the
sibling sits. `merkle.proof === null && merkle.merkle_root === null` means
not yet batched (amber). An unbatched receipt that states `btc_block`,
`block_hash` or `block_header_hex`, or whose ZIP carries `merkle-root.ots` or
`btc-block-header.bin`, contradicts itself and is red.

## Links 4 and 5: OpenTimestamps and the header

- The OTS file's file hash must be `sha256(ascii(merkle_root_hex))`.
- The walk is bounded: the working message may never exceed 4096 bytes
  (OpenTimestamps' own cap), an append/prepend argument may not exceed 4096
  bytes, at most 10000 operations and 256 nested forks per file. Violations
  are red (`R_OTS`) and are detected without hashing the oversized message.
- `bitcoin.btc_block` must equal one of the Bitcoin attestation heights. A
  receipt that states `btc_block` while its OTS proof carries only pending
  attestations is red (`R_OTS`), not amber: the claim is false. The same
  holds for a stated `block_hash`. When several Bitcoin attestations sit at the
  stated height, the one ending at the header's Merkle root is used.
- The proof must end exactly where the timestamp tree ends, and each
  attestation payload must be consumed exactly; trailing bytes are red.
  Supported ops: append (0xf0), prepend (0xf1), SHA-256 (0x08). SHA-1 (0x02)
  and RIPEMD160 (0x03) are red: Tower's proofs never use them.
- `btc-block-header.bin`, when present, must be exactly 80 bytes.
- The header is real when, in this order:
  1. the claimed height (`btc_block`, else the lowest attested height) is at
     least `MIN_ANCHOR_HEIGHT = 940842` (`R_HEADER_HEIGHT`);
  2. the header's own target, decoded from its `bits`, is at most
     `MAX_TARGET` (`R_HEADER_WORK`). `MAX_TARGET` is four times the easiest
     target among the twelve real headers Tower has anchored, the same for
     every height;
  3. the header timestamp (bytes 68-71) is at least `MIN_HEADER_TIME`
     (`R_HEADER_TIME`);
  4. `sha256d(header)`, read as a little-endian number, is at most its own
     target (`R_HEADER_POW`);
  5. the 80 bytes in `btc-block-header.bin`, when present, equal
     `block_header_hex`, and the computed block hash equals `bitcoin.block_hash`
     when stated (`R_HEADER`).
  Then the OTS attestation's message must equal header bytes 36-67 byte for
  byte (`R_OTS`).
- `scripts/derive-header-constants.js` recomputes the three constants from
  `test-vectors/anchored-headers.json` and fails if they drift.

**Residual, stated plainly.** Offline, the verifier proves the header carries
real launch-era Bitcoin work. It does not prove the block is in the main
chain; the result links the block on a public explorer for that one-click
check. Forging a header that passes would need mining a block at real
Bitcoin difficulty (at today's difficulty, roughly the cost of one block).

## Owner input

The owner may supply a plaintext and a salt (typed, or from the key file).
On a hidden receipt (`[SEALED]`) they are checked by link 1. On a receipt
that shows its text they must agree with it: a different plaintext, a salt
different from `commit_salt`, or any salt on an `A-plain` entry is red
(`R_CONTENT_MISMATCH`).

## Outcome codes

Every result carries `overall` (`green` | `amber` | `red`), a stable `code`,
`link1Rule` and `link2Rule` (a rule id, or `"not evaluated"`), and `steps`.
Amber results also list every amber reason in `ambers`. Every result also
carries `label`, the traffic-light text: `VERIFIED` for the content-bearing
greens (`G_CONTENT`, `G_OWNER_CONTENT`, `G_ENVELOPE`), `COMMITMENT ANCHORED —
CONTENT HIDDEN` for `G_HIDDEN`, `NOT FULLY PROVEN` for amber, `FAILED` for red.
A green result carries `blockHeight`, `blockHashHex` and `blockTime` (the
header's own timestamp, the only proven date); `statedCreatedAt` (the receipt's
`created_at`) is present only when link 2 held. The full list is
`OUTCOME_CODES` in `src/verify-core.js`; `test/run.js` fails if any code has no
vector.
