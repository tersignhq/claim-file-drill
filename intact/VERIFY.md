# Verify this bundle — fully offline

Everything below runs from this directory with no Tersign dependency. Section 1 needs no
network; sections 0 and 2 fetch the published verifier and FreeTSA's certificate.

## What PASS means (read first)

The python verifier proves **integrity and internal consistency**: every file hashes to
its entry in the bundle's own file list (`manifest.json`, which nothing signs), every record
hashes to the digest the chain and the anchor commit to, every signature recovers, the chain is dense
and unforked, and the anchor binds the **chain commitment** — an accumulator
folded over every counter-signed link from seq 1, so the one anchored digest
commits to the whole prefix (no-omission for every record with
seq ≤ `coversSeqThrough`), not just to the last record. **The scope of that
no-omission claim:** it is relative to the anchored commitment — tamper-evidence
against the record-holder and against any later rewrite, on the assumption that the
counter-signing ledger did not sign two divergent chains for the same party.
Nothing inside a single bundle can rule that out; that is a property of
the ledger's publication, not of this archive. **Authorship is a
separate question**: signer identity read from the bundle itself proves nothing
(a forger can ship a self-consistent bundle under their own keys). To prove
authorship, obtain the ledger signer address **out-of-band** — published at
`https://tersign.ai/v1/ledger` — and pass it explicitly. A synthetic worked example uses labeled test
keys (`manifest.mode`); a production bundle's `--signer` value is the published
production address.

PASS does **not** show:

- **that the archive is the holder's whole history.** `coversSeqThrough` is whatever
  the shipped anchor commits to, and whoever builds the bundle picks the anchor. An
  archive that stops at an earlier anchored commitment passes, and says nothing about
  later records.
- **when the records existed.** The python verifier never opens `anchors/proof.tsr` or
  `anchors/proof.ots`. On a PASS it prints the anchor's time-stamp claims, marked
  unverified, and the commands of section 2 for this bundle; the time bound holds only once
  section 2 passes against FreeTSA's own certificate (or section 3, once its proof is
  complete). A `calendar-pending` OpenTimestamps proof bounds nothing until it is upgraded.
- **when each counter-signature was made.** A counter-signature that recovers to the
  ledger key shows the key signed that link, not when.
- **that the file list is the one the bundle was built with.** Nothing signs
  `manifest.json`: `files.closedSet` compares the disk with the bundle's own list, so a
  holder can add or remove a file that is not a record (`MAPPING.md`, this file, a
  time-stamp proof) and rewrite the list.

## 0. The verifier in this archive is a convenience, not a trust root

`verify/` ships inside the bundle it checks. That is fine for a worked example, and it is
**not** the right posture for evidence handed to you by an interested party: a bundle can
ship a checker that blesses it. For adversarial input, fetch the verifier out-of-band and run
that copy against the archive:

```bash
base=https://tersign.ai/verify/v1
mkdir -p oob && curl -fsSL "$base/SHA256SUMS" -o oob/SHA256SUMS
for f in verify_bundle.py keccak.py secp256k1.py; do curl -fsSL "$base/$f" -o "oob/$f"; done
( cd oob && shasum -a 256 -c SHA256SUMS )      # published digests must match what you fetched
python3 oob/verify_bundle.py . --signer <ledger address obtained out-of-band>
```

Compare `oob/` against `verify/` (`diff -r oob verify`) — on an honest bundle they are
identical, and a difference is itself the finding. The published copy is the same source, kept
byte-identical by a build check; ordinary fixes ship in place and move the digests in
`SHA256SUMS`, so diffing that file is how you notice. The same caution is why section 2
never uses `anchors/freetsa-cacert.pem`: it fetches FreeTSA's own certificate.

## 1. Structural + cryptographic checks (python, stdlib only)

```bash
python3 verify/verify_bundle.py . --signer <ledger address obtained out-of-band>
```

Expected: every line `PASS`, a `SCOPE:` line naming the committed range, `TIME:`
lines (the anchor's time-stamp claims, unverified by this tool, and the section-2
command for this bundle), final line `VERDICT: PASS`. Omitting `--signer` still runs every check but the verdict
is explicitly downgraded to `PASS (integrity-only)`. Covered: closed file set +
per-file sha256, artifact digests (RFC 8785 + Keccak-256; receipts digest the
signed artifact, action records digest `artifact.record`), party EIP-712
recovery per format, chain density / `prevDigest == previous artifactDigest`
(`null` at seq 1) / head, the accumulator (`accDigest` per link from
`keccak256("tersign-chain-commitment-v1")`), the commitment object
`{acc, head, schema, seq}` and its digest, the counter-signature's one accepted
encoding (`0x` + 130 hex digits, v 27/28, s <= n/2, checked before recovery) and its
recovery (EIP-191 over each raw 32-byte link), `anchoredDigest = sha256(commitmentDigest)`, merkle
path replay, and the anchor signature: the same one accepted encoding, then EIP-191 over
`tersign-anchor-v1:<root>`.

## 2. Time bound — RFC-3161 (openssl)

Run only if `anchors/anchor.json` → `methods.rfc3161.status` is `complete`
(other statuses are named there honestly; a degraded build fails loudly at
build time). The token is checked against FreeTSA's own CA certificate, fetched from
FreeTSA, never against `anchors/freetsa-cacert.pem`: whoever holds the bundle controls that
copy, and can replace it and the token with a self-made authority's, which then verify
against each other at any time it picks. The certificate's SHA-256 is pinned, and each command
runs only if the one before it succeeded:

```bash
CA=$(mktemp -d)/freetsa-cacert.pem &&
curl -fsSL https://freetsa.org/files/cacert.pem -o "$CA.download" &&
python3 -I -c "import hashlib,os,sys; d = hashlib.sha256(open(sys.argv[1] + '.download', 'rb').read()).hexdigest(); print(d); os.replace(sys.argv[1] + '.download', sys.argv[1]) if d == '2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438' else sys.exit('not the pinned FreeTSA certificate')" "$CA" &&
ROOT=$(python3 -I -c "import json;print(json.load(open('anchors/anchor.json'))['batchRoot'][2:])") &&
openssl ts -verify -digest "$ROOT" -sha256 \
  -in anchors/proof.tsr -CAfile "$CA" &&
openssl ts -reply -in anchors/proof.tsr -text | grep "Time stamp"
```

Expected: the pinned digest, then `Verification: OK` (some OpenSSL builds print a
`Using configuration from …` line ahead of each `openssl` command's output), then the `Time stamp:` the token states. The pin is the
SHA-256 of `https://freetsa.org/files/cacert.pem` fetched on 2026-10-02, byte-identical to the
copy in `anchors/`. The download goes into a directory `mktemp -d` has just made, and the first
`python3` line gives it the name `openssl` reads only when it matches, so nothing in this
directory, which the holder wrote, can stand in for it; `python3 -I` ignores this directory
when it imports, so a `hashlib.py` or `json.py` placed here cannot stand in for the standard
library. A failed download or a pin miss stops the block before `openssl` runs. The digest is
read from this bundle's own `anchors/anchor.json`, never typed in, so on a bundle whose batch
root changed while its token did not, this prints `Verification: FAILED` with a `message
imprint mismatch` error; a token from any authority other than FreeTSA prints
`Verification: FAILED` too, and neither prints a time. A bundle re-anchored under a new root
with a fresh FreeTSA token over it verifies, at the later time that token states. On a PASS,
step 1 prints these commands with this bundle's paths. The `.tsr` embeds the TSA's own
certificate.

## 3. Time bound — OpenTimestamps (optional)

Run only if `methods.opentimestamps.status` is not `omitted`. Requires the stock
client (`pip install opentimestamps-client`, console script `ots` — the
`python3 -m otsclient.ots` module form is a silent no-op; never use it):

```bash
ots info anchors/proof.ots         # offline parse; a confirmed proof prints its Bitcoin block
```

**Binding check** — the `File sha256 hash` line ots prints must equal what
`methods.opentimestamps.stamped` names:

- `stamped: "batchRoot"` (synthetic worked example — the root itself was stamped):
  `python3 -I -c "import hashlib,json;print(hashlib.sha256(bytes.fromhex(json.load(open('anchors/anchor.json'))['batchRoot'][2:])).hexdigest())"`
- `stamped: "leaf"` (production — the leaf's own detached proof): the
  `anchoredDigest` of the leaf whose `subjectDigest == chain.commitmentDigest`;
  the proof's first ops are exactly that leaf's `path` up to `batchRoot`, then
  the calendar's path to the Bitcoin block header.

`ots upgrade anchors/proof.ots` (network) upgrades a `calendar-pending` proof;
`ots verify` against a local Bitcoin node is the full check.

## What a failure means

- a mutated artifact byte → `record[n].artifactDigest` FAIL
- a missing or forged counter-signature → `record[n].countersig` FAIL
- a re-encoded counter-signature (its high-s twin, recovery id 0/1, a prefix other than
  `0x`, surrounding whitespace, extra bytes) → `record[n].countersig` FAIL, although it
  recovers the ledger key
- a re-encoded anchor signature (the same forms) → `anchors.ledgerSignature` FAIL, although it
  recovers the ledger key
- an anchor proof over a different root → `anchors.merklePath` / step-2 FAIL
- a gapped or forked chain → `chain.density` / `record[n].prevDigest` FAIL
- an extra or missing file (decoys included) → `files.closedSet` FAIL
- a manifest that overstates the record count → `manifest.chain.reconciled` FAIL
- `prevDigest` chained on the previous **link** digest instead of the previous **artifact** digest → `record[2].prevDigest` FAIL
- the party named in `chain.json` relabelled away from the one in `manifest.json` → `identity.partyIdConsistent` FAIL
- the manifest advertising a timestamp method the anchor does not carry → `anchors.methodsDeclared` FAIL
- a timestamp method whose status is not one of the five the format defines (`complete`, `calendar-pending`, `omitted`, `unavailable-at-build`, `obtained-but-verify-failed`) → `anchors.methods.status` FAIL
- a wrong accumulator step → `chain.links[n].accDigest` FAIL
- a commitment object that does not match the recomputed `{acc, head, seq}` → `chain.commitment` FAIL
- a truncated prefix (the last record removed from `records/`, `chain.json` and the manifest) whose `chain.json` still claims the anchored commitment → `chain.head`, `chain.acc`, `chain.commitment`, `chain.commitmentDigest` and `anchors.leafForCommitment` FAIL, five in all
- a substituted, re-counter-signed prefix (record 1 rewritten, every link re-counter-signed under the ledger key, so the head is unchanged and every signature recovers) whose `chain.json` still claims the anchored commitment → `chain.acc`, `chain.commitment`, `chain.commitmentDigest` and `anchors.leafForCommitment` FAIL, four in all: the anchored commitment is what catches it
- a truncated prefix with `chain.json` and the manifest recomputed to match it → `anchors.leafForCommitment` FAIL, and nothing else: no leaf in the anchor carries that commitment, while every file the holder rewrote agrees with itself
- a prefix that stops at an **earlier anchored commitment**, shipped with that earlier anchor → PASS: the verdict covers records 1 to `coversSeqThrough` and says nothing about later ones

The build that produced this bundle ran `reject-tests.sh` cases 1–26 against it (24
rejecting cases and their accepting twins 15 and 23) and the substituted-prefix case. Together they cover every rejecting class above except
two added after it was built, which `reject-tests.sh` runs against this bundle: the recomputed
truncated prefix (case 27) and the status outside the five (case 28, with case 29, a status
from the five, as its accepting twin). Each case requires the named check to fail; the full
sets of five and four FAIL lines above are what the verifier printed when run on those shapes.
Each re-encoding class sits beside an accepting twin (upper-case hex digits behind `0x`) —
two-sided by policy, because an all-happy-path artifact proves nothing. Reproduce
any of them yourself: mutate the named field and re-run step 1; the verifier prints the
failing check by name.

## Every check step 1 prints

Each line of step 1 is `PASS <check>` or `FAIL <check> — <detail>`. This is every check
name the verifier can print; `n` is a record's seq. Control and format characters in any line
are printed as escapes, so no file name or field can print a line of its own, and the bundle's
unsigned claims on the `TIME:` and `UNAUTHENTICATED` lines are printed JSON-quoted.

| check | what it compares |
|---|---|
| `manifest.schema` | `manifest.json` names `tersign-evidence-bundle-v1` |
| `manifest.version` | the bundle format version is `0.2.0` |
| `files.closedSet` | the files on disk equal `manifest.files` (plus `manifest.json`), no extra and none missing |
| `file:<path>` | that file's sha256 equals its `manifest.files` entry |
| `trust.ledgerSigner==--signer` | with `--signer`: the manifest's ledger signer is the address you passed |
| `trust.partySigner==--party` | with `--party`: the manifest's party signer is the address you passed |
| `trust.actionSigner==--party` | with `--party`: a separately named action-record key is that same address |
| `manifest.party.signers.tiles` | the party's listed key runs start at seq 1 and follow on with no gap or overlap |
| `manifest.party.signers.currentIsSigner` | the last key run is `manifest.party.signer` |
| `chain.nonEmpty` | the chain holds at least one record |
| `chain.density` | the chain's seqs are exactly 1 to N |
| `chain.coversSeqThrough` | `chain.json` `coversSeqThrough` equals N |
| `manifest.chain.reconciled` | the manifest's record count and `coversSeqThrough` equal N |
| `identity.partyIdConsistent` | `chain.json` and `manifest.json` name the same party |
| `manifest.mode` | `mode` is `synthetic` or `production` |
| `records.fileSetMatchesChain` | `records/` holds exactly one file per seq 1 to N |
| `record[n].present` | the record file exists |
| `record[n].readable` | the record file parses as JSON with no duplicate key |
| `record[n].format` | the record is a receipt or an action-record envelope of the stated format |
| `record[n].artifactDigest` | the recomputed artifact digest equals the record's and the chain's |
| `record[n].actionDigest` | an action record's attestation binds that digest and its `occurredAt` |
| `record[n].partySig` | the party signature recovers to the party key for that seq |
| `record[n].prevDigest` | `prevDigest` is the previous record's artifact digest (`null` at seq 1) |
| `record[n].linkDigest` | the recomputed link digest equals the record's and the chain's |
| `chain.links[n].accDigest` | the accumulator after link n equals the chain's value |
| `record[n].countersig` | the counter-signature is in its one accepted encoding and recovers to the ledger signer |
| `chain.head` | the last artifact digest equals the head in `chain.json` and the manifest |
| `chain.acc` | the recomputed accumulator equals `chain.json` and the manifest |
| `chain.commitment` | the commitment object equals the recomputed `{acc, head, schema, seq}` |
| `chain.commitmentDigest` | its digest equals `chain.json` and the manifest |
| `anchors.methodsDeclared` | the manifest and `anchors/anchor.json` name the same time-stamp methods (names only; no proof is opened) |
| `anchors.methods.status` | each method's status in `anchors/anchor.json` is one of the five the format defines |
| `anchors.batchRoot==manifest` | the anchor's batch root equals the manifest's |
| `anchors.leafForCommitment` | some leaf in `anchors/anchor.json` carries this archive's commitment digest |
| `anchors.leaf.subjectSchema` | that leaf is a chain commitment |
| `anchors.anchoredDigest` | the leaf's anchored digest is sha256 of the commitment digest |
| `anchors.merklePath` | the leaf's path replays to the batch root |
| `anchors.ledgerSignature` | the anchor signature is in its one accepted encoding and recovers to the ledger signer |
| `bundle.shape` | the bundle has a structural defect the checks above cannot read past (a symlink, say) |
| `bundle.unreadable` | an unexpected error stopped the run; the verdict is FAIL |

No check opens `anchors/proof.tsr` or `anchors/proof.ots`; sections 2 and 3 do.
