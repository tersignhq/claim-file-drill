# claim-file-drill

If the party that keeps a log deletes an entry, or changes a date, and then rewrites every file it controls so the log still looks whole, can you tell? This repository lets you test that yourself, offline, with Python 3 and nothing else.

It holds one small evidence archive in three states, and the checker that reads them:

| folder | what the record-holder did | verdict |
|---|---|---|
| `intact/` | nothing | `VERDICT: PASS (integrity-only) — ...` |
| `record-omitted/` | deleted the last record, then rewrote every file it controls | `VERDICT: FAIL (1): anchors.leafForCommitment` |
| `back-dated/` | moved the last record one hour earlier, re-signed it with its own key, then rewrote every file it controls | `VERDICT: FAIL (2): record[4].countersig, anchors.leafForCommitment` |

The archive is synthetic: four made-up agent records (three payment receipts and one action record), signed with labelled, publicly known test keys. Nothing in it is a real transaction or a real party.

## 1. Run the checker

```bash
git clone --depth 1 https://github.com/tersignhq/claim-file-drill
cd claim-file-drill
python3 verify/verify_bundle.py intact
python3 verify/verify_bundle.py record-omitted
python3 verify/verify_bundle.py back-dated
```

Each run prints one line per check (`PASS <check>` or `FAIL <check> — <detail>`) and ends with a verdict. The exit code is 0 for PASS and 1 for FAIL. The verdict lines:

```text
intact          VERDICT: PASS (integrity-only) — the bundle is internally consistent and tamper-evident, but signer identity was read from the bundle itself. ...
record-omitted  VERDICT: FAIL (1): anchors.leafForCommitment
back-dated      VERDICT: FAIL (2): record[4].countersig, anchors.leafForCommitment
```

On a PASS the checker also prints `TIME:` lines. It never opens the time-stamp proofs, so those lines list the anchor's time-stamp methods as unverified and print the commands that check the RFC 3161 token against FreeTSA's own certificate (step 5).

## 2. Make the edits yourself

`tamper.py` plays the record-holder. It is one file of standard-library Python; read it before you run it. It holds every file in the archive and its own signing key. It does not hold the counter-signer's key, and it cannot change the anchor. It writes a changed copy to a new folder and never modifies the folder it reads.

```bash
python3 tamper.py omit intact my-omitted
python3 verify/verify_bundle.py my-omitted       # VERDICT: FAIL (1): anchors.leafForCommitment
python3 tamper.py backdate intact my-backdated
python3 verify/verify_bundle.py my-backdated     # VERDICT: FAIL (2): record[4].countersig, anchors.leafForCommitment
python3 tamper.py rewrite intact my-rewritten
python3 verify/verify_bundle.py my-rewritten     # VERDICT: PASS (integrity-only) — ...
diff -r intact my-rewritten                      # no output
diff -r record-omitted my-omitted                # no output
diff -r back-dated my-backdated                  # no output
```

`rewrite` changes no record. It re-signs only the last record with the holder's key, which gives the same bytes because the signature is deterministic (RFC 6979), and it recomputes and rewrites every record's digests, the chain, the commitment and the manifest. It reproduces the original bytes exactly. That is the control case: the failures above come from the edits, not from the rewriting. The last two `diff` lines show that the folders shipped here are exactly what the script makes.

## 3. Why the edits fail

In the system this archive models, a separate party counter-signs each record as it is written and folds it, in order, into a running digest. The digest over records 1 to 4, the *commitment*, sits in a batch that the counter-signer signed and that an independent time-stamping authority (FreeTSA, RFC 3161) then stamped. Those pieces are the `countersignature` inside each record and the files under `anchors/`. The holder can copy them, but it cannot make new ones.

- **Omitting a record.** The holder recomputes a commitment over records 1 to 3, and every file it controls agrees with that commitment. The anchor still holds the commitment over records 1 to 4, so `anchors.leafForCommitment` fails: no anchored commitment matches the archive. It is the only check that fails.
- **Back-dating a record.** The holder changes the time in record 4 and re-signs the record with its own key, so `record[4].partySig` passes. The counter-signature on record 4 covers the old content, so `record[4].countersig` fails, and the anchored commitment no longer matches either.

The `anchors/` files are byte-identical in all three folders, so the time stamp itself still verifies on each of them (step 5). What fails is the link between the records and that anchor.

## 4. What PASS proves, and what it does not

PASS on `intact/` shows that:

- every file on disk is one that the archive's own file list (`manifest.json`) names, byte for byte, and nothing the list names is missing;
- none of records 1 to 4 is missing: each carries a counter-signature that recovers to the counter-signer's key, and each is folded, in order, into the anchored commitment;
- the content of each record, including the time it states, and the order of the records are bound to that anchor, so changing any of them afterwards changes the commitment and fails the check.

PASS does not show:

- **that every event was recorded.** A record that was never sent for counter-signing leaves no gap. Selective emission is outside what counter-signing shows.
- **that the archive is the holder's whole history.** The checker covers records 1 to N, where N is set by the anchor the archive carries, and whoever assembles an archive picks that anchor. One that stops at an earlier anchored commitment passes.
- **that the file list is the one the archive was made with.** Nothing signs `manifest.json`. A holder can add or remove a file that is not a record, such as `MAPPING.md` or a time-stamp proof, rewrite the list, and the archive still passes.
- **when the records existed, from the checker alone.** The checker never opens `anchors/proof.tsr` or `anchors/proof.ots`, and its `TIME:` lines say so. The time bound holds only through step 5, run against FreeTSA's own certificate: the records then existed no later than the time the token states. The copy of that certificate in `anchors/` bounds nothing, because the holder can replace it together with the token. The OpenTimestamps proof in this archive is calendar-pending, so it bounds nothing yet.
- **that the time written inside a record was true when it was written.** The time stamp bounds when the records existed, not when the events happened.
- **when each record was counter-signed.** A counter-signature that recovers to the counter-signer's key shows that the key signed the record, not when.
- **who signed.** The keys here are labelled test keys, and without `--signer` the checker reads the signer addresses from the archive itself. That is why the verdict says integrity-only. On a production archive you pass the counter-signer's address, obtained separately from https://tersign.ai/v1/ledger, with `--signer`; every counter-signature and the anchor signature must then recover to that address.
- **that the counter-signer kept one history per holder.** The no-omission result assumes the counter-signer did not sign two different histories for the same holder. Nothing inside a single archive can rule that out.

In this synthetic archive the counter-signer's key is a public test key too, so anyone could make new counter-signatures and a new anchor with it. The drill shows what a holder without that key can and cannot do, which is the production case; there, `--signer` and the time stamp checked in step 5 against FreeTSA's own certificate are what a reader relies on.

## 5. Check the time stamp (optional, needs OpenSSL and the network)

The checker does not do this step. It checks the RFC 3161 token in `anchors/proof.tsr` against FreeTSA's own CA certificate, fetched from FreeTSA, and never against the copy in `anchors/freetsa-cacert.pem` or any other file the holder could place. The holder controls that copy: it can replace the certificate and the token with ones from a time-stamping authority it made itself, and the two then verify against each other, at any time it chooses. The certificate's SHA-256 is pinned in the block. Set `F` to the folder you checked; the digest is read from that folder's own `anchors/anchor.json`, never typed in. Each command runs only if the one before it succeeded:

```bash
F=intact
CA=$(mktemp -d)/freetsa-cacert.pem &&
curl -fsSL https://freetsa.org/files/cacert.pem -o "$CA.download" &&
python3 -I -c "import hashlib,os,sys; d = hashlib.sha256(open(sys.argv[1] + '.download', 'rb').read()).hexdigest(); print(d); os.replace(sys.argv[1] + '.download', sys.argv[1]) if d == '2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438' else sys.exit('not the pinned FreeTSA certificate')" "$CA" &&
ROOT=$(python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['batchRoot'][2:])" "$F/anchors/anchor.json") &&
openssl ts -verify -digest "$ROOT" -sha256 -in "$F/anchors/proof.tsr" -CAfile "$CA" &&
openssl ts -reply -in "$F/anchors/proof.tsr" -text | grep "Time stamp"
```

It prints:

```text
2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438
Verification: OK
Time stamp: Sep 30 08:53:58 2026 GMT
```

The pin is the SHA-256 of https://freetsa.org/files/cacert.pem as fetched on 2026-10-02, which is byte-identical to the copy in `anchors/`. The download goes into a directory that `mktemp -d` has just made, and the first `python3` line gives it the name `openssl` reads only when its digest equals the pin, so `openssl` never reads a certificate that differs from it, from whichever directory you run the block, the archive's own included. `python3 -I` ignores the current directory when it imports, so a file such as `hashlib.py` placed in an archive cannot stand in for the standard library. If the download fails, or FreeTSA replaces its certificate (the `python3` line then stops with `not the pinned FreeTSA certificate`), the block stops before `openssl` runs and prints no time.

`batchRoot` is the value the time-stamping authority stamped, and the checker's `TIME:` lines print the same commands for the folder it checked. Each outcome:

- An archive whose root changed but whose token did not prints `Verification: FAILED` with a `message imprint mismatch` error.
- A token and certificate from an authority the holder made itself print `Verification: FAILED`, because the token does not chain to FreeTSA's certificate.
- An archive re-anchored under a new root, with a fresh FreeTSA token over that root, prints `Verification: OK` and the later time that token states. Making a new anchor takes the counter-signer's key (section 4). Step 5 bounds when the root in the archive existed, not when the first root was stamped.

A `FAILED` verification prints no time, and the block exits nonzero. Some OpenSSL builds also print a `Using configuration from …` line ahead of each `openssl` command's own output, so one can appear between `Verification: OK` and `Time stamp:`.

## 6. Do not trust the checker in this repository

`verify/` holds the three files published at https://tersign.ai/verify/v1/ as of the `synced_at` date in `.sync-provenance`: this repository is synced only while the two match. The published files can change after that date, so compare them with the published digests before you rely on a verdict. Download the list, point it at `verify/`, and check it with the tool your system has:

```bash
curl -fsSL https://tersign.ai/verify/v1/SHA256SUMS -o published-SHA256SUMS
sed 's#  #  verify/#' published-SHA256SUMS > published-verify.sums
shasum -a 256 -c published-verify.sums           # macOS
sha256sum -c published-verify.sums               # Linux (GNU coreutils)
# verify/verify_bundle.py: OK
# verify/keccak.py: OK
# verify/secp256k1.py: OK
```

Those three `OK` lines hold as of the `synced_at` date. A `FAILED` line means the published checker changed after it: run the published copy instead.

`CHECKSUMS` holds the same digests for an offline comparison: `shasum -a 256 -c CHECKSUMS` on macOS, `sha256sum -c CHECKSUMS` on Linux. Each archive also carries its own copy of the checker, under `<folder>/verify/`. A holder controls that copy too, which is why you run the one you compared. Each archive's `VERIFY.md` lists every check the checker prints and what a failure of each class means.

— Tersign
