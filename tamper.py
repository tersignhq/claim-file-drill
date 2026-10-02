#!/usr/bin/env python3
"""tamper.py: play the record-holder against a tersign-evidence-bundle-v1 archive.

Usage:
    python3 tamper.py omit     <archive> <new-folder>   delete the last record, rewrite the rest
    python3 tamper.py backdate <archive> <new-folder>   move the last record one hour earlier
                                                        and re-sign it with the holder's key
    python3 tamper.py rewrite  <archive> <new-folder>   rewrite every file the holder controls,
                                                        changing no record (the control case)

What the holder controls here: every file in the archive, and its own signing key.
What it does not control: the key of the separate party that counter-signed each record,
and the anchor (a batch that party signed, which an independent time-stamping authority
then stamped). Those are left exactly as they were.

The script reads the archive in <archive>, writes a changed copy to <new-folder> (which
must not exist yet), and never touches the original. It uses only Python's standard
library and the checker's own functions from verify/ beside this file, so every digest
it writes is computed exactly the way the checker recomputes it.
"""

import hashlib
import hmac
import json
import os
import shutil
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "verify"))
import verify_bundle as v  # noqa: E402
ec = v.ec

# The holder's signing key in this synthetic archive: Hardhat/Anvil default account #0, a
# publicly known TEST key. It signs nothing real anywhere; the archive's manifest names its
# address (0xf39F...2266) as the party signer. The script refuses any archive whose party
# signer is a different key.
HOLDER_TEST_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80  # gitleaks:allow
ONE_HOUR = 3600


def holder_address():
    return ec.pubkey_to_address(ec._mul(HOLDER_TEST_KEY, (ec.Gx, ec.Gy)))


def _rfc6979_nonce(key: int, msg_hash: bytes) -> int:
    """Deterministic ECDSA nonce (RFC 6979 section 3.2, HMAC-SHA256), so a re-run writes the
    same bytes."""
    x = key.to_bytes(32, "big")
    h = (int.from_bytes(msg_hash, "big") % ec.N).to_bytes(32, "big")
    k_mac, val = b"\x00" * 32, b"\x01" * 32
    k_mac = hmac.new(k_mac, val + b"\x00" + x + h, hashlib.sha256).digest()
    val = hmac.new(k_mac, val, hashlib.sha256).digest()
    k_mac = hmac.new(k_mac, val + b"\x01" + x + h, hashlib.sha256).digest()
    val = hmac.new(k_mac, val, hashlib.sha256).digest()
    while True:
        val = hmac.new(k_mac, val, hashlib.sha256).digest()
        k = int.from_bytes(val, "big")
        if 1 <= k < ec.N:
            return k
        k_mac = hmac.new(k_mac, val + b"\x00", hashlib.sha256).digest()
        val = hmac.new(k_mac, val, hashlib.sha256).digest()


def holder_sign(msg_hash: bytes) -> str:
    """Sign a 32-byte EIP-712 hash with the holder's test key: r || s || v, low s, v 27/28."""
    k = _rfc6979_nonce(HOLDER_TEST_KEY, msg_hash)
    point = ec._mul(k, (ec.Gx, ec.Gy))
    r = point[0] % ec.N
    s = pow(k, ec.N - 2, ec.N) * (int.from_bytes(msg_hash, "big") + r * HOLDER_TEST_KEY) % ec.N
    recid = point[1] & 1
    if s > ec.N // 2:
        s, recid = ec.N - s, recid ^ 1
    sig = "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recid])).hex()
    if ec.recover_address(msg_hash, sig).lower() != holder_address().lower():
        raise SystemExit("internal error: the new signature does not recover to the holder key")
    return sig


def resign_party(rec: dict) -> None:
    """Recompute the record's own digest and re-sign it with the holder's key, by format."""
    art = rec["artifact"]
    if rec["format"] == v.FORMAT_ACTION:
        payload = art["attestation"]["payload"]
        payload["actionDigest"] = v.digest_of(art["record"])
        payload["occurredAt"] = art["record"]["occurredAt"]
        art["attestation"]["signature"] = holder_sign(v.action_eip712_digest(payload))
    elif rec["format"] == v.FORMAT_RECEIPT:
        art["signature"] = holder_sign(v.receipt_eip712_digest(art["payload"]))
    else:
        raise SystemExit("unknown record format %r" % rec["format"])


def artifact_digest(rec: dict) -> str:
    art = rec["artifact"]
    return v.digest_of(art["record"] if rec["format"] == v.FORMAT_ACTION else art)


def write_json(path: str, obj) -> None:
    # newline="\n": the archive's bytes are hashed, and text mode on Windows would write CRLF.
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return "sha256:" + hashlib.sha256(fh.read()).hexdigest()


def rebuild(folder: str, records: dict) -> None:
    """Rewrite every holder-controlled file so the archive is consistent again: each record's
    digests, the chain, the commitment, and the manifest's summary and file list. The
    counter-signatures and everything under anchors/ are left as they were."""
    chain = v.load_json(os.path.join(folder, "chain.json"))
    manifest = v.load_json(os.path.join(folder, "manifest.json"))
    prev, acc, links = None, v.ACC_GENESIS, []
    for seq in sorted(records):
        rec = records[seq]
        digest = artifact_digest(rec)
        link = v.chain_link(digest, prev, seq)
        acc = v.acc_step(acc, link)
        rec["artifactDigest"], rec["prevDigest"], rec["linkDigest"] = digest, prev, link
        links.append({"seq": seq, "artifactDigest": digest, "prevDigest": prev,
                      "linkDigest": link, "accDigest": acc})
        write_json(os.path.join(folder, "records", "%06d.json" % seq), rec)
        prev = digest
    count = len(links)
    chain["head"], chain["acc"] = prev, acc
    chain["commitment"] = {"acc": acc, "head": prev, "schema": v.CHAIN_COMMITMENT_SCHEMA, "seq": count}
    chain["commitmentDigest"] = v.digest_of(chain["commitment"])
    chain["coversSeqThrough"] = count
    chain["links"] = links
    write_json(os.path.join(folder, "chain.json"), chain)
    manifest["chain"].update(head=prev, acc=acc, commitmentDigest=chain["commitmentDigest"],
                             coversSeqThrough=count, records=count)
    files = [f for f in v.walk_files(folder) if f != "manifest.json"]
    manifest["files"] = {f: sha256_file(os.path.join(folder, f)) for f in sorted(files)}
    write_json(os.path.join(folder, "manifest.json"), manifest)


def main(argv) -> int:
    if len(argv) != 3 or argv[0] not in ("omit", "backdate", "rewrite"):
        print(__doc__)
        return 2
    mode, src, dst = argv
    if not os.path.isfile(os.path.join(src, "manifest.json")):
        print("not an archive folder (no manifest.json): %s" % src, file=sys.stderr)
        return 2
    if os.path.exists(dst):
        print("refusing to overwrite %s; pick a new folder name" % dst, file=sys.stderr)
        return 2
    manifest = v.load_json(os.path.join(src, "manifest.json"))
    if str(manifest["party"]["signer"]).lower() != holder_address().lower():
        print("this archive's party signer is not the labelled test key; tamper.py only "
              "re-signs with that key", file=sys.stderr)
        return 2

    shutil.copytree(src, dst)
    chain = v.load_json(os.path.join(dst, "chain.json"))
    last = max(link["seq"] for link in chain["links"])
    records = {seq: v.load_json(os.path.join(dst, "records", "%06d.json" % seq))
               for seq in range(1, last + 1)}

    if mode == "omit":
        os.remove(os.path.join(dst, "records", "%06d.json" % last))
        del records[last]
        print("deleted record %d; rewrote the chain, the commitment and the manifest" % last)
    elif mode == "backdate":
        rec = records[last]
        if rec["format"] == v.FORMAT_ACTION:
            body = rec["artifact"]["record"]
            body["occurredAt"] -= ONE_HOUR
            if isinstance(body.get("disclosure"), dict) and "presentedAt" in body["disclosure"]:
                body["disclosure"]["presentedAt"] -= ONE_HOUR
        else:
            rec["artifact"]["payload"]["issuedAt"] -= ONE_HOUR
        resign_party(rec)
        print("moved record %d one hour earlier and re-signed it with the holder's key; "
              "rewrote the chain, the commitment and the manifest" % last)
    else:
        resign_party(records[last])
        print("re-signed record %d unchanged; rewrote the chain, the commitment and the "
              "manifest" % last)

    rebuild(dst, records)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
