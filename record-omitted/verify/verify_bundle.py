#!/usr/bin/env python3
"""verify_bundle.py — stdlib-only offline verifier for tersign-evidence-bundle-v1 (0.2.0).

Usage:
    python3 verify_bundle.py <bundle-dir> [--signer 0x<ledger-address>] [--party 0x<address>]

Checks steps 1-7 of spec/evidence-bundle-v1.md entirely offline: closed file set +
integrity, artifact digests (JCS + keccak256), party EIP-712 recovery (receipt and
action-record formats), chain density / prevDigest continuity / head, the commitment
accumulator (acc folded over every counter-signed link) and the anchored commitment
object, ledger counter-signature recovery, anchor relation + merkle replay, anchor
signature. Step 8 (RFC-3161 / OTS time bound) is NOT checked here: this tool never opens
proof.tsr or proof.ots. On a PASS it prints the anchor's time-stamp claims as unverified and
the commands that check the RFC-3161 token against FreeTSA's own CA certificate, fetched from
FreeTSA and never taken from the archive — see VERIFY.md sections 2-3.

OUTPUT: every line goes out with its control, format and line-separator characters escaped,
so no file name or field can print a line of its own (a forged TIME or VERDICT line, a cursor
move, a cleared line); the bundle's unsigned claims on the TIME and UNAUTHENTICATED lines, and
the party labels the identity check compares, are printed JSON-quoted.

TRUST ANCHOR (read this): without --signer, identity values come from the bundle's
own manifest — PASS then proves INTEGRITY AND INTERNAL CONSISTENCY, not authorship
(a forger with their own keys can produce a self-consistent bundle). To prove
authorship, pass --signer with the ledger address obtained OUT-OF-BAND (published:
https://tersign.ai/v1/ledger); the verifier then binds
every counter-signature and the anchor signature to THAT address and fails if the
manifest disagrees. --party does the same for the party authorization key.

Exit 0 = every check PASS. Exit 1 = any FAIL. No network. No third-party imports.
"""

import hashlib
import json
import os
import shlex
import sys
import unicodedata

# The sibling imports below must not leave bytecode beside them: a verify/__pycache__/ written
# into the bundle is an unlisted file, and the closed-set check would then fail the very bundle
# it was run on (as it did, on a stock CPython, for the archive's own genuine bytes).
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from keccak import keccak256 as keccak_256  # noqa: E402
import secp256k1 as ec  # noqa: E402

GENESIS = "0x" + "00" * 32                       # link-genesis sentinel: prevDigest null hashes as 32 zero bytes
CHAIN_COMMITMENT_SCHEMA = "tersign-chain-commitment-v1"
ACC_GENESIS = "0x" + keccak_256(CHAIN_COMMITMENT_SCHEMA.encode("utf-8")).hex()  # accumulator seed (tagged digest)
FORMAT_RECEIPT = "eip712"
FORMAT_ACTION = "tersign-action-record-v1"
MAX_CANONICAL_DEPTH = 64  # parity with the ledger's canonical encoder
# The five time-stamp method statuses spec/evidence-bundle-v1.md defines ("Method status enum").
# Anything else is a FAIL (anchors.methods.status), never text to print beside a PASS.
METHOD_STATUSES = ("complete", "calendar-pending", "omitted", "unavailable-at-build",
                   "obtained-but-verify-failed")
# The RFC 3161 token is FreeTSA's. Its CA certificate is fetched from FreeTSA and compared with
# this digest before use, never taken from anchors/: the holder controls that copy, and a
# self-made authority's certificate and token verify against each other at any time it picks.
# Digest of https://freetsa.org/files/cacert.pem, fetched and byte-compared with the example
# bundle's copy on 2026-10-02.
FREETSA_CA_URL = "https://freetsa.org/files/cacert.pem"
FREETSA_CA_SHA256 = "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"
FAILS = []


class BundleShapeError(Exception):
    """A malformed bundle. Raised instead of letting a KeyError, TypeError or FileNotFoundError
    escape: this file is fetched from tersign.ai and run by strangers on evidence they did not
    produce, and a traceback at that moment spends the credibility of an evidence tool on an
    unhandled shape. Nine such inputs did exactly that, two of them printing sixty PASS lines
    and then no VERDICT at all — which reads far worse than a clean FAIL, because it leaves the
    reader unable to say what the tool concluded."""



def _escape_char(ch):
    cp = ord(ch)
    return "\\x%02x" % cp if cp < 0x100 else ("\\u%04x" % cp if cp < 0x10000 else "\\U%08x" % cp)


def say(line=""):
    """The ONE way this file prints. Control, format, surrogate and line/paragraph-separator
    characters become escapes, so a file name or a field holding a newline, an ESC sequence or a
    bidi override cannot print a line of its own or rewrite one already printed. The bundle is
    written by the party it is evidence against; only the batch root is signed, and anchor.json's
    method table, file names and the manifest's labels are printed beside a PASS."""
    print("".join(_escape_char(c) if unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") else c
                  for c in line))


def q(value):
    """A value the bundle supplies, as it may appear in output: JSON-quoted, so it reads as a
    quoted value and never as the tool's own words."""
    return json.dumps(value, ensure_ascii=False)


def check(name, ok, detail="", on_pass=None):
    """detail prints on FAIL; on_pass (when given) prints on PASS — recovered addresses and
    recomputed digests are worth showing either way, expectation prose only on failure."""
    shown = detail if not ok else (on_pass if on_pass is not None else detail)
    say("%s %s%s" % ("PASS" if ok else "FAIL", name, (" — " + shown) if shown else ""))
    if not ok:
        FAILS.append(name)


def canonical(v, depth=0):
    if depth > MAX_CANONICAL_DEPTH:
        raise ValueError("artifact exceeds MAX_CANONICAL_DEPTH")
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise ValueError("float in artifact — outside bundle digest domain")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x, depth + 1) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(val, depth + 1)
                              for k, val in items) + "}"
    raise ValueError("unsupported type %r" % type(v))


def digest_of(v) -> str:
    return "0x" + keccak_256(canonical(v).encode("utf-8")).hex()


def hx(h: str) -> bytes:
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


def chain_link(artifact_digest: str, prev_digest, seq: int) -> str:
    """link_k = keccak256(a_k || a_{k-1} || uint64be(k)); prevDigest null → 32 zero bytes."""
    return "0x" + keccak_256(hx(artifact_digest) + hx(prev_digest or GENESIS) + seq.to_bytes(8, "big")).hex()


def countersig_verdict(link: str, signature, ledger_signer: str):
    """Step 5 for one link -> (ok, recovered address). The counter-signature must be its one
    accepted encoding (ec.countersignature_error, decided on the bytes before recovery), and
    EIP-191 recovery over the raw 32-byte link must equal ledger_signer. Raises ValueError,
    text starting with the reason code, when the encoding is refused or recovery fails."""
    addr = ec.recover_countersigner(hx(link), signature)
    return addr.lower() == ledger_signer.lower(), addr


def acc_step(acc: str, link: str) -> str:
    """acc_k = keccak256(acc_{k-1} || link_k) from acc_0 = keccak256(utf8(schema))."""
    return "0x" + keccak_256(hx(acc) + hx(link)).hex()


DOMAIN_TYPEHASH = keccak_256(b"EIP712Domain(string name,string version,uint256 chainId)")
RECEIPT_TYPEHASH = keccak_256(
    b"Receipt(uint256 version,string network,string resourceUrl,string payer,"
    b"uint256 issuedAt,string transaction)")
ACTION_TYPEHASH = keccak_256(b"ActionAttestation(uint256 version,bytes32 actionDigest,uint256 occurredAt)")


def _u256(n: int) -> bytes:
    return int(n).to_bytes(32, "big")


def _s(text: str) -> bytes:
    return keccak_256(text.encode("utf-8"))


def receipt_eip712_digest(payload: dict) -> bytes:
    domain_sep = keccak_256(DOMAIN_TYPEHASH + _s("x402 receipt") + _s("1") + _u256(1))
    struct = keccak_256(
        RECEIPT_TYPEHASH + _u256(payload["version"]) + _s(payload["network"]) +
        _s(payload["resourceUrl"]) + _s(payload["payer"]) + _u256(payload["issuedAt"]) +
        _s(payload["transaction"]))
    return keccak_256(b"\x19\x01" + domain_sep + struct)


def action_eip712_digest(payload: dict) -> bytes:
    """EIP-712 hash of ActionAttestation under domain {name:"tersign action-record", version:"1",
    chainId:1} — byte-identical to the ledger and SDK action encoders."""
    domain_sep = keccak_256(DOMAIN_TYPEHASH + _s("tersign action-record") + _s("1") + _u256(1))
    struct = keccak_256(
        ACTION_TYPEHASH + _u256(payload["version"]) + hx(payload["actionDigest"]) + _u256(payload["occurredAt"]))
    return keccak_256(b"\x19\x01" + domain_sep + struct)


def _no_dupes(pairs):
    """json object_pairs_hook refusing duplicate keys.

    json.load is last-wins, while every human reader, every grep and most first-wins parsers
    take the FIRST. Two "resourceUrl" keys therefore split the exhibit from the value the
    signature covers: the reader sees the attacker's line, the verifier blesses the real one,
    and everything prints PASS. For a tool whose output is an exhibit in front of an
    adjudicator, agreement between what is read and what is checked IS the product.
    """
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError("duplicate key %r — one JSON object, two values for one name" % k)
        seen[k] = v
    return seen


def load_json(path):
    """The ONE way this file reads JSON. Every load goes through here so a new call site cannot
    quietly reintroduce last-wins parsing."""
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf8"), object_pairs_hook=_no_dupes)


def walk_files(base):
    # NO carve-outs: "closed file set" and "except one filename with arbitrary contents"
    # cannot both be true — a decoy named .DS_Store rides such an exception.
    # The BUILDER deletes Finder cruft before manifesting;
    # a bundle that arrives with one fails, as any unlisted extra must.
    # Symlinks are refused rather than followed. "Closed file set" and "one entry whose bytes
    # live somewhere else on the reader's disk" cannot both be true: a symlinked record hashes
    # to whatever it points at, passes files.closedSet and its own digest check, and the bytes
    # that were verified are not in the archive. Info-ZIP restores symlinks, so this survives
    # the round trip.
    out, links = [], []
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for d in list(dirnames):
            if os.path.islink(os.path.join(dirpath, d)):
                links.append(os.path.relpath(os.path.join(dirpath, d), base).replace(os.sep, "/"))
                dirnames.remove(d)
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, base).replace(os.sep, "/")
            (links if os.path.islink(p) else out).append(rel)
    if links:
        raise BundleShapeError("bundle contains symlink(s), which a closed file set cannot: %s"
                               % ", ".join(sorted(links)))
    return sorted(out)


def _time_lines(bundle, anc, root, ondisk):
    """The TIME lines printed under a PASS. They report what anchor.json CLAIMS for each
    time-stamp method and nothing stronger: this tool never opens proof.tsr or proof.ots, so
    it cannot say when anything existed. Every value from anchor.json is printed quoted (q):
    only the batch root is signed, and a status or a method name holding a newline once printed
    a TIME line of the holder's choosing beside a PASS.

    The RFC 3161 commands read the digest from THIS bundle's anchor.json (never a value typed in
    elsewhere), so a bundle whose batch root was swapped fails them instead of borrowing another
    bundle's token. They check the token against FreeTSA's own CA certificate, fetched from
    FreeTSA and compared with FREETSA_CA_SHA256 before use, never against the copy in anchors/:
    a holder can replace that copy and the token with a self-made authority's, and the two then
    verify against each other at any time the holder picks.

    The commands are chained with && and the certificate lives in a directory mktemp -d has just
    made, because a reader runs them from wherever they are, the holder's bundle included. Round 3
    wrote the certificate to the current directory in unchained lines: a holder's own CA planted
    there as freetsa-cacert.pem survived a failed download or a pin miss, and openssl printed
    Verification: OK on a forged token. python3 runs with -I so no module in the current
    directory (a planted hashlib.py or json.py) stands in for the standard library. The time
    prints only after a successful verify."""
    methods = anc.get("methods") or {}
    if not isinstance(methods, dict) or not methods:
        return ["TIME: none — anchor.json names no time-stamp method, so nothing here bounds "
                "WHEN these records existed. Integrity and sequence are unaffected."]
    claims, proof = [], {}
    for name in sorted(methods):
        meta = methods[name] if isinstance(methods[name], dict) else {}
        f = meta.get("file")
        rel = "anchors/" + f if isinstance(f, str) and f else None
        proof[name] = rel if rel in ondisk else None
        where = "no proof file named" if rel is None else "%s %s" % (q(rel), "present" if rel in ondisk else "ABSENT")
        claims.append("%s status=%s (%s)" % (q(name), q(meta.get("status")), where))
    out = ["TIME: NOT CHECKED BY THIS TOOL — it never opens a time-stamp proof, so nothing above "
           "bounds WHEN these records existed.",
           "TIME: anchor.json claims (unverified here): %s." % "; ".join(claims)]
    if proof.get("rfc3161"):
        tsr = shlex.quote(os.path.join(bundle, proof["rfc3161"]))
        out.append("TIME: check the RFC 3161 token with these commands (OpenSSL and the network). They "
                   "fetch FreeTSA's own CA certificate into a new temporary directory and use it only if "
                   "its sha256 equals the pin, never the copy in the archive: whoever holds the archive can "
                   "replace that copy and the token with a self-made authority's, and the two verify against "
                   "each other. Each command runs only if the one before it succeeded, so the time prints "
                   "only after Verification: OK.")
        out.append("  CA=$(mktemp -d)/freetsa-cacert.pem &&")
        out.append("  curl -fsSL %s -o \"$CA.download\" &&" % FREETSA_CA_URL)
        out.append("  python3 -I -c \"import hashlib,os,sys; d = hashlib.sha256(open(sys.argv[1] + '.download', "
                   "'rb').read()).hexdigest(); print(d); os.replace(sys.argv[1] + '.download', sys.argv[1]) "
                   "if d == '%s' else sys.exit('not the pinned FreeTSA certificate')\" \"$CA\" &&"
                   % FREETSA_CA_SHA256)
        out.append("  openssl ts -verify -digest %s -sha256 -in %s -CAfile \"$CA\" &&"
                   % (shlex.quote(root[2:] if root.startswith("0x") else root), tsr))
        out.append("  openssl ts -reply -in %s -text | grep \"Time stamp\"" % tsr)
    if "opentimestamps" in methods:
        out.append("TIME: the OpenTimestamps proof is checked with the stock `ots` client "
                   "(VERIFY.md section 3); one that is calendar-pending is not yet in a Bitcoin "
                   "block and bounds nothing until `ots upgrade` completes it.")
    return out


def main(bundle: str, expected_ledger=None, expected_party=None) -> int:
    manifest = load_json(os.path.join(bundle, "manifest.json"))
    check("manifest.schema", manifest.get("schema") == "tersign-evidence-bundle-v1",
          manifest.get("schema", "?"))
    # A container whose prevDigest chains on the previous LINK digest, or which carries no
    # accumulator, is not this format: the chain checks below reject it, and this line names
    # the class up front rather than failing deep.
    check("manifest.version", manifest.get("version") == "0.2.0", str(manifest.get("version")))

    # 1 — CLOSED file set + integrity: on-disk set must EXACTLY equal manifest.files
    # (+ manifest.json). Unlisted extras fail (decoy/side-channel files are a hole in
    # an artifact asserting "this is the complete evidence set"); listed-missing fails.
    listed = set(manifest.get("files", {}).keys())
    ondisk = set(walk_files(bundle)) - {"manifest.json"}
    check("files.closedSet", ondisk == listed,
          "extra:%s missing:%s" % (sorted(ondisk - listed)[:3], sorted(listed - ondisk)[:3])
          if ondisk != listed else "")
    for rel in sorted(listed & ondisk):
        got = "sha256:" + hashlib.sha256(open(os.path.join(bundle, rel), "rb").read()).hexdigest()
        check("file:%s" % rel, got == manifest["files"][rel],
              "" if got == manifest["files"][rel] else got)

    # trust anchor
    m_ledger = manifest["ledgerSigner"]["address"].lower()
    m_party = manifest["party"]["signer"].lower()
    if expected_ledger:
        check("trust.ledgerSigner==--signer", m_ledger == expected_ledger.lower(), m_ledger)
        ledger_signer = expected_ledger.lower()
    else:
        ledger_signer = m_ledger
    if expected_party:
        check("trust.partySigner==--party", m_party == expected_party.lower(), m_party)
        party_signer = expected_party.lower()
    else:
        party_signer = m_party
    # Action records are attested by the party's action-record key; it defaults to the receipt
    # signer and is named separately only when the party's keys differ.
    #
    # SECURITY (2026-08-30): actionSigner is BUNDLE-SUPPLIED, so it may not silently override
    # the address the operator pinned out-of-band. It did, and the consequence was full
    # impersonation: any party holding a Tersign account submits their OWN action records —
    # genuinely counter-signed and anchored by the real ledger — then writes a manifest naming
    # the victim as party.signer and themselves as party.actionSigner. trust.partySigner==--party
    # passed (both said victim), every record[k].partySig passed (against the attacker's key),
    # every counter-signature and the anchor passed against the real ledger, and the tool printed
    # PASS - integrity AND authorship for records the named party never signed.
    #
    # The rule the file already applies to `signers` runs twelve lines below is the right one and
    # is simply applied here too: exactly one key is bound out-of-band, and anything the bundle
    # says about a DIFFERENT key is the bundle's own claim. When --party is given, a divergent
    # actionSigner is a FAIL, not a redirection. Without --party nothing is bound out-of-band
    # anyway, so the bundle's own value stands and the verdict stays integrity-only.
    m_action_signer = manifest["party"].get("actionSigner")
    if expected_party and m_action_signer is not None:
        check("trust.actionSigner==--party",
              str(m_action_signer).lower() == expected_party.lower(),
              str(m_action_signer).lower())
    action_signer = str(m_action_signer or party_signer).lower()
    # Receipt keys rotate (an x402 receipt is signed by the offer's payTo key — the ledger
    # binds receipts to the chain, not to one registered key): manifest.party.signers, when
    # present, lists the party's keys as contiguous seq runs; each receipt must recover to
    # the key listed for its seq. The runs must tile 1..N exactly, and `signer` (the key
    # --party binds out-of-band) must be the CURRENT run's key. Only that one key is bound
    # out-of-band — earlier runs are the bundle's own claim of the party's key history.
    signer_runs = manifest["party"].get("signers")
    if signer_runs is not None:
        runs = sorted(signer_runs, key=lambda x: x["seqFrom"])
        tiles = all(runs[i]["seqFrom"] == (1 if i == 0 else runs[i - 1]["seqThrough"] + 1) and runs[i]["seqFrom"] <= runs[i]["seqThrough"]
                    for i in range(len(runs))) and bool(runs)
        check("manifest.party.signers.tiles", tiles, str([(r["seqFrom"], r["seqThrough"]) for r in runs]))
        check("manifest.party.signers.currentIsSigner", bool(runs) and str(runs[-1]["address"]).lower() == m_party,
              str(runs[-1]["address"]) if runs else "empty")

    def receipt_signer_for(seq):
        if signer_runs is None:
            return party_signer
        for run in signer_runs:
            if run["seqFrom"] <= seq <= run["seqThrough"]:
                return str(run["address"]).lower() if str(run["address"]).lower() != m_party else party_signer
        return "<no key listed for seq %d>" % seq

    chain = load_json(os.path.join(bundle, "chain.json"))
    links = sorted(chain["links"], key=lambda r: r["seq"])

    # 4a — density + records-file closure + manifest summary reconciliation
    seqs = [r["seq"] for r in links]
    # A zero-record bundle satisfies every relational check vacuously — no link is out of
    # order when there are no links — and reached PASS with no ledger key at all. The other
    # three implementations refuse seq < 1; this one now agrees with them.
    check("chain.nonEmpty", len(seqs) >= 1, "a bundle must contain at least one record")
    check("chain.density", seqs == list(range(1, len(seqs) + 1)), str(seqs))
    check("chain.coversSeqThrough", chain["coversSeqThrough"] == len(seqs))
    check("manifest.chain.reconciled",
          manifest["chain"].get("coversSeqThrough") == len(seqs)
          and manifest["chain"].get("records") == len(links),
          str(manifest.get("chain")))
    # 4a-bis — identity + provenance consistency. These fields are the bundle's OWN claims;
    # nothing signs manifest.json. What IS checkable is whether the claims agree with each
    # other and with the files, so a forger cannot relabel one copy and leave the rest intact.
    # Everything still unbound after this is listed in the UNAUTHENTICATED block at the end.
    check("identity.partyIdConsistent",
          str(chain.get("partyId")) == str(manifest.get("party", {}).get("id")),
          "chain=%s manifest=%s" % (q(chain.get("partyId")), q(manifest.get("party", {}).get("id"))))
    check("manifest.mode", manifest.get("mode") in ("synthetic", "production"),
          q(manifest.get("mode")))

    expected_recfiles = {"records/%06d.json" % s for s in range(1, len(seqs) + 1)}
    actual_recfiles = {f for f in ondisk if f.startswith("records/")}
    check("records.fileSetMatchesChain", expected_recfiles == actual_recfiles,
          str(sorted(actual_recfiles ^ expected_recfiles)[:3]))

    prev = None           # previous artifactDigest; null at seq 1 (one wire form with /verify)
    acc = ACC_GENESIS
    head = None
    for r in links:
        rec_path = os.path.join(bundle, "records", "%06d.json" % r["seq"])
        try:
            rec = load_json(rec_path)
        except FileNotFoundError as e:
            check("record[%d].present" % r["seq"], False, str(e))
            prev = r.get("artifactDigest", prev)
            continue
        except Exception as e:  # noqa: BLE001
            # Present but unreadable is a DIFFERENT fault from absent, and saying "present:
            # False" about a file sitting right there sends the reader looking for the wrong
            # thing. A duplicate key lands here, and naming it is the whole point: the reader
            # needs to know the document they are looking at disagrees with the one that was
            # checked.
            check("record[%d].readable" % r["seq"], False, "%s: %s" % (type(e).__name__, e))
            prev = r.get("artifactDigest", prev)
            continue
        art = rec["artifact"]
        fmt = rec.get("format")

        # 2 — artifact digest from bytes (malformed artifact = clean FAIL, run continues).
        # Receipts digest the whole signed artifact; action records digest artifact.record
        # (the ledger chains digestOf(signed.record) and stores the {record, attestation}
        # envelope at action ingest).
        try:
            if fmt == FORMAT_RECEIPT:
                check("record[%d].format" % r["seq"], art.get("format") == FORMAT_RECEIPT, str(art.get("format")), on_pass=FORMAT_RECEIPT)
                d = digest_of(art)
            elif fmt == FORMAT_ACTION:
                check("record[%d].format" % r["seq"],
                      art.get("attestation", {}).get("format") == FORMAT_RECEIPT and "record" in art,
                      "action envelope must be {record, attestation:{format:eip712,payload,signature}}", on_pass=FORMAT_ACTION)
                d = digest_of(art["record"])
            else:
                check("record[%d].format" % r["seq"], False, "unknown format %r" % fmt)
                d = digest_of(art)
            check("record[%d].artifactDigest" % r["seq"],
                  d == rec["artifactDigest"] == r["artifactDigest"],
                  d if d != rec["artifactDigest"] else "")
        except Exception as e:  # noqa: BLE001
            check("record[%d].artifactDigest" % r["seq"], False, str(e))
            d = rec.get("artifactDigest", GENESIS)

        # 3 — party recovery per format
        try:
            if fmt == FORMAT_ACTION:
                payload = art["attestation"]["payload"]
                check("record[%d].actionDigest" % r["seq"],
                      payload.get("actionDigest") == d and payload.get("occurredAt") == art["record"].get("occurredAt"),
                      "attestation payload must bind digestOf(record) and record.occurredAt", on_pass="")
                addr = ec.recover_address(action_eip712_digest(payload), art["attestation"]["signature"])
                check("record[%d].partySig" % r["seq"], addr.lower() == action_signer, addr)
            else:
                addr = ec.recover_address(receipt_eip712_digest(art["payload"]), art["signature"])
                check("record[%d].partySig" % r["seq"], addr.lower() == receipt_signer_for(r["seq"]), addr)
        except Exception as e:  # noqa: BLE001
            check("record[%d].partySig" % r["seq"], False, str(e))

        # 4b — linkage: prevDigest is the PREVIOUS ARTIFACT digest (null at 1), then the
        # counter-signed link, then the accumulator step the anchor commits to.
        check("record[%d].prevDigest" % r["seq"], rec["prevDigest"] == prev == r["prevDigest"],
              "expected %s" % (prev if prev is not None else "null"), on_pass="")
        link = chain_link(d, prev, r["seq"])
        check("record[%d].linkDigest" % r["seq"], link == rec["linkDigest"] == r["linkDigest"])
        acc = acc_step(acc, link)
        check("chain.links[%d].accDigest" % r["seq"], r.get("accDigest") == acc, str(r.get("accDigest")))

        # 5 — counter-signature over the RAW 32-byte link: one accepted encoding ("0x" + 130 hex
        # digits, v 27/28, low-s), decided on the bytes before recovery (ec.countersignature_error)
        try:
            ok, addr = countersig_verdict(link, rec["countersignature"], ledger_signer)
            check("record[%d].countersig" % r["seq"], ok, addr)
        except Exception as e:  # noqa: BLE001
            check("record[%d].countersig" % r["seq"], False, str(e))

        prev = d
        head = d

    check("chain.head", head == chain.get("head") == manifest["chain"].get("head"), str(head))
    check("chain.acc", acc == chain.get("acc") == manifest["chain"].get("acc"), str(acc))
    cm = chain.get("commitment")
    expected_cm = {"acc": acc, "head": head, "schema": CHAIN_COMMITMENT_SCHEMA, "seq": len(links)}
    check("chain.commitment", cm == expected_cm, json.dumps(cm, sort_keys=True))
    cmd = digest_of(expected_cm)
    check("chain.commitmentDigest",
          cmd == chain.get("commitmentDigest") == manifest["chain"].get("commitmentDigest"), cmd)

    # 6 — anchor relation + merkle replay: the anchored subject is the COMMITMENT digest
    anc = load_json(os.path.join(bundle, "anchors", "anchor.json"))
    root = anc["batchRoot"]
    declared = set(manifest.get("anchors", {}).get("methods", []))
    present = set(anc.get("methods", {}).keys())
    check("anchors.methodsDeclared", declared == present,
          "manifest=%s anchor.json=%s" % (sorted(declared), sorted(present)))
    # Each method's status is one of the spec's five. Nothing signs anchor.json's method table,
    # and its values are printed beside a PASS, so a status outside the enum is a FAIL here
    # rather than free text there (a status holding "\nTIME: ..." once printed a TIME line).
    off_enum = [(name, meta.get("status") if isinstance(meta, dict) else meta)
                for name, meta in sorted(anc.get("methods", {}).items())
                if not (isinstance(meta, dict) and meta.get("status") in METHOD_STATUSES)]
    check("anchors.methods.status", not off_enum,
          "not one of %s: %s" % (", ".join(METHOD_STATUSES),
                                 "; ".join("%s status=%s" % (q(n), q(st)) for n, st in off_enum)),
          on_pass="")
    check("anchors.batchRoot==manifest", root == manifest["anchors"]["batchRoot"])
    leaf = next((l for l in anc["leaves"] if l["subjectDigest"] == cmd), None)
    check("anchors.leafForCommitment", leaf is not None, "no leaf with subjectDigest == commitmentDigest", on_pass=cmd)
    if leaf:
        check("anchors.leaf.subjectSchema", leaf.get("subjectSchema") == CHAIN_COMMITMENT_SCHEMA,
              str(leaf.get("subjectSchema")))
        anchored = hashlib.sha256(hx(cmd)).hexdigest()
        check("anchors.anchoredDigest", leaf["anchoredDigest"] == "0x" + anchored,
              leaf["anchoredDigest"])
        cur = hx(leaf["anchoredDigest"])
        for step in leaf["path"]:
            sib = hx(step["hash"])
            cur = hashlib.sha256(cur + sib if step["side"] == "R" else sib + cur).digest()
        check("anchors.merklePath", "0x" + cur.hex() == root, "0x" + cur.hex())

    # 7 — anchor signature over the STRING payload (domain-separated). The ledger's own signature,
    # so the counter-signature's one accepted encoding applies ("0x" + 130 hex digits, v 27/28,
    # low-s), decided on the bytes before recovery (ec.recover_ledger_signer)
    try:
        addr = ec.recover_ledger_signer(ec.eip191_hash_text("tersign-anchor-v1:" + root),
                                        anc["ledgerSignature"])
        check("anchors.ledgerSignature", addr.lower() == ledger_signer, addr)
    except Exception as e:  # noqa: BLE001
        check("anchors.ledgerSignature", False, str(e))

    say()
    if FAILS:
        say("VERDICT: FAIL (%d): %s" % (len(FAILS), ", ".join(FAILS[:6])))
        return 1
    # A counter-signature shows that the ledger key signed the link, never WHEN it did; the
    # completeness line says only what the checks above established.
    say("SCOPE: completeness: records 1..%d each carry a counter-signature that recovers to the "
          "ledger signer, and each is folded, in order, into the anchored commitment (seq <= %d). "
          "Records after %d, if any, are outside this archive and outside this verdict."
          % (len(links), len(links), len(links)))
    # 8 — time. This tool never opens a time-stamp proof (proof.tsr, proof.ots). It used to print
    # "existence of every record is bound by that anchor's time" whenever anchor.json NAMED a
    # method and the merkle path replayed: a junk proof.tsr, or none at all once the manifest was
    # rewritten, printed the same line. So it now reports each method as anchor.json's own claim,
    # says whether the proof file is in the bundle, and prints the command that checks the token.
    # A verdict must never be stronger than its checks — including ours.
    for line in _time_lines(bundle, anc, root, ondisk):
        say(line)
    if signer_runs is not None:
        say("SCOPE: party keys: %d run(s) listed in manifest.party.signers; only the current key (manifest.party.signer) "
              "is bound out-of-band by --party — earlier runs are the bundle's own claim of the party's key history."
              % len(signer_runs))
    # The honest half of a PASS: what the bundle ASSERTS but nothing binds. A verifier that
    # prints "authorship" while these ride free is the failure this block exists to prevent.
    say("UNAUTHENTICATED (the bundle's own claims — consistent, but bound by no signature): "
          "party.id=%s · mode=%s · createdAt=%s%s"
          % (q(manifest.get("party", {}).get("id")), q(manifest.get("mode")), q(manifest.get("createdAt")),
             "" if signer_runs is None else " · party.signers[] earlier runs"))
    if expected_ledger:
        say("VERDICT: PASS — integrity AND authorship: signatures bind to the "
              "out-of-band signer %s. Time bound: VERIFY.md sections 2-3." % expected_ledger)
    else:
        say("VERDICT: PASS (integrity-only) — the bundle is internally consistent and "
              "tamper-evident, but signer identity was read from the bundle itself. "
              "For authorship, re-run with --signer <address from https://tersign.ai/v1/ledger>.")
    return 0


def _flag_value(args, flag):
    """Value after `flag`, or a usage exit if the flag is last."""
    if flag not in args:
        return None
    i = args.index(flag)
    if i + 1 >= len(args):
        print("usage: %s requires a value (e.g. %s 0x<address>)" % (flag, flag))
        sys.exit(2)
    return args[i + 1]


if __name__ == "__main__":
    args = sys.argv[1:]
    # A help flag must answer, never be treated as a bundle directory. This file is fetched from
    # tersign.ai and run by strangers on evidence they did not produce; --help is the first thing
    # any of them types, and a Python traceback at that moment is the whole credibility of an
    # evidence tool spent on an unhandled argument. The no-args and trailing-flag cases were
    # already guarded — this one was simply not thought of, so it is now checked mechanically
    # rather than remembered.
    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(0 if args else 2)
    if not os.path.isdir(args[0]):
        print("not a bundle directory: %s\n\nusage: python3 verify_bundle.py <bundle-dir> "
              "[--signer 0x<address>] [--party <id>]" % args[0], file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(main(args[0], _flag_value(args, "--signer"), _flag_value(args, "--party")))
    except SystemExit:
        raise
    except BundleShapeError as e:
        say()
        say("FAIL bundle.shape — %s" % e)
        say("VERDICT: FAIL (1): bundle.shape")
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        # Fail CLOSED and say so in the tool's own vocabulary. The reader gets a verdict, and
        # the class of the fault, instead of a stack trace they must interpret.
        say()
        say("FAIL bundle.unreadable — %s: %s" % (type(e).__name__, e))
        say("VERDICT: FAIL (1): bundle.unreadable")
        sys.exit(1)
