# Mapping scaffold (venue-neutral) — tersign-evidence-bundle-v1 → a venue's contract

> This file is the neutral scaffold. A table filled in for one venue is a separate
> document, issued to that venue; it is not part of this archive.

The bundle is the envelope; a consuming venue's contract names map by field. This
scaffold is venue-neutral by design — a venue-filled variant is issued per
recipient against the exact schema versions that venue provides, and nothing
venue-specific runs on their side beyond the bundled standard-library verify
script.

| bundle field | meaning | → venue contract A | → venue contract B |
|---|---|---|---|
| `records/NNNNNN.json.artifact` | original artifact bytes + party signature | *(venue field)* | — |
| `records/*.countersignature` | ledger counter-signature over the chain link | *(venue field)* | — |
| `chain.json.links[]` + `head` + `acc` + `commitment` | per-party sequence completeness material (counter-signed links; the commitment is what the anchor stamps) | *(venue field)* | — |
| `anchors/proof.tsr` / `proof.ots` | anchor proof bytes (time bound) | *(venue field)* | — |
| `manifest.ledgerSigner` | pinned signer information (verify out-of-band: tersign.ai/v1/ledger) | *(venue field)* | — |
| `verify/` + `VERIFY.md` | offline verification steps | *(venue field)* | — |
| `manifest.json` (identity + hashes) | export identity / notification payload | — | *(venue field)* |
