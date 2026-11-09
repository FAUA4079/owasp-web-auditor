# Phase 7.3 — Human review and evidence-bound scoring

Scope: two already-collected CHK04 observations against pinned OWASP Benchmark Java v1.2. Phase 7.3 does **not** collect new HTTP requests, change CHK04 rules, or approve reviews on behalf of a person.

## On Kali

```bash
cd ~/Downloads/owa-phase7-3
source .venv/bin/activate
ROOT=~/Downloads/owa-phase7-2/research/phase7_2/live-01
python tools/phase7_3_review.py packet --root "$ROOT" --output "$ROOT/human_review_packet.md"
python tools/phase7_3_review.py audit --root "$ROOT"
python tools/phase7_3_review.py score --root "$ROOT"
```

The commands above leave all source observations `PENDING_REVIEW`. Independently examine `human_review_packet.md`, the exact source code and source labels pinned to commit `00bcf97075c409b6762d343496e75046b6a64716`, and original evidence JSONs (may contain cookie values). The packet exposes only cookie names and Secure flags. Check whether the HTTP method and requested servlet correspond to the source label; particularly GET vs POST for BenchmarkTest00087.

For a **genuine independent reviewer only**, after checking evidence, use the evidence SHA-256 from the packet (never a made-up digest), and unique case-specific review record:

```bash
python tools/phase7_3_review.py attest \
 --root "$ROOT" --case BenchmarkTest00016 --decision APPROVED \
 --reviewer 'REPLACE_WITH_ACTUAL_REVIEWER' \
 --reference 'REVIEW-TICKET-00016' \
 --notes 'REPLACE_WITH_ACTUAL_INDEPENDENT_FINDINGS' \
 --evidence-sha256 'REPLACE_WITH_EXACT_64_HEX_FROM_PACKET' \
 --confirm-independent-review
python tools/phase7_3_review.py audit --root "$ROOT"
python tools/phase7_3_review.py score --root "$ROOT"
```

`REJECTED` is a valid review decision if mismatch or insufficient proof is found. The `attest` command refuses overwriting previously reviewed rows; use a new evidence run for a new review. Attestations are JSON, **not cryptographic signatures**. They are bound to source hashes, detector hash, manifest hash, and evidence SHA-256, and validated against the review CSV. The original Phase 7.2 scoring CLI remains available; use this Phase 7.3 **audited** score command for research claims.

## Metrics and limits

`No Issue Observed` on the independently labeled non-vulnerable 00016 could yield TN after review. `Potential` on the vulnerable 00087 remains ABSTAINED, not TP, after review. Other 13 selected cases remain UNEXECUTED. Precision and recall remain undefined with no actual TP/FP and no TP/FN, respectively. No first-party fixture test is an external benchmark execution.

Security limitations: This is a human-declared attestation, not proof of reviewer identity, cryptographic signing, or independent ground truth. Existing Phase 7.2 output can still be scored directly using its legacy CLI, which does not enforce the new attestation records; research reports must explicitly use `phase7_3_review.py score`. Do not share raw evidence or identifying reviewer details without appropriate review.
