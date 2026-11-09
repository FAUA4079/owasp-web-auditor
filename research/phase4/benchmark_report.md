# Phase 4 — Controlled Fixture Evaluation

**Scope:** CHK01–CHK12; two predetermined cases each.

**Important:** This is controlled fixture evaluation, not real-world scanner accuracy or confirmed exploitation.

- TP: 12; FP: 0; TN: 11; FN: 0; Abstained: 1
- Precision (scored only): 1.0
- Recall (scored only): 1.0
- False positive rate (scored only): 0.0
- Coverage of planned fixture cases: 95.8%

| Case | Expected indicator | Observed status | Outcome |
|---|---|---|---|
| CHK01-SECURE-01 | negative | No Issue Observed | negative |
| CHK01-INSECURE-01 | positive | Potential | positive |
| CHK02-SECURE-01 | negative | Inconclusive | abstained |
| CHK02-INSECURE-01 | positive | Potential | positive |
| CHK03-SECURE-01 | negative | No Issue Observed | negative |
| CHK03-INSECURE-01 | positive | Potential | positive |
| CHK04-SECURE-01 | negative | No Issue Observed | negative |
| CHK04-INSECURE-01 | positive | Potential | positive |
| CHK05-SECURE-01 | negative | No Issue Observed | negative |
| CHK05-INSECURE-01 | positive | Potential | positive |
| CHK06-SECURE-01 | negative | No Issue Observed | negative |
| CHK06-INSECURE-01 | positive | Potential | positive |
| CHK07-SECURE-01 | negative | No Issue Observed | negative |
| CHK07-INSECURE-01 | positive | Potential | positive |
| CHK08-SECURE-01 | negative | No Issue Observed | negative |
| CHK08-INSECURE-01 | positive | Potential | positive |
| CHK09-SECURE-01 | negative | No Issue Observed | negative |
| CHK09-INSECURE-01 | positive | Confirmed | positive |
| CHK10-SECURE-01 | negative | No Issue Observed | negative |
| CHK10-INSECURE-01 | positive | Confirmed | positive |
| CHK11-SECURE-01 | negative | No Issue Observed | negative |
| CHK11-INSECURE-01 | positive | Potential | positive |
| CHK12-SECURE-01 | negative | No Issue Observed | negative |
| CHK12-INSECURE-01 | positive | Confirmed | positive |

## Limitations
- MockTransport provides real executed Python decision logic but does not demonstrate network, browser or TLS behavior.
- CHK02 secure framing is Inconclusive by design: policy presence does not prove effective restrictions.
- CHK07 reflects a marker only; it does not prove XSS.
- CHK11 differential is Potential, not proof of SQL injection.
- CHK09–CHK12 depend on the AuditShop-specific adapter and supplied local policies.
- New fixtures are authored transparent lab specifications, not an externally published labeled dataset.
- Independent third-party benchmark and physical lab server validation remain pending.
