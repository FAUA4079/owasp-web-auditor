# Phase 5 — CHK13 role-based authorization testing

CHK13 is an **opt-in**, restricted, read-only AuditShop adapter (`GET /api/rbac/<resource_id>`). It is not a general website role enumerator, and cannot infer permissions or discover roles automatically. No AI-generated security rules, roles, labels, or data are used.

**Research**: ASVS **5.0.0** requirements **V8.1.1, V8.2.1, V8.2.2** and CWE **5.0 CWE-862**. These are requirement/weakness references; they do not prove every implementation detail is fully tested. See `research/phase2_exact_mapping.csv` and the CHK13 metadata.

## Authorization and setup

1. Configure approved **customer** and **admin** test accounts (`expected_role`) under the existing `auditshop-json-v1` project, with unique identities and environment-variable credential references. Do not put credentials in JSON.
2. Configure the *application* under test to serve a **read-only** endpoint `GET /api/rbac/<slug>` returning JSON `{"resource":{"id":"<slug>","private_marker":"secret-controlled-by-lab"}}` for its allowed role, and 401/403/404 for denied roles. This endpoint is a dedicated adapter contract, not an arbitrary production-site URL.
3. Copy `config/rbac.policy.example.json` to a private policy file, set `base_url` equal to `project.base_url`, set `allow` and `deny` to verified account aliases with **different roles**, and `resource_id` to the approved slug. Reviewer must supply a meaningful approval reference and set `authorized_for_testing:true` **only after approval**. This field is an attestation, not a cryptographic authorization proof.
4. Execute `python -m auditor --project PROJECT.json --assess --rbac-policy APPROVED.json --output runs`. The normal existing CHK09–CHK12 checks run as well. CHK13 runs **before** CHK12 logout. `--rbac-policy` without `--assess` is rejected.
5. Test results are saved using the existing evidence integrity system. Private marker and credentials are never written to reports. One denial 401/403/404 produces `No Issue Observed`, identical private resource with stable allowed control produces `Confirmed`, and unmatched 200 / ambiguous output gives `Inconclusive`.

### Limitations and safeguards

- Policy is operator supplied. **Do not use this on unknown or unapproved resources.** No policy, no CHK13 requests. Auth sessions share the existing global request and deadline budget.
- Only fixed `/api/rbac/<slug>` paths with safe slugs and explicitly configured resource IDs are accepted; no redirects, HTTP writes, extra hosts, arbitrary URL templates, or unauthenticated role escalation.
- The existing authenticated assessment can log out test accounts and run CHK11 boolean SQL differential checks. Run against a dedicated testing environment and reviewed target configuration.
- Current tests use first-party controlled HTTP mocks, not an independent third-party benchmark. CHK13 does not claim complete ASVS authorization verification.
