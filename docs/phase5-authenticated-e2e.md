# Phase 5 Extension — Full Authenticated RBAC CLI E2E

## Reproduce

From repository root after `python -m pip install -e . pytest`:

```bash
python tools/phase5_rbac_e2e.py
python -m pytest -q
python -m auditor.rules --validate
cat research/phase5_e2e/rbac_e2e_report.md
```

The runner starts **127.0.0.1 only**, using a randomly allocated TCP port. It launches the original authenticated CLI subprocess with `--project`, `--assess` and `--rbac-policy`. The policy is explicitly approved **only for this synthetic local lab** and is constructed from `config/rbac.policy.example.json`. The accounts are synthetic and credentials live only in subprocess environment variables.

The lab implements `/api/csrf`, `/api/login`, `/api/me`, `/api/orders/{id}`, `/api/products`, `/api/rbac/staff-report` and `/api/logout`. CHK09–CHK12 still execute; CHK13 occurs before logout. The three CHK13 response modes are:

- **secure:** denied customer gets HTTP 403; expected `No Issue Observed`.
- **vulnerable:** denied customer receives identical private marker; expected `Confirmed`.
- **ambiguous:** denied customer gets HTTP 200 without matching private marker; expected `Inconclusive`.

For every mode, the runner checks verified identities, expected CHK13 status, existing CHK09–CHK12 coverage, validated JSON inputs, HTML report, evidence integrity and tamper detection. It then sets `authorized_for_testing: false`, invokes the CLI again, and verifies that the failure happens **without another HTTP request**.

The scanner's AI explanation layer was taught CHK13's limited scope and allowed observation fields. This resolves an `unsupported_rule` exception after confirmed CHK13 findings; it does not change check results. The provider is deliberately unreachable during E2E so no AI text contributes to labels, expectations or evidence. Human-approved policy and stable marker comparison remain authoritative.

## Scientific limitations

This is **first-party** controlled integration testing with real local HTTP/TCP, not an independently labeled third-party dataset. Roles, credentials, resources and labels are explicit lab specifications; no real-world RBAC accuracy figure can be inferred. Browser/TLS behavior, external IdP integration, concurrency and arbitrary production applications remain untested. The synthetic lab policy is not authorization to scan unrelated sites.
