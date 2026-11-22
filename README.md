# OWASP Web Auditor public static test range

This is a purposely synthetic public GitHub Pages frontend for the [OWASP Web Auditor](https://github.com/FAUA4079/owasp-web-auditor).

Publishing source: branch **gh-pages**, folder **/**. Site: https://faua4079.github.io/owasp-web-auditor/

No real users, credentials or private data. The fake traceback and directory listing are harmless static text that may trigger pattern-based checks; detecting them does not prove any real vulnerability.

## Scan real public URLs

```bash
python -m auditor --url https://faua4079.github.io/owasp-web-auditor/ --no-crawl --checks CHK01,CHK02,CHK03
python -m auditor --url https://faua4079.github.io/owasp-web-auditor/error.html --no-crawl --checks CHK05
python -m auditor --url https://faua4079.github.io/owasp-web-auditor/listing/ --no-crawl --checks CHK06
```

Response headers are controlled by GitHub Pages. Expect observed statuses, not hardcoded vulnerabilities.

**GitHub Pages cannot reproduce CHK04 (weak session-cookie headers), CHK07–CHK08 (server query handling), or CHK09–CHK13 (authenticated backend API tests).** To actually test all 13, deploy and assess the accompanying disposable Python backend in a restricted test environment. GitHub only hosts its code; it cannot execute it as a site.

To enable Pages: repository Settings -> Pages -> Build and deployment -> Deploy from a branch -> gh-pages -> /(root) -> Save.
