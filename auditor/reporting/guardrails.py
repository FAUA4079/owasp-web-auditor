"""Conservative model-output admission controls; never infer security truth.

This rejects obvious unsupported assertions and sensitive-looking data. Passing
is NOT a factual verification of free-form AI prose.
"""
import re

_SECRET = [
    re.compile(r'(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/-]{12,}={0,2}\b'),
    re.compile(r'(?i)\b(?:api[_ -]?key|password|passwd|client[_ -]?secret|access[_ -]?token)\s*[:=]\s*["\']?[^\s"\']{6,}'),
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
    re.compile(r'(?i)https?://[^\s<>{}]+[?&](?:token|key|password|secret|auth|session)='),
]
_INJECTION = re.compile(r'(?i)\b(ignore (?:all )?(?:previous|prior) instructions|system prompt|developer instructions|you are now|disregard the instructions)\b')
_OVERCLAIM = re.compile(r'(?i)\b(?:100% secure|completely secure|guaranteed safe|proven (?:exploitable|vulnerable)|confirmed (?:xss|sql injection|rce)|exploited successfully)\b')


def acceptable_prose(value):
    """Bounded screening of AI prose only; false positives are acceptable abstentions."""
    if not isinstance(value, dict):
        return False
    for item in value.values():
        if isinstance(item, str):
            if _INJECTION.search(item) or _OVERCLAIM.search(item):
                return False
            if any(pattern.search(item) for pattern in _SECRET):
                return False
    return True
