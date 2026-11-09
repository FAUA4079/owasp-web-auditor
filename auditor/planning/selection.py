"""Operator-selected rule policy; independent of AI reporting settings."""
from uuid import uuid4
from auditor.planning.coverage import RULES
from auditor.rules import public_rule_ids

TITLES = {
    'CHK01': 'HTTP root HTTPS redirect handling',
    'CHK02': 'Framing policy indicators',
    'CHK03': 'Content type protection configuration',
    'CHK04': 'Cookie attribute observations',
    'CHK05': 'Error disclosure indicators',
    'CHK06': 'Directory listing indicators',
    'CHK07': 'Harmless query marker reflection',
    'CHK08': 'Exceptional numeric input handling',
}
PAGE_RULES = frozenset(('CHK02', 'CHK03', 'CHK04', 'CHK05', 'CHK06'))


def select_checks(value=None, reflection=None, exceptional=None):
    explicit = value is not None
    public_ids = public_rule_ids()
    if tuple(RULES) != public_ids:
        raise ValueError('Rule registry and executable public checks disagree.')
    if value is None or value == 'all':
        selected = list(public_ids)
    else:
        values = value.split(',') if isinstance(value, str) else list(value)
        if not values or any(not isinstance(v, str) or v.strip().upper() not in public_ids for v in values):
            raise ValueError('Checks must be all or a comma-separated list of CHK01 through CHK08.')
        wanted = {v.strip().upper() for v in values}
        selected = [r for r in public_ids if r in wanted]
    for rule, parameter, flag in (('CHK07', reflection, '--reflection-param'),
                                  ('CHK08', exceptional, '--exception-param')):
        if parameter is not None and rule not in selected:
            raise ValueError(flag + ' conflicts with the selected checks.')
        # "all" preserves prerequisite-based skipping, just like the default.
        if explicit and value != 'all' and rule in selected and not parameter:
            raise ValueError(rule + ' requires ' + flag + ' for an explicit selection.')
    return selected


def skipped_by_selection(rule, target):
    return {'id': 'test-' + uuid4().hex[:12], 'rule_id': rule,
            'rule_version': '0.1.0', 'category': RULES[rule]['category'],
            'title': TITLES[rule], 'endpoint': target, 'status': 'Not Tested',
            'reason': 'Disabled by operator check selection.', 'steps': [],
            'expected': RULES[rule]['prerequisites'], 'observed': None,
            'request_count': 0, 'evidence_refs': [],
            'limitations': ['This check was not executed in this run.']}


def print_checks():
    print('Rule   Mode                 Description')
    for rule, title in TITLES.items():
        mode = ('HTTP redirect check' if rule == 'CHK01' else
                'Explicit query probe' if rule in ('CHK07', 'CHK08') else
                'Response inspection')
        print(f'{rule}  {mode:21} {title}')
    from auditor.auth.checks import METADATA
    for rule, (_, title, _) in METADATA.items():
        print(f'{rule}  {"Project assessment":21} {title}')
    print('CHK09–CHK12 require --project FILE --assess (AuditShop adapter).')
    print('CHK13 requires --project FILE --assess --rbac-policy FILE (explicit approved policy).')
    print('CHK07 requires --reflection-param; CHK08 requires --exception-param.')
    print('Response inspection still requires fetching the selected target/pages.')
    print('AI reporting runs automatically after scanning; it is not a security check.')
