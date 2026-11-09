"""Bounded AuditShop checks. Fixed endpoints and explicitly declared resources only."""
import copy
import httpx
from uuid import uuid4
from .sessions import SessionError, response_json

METADATA = {
    'CHK09': ('A01:2025', 'Cross-account order access',
              'An unrelated customer cannot read a declared private order.'),
    'CHK10': ('A01:2025', 'Anonymous private order access',
              'An anonymous request cannot read a declared private order.'),
    'CHK11': ('A05:2025', 'Catalogue SQL boolean differential',
              'Search values are treated as data, not SQL syntax.'),
    'CHK12': ('A07:2025', 'Logout session replay',
              'The old session no longer authenticates after logout.'),
}


def order_identity(response, order_id, owner_id):
    obj = response_json(response).get('order')
    if not isinstance(obj, dict):
        raise SessionError('unsupported_order_response')
    marker = obj.get('private_marker')
    if (type(obj.get('id')) is not int or obj['id'] != order_id
            or type(obj.get('user_id')) is not int or obj['user_id'] != owner_id
            or not isinstance(marker, str) or not 1 <= len(marker) <= 256):
        raise SessionError('owner_control_mismatch')
    # Never persist this tuple or marker.
    return (obj['id'], obj['user_id'], marker)


async def access_check(sessions, resource, *, anonymous=False):
    owner, other = resource['owner'], resource['other']
    if owner not in sessions.verified or (not anonymous and other not in sessions.verified):
        return 'Not Tested', 'Required account identity was not verified.', {}, []
    account = next(a for a in sessions.project['accounts'] if a['alias'] == owner)
    path = '/api/orders/' + str(resource['order_id'])
    baseline = await sessions.request(owner, path)
    expected = order_identity(baseline, resource['order_id'], account['expected_id'])
    if anonymous:
        probe = await sessions.budget._request_once(sessions.project['base_url'] + path)
    else:
        probe = await sessions.request(other, path)
    after = await sessions.request(owner, path)
    stable = expected == order_identity(after, resource['order_id'], account['expected_id'])
    observed = {'baseline_status': baseline['status_code'], 'probe_status': probe['status_code'],
                'owner_control_stable': stable, 'private_resource_match': False,
                'anonymous_probe': anonymous}
    steps = ['Verify owner response identity and private marker.',
             'Request the declared resource with an isolated guest or unrelated customer session.',
             'Repeat owner control and compare identity in memory; discard response bodies.']
    if not stable:
        return 'Inconclusive', 'Owner controls changed during the comparison.', observed, steps
    if probe['status_code'] in (401,403,404):
        return 'No Issue Observed', 'The tested request was denied; only this resource and actor were checked.', observed, steps
    if probe['status_code'] == 200:
        try:
            observed['private_resource_match'] = expected == order_identity(probe, resource['order_id'], account['expected_id'])
        except SessionError:
            pass
        if observed['private_resource_match']:
            return 'Confirmed', 'The declared private order identity and marker were returned to an actor without ownership under the configured policy.', observed, steps
    return 'Inconclusive', 'The response did not establish either denial or matching private-resource disclosure.', observed, steps


def product_ids(response):
    obj = response_json(response)
    products = obj.get('products')
    if (not isinstance(products, list) or len(products) > 100 or type(obj.get('count')) is not int
            or obj['count'] != len(products)):
        raise SessionError('unsupported_catalogue_response')
    ids = []
    for product in products:
        if not isinstance(product, dict) or type(product.get('id')) is not int:
            raise SessionError('unsupported_catalogue_response')
        ids.append(product['id'])
    if len(set(ids)) != len(ids):
        raise SessionError('duplicate_catalogue_identity')
    return sorted(ids)


async def sql_differential(sessions):
    endpoint = sessions.project['base_url'] + '/api/products'
    baseline = product_ids(await sessions.budget.fetch_query_probe(endpoint, 'search', ''))
    negative = product_ids(await sessions.budget.fetch_query_probe(endpoint, 'search', 'AUDITOR_' + uuid4().hex))
    true_value = "'))>0) OR 1=1 -- "
    false_value = "'))>0) AND 1=0 -- "
    pairs = []
    for _ in range(2):
        pairs.append((product_ids(await sessions.budget.fetch_query_probe(endpoint, 'search', true_value)),
                      product_ids(await sessions.budget.fetch_query_probe(endpoint, 'search', false_value))))
    after = product_ids(await sessions.budget.fetch_query_probe(endpoint, 'search', ''))
    stable = bool(baseline) and len(baseline) < 100 and baseline == after and not negative
    differential = stable and all(set(baseline).issubset(t) and t == pairs[0][0] and len(t) < 100 and not f for t, f in pairs)
    literal = stable and all(not t and not f for t, f in pairs)
    observed = {'baseline_count': len(baseline), 'negative_control_count': len(negative),
                'baseline_stable': stable, 'repeatable_boolean_differential': differential,
                'literal_rejection_observed': literal, 'probe_pairs': 2}
    steps = ['Fetch catalogue and random nonmatching search controls.',
             'Compare two true/false boolean search pairs without extracting other data.',
             'Repeat the baseline and discard response contents and product IDs.']
    if differential:
        return 'Potential', 'Two boolean probe pairs changed the returned catalogue consistently. SQL execution is not independently established.', observed, steps
    if literal:
        return 'No Issue Observed', 'These two probe strings returned no matches, consistent with literal search handling.', observed, steps
    return 'Inconclusive', 'The controlled response pattern did not support a reliable SQL-injection conclusion.', observed, steps


async def logout_replay(sessions, account):
    alias = account['alias']
    if alias not in sessions.verified:
        return 'Not Tested', 'Account identity was not verified.', {}, []
    before = response_json(await sessions.request(alias, '/api/me'))
    if before.get('id') != account['expected_id'] or before.get('role') != account['expected_role']:
        raise SessionError('identity_control_changed')
    # Copy a jar in memory before logout. Never persist or send it to an AI.
    cookies = httpx.Cookies()
    for cookie in sessions.clients[alias].cookies.jar:
        cookies.jar.set_cookie(copy.copy(cookie))
    acknowledged = False
    try:
        logout = await sessions.request(alias, '/api/logout', method='POST', body={})
        if logout['status_code'] != 204:
            raise SessionError('logout_not_acknowledged')
        acknowledged = True
        async with httpx.AsyncClient(cookies=cookies, verify=True, follow_redirects=False,
                trust_env=False, timeout=sessions.budget.profile['request_timeout_seconds'],
                headers={'Accept-Encoding':'identity'},
                transport=sessions.transport_factory(alias) if sessions.transport_factory else None) as replay:
            result = await sessions.budget._request_once(sessions.project['base_url'] + '/api/me', session_client=replay)
            replay.cookies.clear()
        observed = {'baseline_status':200, 'logout_status':204, 'probe_status':result['status_code'],
                    'replayed_identity_matches':False}
        steps = ['Verify authenticated identity.', 'Logout using the current CSRF token.',
                 'Replay the pre-logout session cookie once against /api/me.']
        if result['status_code'] in (401,403):
            return 'No Issue Observed', 'The old session was rejected immediately after logout.', observed, steps
        if result['status_code'] == 200:
            identity = response_json(result)
            observed['replayed_identity_matches'] = (type(identity.get('id')) is int and
                identity['id'] == account['expected_id'] and identity.get('role') == account['expected_role'])
            if observed['replayed_identity_matches']:
                return 'Confirmed', 'The pre-logout session still authenticated as the same account after logout was acknowledged.', observed, steps
        return 'Inconclusive', 'The replay response did not establish rejection or continued authentication.', observed, steps
    finally:
        cookies.clear()
        # A second logout cannot prove revocation and the server deleted the local cookie.
        if acknowledged:
            sessions.logged_in.discard(alias)
            sessions.verified.discard(alias)
            sessions.tokens.pop(alias, None)
            sessions.cleanup[alias] = 'logout_test_acknowledged'
