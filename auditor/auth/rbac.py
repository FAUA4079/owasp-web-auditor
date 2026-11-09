"""Read-only CHK13 policy evaluator for the explicit AuditShop /api/rbac/<slug> adapter.
No inferred permissions, dynamic URL templates, body persistence, or AI decisions.
"""
import json
import re
from pathlib import Path
from .project import ProjectError, unique_object
from .sessions import SessionError, response_json

SLUG = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")

def load_policy(path, project):
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 16384:
            raise ProjectError('RBAC policy exceeds size limit.')
        policy = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ProjectError('Invalid RBAC policy JSON.') from exc
    if not isinstance(policy, dict) or set(policy) != {'schema_version','base_url','authorization','cases'} or type(policy['schema_version']) is not int or policy['schema_version'] != 1:
        raise ProjectError('Unsupported RBAC policy schema.')
    if policy['base_url'] != project['base_url']:
        raise ProjectError('RBAC policy origin does not match project.')
    approval=policy['authorization']
    if not isinstance(approval, dict) or set(approval) != {'approved_by','approval_reference','authorized_for_testing'}:
        raise ProjectError('RBAC approval fields missing.')
    if not (approval['authorized_for_testing'] is True and isinstance(approval['approved_by'],str)
            and 3 <= len(approval['approved_by']) <= 100 and isinstance(approval['approval_reference'],str)
            and 3 <= len(approval['approval_reference']) <= 120):
        raise ProjectError('RBAC policy requires explicit authorization attestation.')
    cases=policy['cases']
    if not isinstance(cases,list) or not 1 <= len(cases) <= 8:
        raise ProjectError('RBAC policy requires 1-8 cases.')
    account_by_alias={a['alias']:a for a in project['accounts']}
    seen=set()
    for case in cases:
        if not isinstance(case,dict) or set(case) != {'resource_id','allow','deny'}:
            raise ProjectError('RBAC case fields invalid.')
        slug=case['resource_id']
        if not isinstance(slug,str) or SLUG.fullmatch(slug) is None or slug in seen:
            raise ProjectError('RBAC resource IDs must be unique safe slugs.')
        seen.add(slug)
        allow,deny=case['allow'],case['deny']
        if not isinstance(allow,str) or not isinstance(deny,str) or allow not in account_by_alias or deny not in account_by_alias or allow==deny:
            raise ProjectError('RBAC actors must be different configured identities.')
        if account_by_alias[allow]['expected_role'] == account_by_alias[deny]['expected_role']:
            raise ProjectError('CHK13 requires two distinct configured roles.')
    return policy


def resource_identity(result, slug):
    obj = response_json(result).get('resource')
    if not isinstance(obj,dict) or set(obj) != {'id','private_marker'}:
        raise SessionError('unsupported_rbac_response')
    marker=obj['private_marker']
    if obj.get('id') != slug or not isinstance(marker,str) or not 1 <= len(marker) <= 256:
        raise SessionError('rbac_identity_mismatch')
    return (slug,marker)  # in-memory only; do not persist


async def role_access_check(sessions, case):
    allow,deny,slug=case['allow'],case['deny'],case['resource_id']
    if allow not in sessions.verified or deny not in sessions.verified:
        return 'Not Tested','Required accounts were not verified.',{},[]
    path='/api/rbac/'+slug
    baseline=await sessions.request(allow,path)
    identity=resource_identity(baseline,slug)
    probe=await sessions.request(deny,path)
    after=await sessions.request(allow,path)
    stable=identity==resource_identity(after,slug)
    observation={'allow_status':baseline['status_code'],'deny_status':probe['status_code'],
                 'allow_control_stable':stable,'denied_actor_received_same_private_resource':False}
    steps=['Validate authorized actor identity and resource marker in memory.',
           'Compare response using separately authenticated denied role.',
           'Repeat authorized control; discard all response bodies and markers.']
    if not stable:
        return 'Inconclusive','Authorized control changed during comparison.',observation,steps
    if probe['status_code'] in (401,403,404):
        return 'No Issue Observed','The denied role could not access this declared resource.',observation,steps
    if probe['status_code']==200:
        try:
            observation['denied_actor_received_same_private_resource']=(resource_identity(probe,slug)==identity)
        except SessionError:
            pass
        if observation['denied_actor_received_same_private_resource']:
            return 'Confirmed','Denied role accessed the exact private resource under the supplied operator-approved policy.',observation,steps
    return 'Inconclusive','Response was not an explicit denial or a proven identical private-resource disclosure.',observation,steps
