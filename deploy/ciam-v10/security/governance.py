"""Discover and update only native per-tenant login-failure governance properties.

Never auto-enables reCAPTCHA: it needs a legitimate configured challenge provider.
The enable key is from live GA 7.3 tenant REST catalog, not the /latest/ docs.
No alias, fallback or silent creation of a missing configuration key is allowed.
Avoids permanent account lock and refuses unknown/non-GA connector shapes.
"""
from urllib.parse import quote

DESIRED={
    'aurora.identity.test': {
        'account.lock.handler.lock.on.max.failed.attempts.enable': 'true',
        'account.lock.handler.On.Failure.Max.Attempts': '8',
        'account.lock.handler.Time': '5',
        'account.lock.handler.login.fail.timeout.ratio': '2',
    },
    'brisa.identity.test': {
        'account.lock.handler.lock.on.max.failed.attempts.enable': 'true',
        'account.lock.handler.On.Failure.Max.Attempts': '12',
        'account.lock.handler.Time': '3',
        'account.lock.handler.login.fail.timeout.ratio': '2',
    },
}

class GovernanceMismatch(RuntimeError): pass


def _list_of(value, name, wrapper=None, maximum=200):
    """Decode documented GA list or a narrowly known list wrapper."""
    if isinstance(value, dict) and wrapper is not None:
        value = value.get(wrapper)
    if not isinstance(value, list) or len(value) > maximum:
        raise GovernanceMismatch('INVALID_' + name + '_CATALOG')
    return value


def discovered(tenant, get):
    """Bounded readback via category + connector GETs (never infer missing values).

    GA responses may omit properties in the connector *listing*: the individual
    connector endpoint is the authoritative property readback. No settings are
    changed here. Stop on duplicate keys or inconsistent returned connector ids.
    """
    if tenant not in DESIRED:
        raise GovernanceMismatch('TENANT_NOT_ALLOWLISTED')
    cats = _list_of(get(tenant, '/api/server/v1/identity-governance'),
                    'CATEGORY', wrapper='categories', maximum=30)
    found = {}
    for category in cats:
        if not isinstance(category, dict) or not isinstance(category.get('id'), str):
            raise GovernanceMismatch('CATEGORY_ID_INVALID')
        cid = quote(category['id'], safe='')
        path = '/api/server/v1/identity-governance/' + cid + '/connectors'
        connectors = _list_of(get(tenant, path), 'CONNECTOR', wrapper='connectors', maximum=100)
        for connector in connectors:
            if not isinstance(connector, dict) or not isinstance(connector.get('id'), str):
                raise GovernanceMismatch('CONNECTOR_ID_INVALID')
            coid = connector['id']
            cpath = path + '/' + quote(coid, safe='')
            props = connector.get('properties')
            if not isinstance(props, list) or not props:
                detail = get(tenant, cpath)
                if not isinstance(detail, dict) or detail.get('id') != coid:
                    raise GovernanceMismatch('CONNECTOR_DETAIL_ID_MISMATCH')
                props = detail.get('properties')
            if not isinstance(props, list) or len(props) > 300:
                raise GovernanceMismatch('CONNECTOR_PROPERTIES_INVALID')
            for prop in props:
                if not isinstance(prop, dict):
                    raise GovernanceMismatch('CONNECTOR_PROPERTY_INVALID')
                key = prop.get('name')
                if key not in DESIRED[tenant]:
                    continue
                if key in found:
                    raise GovernanceMismatch('ACCOUNT_LOCK_KEY_AMBIGUOUS_' + key)
                value = prop.get('value')
                if not isinstance(value, (str, bool, int)) or len(str(value)) > 80:
                    raise GovernanceMismatch('ACCOUNT_LOCK_VALUE_INVALID_' + key)
                found[key] = {'value': str(value).lower(), 'path': cpath}
    absent = set(DESIRED[tenant]) - set(found)
    if absent:
        # Property names are non-secret, but do not enumerate arbitrary values.
        raise GovernanceMismatch('ACCOUNT_LOCK_KEYS_MISSING_' + ','.join(sorted(absent)))
    return found


def delta(tenant, found):
    return {key:dict(before=found[key]['value'],after=wanted,path=found[key]['path'])
            for key,wanted in DESIRED[tenant].items() if found[key]['value']!=wanted}


def apply(tenant, get, patch, before):
    # Validate complete current readback before any mutation. Each connector can
    # hold multiple properties; group PATCH by category/connector path.
    fresh=discovered(tenant,get)
    if fresh != before: raise GovernanceMismatch('governance changed since security plan')
    grouped={}
    for k,x in delta(tenant,fresh).items():
        grouped.setdefault(x['path'],[]).append({'name':k,'value':x['after']})
    for path, properties in sorted(grouped.items()):
        patch(tenant,path,{'operation':'UPDATE','properties':properties})
        verified=discovered(tenant,get)
        for p in properties:
            if verified[p['name']]['value']!=p['value']:
                raise GovernanceMismatch('native governance GET readback mismatch; stop')
    return discovered(tenant,get)
