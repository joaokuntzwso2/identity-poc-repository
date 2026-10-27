"""Strict WSO2 v10 token-introspection TOML policy. No privileges are granted here."""
import tomllib

HANDLER = '''[[resource.access_control]]
context = "(.*)/oauth2/introspect(.*)"
http_method = "all"
secure = true
allowed_auth_handlers = "BasicClientAuthentication"
'''
SCOPE = '''[resource_access_control.introspect]
scopes = ["internal_oauth2_introspect"]
'''

class PolicyRefused(ValueError):
    pass

def ensure_introspection_policy(raw: str) -> str:
    """Append only an exactly supported rule; reject drift, duplicates and empty scopes."""
    cfg = tomllib.loads(raw)
    oauth = cfg.get('oauth', {})
    cross_tenant = oauth.get('introspect', {}) if isinstance(oauth, dict) else {}
    if isinstance(cross_tenant, dict) and (cross_tenant.get('allow_cross_tenant') is True or cross_tenant.get('allow_cross_sub_org') is True):
        raise PolicyRefused('CROSS_TENANT_OR_SUBORG_INTROSPECTION_UNSAFE')
    resource = cfg.get('resource', {})
    rules = resource.get('access_control', []) if isinstance(resource, dict) else []
    if isinstance(rules, dict):
        rules = [rules]
    if not isinstance(rules, list):
        raise PolicyRefused('ACCESS_CONTROL_NOT_ARRAY')
    matching = [r for r in rules if isinstance(r, dict) and 'introspect' in str(r.get('context', ''))]
    if len(matching) > 1:
        raise PolicyRefused('DUPLICATE_INTROSPECTION_RULE')
    if matching:
        rule = matching[0]
        expected = tomllib.loads(HANDLER)['resource']['access_control'][0]
        if rule != expected:
            raise PolicyRefused('CONFLICTING_INTROSPECTION_RULE')
    access = cfg.get('resource_access_control', {})
    introspect = access.get('introspect') if isinstance(access, dict) else None
    if introspect is not None and introspect != {'scopes': ['internal_oauth2_introspect']}:
        raise PolicyRefused('INTROSPECTION_SCOPE_POLICY_CONFLICT_OR_UNSAFE')
    additions = []
    if not matching: additions.append(HANDLER)
    if introspect is None: additions.append(SCOPE)
    new = raw.rstrip() + '\n\n' + '\n'.join(additions) if additions else raw
    verified = tomllib.loads(new)
    verified_rule = verified.get('resource', {}).get('access_control', [])
    if isinstance(verified_rule, dict): verified_rule = [verified_rule]
    if sum(r.get('context') == '(.*)/oauth2/introspect(.*)' for r in verified_rule) != 1:
        raise PolicyRefused('INTROSPECTION_RULE_NOT_UNIQUE')
    if verified.get('resource_access_control', {}).get('introspect', {}).get('scopes') != ['internal_oauth2_introspect']:
        raise PolicyRefused('INTROSPECTION_REQUIRED_SCOPE_NOT_PINNED')
    return new
