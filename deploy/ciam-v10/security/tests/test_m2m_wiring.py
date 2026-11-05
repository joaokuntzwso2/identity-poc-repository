"""Regression checks after guarded M2M wiring to the Magalu bootstrap."""
import ast
from pathlib import Path
import unittest

BOOT = Path(__file__).resolve().parents[1] / 'bootstrap.py'


class WiringTests(unittest.TestCase):
    def test_basic_is_not_used_for_rest_requests(self):
        source = BOOT.read_text()
        tree = ast.parse(source)
        request = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'request')
        body = '\n'.join(source.splitlines()[request.lineno - 1:request.end_lineno])
        self.assertIn('management_request(home(), tenant', body)
        self.assertNotIn('Authorization', body)
        self.assertNotIn('admin(tenant)', body)

    def test_write_scopes_preflight_before_any_runtime_stage(self):
        body = BOOT.read_text()
        fn = body[body.index('def do_apply('):body.index('def activation_readback(')]
        self.assertLess(fn.index('preflight_write_scopes(p, tenant, ctx)'), fn.index('jar_sha=build_from_running_ga(rt)'))
        self.assertLess(fn.index('preflight_write_scopes(p, tenant, ctx)'), fn.index('db_setup(rt'))
        self.assertLess(fn.index('preflight_write_scopes(p, tenant, ctx)'), fn.index('make_overlay(p,rt)'))

    def test_auth_check_is_read_only(self):
        body = BOOT.read_text()
        fn = body[body.index('def do_auth_check():'):body.index('def do_inventory():')]
        self.assertIn("request(tenant, path)", fn)
        self.assertNotIn("'PATCH'", fn)
        self.assertNotIn('db_setup', fn)
        self.assertNotIn('make_overlay', fn)

if __name__ == '__main__': unittest.main()
