"""Regression: read-only auth-check, inventory and plan never invoke apply/verify."""
from contextlib import ExitStack
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SECURITY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SECURITY))
import bootstrap as b


class CommandDispatchTests(unittest.TestCase):
    def test_single_command_no_verify_fallthrough(self):
        functions = ('do_auth_check', 'do_inventory', 'do_plan',
                     'do_apply', 'do_verify', 'do_rollback')
        cases = {
            'auth-check': 'do_auth_check',
            'inventory': 'do_inventory',
            'plan': 'do_plan',
            'verify': 'do_verify',
        }
        for command, expected in cases.items():
            with self.subTest(command=command), ExitStack() as stack:
                spies = {name: stack.enter_context(patch.object(b, name))
                         for name in functions}
                stack.enter_context(patch.object(sys, 'argv', ['bootstrap.py', command]))
                b.main()
                for name, spy in spies.items():
                    if name == expected:
                        spy.assert_called_once_with()
                    else:
                        spy.assert_not_called()

    def test_apply_and_rollback_only_when_explicitly_selected(self):
        for command, target in [('apply', 'do_apply'), ('rollback', 'do_rollback')]:
            with self.subTest(command=command), ExitStack() as stack:
                spies = {name: stack.enter_context(patch.object(b, name))
                         for name in ('do_auth_check', 'do_inventory', 'do_plan',
                                      'do_apply', 'do_verify', 'do_rollback')}
                stack.enter_context(patch.object(sys, 'argv', ['bootstrap.py', command, '--approve', 'test-hash']))
                b.main()
                spies[target].assert_called_once_with('test-hash')
                for name, spy in spies.items():
                    if name != target:
                        spy.assert_not_called()


if __name__ == '__main__':
    unittest.main()
