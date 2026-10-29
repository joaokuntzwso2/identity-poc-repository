"""Static execution of only the isolated Cases identifier guard; never contacts WSO2."""
import ast
import os
from pathlib import Path
import unittest
import urllib
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[2] / 'cases-rbac/bootstrap.py'
KEY = 'WSO2_CIAM_CASES_API_IDENTIFIER'

class GuardRejected(Exception):
    pass

def require(ok, *_):
    if not ok: raise GuardRejected()

class CasesIdentifierFormat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse(PATH.read_text())
        funcs = [x for x in tree.body if isinstance(x, ast.FunctionDef)
                 and x.name in ('_valid_case_resource_urn', 'case_identifier')]
        if len(funcs) != 2: raise AssertionError('SOURCE_FUNCTIONS_CHANGED')
        ns = {'os': os, 'urllib': urllib, 'require': require}
        exec(compile(ast.Module(body=funcs, type_ignores=[]), str(PATH), 'exec'), ns)
        cls.identifier = staticmethod(ns['case_identifier'])

    def accepted(self, value):
        with patch.dict(os.environ, {KEY: value}):
            self.assertEqual(self.identifier(), value)

    def rejected(self, value):
        with patch.dict(os.environ, {KEY: value}):
            with self.assertRaises((GuardRejected, ValueError)):
                self.identifier()

    def test_https_existing_behavior(self):
        self.accepted('https://api.example.test/cases')

    def test_existing_urn_family(self):
        self.accepted('urn:wso2:ciam:cases')
        self.accepted('urn:example-org:cases/v1')

    def test_malformed_urn_rejected(self):
        for value in ('urn:x:cases','urn:urn:cases','urn:example:','urn:example:cases%GG',
                      'urn:example:cases?bad=1','urn:example:cases#fragment',
                      'urn:example:cases with space','urn:example:cases\n',
                      'urn:example:casés','urn:example:cases%0',
                      'http://api.example.test/cases','https://evil@api.example.test/cases'):
            with self.subTest(value=repr(value)): self.rejected(value)

if __name__=='__main__': unittest.main()
