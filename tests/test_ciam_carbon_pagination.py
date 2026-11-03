"""Offline, no-network regressions for Carbon Super WSO2 cursor traversal."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('carbon_pagination', ROOT/'scripts/ciam-carbon-super-readback.py')
carbon=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(carbon)
ENDPOINT=carbon.API_RESOURCE_PATH


def page(start, count, total, link=None):
    obj={'apiResources':[{'identifier':f'demo-resource-{i:04d}'} for i in range(start,start+count)], 'totalResults':total}
    if link is not None:
        obj['links']=[{'rel':'next','href':link}]
    return obj


class CarbonPaginationTests(unittest.TestCase):
    def run_pages(self, pages):
        requested=[]
        def fake_get(path,auth,context):
            requested.append(path)
            if len(requested)>len(pages):
                raise AssertionError('Unexpected extra request')
            return pages[len(requested)-1]
        with patch.object(carbon,'get',side_effect=fake_get):
            return carbon.complete_api_resources('not-a-real-secret',None),requested

    def test_first_page_100_still_requires_verified_cursor(self):
        summary,requests=self.run_pages([(200,page(0,100,184))])
        self.assertEqual(summary['status'],'PARTIAL_OR_UNVERIFIED')
        self.assertEqual(summary['verificationCode'],'FORWARD_CURSOR_UNVERIFIED')
        self.assertEqual(requests,[carbon.PATHS['superApiResources']])

    def test_https_local_forward_cursor_fetches_all_184(self):
        full='https://localhost:9443/api/server/v1/api-resources?limit=100&after=T1BBUVVFX1RPS0VO'
        result,requests=self.run_pages([(200,page(0,100,184,full)),(200,page(100,84,184))])
        self.assertEqual(result['status'],'FULL_PAGINATED')
        self.assertEqual((result['pageCount'],result['reportedTotal'],result['pagesFetched']),(184,184,2))
        self.assertEqual(len(set(result['resourceIdentifiers'])),184)
        self.assertEqual(requests[1],ENDPOINT+'?limit=100&after=T1BBUVVFX1RPS0VO')
        self.assertNotIn('https:',requests[1]);self.assertNotIn('9443',requests[1])

    def test_relative_and_query_only_forward_links(self):
        for link in (ENDPOINT+'?after=c2&limit=100','?after=c2&limit=100',
                     'https://127.0.0.1:9444'+ENDPOINT+'?after=c2&limit=100'):
            with self.subTest(link=link):
                result,_=self.run_pages([(200,page(0,100,184,link)),(200,page(100,84,184))])
                self.assertEqual(result['status'],'FULL_PAGINATED')

    def test_malicious_or_unpinned_next_links_never_followed(self):
        bad=['https://attacker.example'+ENDPOINT+'?after=private',
             'http://localhost:9444'+ENDPOINT+'?after=a',
             'https://localhost:9445'+ENDPOINT+'?after=a',
             'https://localhost:9444/other/path?after=a',
             ENDPOINT+'?limit=100&after=a&extra=1',
             ENDPOINT+'?after=a&after=b',ENDPOINT+'?before=a',
             ENDPOINT+'?after=%0d%0a',ENDPOINT+'?limit=100&after=a#fragment',
             ENDPOINT+'?after=']
        for link in bad:
            with self.subTest(link=link):
                result,requests=self.run_pages([(200,page(0,100,184,link))])
                self.assertEqual(result['status'],'PARTIAL_OR_UNVERIFIED')
                self.assertEqual(len(requests),1)

    def test_direct_get_allowlist_rejects_unsafe_generated_paths(self):
        allowed=ENDPOINT+'?limit=100&after=token%2Bvalue%2F%3D'
        self.assertTrue(carbon.is_approved_cursor_request(allowed))
        self.assertFalse(carbon.is_approved_cursor_request(ENDPOINT+'?limit=100&after=a&after=b'))
        self.assertFalse(carbon.is_approved_cursor_request(ENDPOINT+'?limit=100&after=a&offset=100'))
        self.assertFalse(carbon.is_approved_cursor_request('/scim2/Users?limit=100&after=a'))

    def test_duplicate_identifier_or_changed_total_never_proves_full(self):
        good_page=(200,page(0,100,184,ENDPOINT+'?limit=100&after=MTIz'))
        duplicate=(200,page(99,84,184))
        wrong_total=(200,page(100,84,185))
        for bad in (duplicate,wrong_total):
            result,_=self.run_pages([good_page,bad])
            self.assertEqual(result['status'],'PARTIAL_OR_UNVERIFIED')

    def test_non_200_or_malformed_second_page_is_inconclusive(self):
        first=(200,page(0,100,184,ENDPOINT+'?limit=100&after=c2'))
        for second in ((403,None),(200,{'apiResources':[],'totalResults':184}),
                       (200,{'apiResources':[],'totalResults':'184'})):
            with self.subTest(second=second):
                result,_=self.run_pages([first,second])
                self.assertEqual(result['status'],'PARTIAL_OR_UNVERIFIED')

    def test_repeating_cursor_refused(self):
        cursor=ENDPOINT+'?limit=100&after=c2'
        result,requests=self.run_pages([(200,page(0,75,184,cursor)),
                                        (200,page(75,75,184,cursor))])
        self.assertEqual(result['status'],'PARTIAL_OR_UNVERIFIED')
        self.assertEqual(result['verificationCode'],'REPEATED_CURSOR')
        self.assertEqual(len(requests),2)

    def test_no_secret_or_cursor_value_in_failed_summary(self):
        secret='DontPrintMeSecret123'
        result,_=self.run_pages([(200,page(0,100,184,ENDPOINT+'?after='+secret)),
                                 (403,None)])
        self.assertNotIn(secret,str(result))
        self.assertEqual(result['verificationCode'],'PAGE_HTTP_UNVERIFIED')

    def test_zero_or_single_page_remains_first_page_status(self):
        for count in (0,20,100):
            result,_=self.run_pages([(200,page(0,count,count))])
            self.assertEqual(result['status'],'FULL_FIRST_PAGE')
            self.assertEqual(result['pageCount'],count)


if __name__=='__main__':unittest.main()
