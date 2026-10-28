#!/usr/bin/env python3
"""Idempotently append an inspection reference to the root README (source write only)."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
README=ROOT/'README.md'
BEGIN='<!-- CIAM_V10_INSPECTION_BEGIN -->'
END='<!-- CIAM_V10_INSPECTION_END -->'
SECTION='''

<!-- CIAM_V10_INSPECTION_BEGIN -->
## Read-only CIAM v10 repository and WSO2 inspection (P0.01–P0.03)

Before implementing new CIAM features, run the [source and runtime inspection](docs/CIAM_V10_INSPECTION.md) against a pinned Git commit. It inventories Carbon Super, Aurora, and Brisa using existing private WSO2 credentials; compares live management-API readbacks with journaled resources; checks OIDC clients, grants, PKCE, discovery, and audience configuration; and records blockers without changing WSO2 resources. Reports remain private in `${CIAM_V10_HOME:-$HOME/wso2-ciam-v10}/inspection/` and must not be committed.

```bash
python3 -m unittest discover -s tests -p 'test_ciam_v10_inspect.py' -v
python3 scripts/ciam-v10-inspect.py --mode all --with-runtime-negative
```

This is a read-only inspection, **not** browser authentication, MFA, consent, or update-level certification. The image tag alone cannot attest the exact WSO2 product update level.
<!-- CIAM_V10_INSPECTION_END -->
'''

def main():
    if not README.is_file() or not (ROOT/'deploy/ciam-v10/cli.py').is_file():
        raise SystemExit('REFUSE: not the CIAM v10 repository root')
    if README.is_symlink():
        raise SystemExit('REFUSE: README is a symlink')
    body=README.read_text(encoding='utf8')
    if BEGIN in body or END in body:
        if body.count(BEGIN)==1 and body.count(END)==1:
            print('README_INSPECTION_SECTION_ALREADY_PRESENT')
            return
        raise SystemExit('REFUSE: conflicting README inspection markers')
    README.write_text(body.rstrip('\n')+SECTION,encoding='utf8')
    print('README_INSPECTION_SECTION_ADDED')

if __name__=='__main__':
    main()
