#!/usr/bin/env python3
"""Install a minimal, idempotent dispatcher into the existing v10 facade.

Run after merging the overlay into the *pinned* v10 checkout. It never replaces
scripts/ciam-v10.sh or edits bootstrap_all()/fresh*/legacy lab entry points.
"""
import os
import pathlib
import sys
import tempfile

root=pathlib.Path(__file__).resolve().parents[1]
facade=root/'scripts/ciam-v10.sh'
marker='# BEGIN magalu-security-operator-dispatch'
injection='''# BEGIN magalu-security-operator-dispatch
case "${1:-}" in
  security-inventory|security-plan|security-bootstrap|security-apply|security-verify|security-rollback)
    exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ciam-v10-security.sh" "$@"
    ;;
esac
# END magalu-security-operator-dispatch
'''

def inject(text):
    if marker in text:
        if injection in text:return text
        raise RuntimeError('unknown existing security dispatch/drift; refuse to overwrite')
    if not text.startswith('#!/usr/bin/env bash\n') and not text.startswith('#!/bin/bash\n'):
        raise RuntimeError('unrecognized existing ciam-v10.sh facade')
    # Insert before *any* prehooks/side effects, preserving the rest byte-for-byte.
    pos=text.index('\n')+1
    return text[:pos]+injection+text[pos:]

if __name__=='__main__':
    if not facade.is_file():raise SystemExit('missing existing v10 facade: merge into the actual checkout first')
    before=facade.read_text()
    after=inject(before)
    if before==after:
        print('SECURITY_DISPATCH_EXISTS')
    else:
        mode=facade.stat().st_mode & 0o777
        fd,path=tempfile.mkstemp(prefix='.ciam-v10.',dir=facade.parent)
        with os.fdopen(fd,'w') as f:f.write(after);f.flush();os.fsync(f.fileno())
        os.chmod(path,mode);os.replace(path,facade)
        print('SECURITY_DISPATCH_ADDED (other v10 paths unchanged)')
