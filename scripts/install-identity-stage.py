#!/usr/bin/env python3
"""Wire the real-identity seed to the existing guarded full bootstrap, exactly once."""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit('Usage: python3 scripts/install-identity-stage.py REPOSITORY_ROOT')
root=Path(sys.argv[1]).resolve()
cli=root/'deploy/ciam-v10/cli.py'
text=cli.read_text()
identifier="IDENTITIES = HERE / 'identities/bootstrap.py'"
anchor="AUTHORITY = HERE / 'authority/bootstrap.py'"
needle="    output(auth_report)\n    # The BFF bridge must run AFTER the authority journal and WSO2 readback;"
replacement="""    output(auth_report)
    # No person/role may appear in a portal until WSO2 owns it and readback passes.
    seed_env = os.environ.copy()
    seed_env['WSO2_CIAM_V10_IDENTITIES_CONFIRM'] = 'CREATE_DEMO_PEOPLE_AND_APP_ROLES'
    run([sys.executable, IDENTITIES, 'plan'])
    run([sys.executable, IDENTITIES, 'apply'], env=seed_env)
    run([sys.executable, IDENTITIES, 'verify'])
    # The BFF bridge must run AFTER the authority journal and WSO2 readback;"""
if identifier in text:
    if "run([sys.executable, IDENTITIES, 'verify'])" not in text:
        raise SystemExit('Refusing partially modified cli.py')
    print('Already installed; no changes')
    raise SystemExit(0)
if text.count(anchor)!=1 or text.count(needle)!=1:
    raise SystemExit('Refusing to patch: expected v10 cli.py anchors differ')
new=text.replace(anchor, anchor+'\n'+identifier).replace(needle,replacement)
compile(new,str(cli),'exec')
cli.write_text(new)
print('Updated deploy/ciam-v10/cli.py: real identities run before BFF startup')
