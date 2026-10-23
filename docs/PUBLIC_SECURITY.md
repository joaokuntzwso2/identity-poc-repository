# Public repository safeguards

**Public-safe by design:** no customer names, private proposal materials, procurement metrics, credentials, client secrets, internal tenant lists, or copied production datasets.

## Before a commit

```bash
./provider.sh test
./experience.sh operations-test
./experience.sh build
python3 scripts/security/check_public.py --staged

git diff --cached --check
git diff --cached --name-only
```

Review the diff manually. A scanner may not detect every commercially sensitive or indirectly identifying detail.

## Files never to publish

Keep private: contracts, RFP and requirements traceability, design workbooks, commercial volumes, credentials, `.env` settings, live issuer hostnames, runtime attestations, real tokens, user evidence, private test result logs and generated `var/` DBs/reports. The built in-memory and SQLite scenarios use fictional reserved `.example` data.

The provider status endpoint returns only counts and prerequisite names. It must not expose actual issuer URLs, client IDs, secrets or internal approval data. The browser cannot trigger an arbitrary discovery request.

## Operational limitations

This is a standalone loopback-only demonstration, not a hardened hosted CIAM service. The local preview is intentionally disconnected from real auth. A working UI never implies compliance, resilience, production security posture or scale.
