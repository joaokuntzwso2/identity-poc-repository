# P2.24 — WSO2 7.3.0 GA API-resource collection compatibility

## Evidence and scope

The local live GET-only probe returned `HTTP 200` and `apiResources` (lowercase `a`) for the two exact API identifiers, each with `totalResults: 1` and no next-page link. The unfiltered first page had `totalResults: 184` and a next cursor. Existing P2 bootstrap required `APIResources`, causing `ORG_API_RESOURCE_QUERY_INCOMPLETE` before any management write.

This patch accepts **exactly one** of `apiResources` or `APIResources`, requires a real list and a bounded consistent `totalResults`, refuses any next/after cursor, verifies row identifier and ID, and performs a separate resource-detail GET to verify the required `internal_org_organization_view` scope. It does **not** treat a missing collection as empty, nor silently truncate a paginated response. No other code path, OAuth permission, WSO2 configuration, private journal or deployment image is changed by installation.

## Automated installation and approved execution

Download `p2_24_api_resource_ga_fix_v5.zip` to `~/Downloads`, then run:

```bash
cd "$HOME/wso2mi/Projects/Demo/poc-implementation"
unzip -oq "$HOME/Downloads/p2_24_api_resource_ga_fix_v5.zip" -d "$HOME/Downloads"
python3 "$HOME/Downloads/p2_24_api_resource_ga_fix_v5/install.py" "$PWD" && \
python3 -m unittest discover -s tests/p2 -p 'test_m2m_*.py' -q && \
node --test tests/p2/m2m-root-guard.test.mjs && \
python3 "$HOME/Downloads/p2_24_api_resource_ga_fix_v5/run_with_tls.py"
```

The source installer and tests perform **no WSO2 writes**. The final `run_with_tls.py` helper re-verifies the pinned Docker image and local HTTPS certificate, configures `NODE_EXTRA_CA_CERTS` and `SSL_CERT_FILE` for its child processes, runs a **read-only plan first**, and only if that succeeds launches the existing approved `run-approved-orgview.sh`. The launcher can perform the previously approved Aurora-only application registration and organization-view API authorization, using durable journals and verified WSO2 readback. It does not ask for interactive input. If the WSO2 API response is not as expected, it fails closed rather than inventing permissions. If any mutation was attempted and the resulting journal is incomplete or uncertain, do **not** retry or delete the journal; reconcile live state first. The installer is source-only and cannot run management operations.

## Acceptance evidence

- Source-only patch installed and fixture-tested: does not prove a live WSO2 feature.
- Real API discovery requires a live plan with exact API-resource-detail scope readback.
- M2M provisioning requires separately confirmed application registration, authorized scope readback, scoped token issuance and organization metadata readback.
- Partner organization creation, delegated administration, cross-partner denial and deactivation are **not** part of this increment.

Never commit private journals, access tokens, application secrets or public cert pins as if they were credentials. Preserve Carbon Super, Aurora and Brisa roots as separate identity realms.
