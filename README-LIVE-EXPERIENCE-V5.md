# CIAM v5 – original Experience Center with real WSO2-backed identity

This overlay is based on the user's 266-file source snapshot at `main` commit `4a99dd5`. It restores the **original visual design language** and six guided journeys as a BFF-served, dependency-free frontend; it does **not** literally reinstate the old React runtime because that implementation called the blocked synthetic `/api/experience/*` service and depended on a deleted persona fixture. Original Experience Center CSS and retail CSS are reused, and the journeys are adapted to real WSO2-backed actions. Non-identity storefront products remain explicitly labeled as illustrative.

## Install (source-only, no WSO2 writes)

```bash
cd "$HOME/wso2mi/Projects/Demo/poc-implementation"
tar -xzf "$HOME/Downloads/WSO2_CIAM_V5_Live_Experience_Center.tar.gz"
python3 scripts/install-live-experience-v5.py --check
python3 scripts/install-live-experience-v5.py --apply
python3 scripts/install-live-experience-v5.py --verify
node --test tests/live-experience-v5.test.mjs
python3 scripts/zero-mock-gate.py .
```

The installer adds only exact known static routes and a strict allowlist for OAuth return URLs. If the anchors differ from your v4.4 source, **stop** and share the refusal, don't force the patch. The installer does not stage or commit Git files.

## Restart the known BFF only

Preserve its working environment and the existing business API settings:

```bash
export CIAM_BUSINESS_DATA_DIR="$HOME/wso2-ciam-v10/private/business-cases-v4"
export WSO2_CASES_API_AUDIENCE="urn:ciampoc:service-requests:v1"
export WSO2_CASES_SCOPES_ENABLED=1
```

Stop the verified BFF process, run `./scripts/ciam-v10.sh bff-diagnose`, clear the *confirmed stale* PID with `WSO2_CIAM_V10_STALE_PID_CONFIRM=CLEAR_DEAD_PID_ONLY ./scripts/ciam-v10.sh bff-clear-stale`, then `./scripts/ciam-v10.sh bff-start` and `bff-diagnose`. Do not stop random processes on 4400 or restart Docker.

Run `bash scripts/live-experience-v5-acceptance.sh` and open **http://127.0.0.1:4400/lab**.

## Capability and acceptance honesty

The 4 website routes exist and use their respective WSO2 OIDC clients, but *positive live login is not established by local source tests*. Aurora Web had previously passed end-to-end positive customer and seller cases, while the 3 remaining clients need positive login, profile and authorization testing. B2B delegation, real consent preferences, token exchange and successful TOTP approval remain unavailable. See `docs/CIAM_V5_EXPERIENCE_AND_WSO2_RELATIONSHIPS.md` for the complete architecture and limitations.

### Single-command automated deployment

After extracting the archive, run:

```bash
python3 scripts/ciam-v5-deploy.py deploy
```

This executes installer preflight/apply/verify (or verified idempotent skip), tests, zero-mock gate, guarded stop of only the known BFF process, confirmed stale-PID cleanup, BFF restart and anonymous HTTP acceptance. It preserves real WSO2 tenant state, journals and case records. If a guard refuses, **stop** and share the output. Positive login into each of the four OAuth clients still requires genuine WSO2 login and evidence.
