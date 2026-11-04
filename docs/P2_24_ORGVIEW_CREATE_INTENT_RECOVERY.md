# P2.24 — Recovery of one previously created Aurora M2M application (v7)

This recovery is **specific to the observed November 4, 2026 failure** after an approved application creation POST. Its initial create response did not yield a valid ID. A subsequent **GET-only** complete application inventory found one matching application, seven total applications (six before the create attempt), exact `client_credentials` OIDC configuration, and zero API authorizations. The observed SHA-256 ID fingerprint prefix was `837c9f0ac85efca8`.

**Ownership limitation:** The original `CREATE_INTENT` journal does **not** contain the server-generated application ID. Consequently the existing application's authorship by that exact POST cannot be cryptographically established from the journal. This recovery is a tightly scoped, operator-approved *binding* to that one specific, reverified candidate, not a general-purpose app adoption mechanism. It must refuse if the matching name is ambiguous, inventory changes, fingerprint changes, expected description/grant or client secret is unavailable, or the API resource no longer matches the journal.

## Operator-approved operation

The user's authorization covers the dedicated **Aurora-only application plus the single organization-view API authorization**; it does not cover any new creation attempt, extra scopes, Brisa, Carbon Super, role grants, secret generation, organization creation or WSO2 upgrade. This recovery performs **zero application-create POSTs**, at most **one application `authorized-apis` POST**, a necessary OAuth token request, and readbacks. It uses the pinned public TLS certificate and v2 authority guard.

Install and execute from the project root (no manual secrets or UUIDs):

```bash
unzip -oq "$HOME/Downloads/p2_24_orgview_recovery_v7.zip" -d "$HOME/Downloads"
python3 "$HOME/Downloads/p2_24_orgview_recovery_v7/install.py" "$PWD" && \
  bash scripts/p2/run-one-time-orgview-recovery-v7.sh
```

The installer changes **only source and test files**. The runner executes local tests, a GET-only plan, then the one preapproved authorization continuation and GET-only partner discovery. It never calls the original `run-approved-orgview.sh`, which could attempt to create a second app. The old journal is advanced through `AUTHORIZATION_INTENT` before the authorization POST and then `COMPLETE` only after exact scope, issued OAuth token and Aurora root readback. Original create-intent digest is retained for audit. All private credentials/token artifacts are stored owner-only outside the Git repository.

**If ANY step fails after the apply begins, do not rerun this launcher.** The journal may have advanced to `AUTHORIZATION_INTENT`, and WSO2 may already have accepted the one authorization POST. Reconcile GET-only before any follow-on mutation; do not delete/replace private journals. If the GET-only plan fails, it has not modified WSO2. A failure after the successful `COMPLETE` result but during `plan-partner` does not undo the completed M2M authorization; only the organization discovery still needs investigation.

Status is not live-verified until run against the Mac deployment. Never commit private journals, TLS key material, tokens or client secrets. The pinned public certificate is local-only and not a production trust anchor.
