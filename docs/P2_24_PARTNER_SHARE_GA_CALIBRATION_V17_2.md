# V17.2 | Live GA empty-sharing calibration

V17.1 observed that WSO2 7.3 GA returns HTTP 200 `{}` for four independent read-only sharing calls for the newly registered, unshared Aurora partner portal. Empty objects are **not** accepted as evidence by default. This V17.2 adapter uses an existing non-management Aurora application as an empirical *positive control* for the same two documented GET endpoints, requiring matching nonempty organization IDs across `/share` and `/shared-apps` before it can interpret the portal's repeated exact `{}` as GA empty-state serialization.

Safety prerequisites: V16.3 journal and callback GET readback, V13 partner/root fingerprints, unchanged V17 source SHA, complete tenant application inventory, pinned HTTPS certificate and qualified Aurora administrator, two consecutive rounds of four exact `{}` results from portal, independent original V17 check, same-lock recalibration immediately before the write. No share is allowed when positive control is absent, permissions fail, any response shape changes, or a portal sharing relationship appears. The control application is GET-only and is **never** selected for any write.

When all prerequisites pass, the already approved V17 `SELECTED_ORG_ONLY`/`roleSharing.NONE` payload is sent once after an exclusive fsynced private intent journal. HTTP 202 is not completion. Completion requires V17 independent WSO2 share-policy and shared-app mapping readbacks. An INTENT journal disables all subsequent automatic POSTs. V17.2 does not share users, assign roles, enable login, expand scopes or modify Brisa/Carbon Super.

Automatic startup paths: `npm run start:bff` and `./scripts/ciam-v10.sh bff-start`, stage after V16.3 and before business ledger preparation. `status` is read-only. `bootstrap` may perform the **one** preapproved management POST only when proof passes. `reconcile` uses GET-only path when intent already exists.

Do not delete, reset or edit the private journal. If WSO2's positive control is not conclusive, keep `PENDING` and report the sanitized output. Even a `VERIFIED` application share is not business authorization or delegated-administrator acceptance.
