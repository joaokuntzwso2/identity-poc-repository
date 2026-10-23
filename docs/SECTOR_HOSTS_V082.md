# Live pairwise sector hosts: Aurora / Brisa (v0.8.2)

**WSO2 Identity Server 7.3.0 Update 18+ — local lab and AWS plan.**

## Critical OIDC correctness repair

OIDC Core §8.1 derives the sector identifier from the *hostname*, not path, of a `sector_identifier_uri`. The earlier `/sectors/aurora.json` and `/sectors/brisa.json` on one HTTPS origin would not isolate the two brands. **v0.8.2 requires two distinct HTTPS hosts**, one shared by Aurora's web/mobile clients, one shared by Brisa's web/mobile clients.

For AWS / persistent demonstrations, set in your private `var/wso2/lab.env`:

```dotenv
DEMO_AURORA_SECTOR_BASE_URL=https://sector-aurora.your-owned-domain.example
DEMO_BRISA_SECTOR_BASE_URL=https://sector-brisa.your-owned-domain.example
```

Publish the exact callbacks, respectively, at `/sectors/aurora.json` and `/sectors/brisa.json` over publicly trusted TLS, using stable DNS hostnames and managed certificates. Do not move already-registered clients to new sector hostnames without planning for changes in pairwise `sub`.

For short-lived local tests only, v0.8.2 can use two *separate* Cloudflare Quick Tunnels. Each tunnel exposes only one generated JSON document, not the application, credentials, API, or WSO2 Console. URLs change on tunnel restart. Do not use temporary tunnel hosts for persistent subject IDs, production, or acceptance claims. Public internet access to the documents is necessary for this workflow; they're not confidential.

### Local first live run

1. WSO2 Update 18+ running; trust/discovery verified; update attestation and admin credentials already in `var/wso2/lab.env`.
2. `brew install cloudflared` (if needed).
3. `./wso2-lab.sh sectors` (the local server will also derive exact documents from the validated plan).
4. `./wso2-lab.sh test`.
5. **One command:** `WSO2_LAB_CONFIRM=CREATE_SYNTHETIC_RESOURCES ./wso2-lab.sh bootstrap-local`.

This starts two HTTPS tunnels, checks both public JSON documents, and runs the v0.8.1 automatic management-client/token bootstrap. The process **intentionally stays running** afterward so that the registered sector URLs remain reachable. Press Ctrl+C only once you're finished with your disposable identity tests. The tool stores temporary URL settings in `var/wso2/local-sector-tunnels.env` (0600, Git-ignored) for other local terminal commands such as `./wso2-lab.sh bff-env`. It removes the file on clean termination. If provisioning fails, it retains the tunnels so the same URLs can be reused for a safe retry from a second terminal: `WSO2_LAB_CONFIRM=CREATE_SYNTHETIC_RESOURCES ./wso2-lab.sh apply`.

Alternatively use `./wso2-lab.sh sectors-local` in one terminal, and invoke `apply` in another after `SECTOR_HTTPS_READY`. The tunnel endpoints are disposable and are not suitable for reproducible pairwise identities across multiple runs.

**AWS:** Deploy public sector JSON through HTTPS under **two distinct persistent hostnames** (Route 53 / CloudFront + ACM / S3 or ALB) with a CI check that the JSON lists exactly the registered callbacks. Keep `lab.env`, credentials, and operator endpoints private; do not use Cloudflare Quick Tunnels in AWS. The BFF session and issuer TLS topology require a separate integration plan.

**Evidence:** Successful bootstrap only verifies creation responses. Capture real OIDC `sub` for four clients for the same user, require Aurora Web = Aurora Mobile and Brisa Web = Brisa Mobile and Aurora ≠ Brisa, and bind the observed issuer to each token. Until then, pairwise compliance is **NOT_VERIFIED**.

Reference: [OpenID Connect Core 1.0 §8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg), [OpenID Dynamic Registration §5](https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation).
