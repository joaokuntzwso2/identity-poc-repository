#!/usr/bin/env python3
"""Validate *sanitized BFF-reported* browser-login evidence from stdin.

Never handles OAuth tokens or credentials. This is NOT a cryptographic JWT verifier:
the actual signed ID-token checks live in services/identity-bff/src/oidc.js.
"""
import json
import sys
from datetime import datetime

CLIENTS = {
    "aurora-web": "aurora.identity.test",
    "aurora-app": "aurora.identity.test",
    "brisa-web": "brisa.identity.test",
    "brisa-app": "brisa.identity.test",
}
MAX_BYTES = 100_000


def check(document):
    if not isinstance(document, dict):
        raise ValueError("SESSION_RESPONSE_NOT_AN_OBJECT")
    clients = document.get("clients")
    if not isinstance(clients, dict):
        raise ValueError("SESSION_CLIENTS_MISSING")
    report = {
        "gate": "CIAM_V10_BROWSER_SESSION_EVIDENCE",
        "identitySourceVerified": document.get("identitySource") == "WSO2_SIGNED_ID_TOKEN",
        "bffSignedTokenEvidence": document.get("evidence") == "BFF_VALIDATED_SIGNED_ID_TOKEN",
        "globalAuthenticated": document.get("authenticated") is True,
        "channels": {},
    }
    for key, domain in CLIENTS.items():
        entry = clients.get(key)
        if not isinstance(entry, dict):
            entry = {}
        expected_issuer = f"https://localhost:9444/t/{domain}/oauth2/token"
        date = entry.get("verifiedAt")
        valid_date = False
        if isinstance(date, str):
            try:
                parsed = datetime.fromisoformat(date.replace("Z", "+00:00"))
                valid_date = parsed.tzinfo is not None
            except ValueError:
                pass
        checks = {
            "configured": entry.get("configured") is True,
            "authenticated": entry.get("authenticated") is True,
            "tenantIssuerMatches": entry.get("issuer") == expected_issuer,
            "verifiedAtPresent": valid_date,
            "subjectFingerprintPresent": isinstance(entry.get("subjectFingerprint"), str) and 8 <= len(entry["subjectFingerprint"]) <= 128,
        }
        report["channels"][key] = {
            "passed": all(checks.values()),
            "checks": checks,
        }
    report["passed"] = (
        report["identitySourceVerified"]
        and report["bffSignedTokenEvidence"]
        and report["globalAuthenticated"]
        and all(v["passed"] for v in report["channels"].values())
    )
    report["limits"] = [
        "BFF_REPORTED_EVIDENCE_NOT_INDEPENDENT_TOKEN_VERIFICATION",
        "PAIRWISE_SECTORS_NOT_VERIFIED",
        "CROSS_TENANT_SSO_NOT_VERIFIED",
        "NATIVE_MOBILE_NOT_TESTED",
    ]
    return report


def main():
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        print("CIAM_V10_ACCEPTANCE_STOP: INPUT_TOO_LARGE", file=sys.stderr)
        return 2
    try:
        session = json.loads(raw)
        report = check(session)
    except (ValueError, UnicodeError) as exc:
        print("CIAM_V10_ACCEPTANCE_STOP: INVALID_SANITIZED_SESSION_JSON", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
