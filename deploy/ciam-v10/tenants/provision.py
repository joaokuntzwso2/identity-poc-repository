#!/usr/bin/env python3
"""WSO2 7.3 isolated v10, phase 1: guarded creation of TWO ROOT TENANTS.
This does not claim user, OAuth client, or browser provisioning.
"""
import base64
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import sys
import tempfile
import urllib.parse

BASE = "https://localhost:9444"
BRANDS = {"aurora": "aurora.identity.test", "brisa": "brisa.identity.test"}
ROOT = Path(os.environ.get("CIAM_V10_HOME", str(Path.home() / "wso2-ciam-v10")))
ADMIN = ROOT / "private/admin.private.json"
STATE = ROOT / "private/bootstrap-tenants-v10.private.json"
LOCK = ROOT / "private/bootstrap-tenants-v10.lock"
OWNER_USERNAME = "labtenantadmin"
SCOPE_PATH = "/api/server/v1/tenants"
ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{5,128}$")

class Refuse(Exception):
    pass

def check_private(path: Path):
    if path.is_symlink() or not path.is_file():
        raise Refuse("PRIVATE_FILE_NOT_REGULAR_" + path.name)
    s = path.stat()
    if stat.S_IMODE(s.st_mode) != 0o600 or s.st_uid != os.getuid():
        raise Refuse("PRIVATE_FILE_PERMISSIONS_" + path.name)
    return json.loads(path.read_text())

def state_write(path: Path, state: dict):
    """Atomic, restrictive write; fsync before rename, never follow a symlink."""
    if path.is_symlink():
        raise Refuse("JOURNAL_SYMLINK_REFUSED")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".bootstrap-tenants.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(state, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def fresh_owner(brand):
    return {"username": OWNER_USERNAME, "password": secrets.token_urlsafe(36) + "!aA9",
            "firstname": "Identity", "lastname": "Lab",
            "email": f"ciam-admin-{brand}@example.invalid", "provisioningMethod": "inline-password"}

class HTTPS:
    """Local TLS trust-on-first-use, same method used in the successful v10 admin preflight."""
    def __init__(self, username, password):
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        cert = ssl.get_server_certificate(("localhost", 9444))
        self.context = ssl.create_default_context(cadata=cert)
        self.context.check_hostname = False

    def call(self, method, path, payload=None, basic_override=None):
        if method not in {"GET", "POST"} or not path.startswith("/") or path.startswith("//") or ".." in path:
            raise Refuse("UNSAFE_HTTP_METHOD_OR_PATH")
        conn = http.client.HTTPSConnection("localhost", 9444, context=self.context, timeout=15)
        auth = self.auth
        if basic_override is not None:
            user, password = basic_override
            if not user or not password: raise Refuse("EMPTY_BASIC_AUTH")
            auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        headers = {"Authorization": auth, "Accept": "application/json"}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload)
        try:
            conn.request(method, path, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read(524289)
            if len(data) > 524288: raise Refuse("WSO2_RESPONSE_TOO_LARGE")
            if 300 <= r.status < 400: raise Refuse("WSO2_REDIRECT_REFUSED")
            try: parsed = json.loads(data) if data else {}
            except json.JSONDecodeError: parsed = None
            return r.status, parsed
        finally:
            conn.close()

def inventory(client):
    status, data = client.call("GET", SCOPE_PATH + "?limit=100&offset=0")
    if status != 200: raise Refuse(f"TENANT_INVENTORY_HTTP_{status}")
    if not isinstance(data, dict): raise Refuse("TENANT_INVENTORY_NOT_OBJECT")
    values = data.get("tenants")
    if values is None and data.get("totalResults") == 0 and data.get("count") == 0 and data.get("links") == []:
        values = []
    if not isinstance(values, list) or data.get("totalResults") != len(values):
        raise Refuse("TENANT_INVENTORY_INCOMPLETE_REFUSED")
    return {x.get("domain"): x for x in values if isinstance(x, dict)}

def owner_readback(client, brand, item):
    domain = BRANDS[brand]
    code, d = client.call("GET", SCOPE_PATH + "/domain/" + domain)
    if code != 200 or not isinstance(d, dict) or d.get("domain") != domain:
        raise Refuse("TENANT_READBACK_FAILED_" + brand + "_HTTP_" + str(code))
    tid = d.get("id")
    if not isinstance(tid, str) or not ID_PATTERN.fullmatch(tid) or d.get("lifecycleStatus", {}).get("activated") is not True:
        raise Refuse("TENANT_READBACK_INVALID_" + brand)
    if item.get("tenantId") and item["tenantId"] != tid: raise Refuse("TENANT_ID_DRIFT_"+brand)
    code, owners = client.call("GET", SCOPE_PATH + "/" + tid + "/owners")
    if code != 200 or not isinstance(owners, list): raise Refuse("OWNER_LIST_FAILED_"+brand)
    matching = [x for x in owners if isinstance(x, dict) and x.get("username") == OWNER_USERNAME]
    if len(matching) != 1 or not ID_PATTERN.fullmatch(str(matching[0].get("id", ""))):
        raise Refuse("OWNER_NOT_UNIQUE_" + brand)
    oid = matching[0]["id"]
    if item.get("ownerId") and item["ownerId"] != oid: raise Refuse("OWNER_ID_DRIFT_"+brand)
    code, detail = client.call("GET", SCOPE_PATH + "/" + tid + "/owners/" + oid)
    if code != 200 or not isinstance(detail, dict): raise Refuse("OWNER_DETAILS_FAILED_"+brand)
    if detail.get("id") != oid or any(detail.get(k) != item["owner"].get(k) for k in ("username", "firstname", "lastname", "email")):
        raise Refuse("OWNER_DETAILS_MISMATCH_"+brand)
    return tid, oid

def run(client, state_file=STATE, mode="plan", save=state_write):
    found = inventory(client)
    s = check_private(state_file) if state_file.exists() or state_file.is_symlink() else None
    if s and (s.get("schema") != "identity.wso2.ciam.v10.tenants" or s.get("base") != BASE or
              s.get("domains") != BRANDS or not isinstance(s.get("tenants"), dict)):
        raise Refuse("PRIVATE_JOURNAL_CONTEXT_MISMATCH")
    if not s: s = {"schema": "identity.wso2.ciam.v10.tenants", "base": BASE, "domains": BRANDS, "tenants": {}, "acceptance": "NOT_VERIFIED"}
    if any(d not in BRANDS.values() for d in found):
        raise Refuse("NON_LAB_TENANT_PRESENT_REFUSED")
    if mode == "plan":
        return {"mode": "PLAN_GET_ONLY", "rootTenantCount": len(found), "journaledTenantCount": len(s["tenants"]),
                "plannedDomains": list(BRANDS.values()), "writes": 0, "browserAuthentication": "NOT_VERIFIED"}
    if mode != "apply": raise Refuse("UNSUPPORTED_MODE")
    if os.environ.get("WSO2_CIAM_V10_CONFIRM") != "CREATE_TWO_NEW_ROOT_TENANTS":
        raise Refuse("EXPLICIT_V10_WRITE_CONFIRMATION_REQUIRED")
    if not state_file.exists() and found:
        raise Refuse("FRESH_DEPLOYMENT_HAS_UNJOURNALED_TENANTS")
    for brand, domain in BRANDS.items():
        item = s["tenants"].get(brand)
        if item is None:
            if domain in found: raise Refuse("UNOWNED_TENANT_COLLISION_"+brand)
            item = {"domain": domain, "owner": fresh_owner(brand), "status": "prepared"}
            s["tenants"][brand] = item
            save(state_file, s)
        if item.get("domain") != domain or item.get("owner",{}).get("username") != OWNER_USERNAME or not item["owner"].get("password"):
            raise Refuse("OWNER_JOURNAL_DRIFT_"+brand)
        if item["status"] == "prepared":
            if domain in found: raise Refuse("PREPARED_TENANT_ALREADY_EXISTS_"+brand)
            item["status"] = "create-started"
            save(state_file, s)
            try:
                code, _ = client.call("POST", SCOPE_PATH,
                    {"name": "Identity Lab " + brand.title(), "domain": domain, "owners": [item["owner"]]})
            except Exception:
                raise Refuse("TENANT_CREATE_OUTCOME_UNKNOWN_"+brand+"_DO_NOT_RETRY") from None
            if code != 201:
                raise Refuse("TENANT_CREATE_HTTP_"+str(code)+"_"+brand+"_DO_NOT_RETRY")
            item["status"] = "api-acknowledged"
            save(state_file, s)
        if item["status"] == "create-started":
            raise Refuse("UNRESOLVED_TENANT_CREATION_"+brand+"_DO_NOT_RETRY")
        if item["status"] not in {"api-acknowledged", "readback-verified"}:
            raise Refuse("UNKNOWN_TENANT_JOURNAL_STATE_"+brand)
        tid, oid = owner_readback(client, brand, item)
        item["tenantId"], item["ownerId"] = tid, oid
        item["status"] = "readback-verified"
        save(state_file, s)
        found[domain] = {"id": tid}
    s["acceptance"] = "TWO_ROOT_TENANTS_READBACK_VERIFIED_AUTH_NOT_VERIFIED"
    save(state_file, s)
    authority = {}
    for brand, domain in BRANDS.items():
        url = f"/t/{domain}/api/server/v1/applications?limit=1"
        try:
            root_code, _ = client.call("GET", url)
        except Exception:
            root_code = "REQUEST_FAILED"
        try:
            owner = s["tenants"][brand]["owner"]
            # One tenant-local Basic API attempt per fresh owner; no login form submissions.
            owner_code, _ = client.call("GET", url, basic_override=(OWNER_USERNAME, owner["password"]))
        except Exception:
            owner_code = "REQUEST_FAILED"
        authority[brand] = {"superAdminTenantApplicationReadHTTP": root_code,
                            "tenantLocalOwnerApplicationReadHTTP": owner_code}
    return {"mode": "APPLIED", "tenants": {b: {"domain": BRANDS[b], "status": s["tenants"][b]["status"]} for b in BRANDS},
            "passwords": "GENERATED_PRIVATE_NOT_PRINTED", "ownerLogin": "NOT_BROWSER_VERIFIED", "tenantApiAuthorization": authority,
            "clients": "NOT_PROVISIONED", "users": "NOT_PROVISIONED",
            "nextStage": "MANAGEMENT_SCOPES_AND_SCIM_AUTOMATION"}

def main():
    cmd = sys.argv[1] if len(sys.argv)>1 else "plan"
    if cmd not in {"plan", "apply", "status"}: raise Refuse("EXPECTED_plan_apply_status")
    if cmd == "status":
        if STATE.exists():
            s = check_private(STATE)
            print(json.dumps({"state": s.get("acceptance"), "tenants": {b: s.get("tenants",{}).get(b, {}).get("status", "NOT_STARTED") for b in BRANDS},
              "secretsPrinted": False, "browserLogin": "NOT_VERIFIED"}, indent=2))
        else: print('{"state":"NOT_STARTED"}')
        return
    adm = check_private(ADMIN)
    if adm.get("username") != "admin" or not isinstance(adm.get("password"), str) or len(adm["password"]) < 24:
        raise Refuse("ADMIN_CREDENTIALS_INVALID")
    if STATE.exists() or STATE.is_symlink(): check_private(STATE)
    client = HTTPS(adm["username"], adm["password"])
    if cmd == "apply":
        if LOCK.exists() or LOCK.is_symlink(): raise Refuse("POSSIBLE_CONCURRENT_BOOTSTRAP_LOCK")
        fd = os.open(str(LOCK), os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600)
        try:
            os.write(fd, b"CIAM v10 exclusive bootstrap lock\n")
            print(json.dumps(run(client, mode="apply"), indent=2))
        finally:
            os.close(fd)
            LOCK.unlink()
    else:
        print(json.dumps(run(client, mode="plan"), indent=2))

if __name__ == "__main__":
    try: main()
    except (Refuse, OSError, ValueError, ssl.SSLError) as e:
        print("CIAM_V10_TENANTS_STOP: " + (str(e) if isinstance(e, Refuse) else type(e).__name__), file=sys.stderr)
        sys.exit(1)
