#!/bin/bash

# POC: Keycloak Direct Grant for RHDH API Authentication
# Tests acquiring a user-type JWT token and using it for RHDH RBAC API calls

set -e

# Configuration - Update these with your environment values
KEYCLOAK_URL="${KEYCLOAK_URL:-https://keycloak.example.com}"
REALM_NAME="${REALM_NAME:-your-realm}"
CLIENT_ID="${CLIENT_ID:-rhdh-client}"
USERNAME="${USERNAME:-service-user}"
PASSWORD="${PASSWORD:-changeme}"
RHDH_API_URL="${RHDH_API_URL:-https://rhdh.example.com}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo "RHDH Authentication POC - Keycloak Direct Grant"
echo "=================================================="
echo ""

# Validate jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}ERROR: jq is not installed. Please install it first.${NC}"
    exit 1
fi

echo "Configuration:"
echo "  Keycloak URL: $KEYCLOAK_URL"
echo "  Realm: $REALM_NAME"
echo "  Client ID: $CLIENT_ID"
echo "  Username: $USERNAME"
echo "  RHDH API URL: $RHDH_API_URL"
echo ""

echo "=== Step 1: Acquiring token from Keycloak ==="
TOKEN_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
  echo -e "${RED}ERROR: Failed to acquire token${NC}"
  echo "Response:"
  echo $TOKEN_RESPONSE | jq '.'
  exit 1
fi

echo -e "${GREEN}✓ Token acquired successfully${NC}"
echo "Token preview: ${ACCESS_TOKEN:0:50}..."
echo ""

echo "=== Step 2: Decoding token to verify principal type ==="
TOKEN_PAYLOAD=$(echo $ACCESS_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null)
echo "Token claims:"
echo $TOKEN_PAYLOAD | jq '{typ, preferred_username, azp, exp}'
echo ""

PRINCIPAL_TYPE=$(echo $TOKEN_PAYLOAD | jq -r '.typ // "unknown"')
USERNAME_IN_TOKEN=$(echo $TOKEN_PAYLOAD | jq -r '.preferred_username // "unknown"')

if [ "$PRINCIPAL_TYPE" == "Bearer" ] && [ "$USERNAME_IN_TOKEN" != "unknown" ]; then
    echo -e "${GREEN}✓ Token is user-type (required for RBAC write operations)${NC}"
else
    echo -e "${YELLOW}⚠ Token type may not be suitable for write operations${NC}"
fi
echo ""

echo "=== Step 3: Testing READ operation (list permissions) ==="
READ_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X GET "${RHDH_API_URL}/api/permission/policies" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json")

HTTP_STATUS=$(echo "$READ_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$READ_RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" == "200" ]; then
    POLICY_COUNT=$(echo "$BODY" | jq '. | length')
    echo -e "${GREEN}✓ READ operation successful${NC}"
    echo "Number of existing policies: $POLICY_COUNT"
else
    echo -e "${RED}✗ READ operation failed (HTTP $HTTP_STATUS)${NC}"
    echo "$BODY" | jq '.' || echo "$BODY"
fi
echo ""

echo "=== Step 4: Testing WRITE operation (create test permission) ==="
TEST_POLICY='[
  {
    "entityReference": "role:default/poc-test-role",
    "permission": "catalog-entity",
    "policy": "read",
    "effect": "allow"
  }
]'

CREATE_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "${RHDH_API_URL}/api/permission/policies" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$TEST_POLICY")

HTTP_STATUS=$(echo "$CREATE_RESPONSE" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "$CREATE_RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" == "201" ] || [ "$HTTP_STATUS" == "200" ]; then
    echo -e "${GREEN}✓ WRITE operation successful!${NC}"
    echo "Response:"
    echo "$BODY" | jq '.'
else
    echo -e "${RED}✗ WRITE operation failed (HTTP $HTTP_STATUS)${NC}"
    echo "Response:"
    echo "$BODY" | jq '.' || echo "$BODY"
    
    if echo "$BODY" | grep -q "Only credential principal with type 'user' permitted"; then
        echo -e "\n${YELLOW}This confirms the token is not recognized as a user principal.${NC}"
        echo "Possible issues:"
        echo "  - Direct Access Grants not enabled on Keycloak client"
        echo "  - Token format not recognized by RHDH backend"
        echo "  - Service account being used instead of user account"
    fi
fi
echo ""

echo "=================================================="
echo "POC Test Complete"
echo "=================================================="

