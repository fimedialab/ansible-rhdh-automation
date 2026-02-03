# Keycloak Direct Grant POC

## Purpose

Proof of concept for authenticating to RHDH RBAC Backend API using Keycloak's Direct Grant (Resource Owner Password Credentials) flow.

## Problem Statement

RHDH's RBAC Backend API restricts static service-to-service tokens to read-only operations. Write operations (create/update/delete permissions) require a user-type JWT token.

Reference: [RBAC Backend Source](https://github.com/backstage/community-plugins/blob/ded22e4e1888493df5059015ffb8962dfc2e4563/workspaces/rbac/plugins/rbac-backend/src/service/policies-rest-api.ts)

## Solution

Use Keycloak's Direct Grant flow to authenticate as a user and obtain a user-type JWT token that can perform write operations.

## Prerequisites

1. **Keycloak Configuration**:
   - Direct Access Grants enabled on RHDH client
   - Service user account created in realm
   - User has appropriate RHDH permissions

2. **Tools**:
   - `curl`
   - `jq`
   - `base64`

## Running the POC

### Option 1: Environment Variables
```bash
export KEYCLOAK_URL="https://your-keycloak.com"
export REALM_NAME="your-realm"
export CLIENT_ID="rhdh-client"
export USERNAME="service-automation-user"
export PASSWORD="your-password"
export RHDH_API_URL="https://your-rhdh.com"

./test_auth.sh
```

### Option 2: Direct Editing

Edit `test_auth.sh` and update the configuration variables at the top of the script.

## Expected Results

### Success Scenario
```
✓ Token acquired successfully
✓ Token is user-type (required for RBAC write operations)
✓ READ operation successful
✓ WRITE operation successful!
```

### Common Failures

**"Direct grant is disabled for the client"**
- Enable "Direct Access Grants" in Keycloak client settings

**"Invalid credentials"**
- Verify username/password are correct
- Check user exists in the specified realm

**"Only credential principal with type 'user' permitted"**
- Token is not recognized as user-type
- May indicate service account being used instead of user account
- Check Keycloak client configuration

## Next Steps

Once validated, this authentication flow will be implemented as an Ansible role (`rhdh_auth`) for use in automated RHDH configuration workflows.
