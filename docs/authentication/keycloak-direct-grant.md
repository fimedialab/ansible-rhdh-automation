# Keycloak Direct Grant Authentication for RHDH

## Overview

This document describes the authentication mechanism used to obtain JWT tokens for RHDH RBAC Backend API write operations.

## Background

### The Challenge

RHDH's RBAC Backend API has a built-in security constraint:
```typescript
if (principal.type !== 'user') {
  // Only user principals can modify permissions
}
```

This means:
- ✅ Static service tokens: Read-only access
- ✅ User JWT tokens: Full read/write access

### The Solution

Use Keycloak's **Direct Grant** (Resource Owner Password Credentials) flow to authenticate as a service user and obtain a user-type JWT token.

## Authentication Flow
```
┌─────────┐                ┌──────────┐                ┌──────┐
│ Ansible │                │ Keycloak │                │ RHDH │
└────┬────┘                └────┬─────┘                └───┬──┘
     │                          │                          │
     │ 1. POST /token           │                          │
     │   (username/password)    │                          │
     ├─────────────────────────>│                          │
     │                          │                          │
     │ 2. JWT Token             │                          │
     │<─────────────────────────┤                          │
     │                          │                          │
     │ 3. POST /api/permission/policies                    │
     │   Authorization: Bearer <token>                     │
     ├────────────────────────────────────────────────────>│
     │                          │                          │
     │ 4. Success Response      │                          │
     │<────────────────────────────────────────────────────┤
     │                          │                          │
```

## Implementation Details

### Token Endpoint
```
POST {keycloak_url}/realms/{realm}/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password
client_id={rhdh_client_id}
username={service_user}
password={service_password}
```

### Response
```json
{
  "access_token": "eyJhbGc...",
  "expires_in": 300,
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer"
}
```

### Using the Token
```
POST {rhdh_url}/api/permission/policies
Authorization: Bearer {access_token}
Content-Type: application/json
```

## Security Considerations

1. **Service User Credentials**
   - Store in secure credential management (e.g., HashiCorp Vault)
   - Use dedicated service account with minimal required permissions
   - Rotate credentials regularly

2. **Token Handling**
   - Tokens are short-lived (typically 5-15 minutes)
   - Do not log or persist tokens
   - Request new tokens for each automation run

3. **Keycloak Configuration**
   - Ensure Direct Access Grants is enabled only on necessary clients
   - Configure appropriate token lifetime policies
   - Monitor authentication attempts

## Troubleshooting

### Direct Grant Disabled

**Error**: `"error": "unauthorized_client"`

**Solution**: Enable Direct Access Grants in Keycloak:
1. Admin Console → Clients → [RHDH Client]
2. Settings → Direct Access Grants Enabled: ON
3. Save

### Invalid Credentials

**Error**: `"error": "invalid_grant"`

**Solution**: Verify:
- Username/password are correct
- User exists in the specified realm
- User account is enabled

### Token Not Accepted for Write Operations

**Error**: "Only credential principal with type 'user' permitted"

**Diagnosis**:
Decode the JWT payload to check principal type:
```bash
echo $TOKEN | cut -d'.' -f2 | base64 -d | jq '.'
```

Look for `preferred_username` field - should contain the service user's username, not a service account identifier.

## References

- [Keycloak Direct Grant Documentation](https://www.keycloak.org/docs/latest/securing_apps/#_resource_owner_password_credentials_flow)
- [RHDH RBAC Backend Source](https://github.com/backstage/community-plugins/tree/main/workspaces/rbac/plugins/rbac-backend)
- [Backstage Service-to-Service Auth](https://backstage.io/docs/auth/service-to-service-auth/)
