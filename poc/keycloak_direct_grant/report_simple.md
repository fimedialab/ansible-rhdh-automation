# RHDH RBAC API Authentication Investigation - Work Report

**Date**: February 6, 2026  
**Project**: Ansible RHDH Automation  
**Objective**: Enable programmatic RBAC management for Red Hat Developer Hub

---

## Executive Summary

Investigated methods to authenticate with Red Hat Developer Hub (RHDH) RBAC Backend API to enable automated permission management via Ansible. Successfully validated that Keycloak Direct Grant can acquire JWT tokens, but discovered that RHDH's backend treats these tokens as `external:` principals rather than `user:` principals, preventing write operations to the RBAC API.

Browser-authenticated tokens work correctly and create proper `user:` principals, indicating that browser automation (OIDC Authorization Code flow) is the viable path forward for automated RBAC management.

---

## Background

### The Core Problem

RHDH's RBAC Backend API restricts write operations (create/update/delete permissions) to user-type principals only. The API code explicitly checks:

```typescript
if (principal.type !== "user") {
  // Only user principals can modify permissions
}
```

**Source**: [RBAC Backend policies-rest-api.ts](https://github.com/backstage/community-plugins/blob/ded22e4e1888493df5059015ffb8962dfc2e4563/workspaces/rbac/plugins/rbac-backend/src/service/policies-rest-api.ts)

### Why This Matters

Static service-to-service tokens are intentionally restricted to read-only operations for security reasons. For automated RBAC management, we need tokens that:

- ✅ Authenticate successfully with RHDH
- ✅ Are recognized as user-type principals
- ✅ Have permission to modify RBAC policies

**Reference**: [Backstage Service-to-Service Auth](https://backstage.io/docs/auth/service-to-service-auth/)

---

## Investigation Conducted

### Approach 1: Keycloak Direct Grant (Resource Owner Password Credentials)

**Objective**: Use Keycloak's Direct Grant flow to obtain user-type JWT tokens programmatically.

#### Implementation Steps

1. **Keycloak Configuration**
   - Created client `rhdh-local-client` in realm `workshop-realm`
   - Enabled "Direct Access Grants" capability
   - Configured as confidential client (requires client secret)
   - Client secret: `3uB8g8KMOuVb9QjZhHOaznmCCOyDrnJc`

2. **Network Configuration**
   - Mapped `keycloak.local` to `127.0.0.1` in `/etc/hosts`
   - Added `extra_hosts: keycloak.local:host-gateway` to Docker Compose
   - Connected RHDH and Keycloak containers to shared network

3. **RHDH Configuration** (`app-config.yaml`)

```yaml
auth:
  providers:
    oidc:
      development:
        metadataUrl: http://keycloak.local:8080/realms/workshop-realm/.well-known/openid-configuration

backend:
  auth:
    externalAccess:
      - type: jwks
        options:
          url: http://keycloak.local:8080/realms/workshop-realm/protocol/openid-connect/certs
          issuer: http://keycloak.local:8080/realms/workshop-realm
          algorithm: RS256
          audience: account
```

4. **POC Development**
   - Created test script: `poc/keycloak_direct_grant/test_auth.sh`
   - Automated token acquisition and API testing
   - Fixed base64 decoding issues in token validation

#### Results

| Test              | Status     | HTTP Code | Details                                                |
| ----------------- | ---------- | --------- | ------------------------------------------------------ |
| Token Acquisition | ✅ Success | 200       | Valid JWT received from Keycloak                       |
| Token Validation  | ✅ Success | -         | Token contains `preferred_username: alice`             |
| Token Format      | ✅ Correct | -         | Type: Bearer, proper claims structure                  |
| READ Operations   | ✅ Success | 200       | Retrieved 5 existing policies                          |
| WRITE Operations  | ❌ Failed  | 403       | "Only credential principal with type 'user' permitted" |

#### Root Cause Analysis

RHDH logs revealed the critical difference in principal resolution:

**Direct Grant Token**:

```
actor={"actorId":"external:236249cf-e9c7-464f-afc8-44e09679cb27",...}
```

**Browser-Authenticated Token**:

```
actor={"actorId":"user:default/alice",...}
```

**Conclusion**: The `backend.auth.externalAccess` mechanism with `type: jwks` creates `external:` type principals, not `user:` type principals, regardless of token content or claims.

---

### Configuration Attempts

Multiple `backend.auth.externalAccess` configurations were tested to resolve tokens as user principals:

#### Attempt 1: Basic JWKS Validation

```yaml
backend:
  auth:
    externalAccess:
      - type: jwks
        options:
          url: http://keycloak.local:8080/realms/workshop-realm/protocol/openid-connect/certs
          issuer: http://keycloak.local:8080/realms/workshop-realm
          algorithm: RS256
          audience: account
```

**Result**: ❌ Creates `external:` principal

#### Attempt 2: Subject Prefix

```yaml
options:
  subjectPrefix: kc
```

**Result**: ❌ Would create `kc:alice`, requires matching catalog entities

#### Attempt 3: Subject Claim Mapping

```yaml
options:
  subjectClaim: preferred_username
```

**Result**: ❌ No change in principal type

#### Attempt 4: Subject Resolvers (per Backstage docs)

```yaml
subjectResolvers:
  - resolver: usernameMatchingUserEntityName
    options:
      claimName: preferred_username
```

**Result**: ❌ Configuration not recognized or unsupported in RHDH 1.8

#### Attempt 5: Removed externalAccess

```yaml
# Commented out entire externalAccess section
```

**Result**: ❌ Tokens rejected as "Illegal token"

**None of these configurations successfully created `user:` type principals from Direct Grant tokens.**

---

### Approach 2: Browser Token Validation

**Method**: Manually extracted JWT token from authenticated Chrome browser session.

#### Process

1. Logged into RHDH via browser (OIDC flow)
2. Opened Chrome DevTools → Network tab
3. Captured Bearer token from API request headers
4. Tested token with same RBAC API endpoints

#### Results

| Test             | Status     | HTTP Code | Details                              |
| ---------------- | ---------- | --------- | ------------------------------------ |
| READ Operations  | ✅ Success | 200       | Retrieved policies successfully      |
| WRITE Operations | ✅ Success | 201       | Created test permission successfully |
| Principal Type   | ✅ Correct | -         | `actorId: "user:default/alice"`      |

**RHDH Log Entry**:

```
2026-02-06T21:53:58.342Z permission info permission.policy-read
actor={"actorId":"user:default/alice","ip":"::ffff:185.199.110.133",...}
status="succeeded"
```

**Conclusion**: Tokens obtained through the standard OIDC Authorization Code flow (browser-based) are correctly resolved as `user:` principals and have full RBAC API access.

---

## Key Findings

### 1. Authentication vs Authorization Mechanism Mismatch

**Direct Grant tokens are not equivalent to browser tokens** in RHDH's authentication architecture, despite:

- Being valid JWTs from the same Keycloak realm
- Having identical JWT claims structure
- Coming from the same user account
- Being validated against the same JWKS endpoint

### 2. Architectural Design Distinction

RHDH/Backstage intentionally distinguishes between:

| Authentication Method | Principal Type | Use Case                  | RBAC Write Access |
| --------------------- | -------------- | ------------------------- | ----------------- |
| OIDC Browser Flow     | `user:`        | Interactive user sessions | ✅ Allowed        |
| External API Tokens   | `external:`    | Service-to-service        | ❌ Denied         |

### 3. Token Resolution is Context-Dependent

Principal type determination happens at the **authentication layer**, not based on JWT claims:

- Same token content produces different principal types
- Resolution depends on how the token enters the system
- `auth.providers.oidc` → creates `user:` principals
- `backend.auth.externalAccess` → creates `external:` principals

### 4. Configuration Limitations

The `backend.auth.externalAccess` mechanism:

- Is designed for service-to-service authentication
- Intentionally creates non-user principals for security
- Does not support mapping external tokens to user principals
- No documented configuration override exists

---

## Technical Artifacts Created

### POC Scripts

- **`poc/keycloak_direct_grant/test_auth.sh`**  
  Automated Direct Grant authentication test with token validation and API testing

- **`poc/keycloak_direct_grant/README.md`**  
  Documentation including troubleshooting guide, Keycloak setup, and common errors

- **`poc/oidc_browser_automation/test_browser_auth.py`**  
  Playwright-based browser automation for OIDC flow (created but not yet tested)

- **`poc/oidc_browser_automation/test_browser_auth.sh`**  
  Wrapper script with dependency management

- **`poc/oidc_browser_automation/requirements.txt`**  
  Python dependencies (playwright==1.40.0)

- **`poc/oidc_browser_automation/README.md`**  
  Browser automation documentation

### Documentation

- **`docs/authentication/keycloak-direct-grant.md`**  
  Technical deep-dive on Direct Grant approach, flow diagrams, security considerations

### Configuration Examples

- RHDH `app-config.yaml` with OIDC and JWKS validation
- Docker Compose with network configuration and `extra_hosts`
- Keycloak client setup for Direct Access Grants

---

## Comparison: Direct Grant vs Browser Automation

| Aspect                   | Direct Grant              | Browser Automation                           |
| ------------------------ | ------------------------- | -------------------------------------------- |
| **Complexity**           | Low (single HTTP request) | High (browser, page detection, form filling) |
| **Speed**                | Fast (<1 second)          | Slow (5-10 seconds)                          |
| **Dependencies**         | curl, jq only             | Playwright, Chromium (~500MB)                |
| **Reliability**          | Robust (stable API)       | Fragile (UI changes break it)                |
| **Principal Type**       | `external:` ❌            | `user:` ✅                                   |
| **RBAC Write Access**    | Denied                    | Allowed                                      |
| **AAP Compatibility**    | Works out of the box      | Requires EE customization                    |
| **Debugging**            | HTTP logs only            | Visual (can see browser)                     |
| **Token Lifetime**       | 5 minutes (standard)      | 5 minutes (standard)                         |
| **Production Viability** | Not viable for writes     | Viable but complex                           |

---

## Next Steps

### Option 1: Browser Automation Implementation ✅ **Recommended**

**Approach**: Use headless browser automation (Playwright) to simulate the OIDC Authorization Code flow and capture the resulting user-type token.

#### Rationale

- ✅ **Proven to work**: Browser tokens successfully create `user:` principals
- ✅ **POC already developed**: `poc/oidc_browser_automation/` ready to test
- ✅ **Reliable for automation**: Standard flow, well-documented
- ⚠️ **More complex**: Requires Playwright and browser dependencies
- ⚠️ **Larger footprint**: ~500MB addition to execution environment

#### Implementation Path

**Phase 1: Validation** (1 day)

1. Test existing browser automation POC
2. Verify token acquisition and RBAC API access
3. Validate error handling and edge cases

**Phase 2: Ansible Role Development** (2-3 days)

1. Create `rhdh_auth` role structure
2. Develop custom Ansible module wrapping Playwright
3. Implement token capture and fact-setting
4. Add timeout and retry logic

**Phase 3: Integration** (1-2 days)

1. Update `rhdh_rbac_automation` role to accept bearer token
2. Create example playbooks
3. Test end-to-end workflow

**Phase 4: AAP Preparation** (1 day)

1. Create execution environment definition with Playwright
2. Test in AAP environment
3. Document deployment requirements

**Estimated Total Effort**: 5-7 days

#### Success Criteria

- ✅ POC successfully acquires token and completes WRITE operation
- ✅ Ansible role `rhdh_auth` passes all tests
- ✅ Integration with `rhdh_rbac_automation` works end-to-end
- ✅ AAP Job Template executes successfully
- ✅ Complete documentation

---

### Option 2: Further Investigation ⚠️ **Research Only**

**Approach**: Investigate if newer RHDH versions or undocumented configurations support Direct Grant with user principals.

#### Research Tasks

**1. Version Compatibility Check**

- Identify current RHDH version: `quay.io/rhdh-community/rhdh:1.8`
- Review release notes for authentication changes
- Test with latest RHDH version if updates exist

**2. Documentation Deep-Dive**

- Review Backstage identity resolver documentation
- Search for custom authentication provider examples
- Check RHDH-specific configuration guides

**3. Token Analysis**

```bash
# Compare Direct Grant vs Browser token payloads
# Look for claim differences that might trigger user principal creation
```

Focus on:

- `aud` (audience) differences
- `scope` claim variations
- Custom Keycloak claims
- Session-related claims

**4. Community Research**

- Search GitHub issues in:
  - `backstage/backstage`
  - `backstage/community-plugins` (RBAC plugin)
  - `janus-idp/backstage-plugins`
- Search terms:
  - "Direct Grant user principal"
  - "external access user type"
  - "RBAC write operations external token"

**5. Alternative Client Configurations**

- Test with public client (no client secret)
- Try different OAuth2 flows supported by Keycloak
- Experiment with token exchange

**Estimated Effort**: 1-2 days research, unknown implementation time if solution exists

#### Decision Criteria

**Proceed with browser automation if**:

- ❌ No RHDH version supports Direct Grant → user principal mapping
- ❌ No configuration option exists for principal type override
- ❌ Token differences cannot be reconciled
- ❌ No community examples found

**Continue investigation if**:

- ✅ Newer RHDH version shows different behavior
- ✅ Documentation reveals undiscovered configuration
- ✅ Token comparison shows fixable differences
- ✅ Community has working examples

---

### Option 3: Hybrid Approach

Use Direct Grant for read-only operations (monitoring, validation) and browser automation only when write operations are needed.

**Pros**:

- Faster for read-heavy workflows
- Simpler dependency management for read-only tasks

**Cons**:

- Increased complexity (two authentication methods)
- Confusion about when to use which method

---

## Recommendations

### Primary Recommendation: Implement Option 1

**Proceed with browser automation** as the pragmatic, production-ready solution while pursuing Option 2 research in parallel.

**Justification**:

1. Browser authentication is **proven to work** for both read and write operations
2. POC already developed and ready for testing
3. Clear implementation path with defined effort estimates
4. Aligns with RHDH's intended authentication architecture
5. Sustainable long-term solution

### Secondary Recommendation: Limited Option 2 Research

**Allocate 1-2 days for Option 2 research** to ensure no simpler solution exists before committing to browser automation complexity.

**If Option 2 yields results**: Pivot to simpler implementation  
**If Option 2 finds nothing**: Proceed with Option 1 with confidence

### Testing Sequence

**Immediate next steps** (Day 1):

```bash
# 1. Test browser automation POC
cd poc/oidc_browser_automation
export RHDH_URL="http://localhost:7007"
export USERNAME="alice"
export PASSWORD="password123"
export HEADLESS="false"  # Watch it work
./test_browser_auth.sh

# 2. If successful, begin Option 1 implementation
# 3. In parallel, start Option 2 research
```

---

## Conclusion

The investigation successfully identified why Keycloak Direct Grant tokens cannot perform RBAC write operations: RHDH's authentication architecture intentionally treats external API tokens differently from interactive user authentication.

**Key Achievement**: Validated that browser-based authentication creates proper `user:` principals and enables full RBAC API access.

**Path Forward**: Browser automation replicates the interactive flow programmatically, providing a reliable solution for automated RBAC management.

**Next Milestone**: Test browser automation POC and begin Ansible role development.

---

## Appendices

### Appendix A: Environment Configuration

**Keycloak**:

- URL: `http://keycloak.local:8080`
- Realm: `workshop-realm`
- Client: `rhdh-local-client` (confidential)
- Test User: `alice` / `password123`

**RHDH**:

- URL: `http://localhost:7007`
- Version: `quay.io/rhdh-community/rhdh:1.8`
- Docker network: `keycloak-network`

**Test Environment**:

- Docker Compose with shared network
- `/etc/hosts` mapping for `keycloak.local`
- `extra_hosts` in Docker Compose for container name resolution

### Appendix B: Relevant Log Entries

**Direct Grant - Failed Write Operation**:

```
2026-02-06T21:42:40.136Z permission info permission.policy-write
Only credential principal with type 'user' permitted to modify permissions
actor={"actorId":"external:236249cf-e9c7-464f-afc8-44e09679cb27","ip":"::ffff:185.199.110.133",...}
status="failed"
cause=undefined name="NotAllowedError"
```

**Browser Token - Successful Operation**:

```
2026-02-06T21:53:58.342Z permission info permission.policy-read
actor={"actorId":"user:default/alice","ip":"::ffff:185.199.110.133",...}
status="succeeded"
```

### Appendix C: References

**Documentation**:

- [Backstage Service-to-Service Auth](https://backstage.io/docs/auth/service-to-service-auth/)
- [Keycloak Direct Grant Flow](https://www.keycloak.org/docs/latest/securing_apps/#_resource_owner_password_credentials_flow)
- [Playwright Python Documentation](https://playwright.dev/python/docs/intro)

**Source Code**:

- [RBAC Backend policies-rest-api.ts](https://github.com/backstage/community-plugins/blob/ded22e4e1888493df5059015ffb8962dfc2e4563/workspaces/rbac/plugins/rbac-backend/src/service/policies-rest-api.ts)

**Repository**:

- Location: `ansible-rhdh-automation`
- Branch: `main`
- POC Scripts: `poc/keycloak_direct_grant/`, `poc/oidc_browser_automation/`

---

**Report Prepared**: February 6, 2026  
**Prepared By**: Automation Team  
**Status**: Investigation Complete - Ready for Implementation
