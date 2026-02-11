Document 2: Technical Continuation
markdown# RHDH RBAC API Authentication - Technical Continuation Document

**Last Updated**: February 6, 2026  
**Project**: Ansible RHDH Automation  
**Purpose**: Complete technical context for resuming work

---

## Quick Context Summary

**What we're building**: Ansible automation to manage RHDH RBAC permissions programmatically

**The challenge**: RHDH RBAC Backend API only allows write operations from `user:` type principals, not `external:` or service principals

**What we discovered**:

- ✅ Keycloak Direct Grant works but creates `external:` principals (read-only)
- ✅ Browser authentication creates `user:` principals (read+write)
- ✅ Solution: Use browser automation to replicate interactive authentication

**Current state**: POCs complete, ready to implement Ansible role

**Repository**: `ansible-rhdh-automation`

---

## Table of Contents

1. [Environment Setup](#environment-setup)
2. [The Technical Problem](#the-technical-problem)
3. [Investigation Results](#investigation-results)
4. [Implementation Guide - Option 1 (Browser Automation)](#implementation-guide-option-1)
5. [Research Guide - Option 2 (Further Investigation)](#research-guide-option-2)
6. [Reference Commands](#reference-commands)
7. [Integration with Existing Work](#integration-with-existing-work)
8. [Files and Structure](#files-and-structure)

---

## Environment Setup

### Keycloak Configuration

```yaml
URL: http://keycloak.local:8080
Realm: workshop-realm
Client ID: rhdh-local-client
Client Type: Confidential
Client Secret: 3uB8g8KMOuVb9QjZhHOaznmCCOyDrnJc
Direct Access Grants: Enabled
Test User: alice / password123
```

**Keycloak Client Settings**:

- Standard Flow: Enabled
- Direct Access Grants: Enabled
- Valid Redirect URIs: `http://localhost:7007/*`
- Web Origins: `http://localhost:7007`

### RHDH Configuration

```yaml
URL: http://localhost:7007
Version: quay.io/rhdh-community/rhdh:1.8
Container Name: rhdh
Network: keycloak-network
Config File: app-config.yaml
User Entity: user:default/alice (exists in catalog)
```

### Docker Setup

**docker-compose.yaml excerpt**:

```yaml
services:
  rhdh:
    container_name: rhdh
    image: quay.io/rhdh-community/rhdh:1.8
    ports:
      - "7007:7007"
    extra_hosts:
      - "keycloak.local:host-gateway" # Critical for hostname resolution
    networks:
      - keycloak-network

networks:
  keycloak-network:
    external: true
    name: docker_keycloak-network
```

### Host Configuration

**`/etc/hosts`**:

```
127.0.0.1 keycloak.local
```

This mapping allows:

- Host machine to access Keycloak at `http://keycloak.local:8080`
- RHDH container to access Keycloak via `extra_hosts` mapping

### RHDH app-config.yaml

**Working configuration**:

```yaml
auth:
  environment: development
  session:
    secret: ${AUTH_SESSION_SECRET}
  providers:
    oidc:
      development:
        clientId: ${AUTH_KEYCLOAK_CLIENT_ID}
        clientSecret: ${AUTH_KEYCLOAK_CLIENT_SECRET}
        metadataUrl: http://keycloak.local:8080/realms/workshop-realm/.well-known/openid-configuration
        prompt: auto
        signIn:
          resolvers:
            - resolver: preferredUsernameMatchingUserEntityName
            - resolver: emailMatchingUserEntityProfileEmail

signInPage: oidc

permission:
  enabled: true
  rbac:
    admin:
      users:
        - name: user:default/alice

backend:
  auth:
    keys:
      - secret: "development"

    # Note: externalAccess configurations were tested but none
    # successfully created user: principals from Direct Grant tokens
```

---

## The Technical Problem

### RBAC Backend Code Constraint

RHDH's RBAC Backend API has an explicit check:

```typescript
// Source: https://github.com/backstage/community-plugins/blob/ded22e4e1888493df5059015ffb8962dfc2e4563/workspaces/rbac/plugins/rbac-backend/src/service/policies-rest-api.ts

if (principal.type !== "user") {
  throw new NotAllowedError(
    "Only credential principal with type 'user' permitted to modify permissions",
  );
}
```

**What this means**:

- Static service tokens: ❌ Write operations denied
- External API tokens: ❌ Write operations denied
- User principals: ✅ Write operations allowed

### Authentication Flow Comparison

**Direct Grant Flow (Creates `external:` principal)**:

```
┌─────────┐                ┌──────────┐                ┌──────┐
│ Ansible │                │ Keycloak │                │ RHDH │
└────┬────┘                └────┬─────┘                └───┬──┘
     │                          │                          │
     │ POST /token              │                          │
     │ grant_type=password      │                          │
     │ username=alice           │                          │
     ├─────────────────────────>│                          │
     │                          │                          │
     │ JWT Token                │                          │
     │<─────────────────────────┤                          │
     │                          │                          │
     │ POST /api/permission/policies                       │
     │ Authorization: Bearer                        │
     ├────────────────────────────────────────────────────>│
     │                          │                          │
     │                          │  backend.auth.externalAccess
     │                          │  validates token via JWKS
     │                          │  Creates: external:UUID  │
     │                          │                          │
     │ 403 Forbidden            │                          │
     │<────────────────────────────────────────────────────┤
```

**Browser Flow (Creates `user:` principal)**:

```
┌─────────┐       ┌──────┐       ┌──────────┐       ┌──────┐
│ Browser │       │ RHDH │       │ Keycloak │       │ RHDH │
└────┬────┘       └───┬──┘       └────┬─────┘       └───┬──┘
     │                │                │                 │
     │ GET /          │                │                 │
     ├───────────────>│                │                 │
     │                │                │                 │
     │ 302 Redirect   │                │                 │
     │<───────────────┤                │                 │
     │                │                │                 │
     │ GET /auth?client_id=...         │                 │
     ├────────────────────────────────>│                 │
     │                │                │                 │
     │ Login Page HTML│                │                 │
     ││                 │
     │                │                │                 │
     │ 302 Redirect with code          │                 │
     │<────────────────────────────────┤                 │
     │                │                │                 │
     │ GET /callback?code=ABC          │                 │
     ├───────────────────────────────────────────────────>│
     │                │                │                 │
     │                │                │  Exchange code  │
     │                │                │  for token      │
     │                │                │                 │
     │                │                │  auth.providers.oidc
     │                │                │  resolves identity
     │                │                │  Creates: user:default/alice
     │                │                │                 │
     │ Set-Cookie: auth-token          │                 │
     │<───────────────────────────────────────────────────┤
     │                │                │                 │
     │ POST /api/permission/policies   │                 │
     │ Cookie: auth-token              │                 │
     ├───────────────────────────────────────────────────>│
     │                │                │                 │
     │ 200 OK         │                │                 │
     │<───────────────────────────────────────────────────┤
```

### Token Payload Comparison

Both tokens contain nearly identical claims, but are resolved differently:

**Direct Grant Token**:

```json
{
  "exp": 1770413134,
  "iat": 1770412834,
  "jti": "a70510dd-ff7a-4c84-8622-3a12254d21c1",
  "iss": "http://keycloak.local:8080/realms/workshop-realm",
  "aud": ["demo-app", "account"],
  "sub": "236249cf-e9c7-464f-afc8-44e09679cb27",
  "typ": "Bearer",
  "azp": "rhdh-local-client",
  "session_state": "7a6c9fb6-c5a2-459c-8656-75822ebb40ef",
  "acr": "1",
  "realm_access": {
    "roles": [
      "default-roles-workshop-realm",
      "offline_access",
      "uma_authorization",
      "user"
    ]
  },
  "resource_access": {
    "demo-app": { "roles": ["viewer"] },
    "account": {
      "roles": ["manage-account", "manage-account-links", "view-profile"]
    }
  },
  "scope": "profile email",
  "email_verified": true,
  "name": "Alice Smith",
  "preferred_username": "alice",
  "given_name": "Alice",
  "family_name": "Smith",
  "email": "alice@example.com"
}
```

**RHDH Resolution**: `external:236249cf-e9c7-464f-afc8-44e09679cb27` (from `sub` claim)

**Browser Token** (similar payload, different resolution):

**RHDH Resolution**: `user:default/alice` (from `preferred_username` via OIDC resolver)

### RHDH Log Evidence

**Direct Grant - Write Attempt**:

```
2026-02-06T21:42:40.136Z permission info permission.policy-write
Only credential principal with type 'user' permitted to modify permissions
isAuditEvent=true eventId="policy-write" severityLevel="medium"
actor={
  "actorId":"external:236249cf-e9c7-464f-afc8-44e09679cb27",
  "ip":"::ffff:185.199.110.133",
  "hostname":"localhost",
  "userAgent":"curl/8.7.1"
}
request={"url":"/api/permission/policies","method":"POST"}
meta={"actionType":"create","source":"rest","response":{"status":403}}
status="failed"
```

**Browser Token - Write Success**:

```
2026-02-06T21:53:58.342Z permission info permission.policy-read
isAuditEvent=true eventId="policy-read" severityLevel="medium"
actor={
  "actorId":"user:default/alice",
  "ip":"::ffff:185.199.110.133",
  "hostname":"localhost",
  "userAgent":"curl/8.7.1"
}
request={"url":"/api/permission/policies","method":"GET"}
meta={"source":"rest","queryType":"all","response":{"status":200}}
status="succeeded"
```

**Key Difference**: `"actorId":"external:..."` vs `"actorId":"user:default/alice"`

---

## Investigation Results

### What Was Tested

#### Configuration Attempts

All attempts to make Direct Grant tokens resolve as `user:` principals:

**Attempt 1: Basic JWKS**

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

**Result**: ❌ `external:UUID` principal

**Attempt 2: Subject Prefix**

```yaml
options:
  subjectPrefix: kc
```

**Result**: ❌ Would create `kc:alice`, not `user:default/alice`

**Attempt 3: Subject Claim**

```yaml
options:
  subjectClaim: preferred_username
```

**Result**: ❌ No effect on principal type

**Attempt 4: Subject Resolvers** (from Backstage docs)

```yaml
subjectResolvers:
  - resolver: usernameMatchingUserEntityName
    options:
      claimName: preferred_username
```

**Result**: ❌ Configuration not recognized (possibly version-specific)

**Attempt 5: No externalAccess**

```yaml
# Removed entire externalAccess section
```

**Result**: ❌ Token rejected as "Illegal token"

### What Works

**Browser-extracted tokens**:

- ✅ Authenticate successfully
- ✅ Create `user:default/alice` principal
- ✅ Allow READ operations (HTTP 200)
- ✅ Allow WRITE operations (HTTP 201)

**Validation method**:

```bash
# Extract token from Chrome DevTools
# Network tab → API request → Headers → Authorization

BROWSER_TOKEN="eyJhbGc..."

# Test with RBAC API
curl -X POST "http://localhost:7007/api/permission/policies" \
  -H "Authorization: Bearer $BROWSER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{
    "entityReference": "role:default/test",
    "permission": "catalog-entity",
    "policy": "read",
    "effect": "allow"
  }]'
# Returns: HTTP 201 Created
```

### Conclusion

**RHDH/Backstage architecture intentionally treats authentication methods differently**:

| Method       | Entry Point                   | Principal Type | RBAC Write |
| ------------ | ----------------------------- | -------------- | ---------- |
| Browser OIDC | `auth.providers.oidc`         | `user:`        | ✅         |
| Direct Grant | `backend.auth.externalAccess` | `external:`    | ❌         |

This is by design, not a bug or configuration issue.

---

## Implementation Guide - Option 1

### Browser Automation Approach

**Strategy**: Use Playwright to automate the OIDC Authorization Code flow, capturing the bearer token from authenticated API requests.

### Phase 1: Test POC (Day 1)

**Location**: `poc/oidc_browser_automation/`

**Setup**:

```bash
cd poc/oidc_browser_automation

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers (one-time, ~500MB download)
playwright install chromium
```

**Test with visible browser** (recommended first run):

```bash
export RHDH_URL="http://localhost:7007"
export USERNAME="alice"
export PASSWORD="password123"
export HEADLESS="false"  # See the browser in action

./test_browser_auth.sh
```

**Expected output**:

```
==================================================
RHDH Authentication POC - Browser Automation
==================================================

Step 1: Launching browser
  ✓ Browser launched

Step 2: Navigating to RHDH
  ✓ Loaded: http://localhost:7007

Step 3: Detecting authentication page
  → Redirected to: http://keycloak.local:8080/realms/workshop-realm/...

Step 4: Filling login form
  ✓ Entered username
  ✓ Entered password

Step 5: Submitting login
  ✓ Clicked login button
  → Waiting for authentication to complete...
  ✓ Redirected back to: http://localhost:7007/catalog

Step 6: Waiting for API calls with bearer token
  ✓ Captured bearer token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

Step 7: Testing token with RHDH API
  ✓ Token works! Retrieved 5 policies
  Token saved to: /tmp/rhdh_bearer_token.txt

==================================================
POC Complete - Token Successfully Acquired!
==================================================
```

**Test with headless mode**:

```bash
export HEADLESS="true"
./test_browser_auth.sh
```

**If POC succeeds**, proceed to Phase 2.

---

### Phase 2: Create Ansible Role (Days 2-4)

#### Directory Structure

```bash
mkdir -p roles/rhdh_auth/{tasks,defaults,library,meta,files}
touch roles/rhdh_auth/README.md
```

**Structure**:

```
roles/rhdh_auth/
├── defaults/
│   └── main.yml              # Default variables
├── files/
│   └── browser_auth.py       # Playwright script (standalone version)
├── library/
│   └── rhdh_browser_auth.py  # Custom Ansible module
├── meta/
│   └── main.yml              # Role metadata
├── tasks/
│   └── main.yml              # Main tasks
└── README.md                 # Documentation
```

#### Custom Ansible Module

**File**: `roles/rhdh_auth/library/rhdh_browser_auth.py`

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

from ansible.module_utils.basic import AnsibleModule
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
import json
import time

DOCUMENTATION = '''
---
module: rhdh_browser_auth
short_description: Acquire RHDH bearer token via browser automation
description:
    - Uses Playwright to simulate browser login to RHDH via Keycloak
    - Captures bearer token from authenticated API requests
    - Returns token and expiry for use in subsequent RBAC API calls
options:
    rhdh_url:
        description: URL of RHDH instance
        required: true
        type: str
    username:
        description: Keycloak username
        required: true
        type: str
    password:
        description: Keycloak password
        required: true
        type: str
        no_log: true
    timeout:
        description: Maximum time to wait for authentication (seconds)
        required: false
        default: 30
        type: int
author:
    - Ansible RHDH Automation Team
'''

EXAMPLES = '''
# Basic usage
- name: Acquire RHDH bearer token
  rhdh_browser_auth:
    rhdh_url: "https://rhdh.example.com"
    username: "{{ vault_rhdh_username }}"
    password: "{{ vault_rhdh_password }}"
  register: auth_result

# Use token for API calls
- name: List RBAC policies
  uri:
    url: "{{ rhdh_url }}/api/permission/policies"
    headers:
      Authorization: "Bearer {{ auth_result.token }}"
    method: GET
  register: policies

# With custom timeout
- name: Acquire token with longer timeout
  rhdh_browser_auth:
    rhdh_url: "https://rhdh.example.com"
    username: "automation-user"
    password: "{{ vault_password }}"
    timeout: 60
  register: auth_result
'''

RETURN = '''
token:
    description: Bearer token for RHDH API authentication
    type: str
    returned: success
    sample: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
token_expiry:
    description: Token expiration timestamp (Unix epoch)
    type: int
    returned: success
    sample: 1770413134
expiry_seconds:
    description: Seconds until token expires
    type: int
    returned: success
    sample: 300
'''

def extract_token_from_request(route):
    """Extract bearer token from Authorization header"""
    headers = route.request.headers
    auth_header = headers.get('authorization', '')
    if auth_header.startswith('Bearer ') or auth_header.startswith('bearer '):
        return auth_header.split(' ', 1)[1]
    return None

def acquire_token(rhdh_url, username, password, timeout=30):
    """
    Use Playwright to acquire bearer token via browser automation

    Args:
        rhdh_url: RHDH instance URL
        username: Keycloak username
        password: Keycloak password
        timeout: Timeout in seconds

    Returns:
        str: Bearer token if successful

    Raises:
        Exception: If authentication fails
    """

    bearer_token = None

    with sync_playwright() as p:
        # Launch headless browser
        browser = p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage']  # For container environments
        )

        context = browser.new_context(
            viewport={'width': 1280, 'height': 720},
            ignore_https_errors=True,  # For self-signed certs
            user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        )

        page = context.new_page()

        # Capture tokens from API requests
        captured_tokens = []

        def handle_route(route):
            """Intercept API requests to capture Authorization header"""
            token = extract_token_from_request(route)
            if token and token not in captured_tokens:
                captured_tokens.append(token)
            route.continue_()

        # Intercept all RHDH API calls
        page.route(f"{rhdh_url}/api/**", handle_route)

        try:
            # Navigate to RHDH
            page.goto(rhdh_url, timeout=timeout*1000, wait_until='networkidle')

            # Wait for potential redirect to Keycloak
            page.wait_for_timeout(2000)

            current_url = page.url.lower()

            # Check if on Keycloak login page
            if 'keycloak' in current_url or page.locator('input[name="username"]').count() > 0:
                # Fill username
                username_field = page.locator('input[name="username"], input[id="username"]').first
                username_field.fill(username)

                # Fill password
                password_field = page.locator('input[name="password"], input[id="password"]').first
                password_field.fill(password)

                # Submit form
                submit_button = page.locator('input[type="submit"], button[type="submit"]').first
                submit_button.click()

                # Wait for redirect back to RHDH
                page.wait_for_url(f"{rhdh_url}/**", timeout=timeout*1000)

            # Give RHDH time to make authenticated API calls
            page.wait_for_timeout(5000)

            # Navigate to catalog to trigger more API calls
            try:
                page.goto(f"{rhdh_url}/catalog", wait_until='networkidle', timeout=10000)
                page.wait_for_timeout(3000)
            except:
                pass  # Page navigation might timeout but token still captured

            if captured_tokens:
                bearer_token = captured_tokens[0]
            else:
                raise Exception("No bearer token captured from API requests")

        except PlaywrightTimeout as e:
            raise Exception(f"Timeout during authentication: {str(e)}")
        except Exception as e:
            raise Exception(f"Authentication failed: {str(e)}")
        finally:
            browser.close()

    return bearer_token

def decode_jwt_expiry(token):
    """
    Decode JWT token to extract expiry time

    Args:
        token: JWT token string

    Returns:
        int: Expiry timestamp (Unix epoch) or None if decode fails
    """
    try:
        import base64
        # JWT format: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return None

        # Decode payload (add padding if needed)
        payload = parts[1]
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += '=' * padding

        decoded = base64.urlsafe_b64decode(payload)
        payload_json = json.loads(decoded)

        return payload_json.get('exp')
    except:
        return None

def run_module():
    """Main module execution"""

    module_args = dict(
        rhdh_url=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        timeout=dict(type='int', required=False, default=30)
    )

    result = dict(
        changed=False,
        token='',
        token_expiry=0,
        expiry_seconds=0
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=False
    )

    try:
        # Acquire token via browser automation
        token = acquire_token(
            module.params['rhdh_url'],
            module.params['username'],
            module.params['password'],
            module.params['timeout']
        )

        if not token:
            module.fail_json(msg='Failed to capture bearer token', **result)

        # Decode token to get expiry
        expiry = decode_jwt_expiry(token)
        if expiry:
            result['token_expiry'] = expiry
            result['expiry_seconds'] = max(0, expiry - int(time.time()))
        else:
            # Default to 5 minutes (Keycloak default)
            result['token_expiry'] = int(time.time()) + 300
            result['expiry_seconds'] = 300

        result['token'] = token
        result['changed'] = True

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=str(e), **result)

def main():
    run_module()

if __name__ == '__main__':
    main()
```

#### Role Tasks

**File**: `roles/rhdh_auth/tasks/main.yml`

```yaml
---
- name: Validate required variables
  ansible.builtin.assert:
    that:
      - rhdh_url is defined
      - rhdh_url | length > 0
      - rhdh_username is defined
      - rhdh_username | length > 0
      - rhdh_password is defined
      - rhdh_password | length > 0
    fail_msg: "Required variables: rhdh_url, rhdh_username, rhdh_password"
    quiet: true

- name: Display authentication attempt
  ansible.builtin.debug:
    msg: "Acquiring RHDH bearer token for user: {{ rhdh_username }} at {{ rhdh_url }}"
  when: rhdh_auth_verbose | default(false)

- name: Check if Playwright is installed
  ansible.builtin.command: python3 -c "import playwright"
  register: playwright_check
  failed_when: false
  changed_when: false
  check_mode: false

- name: Install Playwright Python package
  ansible.builtin.pip:
    name:
      - playwright=={{ rhdh_auth_playwright_version | default('1.40.0') }}
    state: present
  when: playwright_check.rc != 0
  register: playwright_install

- name: Install Playwright browsers
  ansible.builtin.command: playwright install chromium
  when: playwright_install is changed
  changed_when: true

- name: Acquire RHDH bearer token via browser automation
  rhdh_browser_auth:
    rhdh_url: "{{ rhdh_url }}"
    username: "{{ rhdh_username }}"
    password: "{{ rhdh_password }}"
    timeout: "{{ rhdh_auth_timeout | default(30) }}"
  register: rhdh_auth_result
  no_log: "{{ not (rhdh_auth_verbose | default(false)) }}"

- name: Set token facts for downstream roles
  ansible.builtin.set_fact:
    rhdh_bearer_token: "{{ rhdh_auth_result.token }}"
    rhdh_token_expiry: "{{ rhdh_auth_result.token_expiry }}"
    rhdh_token_expiry_seconds: "{{ rhdh_auth_result.expiry_seconds }}"
  no_log: true

- name: Display authentication success
  ansible.builtin.debug:
    msg: >-
      Successfully acquired RHDH bearer token
      (expires in {{ rhdh_token_expiry_seconds }} seconds)
```

#### Role Defaults

**File**: `roles/rhdh_auth/defaults/main.yml`

```yaml
---
# RHDH Authentication Role - Default Variables

# Playwright version to install
rhdh_auth_playwright_version: "1.40.0"

# Authentication timeout in seconds
rhdh_auth_timeout: 30

# Verbose output (shows token details in logs - USE WITH CAUTION)
rhdh_auth_verbose: false

# Required variables (must be provided by playbook):
# rhdh_url: URL of RHDH instance
# rhdh_username: Username for authentication
# rhdh_password: Password for authentication
```

#### Role Metadata

**File**: `roles/rhdh_auth/meta/main.yml`

```yaml
---
galaxy_info:
  role_name: rhdh_auth
  author: Ansible RHDH Automation Team
  description: Acquire RHDH bearer tokens via browser automation
  company: N/A

  license: MIT

  min_ansible_version: "2.9"

  platforms:
    - name: EL
      versions:
        - 8
        - 9
    - name: Ubuntu
      versions:
        - focal
        - jammy

  galaxy_tags:
    - rhdh
    - backstage
    - authentication
    - rbac
    - keycloak

dependencies: []
```

#### Role Documentation

**File**: `roles/rhdh_auth/README.md`

````markdown
# RHDH Auth Role

Ansible role to acquire Red Hat Developer Hub (RHDH) bearer tokens via browser automation.

## Description

This role uses Playwright to automate the OIDC Authorization Code flow with Keycloak, capturing the bearer token that RHDH issues to authenticated users. The token can then be used for RBAC Backend API operations.

## Requirements

- Python 3.8+
- pip
- Playwright will be installed automatically if not present

## Role Variables

### Required Variables

```yaml
rhdh_url: "https://rhdh.example.com"
rhdh_username: "automation-user"
rhdh_password: "secure-password"
```

### Optional Variables

```yaml
# Playwright version
rhdh_auth_playwright_version: "1.40.0"

# Authentication timeout (seconds)
rhdh_auth_timeout: 30

# Verbose logging (shows token - USE WITH CAUTION)
rhdh_auth_verbose: false
```

### Output Facts

The role sets these facts for use in subsequent roles:

```yaml
rhdh_bearer_token: "eyJhbGc..." # Bearer token
rhdh_token_expiry: 1770413134 # Unix timestamp
rhdh_token_expiry_seconds: 300 # Seconds until expiry
```

## Dependencies

None.

## Example Playbook

```yaml
---
- name: Configure RHDH RBAC
  hosts: localhost
  gather_facts: true

  vars:
    rhdh_url: "https://rhdh.example.com"
    rhdh_username: "{{ vault_rhdh_username }}"
    rhdh_password: "{{ vault_rhdh_password }}"

  roles:
    - role: rhdh_auth

    - role: rhdh_rbac_automation
      vars:
        rbac_bearer_token: "{{ rhdh_bearer_token }}"
```

## AAP Integration

### Execution Environment Requirements

Your AAP execution environment must include Playwright and Chromium:

```dockerfile
RUN pip3 install playwright==1.40.0 && \
    playwright install --with-deps chromium
```

This adds approximately 500MB to the execution environment image.

### Job Template Configuration

No special configuration needed - the role handles dependency installation.

## Token Lifecycle

- Tokens typically expire after 5 minutes (Keycloak default)
- Each playbook run acquires a fresh token
- No token storage or refresh mechanism needed for short playbooks
- For playbooks > 5 minutes, re-run this role to get a new token

## Troubleshooting

### "Failed to capture bearer token"

**Cause**: Browser automation couldn't intercept the token

**Solutions**:

- Verify RHDH URL is correct and accessible
- Check username/password are correct
- Ensure Keycloak OIDC provider is configured in RHDH
- Increase `rhdh_auth_timeout`

### "Timeout during authentication"

**Cause**: RHDH or Keycloak took too long to respond

**Solutions**:

- Increase `rhdh_auth_timeout` (default: 30 seconds)
- Check network connectivity to RHDH and Keycloak
- Verify services are running

### "playwright install failed"

**Cause**: Missing system dependencies for Chromium

**Solutions**:

- If in AAP: Rebuild execution environment with Playwright dependencies
- If local: `playwright install --with-deps chromium`

## Security Considerations

- Credentials are marked with `no_log` to prevent logging
- Tokens are stored as Ansible facts (memory only, not persisted)
- Set `rhdh_auth_verbose: false` in production (default)
- Use Vault for credential storage

## License

MIT

## Author Information

Ansible RHDH Automation Team
````

---

### Phase 3: Integration (Days 5-6)

#### Update RBAC Role

Modify `roles/rhdh_rbac_automation/tasks/main.yml` to use the bearer token:

**Before**:

```yaml
- name: Get permissions
  ansible.builtin.uri:
    url: "{{ rhdh_url }}/api/permission/policies"
    # ... missing authentication
```

**After**:

```yaml
- name: Validate bearer token is provided
  ansible.builtin.assert:
    that:
      - rbac_bearer_token is defined
      - rbac_bearer_token | length > 0
    fail_msg: "rbac_bearer_token is required (provided by rhdh_auth role)"

- name: Get current permissions
  ansible.builtin.uri:
    url: "{{ rhdh_url }}/api/permission/policies"
    method: GET
    headers:
      Authorization: "Bearer {{ rbac_bearer_token }}"
      Content-Type: "application/json"
    return_content: yes
    status_code: 200
  register: current_permissions

- name: Create RBAC permissions
  ansible.builtin.uri:
    url: "{{ rhdh_url }}/api/permission/policies"
    method: POST
    headers:
      Authorization: "Bearer {{ rbac_bearer_token }}"
      Content-Type: "application/json"
    body: "{{ permissions_to_create | to_json }}"
    body_format: json
    status_code: [200, 201]
  register: create_result
  when: permissions_to_create | length > 0

- name: Delete RBAC permissions
  ansible.builtin.uri:
    url: "{{ rhdh_url }}/api/permission/policies"
    method: DELETE
    headers:
      Authorization: "Bearer {{ rbac_bearer_token }}"
      Content-Type: "application/json"
    body: "{{ permissions_to_delete | to_json }}"
    body_format: json
    status_code: [204, 200]
  register: delete_result
  when: permissions_to_delete | length > 0
```

#### Example Playbook

**File**: `playbooks/examples/configure_rhdh_rbac.yml`

```yaml
---
- name: Configure RHDH RBAC Permissions
  hosts: localhost
  gather_facts: true
  connection: local

  vars:
    # RHDH connection
    rhdh_url: "{{ lookup('env', 'RHDH_URL') | default('http://localhost:7007', true) }}"

    # Authentication (from Vault)
    rhdh_username: "{{ vault_rhdh_username }}"
    rhdh_password: "{{ vault_rhdh_password }}"

    # RBAC configuration
    org_label_value: "org-finance"
    role_type: "organisation"
    role_access_level: "admin"

  pre_tasks:
    - name: Display configuration
      ansible.builtin.debug:
        msg: |
          Configuring RBAC for:
            Organization: {{ org_label_value }}
            Role Type: {{ role_type }}
            Access Level: {{ role_access_level }}
            RHDH URL: {{ rhdh_url }}

  roles:
    # Step 1: Authenticate and acquire bearer token
    - role: rhdh_auth
      tags: ["auth", "always"]

    # Step 2: Configure RBAC using the token
    - role: rhdh_rbac_automation
      vars:
        rbac_bearer_token: "{{ rhdh_bearer_token }}"
      tags: ["rbac"]

  post_tasks:
    - name: Display completion
      ansible.builtin.debug:
        msg: "RBAC configuration completed successfully"
```

#### Test Playbook

**File**: `playbooks/test_auth_role.yml`

```yaml
---
- name: Test RHDH Authentication Role
  hosts: localhost
  gather_facts: false

  vars:
    rhdh_url: "http://localhost:7007"
    rhdh_username: "alice"
    rhdh_password: "password123"
    rhdh_auth_verbose: true # Show details for testing

  roles:
    - role: rhdh_auth

  tasks:
    - name: Validate token was acquired
      ansible.builtin.assert:
        that:
          - rhdh_bearer_token is defined
          - rhdh_bearer_token | length > 50
          - rhdh_token_expiry is defined
          - rhdh_token_expiry_seconds is defined
          - rhdh_token_expiry_seconds > 0
        success_msg: "Token acquired successfully"
        fail_msg: "Token acquisition failed"

    - name: Test READ operation with token
      ansible.builtin.uri:
        url: "{{ rhdh_url }}/api/permission/policies"
        method: GET
        headers:
          Authorization: "Bearer {{ rhdh_bearer_token }}"
          Content-Type: "application/json"
        return_content: yes
      register: read_test

    - name: Display READ test result
      ansible.builtin.debug:
        msg: "Successfully retrieved {{ read_test.json | length }} policies"

    - name: Test WRITE operation with token
      ansible.builtin.uri:
        url: "{{ rhdh_url }}/api/permission/policies"
        method: POST
        headers:
          Authorization: "Bearer {{ rhdh_bearer_token }}"
          Content-Type: "application/json"
        body:
          - entityReference: "role:default/test-ansible-role"
            permission: "catalog-entity"
            policy: "read"
            effect: "allow"
        body_format: json
        status_code: [200, 201]
      register: write_test

    - name: Display WRITE test result
      ansible.builtin.debug:
        msg: "Successfully created test permission"

    - name: Cleanup test permission
      ansible.builtin.uri:
        url: "{{ rhdh_url }}/api/permission/policies"
        method: DELETE
        headers:
          Authorization: "Bearer {{ rhdh_bearer_token }}"
          Content-Type: "application/json"
        body:
          - entityReference: "role:default/test-ansible-role"
            permission: "catalog-entity"
            policy: "read"
            effect: "allow"
        body_format: json
        status_code: [200, 204]
      register: cleanup_test

    - name: Final status
      ansible.builtin.debug:
        msg: |
          ✅ All tests passed!
          - Token acquisition: SUCCESS
          - READ operation: SUCCESS
          - WRITE operation: SUCCESS
          - Cleanup: SUCCESS
```

**Run test**:

```bash
ansible-playbook playbooks/test_auth_role.yml
```

---

### Phase 4: AAP Preparation (Day 7)

#### Execution Environment Definition

**File**: `execution-environment.yml`

```yaml
---
version: 3

images:
  base_image:
    name: registry.redhat.io/ansible-automation-platform-24/ee-minimal-rhel9:latest

dependencies:
  galaxy: requirements.yml
  python: requirements.txt
  system: bindep.txt

additional_build_steps:
  prepend_base:
    - RUN microdnf install -y python3.11 python3.11-pip

  append_final:
    - RUN pip3 install --upgrade pip
    - RUN pip3 install playwright==1.40.0
    - RUN playwright install --with-deps chromium
    - RUN chmod -R 755 /root/.cache/ms-playwright
```

**File**: `requirements.yml`

```yaml
---
collections:
  - name: ansible.builtin
  - name: community.general
```

**File**: `requirements.txt`

```
playwright==1.40.0
```

**File**: `bindep.txt`

```
python3-devel [platform:rpm]
gcc [platform:rpm]
```

**Build execution environment**:

```bash
ansible-builder build -t rhdh-automation-ee:latest -v 3
```

#### AAP Job Template

**Template Configuration**:

```yaml
Name: Configure RHDH RBAC
Job Type: Run
Inventory: localhost
Project: ansible-rhdh-automation
Playbook: playbooks/examples/configure_rhdh_rbac.yml
Credentials:
  - RHDH Vault Credential
Execution Environment: rhdh-automation-ee:latest
Extra Variables:
  rhdh_url: https://rhdh.example.com

Survey:
  - Question: Organization
    Variable: org_label_value
    Type: text
    Required: yes

  - Question: Role Type
    Variable: role_type
    Type: multiple_choice
    Choices:
      - organisation
      - environnement
      - cluster
      - division
      - projet
    Required: yes

  - Question: Access Level
    Variable: role_access_level
    Type: multiple_choice
    Choices:
      - admin
      - edit
      - view
    Required: yes
```

---

## Research Guide - Option 2

### Investigation Tasks

#### Task 1: Version Check

**Objective**: Determine if newer RHDH versions handle Direct Grant differently

**Commands**:

```bash
# Current version
docker exec rhdh cat /opt/app-root/package.json | jq '.version'

# Check available versions
docker search quay.io/rhdh-community/rhdh --limit 10

# Pull and test latest
docker pull quay.io/rhdh-community/rhdh:latest
```

**What to look for**:

- Release notes mentioning authentication changes
- New `backend.auth.externalAccess` options
- Changes to identity resolution

#### Task 2: Documentation Review

**Primary Sources**:

- [Backstage Auth Overview](https://backstage.io/docs/auth/)
- [Backstage Service-to-Service Auth](https://backstage.io/docs/auth/service-to-service-auth/)
- [Backstage Identity Resolver](https://backstage.io/docs/auth/identity-resolver)
- [RHDH Documentation](https://access.redhat.com/documentation/en-us/red_hat_developer_hub/)

**Search Terms**:

- "Direct Grant"
- "Resource Owner Password Credentials"
- "external access user principal"
- "token resolver"
- "identity resolver"
- "custom authentication provider"

#### Task 3: Token Analysis

**Compare Direct Grant vs Browser tokens**:

```bash
# Acquire both tokens
DG_TOKEN=$(curl -s -X POST "http://keycloak.local:8080/realms/workshop-realm/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=rhdh-local-client" \
  -d "client_secret=3uB8g8KMOuVb9QjZhHOaznmCCOyDrnJc" \
  -d "username=alice" \
  -d "password=password123" \
  | jq -r '.access_token')

# Browser token: Extract from Chrome DevTools
BROWSER_TOKEN="<paste-here>"

# Decode both
echo "=== Direct Grant Token ===" > /tmp/token_diff.txt
echo $DG_TOKEN | cut -d'.' -f2 | python3 -c \
  "import sys, base64, json; print(json.dumps(json.loads(base64.urlsafe_b64decode(sys.stdin.read() + '===')), indent=2, sort_keys=True))" \
  >> /tmp/token_diff.txt

echo -e "\n=== Browser Token ===" >> /tmp/token_diff.txt
echo $BROWSER_TOKEN | cut -d'.' -f2 | python3 -c \
  "import sys, base64, json; print(json.dumps(json.loads(base64.urlsafe_b64decode(sys.stdin.read() + '===')), indent=2, sort_keys=True))" \
  >> /tmp/token_diff.txt

# Compare
diff <(echo "$DG_TOKEN" | cut -d'.' -f2 | python3 -c "import sys, base64, json; print(json.dumps(json.loads(base64.urlsafe_b64decode(sys.stdin.read() + '===')), indent=2, sort_keys=True))") \
     <(echo "$BROWSER_TOKEN" | cut -d'.' -f2 | python3 -c "import sys, base64, json; print(json.dumps(json.loads(base64.urlsafe_b64decode(sys.stdin.read() + '===')), indent=2, sort_keys=True))")
```

**Look for differences in**:

- `aud` (audience)
- `scope`
- `session_state`
- Custom claims
- Realm or resource access roles

#### Task 4: GitHub Issues Search

**Repositories**:

- https://github.com/backstage/backstage/issues
- https://github.com/backstage/community-plugins/issues
- https://github.com/janus-idp/backstage-plugins/issues

**Search Queries**:

```
repo:backstage/backstage "Direct Grant" OR "Resource Owner Password"
repo:backstage/backstage "external access" AND "user principal"
repo:backstage/community-plugins "RBAC" AND "write operations"
repo:backstage/backstage "identity resolver" AND "custom"
```

**What to look for**:

- Similar use cases
- Workarounds or solutions
- Feature requests
- Configuration examples

#### Task 5: Keycloak Client Experiments

**Test different client configurations**:

**Experiment 1: Public Client**

```bash
# Create new client via Keycloak Admin Console
# - Client ID: rhdh-public-test
# - Client authentication: OFF (public client)
# - Direct access grants: ON
# - Standard flow: ON

# Test token
TOKEN=$(curl -s -X POST "http://keycloak.local:8080/realms/workshop-realm/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=rhdh-public-test" \
  -d "username=alice" \
  -d "password=password123" \
  | jq -r '.access_token')

# Test with RHDH
curl -X POST "http://localhost:7007/api/permission/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"entityReference":"role:default/test","permission":"catalog-entity","policy":"read","effect":"allow"}]'
```

**Experiment 2: Different Scopes**

```bash
# Request specific scopes
TOKEN=$(curl -s -X POST "http://keycloak.local:8080/realms/workshop-realm/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=rhdh-local-client" \
  -d "client_secret=3uB8g8KMOuVb9QjZhHOaznmCCOyDrnJc" \
  -d "username=alice" \
  -d "password=password123" \
  -d "scope=openid profile email" \
  | jq -r '.access_token')
```

**Experiment 3: Token Exchange**

```bash
# Try exchanging Direct Grant token for different token type
# (Requires token exchange enabled in Keycloak)
```

#### Task 6: Custom Auth Provider Research

**Objective**: Determine if RHDH supports custom authentication providers

**Research Areas**:

- Backstage plugin development docs
- Custom auth provider examples
- RHDH plugin architecture

**If viable**:

1. Create custom provider that wraps Direct Grant
2. Configure provider to resolve tokens as `user:` principals
3. Register provider in RHDH configuration

**Example structure**:

```typescript
// hypothetical custom provider
export const directGrantAuthProvider = {
  async authenticate(token: string) {
    // Validate token with Keycloak
    // Map to user principal
    return {
      principal: {
        type: "user",
        userEntityRef: `user:default/${username}`,
      },
    };
  },
};
```

### Decision Tree

```
Start Investigation
│
├─ Version Check
│  ├─ Newer version available?
│  │  ├─ Yes → Test with new version
│  │  │        ├─ Works → Update recommendation
│  │  │        └─ Fails → Continue investigation
│  │  └─ No → Continue investigation
│
├─ Documentation Review
│  ├─ Found relevant config?
│  │  ├─ Yes → Test configuration
│  │  │        ├─ Works → Document solution
│  │  │        └─ Fails → Continue investigation
│  │  └─ No → Continue investigation
│
├─ Token Analysis
│  ├─ Found significant differences?
│  │  ├─ Yes → Attempt to replicate browser token
│  │  │        ├─ Works → Document solution
│  │  │        └─ Fails → Continue investigation
│  │  └─ No → Continue investigation
│
├─ GitHub Issues
│  ├─ Found working example?
│  │  ├─ Yes → Implement and test
│  │  │        ├─ Works → Document solution
│  │  │        └─ Fails → Continue investigation
│  │  └─ No → Continue investigation
│
└─ Client Experiments
   ├─ Found working config?
   │  ├─ Yes → Document solution
   │  └─ No → Recommend Option 1 (Browser Automation)
```

### Stop Conditions

**Proceed with Option 1 if**:

- All research tasks complete with no viable alternative
- Time invested exceeds 2 days
- No promising leads remain

**Continue investigation if**:

- Found promising configuration options
- Community reports success with similar setup
- Token differences suggest fixable issue

---

## Reference Commands

### Token Management

**Acquire Direct Grant token**:

```bash
export KEYCLOAK_URL="http://keycloak.local:8080"
export REALM_NAME="workshop-realm"
export CLIENT_ID="rhdh-local-client"
export CLIENT_SECRET="3uB8g8KMOuVb9QjZhHOaznmCCOyDrnJc"
export USERNAME="alice"
export PASSWORD="password123"

TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  | jq -r '.access_token')

echo "Token: ${TOKEN:0:50}..."
```

**Decode JWT token**:

```bash
# Decode header
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null | jq '.'

# Decode payload
echo $TOKEN | cut -d'.' -f2 | python3 -c \
  "import sys, base64, json; print(json.dumps(json.loads(base64.urlsafe_b64decode(sys.stdin.read() + '===')), indent=2))"
```

### RBAC API Testing

**List permissions** (READ):

```bash
curl -s -X GET "http://localhost:7007/api/permission/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  | jq '.'
```

**Create permission** (WRITE):

```bash
curl -s -X POST "http://localhost:7007/api/permission/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "entityReference": "role:default/test-role",
      "permission": "catalog-entity",
      "policy": "read",
      "effect": "allow"
    }
  ]' \
  | jq '.'
```

**Delete permission**:

```bash
curl -s -X DELETE "http://localhost:7007/api/permission/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "entityReference": "role:default/test-role",
      "permission": "catalog-entity",
      "policy": "read",
      "effect": "allow"
    }
  ]' \
  | jq '.'
```

### RHDH Management

**View logs**:

```bash
# Follow logs
docker logs rhdh -f

# Filter for permission/auth logs
docker logs rhdh --tail 100 | grep -i "permission\|auth\|principal"

# View specific time range
docker logs rhdh --since 5m
```

**Restart RHDH**:

```bash
docker-compose restart rhdh

# Wait for startup
sleep 10

# Check health
curl -s http://localhost:7007/api/catalog/entities | jq '. | length'
```

**Check RHDH config**:

```bash
docker exec rhdh cat /opt/app-root/src/app-config.yaml | grep -A 20 "auth:"
```

### Keycloak Management

**Get admin token**:

```bash
ADMIN_TOKEN=$(curl -s -X POST "http://keycloak.local:8080/realms/master/protocol/openid-connect/token" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  | jq -r '.access_token')
```

**List clients**:

```bash
curl -s -X GET "http://keycloak.local:8080/admin/realms/workshop-realm/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq '.[] | {clientId, enabled, directAccessGrantsEnabled}'
```

**Get specific client config**:

```bash
curl -s -X GET "http://keycloak.local:8080/admin/realms/workshop-realm/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq '.[] | select(.clientId=="rhdh-local-client")'
```

**Check user exists**:

```bash
curl -s -X GET "http://keycloak.local:8080/admin/realms/workshop-realm/users?username=alice" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq '.[0] | {username, enabled, email}'
```

### POC Scripts

**Run Direct Grant POC**:

```bash
cd poc/keycloak_direct_grant
export CLIENT_SECRET="3uB8g8KMOuVb9QjZhHOaznmCCOyDrnJc"
./test_auth.sh
```

**Run Browser Automation POC**:

```bash
cd poc/oidc_browser_automation

# First time setup
pip install -r requirements.txt
playwright install chromium

# Run with visible browser
export HEADLESS="false"
./test_browser_auth.sh

# Run headless
export HEADLESS="true"
./test_browser_auth.sh
```

### Ansible Testing

**Test auth role**:

```bash
ansible-playbook playbooks/test_auth_role.yml
```

**Test full integration**:

```bash
ansible-playbook playbooks/examples/configure_rhdh_rbac.yml \
  -e "org_label_value=test-org" \
  -e "role_type=organisation" \
  -e "role_access_level=admin"
```

**Dry run with check mode**:

```bash
ansible-playbook playbooks/examples/configure_rhdh_rbac.yml --check
```

---

## Integration with Existing Work

### Workflow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ AAP Job Template: Configure RHDH RBAC                       │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│ Playbook: configure_rhdh_rbac.yml                           │
│                                                              │
│  Pre-tasks:                                                  │
│  ├─ Load organization parameters                            │
│  └─ Validate input variables                                │
│                                                              │
│  Roles:                                                      │
│  ├─ rhdh_auth (NEW)                                         │
│  │  ├─ Install Playwright if needed                         │
│  │  ├─ Launch headless browser                              │
│  │  ├─ Navigate to RHDH                                     │
│  │  ├─ Authenticate via Keycloak                            │
│  │  ├─ Capture bearer token                                 │
│  │  └─ Set fact: rhdh_bearer_token                          │
│  │                                                           │
│  └─ rhdh_rbac_automation (EXISTING - MODIFIED)              │
│     ├─ Load role definitions                                │
│     ├─ Get current permissions (using bearer token)         │
│     ├─ Calculate changes (reconciliation)                   │
│     ├─ Create new permissions (using bearer token)          │
│     ├─ Update existing permissions (using bearer token)     │
│     └─ Delete obsolete permissions (using bearer token)     │
│                                                              │
│  Post-tasks:                                                 │
│  └─ Display completion summary                              │
└─────────────────────────────────────────────────────────────┘
```

### Variable Flow

```yaml
# Input (from AAP Survey or Playbook vars)
org_label_value: "org-finance"
role_type: "organisation"
role_access_level: "admin"
rhdh_url: "https://idp-org1.example.com"

# Credentials (from Vault)
vault_rhdh_username: "automation-user"
vault_rhdh_password: "{{ vault_secret }}"

# Passed to rhdh_auth role
rhdh_username: "{{ vault_rhdh_username }}"
rhdh_password: "{{ vault_rhdh_password }}"

# Output from rhdh_auth role (set as facts)
rhdh_bearer_token: "eyJhbGc..." # JWT token
rhdh_token_expiry: 1770413134 # Unix timestamp
rhdh_token_expiry_seconds: 300 # Time until expiry

# Passed to rhdh_rbac_automation role
rbac_bearer_token: "{{ rhdh_bearer_token }}"

# Used in RBAC role for API calls
headers:
  Authorization: "Bearer {{ rbac_bearer_token }}"
```

### File Modifications Required

**New Files**:

```
roles/rhdh_auth/
├── defaults/main.yml
├── library/rhdh_browser_auth.py
├── meta/main.yml
├── tasks/main.yml
└── README.md

playbooks/examples/configure_rhdh_rbac.yml
playbooks/test_auth_role.yml
```

**Modified Files**:

```
roles/rhdh_rbac_automation/tasks/main.yml
  - Add: Bearer token authentication to all API calls
  - Add: Token validation
  - Update: Error handling for authentication failures

roles/rhdh_rbac_automation/defaults/main.yml
  - Add: rbac_bearer_token variable documentation

roles/rhdh_rbac_automation/README.md
  - Update: Authentication section
  - Add: Integration with rhdh_auth role
```

### Backward Compatibility

**Option 1**: Require rhdh_auth role (breaking change)

```yaml
# New playbooks must use both roles
roles:
  - rhdh_auth
  - rhdh_rbac_automation
```

**Option 2**: Support both methods (backward compatible)

```yaml
# In rhdh_rbac_automation/tasks/main.yml
- name: Check authentication method
  ansible.builtin.assert:
    that: >
      (rbac_bearer_token is defined) or
      (rbac_static_token is defined)
    fail_msg: "Either rbac_bearer_token or rbac_static_token required"

- name: Set token header
  ansible.builtin.set_fact:
    rbac_auth_header: >-
      {{ rbac_bearer_token if rbac_bearer_token is defined
         else rbac_static_token }}
```

Recommended: **Option 1** - Clean break, simpler maintenance

---

## Files and Structure

### Current Repository State

```
ansible-rhdh-automation/
├── LICENSE
├── README.md
├── poc/
│   ├── keycloak_direct_grant/
│   │   ├── test_auth.sh                    ✅ Complete
│   │   └── README.md                        ✅ Complete
│   └── oidc_browser_automation/
│       ├── test_browser_auth.py             ✅ Complete
│       ├── test_browser_auth.sh             ✅ Complete
│       ├── requirements.txt                 ✅ Complete
│       └── README.md                        ✅ Complete
├── docs/
│   └── authentication/
│       └── keycloak-direct-grant.md         ✅ Complete
└── roles/
    └── rhdh_rbac_automation/                ✅ Existing (needs update)
```

### Target Repository State (After Implementation)

```
ansible-rhdh-automation/
├── LICENSE
├── README.md                                 🔄 Update with auth info
├── poc/
│   ├── keycloak_direct_grant/               ✅ Complete
│   └── oidc_browser_automation/             ✅ Complete
├── docs/
│   └── authentication/
│       ├── keycloak-direct-grant.md         ✅ Complete
│       └── browser-automation.md            📝 New
├── roles/
│   ├── rhdh_auth/                           📝 New role
│   │   ├── defaults/main.yml
│   │   ├── library/rhdh_browser_auth.py
│   │   ├── meta/main.yml
│   │   ├── tasks/main.yml
│   │   └── README.md
│   └── rhdh_rbac_automation/                🔄 Update for token auth
│       ├── defaults/main.yml
│       ├── tasks/
│       │   └── main.yml
│       └── README.md
├── playbooks/
│   ├── examples/
│   │   └── configure_rhdh_rbac.yml          📝 New
│   └── test_auth_role.yml                   📝 New
└── execution-environment/
    ├── execution-environment.yml             📝 New
    ├── requirements.yml                      📝 New
    ├── requirements.txt                      📝 New
    └── bindep.txt                            📝 New
```

**Legend**:

- ✅ Complete - No changes needed
- 🔄 Update - Modifications required
- 📝 New - To be created

### File Status Checklist

**Phase 1 - POC Validation**:

- [x] poc/oidc_browser_automation/test_browser_auth.py
- [x] poc/oidc_browser_automation/test_browser_auth.sh
- [x] poc/oidc_browser_automation/requirements.txt
- [x] poc/oidc_browser_automation/README.md
- [ ] Test POC successfully

**Phase 2 - Role Development**:

- [ ] roles/rhdh_auth/defaults/main.yml
- [ ] roles/rhdh_auth/library/rhdh_browser_auth.py
- [ ] roles/rhdh_auth/meta/main.yml
- [ ] roles/rhdh_auth/tasks/main.yml
- [ ] roles/rhdh_auth/README.md

**Phase 3 - Integration**:

- [ ] roles/rhdh_rbac_automation/tasks/main.yml (update)
- [ ] roles/rhdh_rbac_automation/defaults/main.yml (update)
- [ ] roles/rhdh_rbac_automation/README.md (update)
- [ ] playbooks/examples/configure_rhdh_rbac.yml
- [ ] playbooks/test_auth_role.yml

**Phase 4 - AAP Preparation**:

- [ ] execution-environment/execution-environment.yml
- [ ] execution-environment/requirements.yml
- [ ] execution-environment/requirements.txt
- [ ] execution-environment/bindep.txt
- [ ] Build and test EE

**Documentation**:

- [ ] docs/authentication/browser-automation.md
- [ ] README.md (update with authentication section)

---

## Open Questions & Decisions Needed

### Technical Questions

1. **Token Lifetime Management**
   - **Question**: Do we need token refresh logic for long playbooks?
   - **Current Answer**: No - assume playbooks complete within 5 minutes
   - **Future Consideration**: Add refresh logic if playbooks grow longer

2. **Error Handling Strategy**
   - **Question**: How many retry attempts for browser automation?
   - **Proposed**: 3 retries with exponential backoff
   - **Alternative**: Fail fast and let AAP handle retries

3. **Execution Environment Size**
   - **Question**: Is 500MB overhead acceptable for Playwright?
   - **Impact**: Longer build times, larger image storage
   - **Mitigation**: Use layer caching, share base images

4. **Concurrent Executions**
   - **Question**: Can we parallelize authentication for multiple IDPs?
   - **Answer**: Yes - use Ansible async tasks
   - **Consideration**: Resource limits on AAP execution nodes

### Design Decisions

1. **Backward Compatibility**
   - **Decision Needed**: Support old authentication method?
   - **Recommendation**: Clean break (Option 1)
   - **Reason**: Simpler code, clearer documentation

2. **Token Storage**
   - **Decision Made**: In-memory only (Ansible facts)
   - **Rationale**: Security, token expiry makes storage unnecessary
   - **Alternative Rejected**: Vault storage - adds complexity

3. **Logging Level**
   - **Decision Needed**: Default verbose level for role?
   - **Recommendation**: Minimal by default, verbose on demand
   - **Implementation**: `rhdh_auth_verbose` variable

### Security Considerations

1. **Credential Handling**
   - **Implemented**: `no_log` on password parameters
   - **Required**: Vault integration for production
   - **Warning**: Never log tokens in production

2. **Browser Security**
   - **Risk**: Running Chromium in container
   - **Mitigation**: Sandboxing flags, read-only filesystem where possible
   - **Note**: Required for functionality

3. **Token Exposure**
   - **Risk**: Token visible in Ansible facts
   - **Mitigation**: Facts cleared after playbook run
   - **Best Practice**: Short-lived tokens (5 min default)

---

## Success Criteria

### Phase 1 Complete When:

- ✅ POC script runs successfully
- ✅ Token captured and verified
- ✅ WRITE operation succeeds (HTTP 201)
- ✅ Clean error messages for common failures

### Phase 2 Complete When:

- ✅ Ansible role structure created
- ✅ Custom module passes ansible-test
- ✅ Role executes without errors
- ✅ Facts properly set for downstream use

### Phase 3 Complete When:

- ✅ Integration playbook works end-to-end
- ✅ RBAC permissions created successfully
- ✅ Error handling covers common scenarios
- ✅ Test playbook validates all operations

### Phase 4 Complete When:

- ✅ Execution environment builds successfully
- ✅ EE size acceptable (<2GB)
- ✅ AAP Job Template executes without errors
- ✅ Survey variables properly passed through

### Documentation Complete When:

- ✅ All README files updated
- ✅ Example playbooks documented
- ✅ Troubleshooting guide complete
- ✅ AAP integration guide written

---

## Quick Reference

### Environment Variables

```bash
# Keycloak
export KEYCLOAK_URL="http://keycloak.local:8080"
export REALM_NAME="workshop-realm"
export CLIENT_ID="rhdh-local-client"
export CLIENT_SECRET="3uB8g8KMOuVb9QjZhHOaznmCCOyDrnJc"
export USERNAME="alice"
export PASSWORD="password123"

# RHDH
export RHDH_API_URL="http://localhost:7007"
export RHDH_URL="http://localhost:7007"

# Browser Automation
export HEADLESS="true"  # or "false" to see browser
```

### Key URLs

**Development**:

- Keycloak: http://keycloak.local:8080
- RHDH: http://localhost:7007
- RHDH API: http://localhost:7007/api/permission/policies

**Documentation**:

- Backstage Auth: https://backstage.io/docs/auth/
- Playwright: https://playwright.dev/python/docs/intro
- RBAC Backend: https://github.com/backstage/community-plugins/tree/main/workspaces/rbac

### Useful Commands

```bash
# Quick token test
./poc/keycloak_direct_grant/test_auth.sh

# Quick browser auth test
./poc/oidc_browser_automation/test_browser_auth.sh

# View RHDH logs
docker logs rhdh -f | grep permission

# Restart RHDH
docker-compose restart rhdh && sleep 10

# Test Ansible role
ansible-playbook playbooks/test_auth_role.yml
```

---

## Next Steps Summary

**If choosing Option 1 (Browser Automation)**:

1. ✅ Test POC (`poc/oidc_browser_automation/test_browser_auth.sh`)
2. 📝 Create role structure (`roles/rhdh_auth/`)
3. 📝 Implement custom module (`library/rhdh_browser_auth.py`)
4. 🔄 Update RBAC role for token authentication
5. 📝 Write integration playbook
6. 🏗️ Build execution environment
7. ✅ Test in AAP

**If choosing Option 2 (Further Research)**:

1. 🔍 Check RHDH version and release notes
2. 📚 Deep-dive Backstage documentation
3. 🔬 Compare token payloads
4. 💬 Search community issues
5. 🧪 Experiment with client configurations
6. 📊 Document findings
7. ⚖️ Make final decision

**Recommended**: Start with Option 1 testing while pursuing Option 2 research in parallel.

---

**Document Version**: 1.0  
**Last Updated**: February 6, 2026  
**Status**: Ready for Implementation

This document contains complete context to resume work at any point. All commands, configurations, and implementation details are included for continuity.
