# Browser Automation Implementation Report

**Date**: February 9, 2026
**Scope**: Implementation of Option 1 (Browser Automation) from the technical continuation document

---

## Summary

All four phases of the browser automation approach were implemented and validated against a live RHDH + Keycloak environment. The solution automates the OIDC Authorization Code flow using Playwright, capturing a Backstage user token that grants full RBAC read+write access.

## What Was Implemented

### Phase 1 - POC (`poc/oidc_browser_automation/`)

Standalone Python script that automates browser login and captures the bearer token.

- `test_browser_auth.py` - Playwright automation script
- `test_browser_auth.sh` - Wrapper that handles venv, dependencies, and Chromium install
- `requirements.txt` - `playwright>=1.40.0`

**Validated**: Token acquired, RBAC policy READ returned HTTP 200.

### Phase 2 - Ansible Role (`roles/rhdh_auth/`)

Custom Ansible module wrapping the browser automation logic.

- `library/rhdh_browser_auth.py` - Custom module returning token, expiry timestamp, and seconds remaining
- `tasks/main.yml` - Validates inputs, installs Playwright if needed, acquires token, sets facts
- `defaults/main.yml` - Configurable Playwright version, timeout, verbosity
- `meta/main.yml` - Role metadata

### Phase 3 - Integration (`playbooks/`)

- `test_auth_role.yml` - End-to-end test: acquires token, tests READ, creates role, creates policy, cleans up
- `examples/configure_rhdh_rbac.yml` - Template playbook for production use with Vault credentials

**Validated**: Full playbook run - 17 tasks, 0 failures. Role creation (HTTP 201), policy creation (HTTP 201), policy deletion (HTTP 204), role deletion (HTTP 204).

### Phase 4 - AAP Execution Environment (`execution-environment/`)

- `execution-environment.yml` - EE definition based on `ee-minimal-rhel9`
- `requirements.yml`, `requirements.txt`, `bindep.txt` - Dependencies

### Supporting

- `ansible.cfg` - Added `roles_path = ./roles` so playbooks find the role

## Discoveries and Deviations from Plan

| Area | Report Assumption | Actual Behavior |
|---|---|---|
| OIDC flow | Direct redirect to Keycloak | RHDH uses a **popup window** for OIDC sign-in |
| Token issuer | Keycloak JWT (5 min expiry) | RHDH-issued `vnd.backstage.user` token (~1 hour expiry) |
| Playwright version | 1.40.0 | **1.58.0** required (greenlet 3.0.1 fails to build on Python 3.14) |
| Env vars | `USERNAME` / `PASSWORD` | **`RHDH_USERNAME`** / **`RHDH_PASSWORD`** (macOS sets `USERNAME` to system user) |
| Policy creation | Direct POST to `/policies` | Role must exist first via `POST /roles` with non-empty `memberReferences` |
| Policy deletion | POST body to `/policies` | `DELETE /policies/:kind/:ns/:name` with JSON array body |
| Playwright CLI | `playwright install chromium` | `python3 -m playwright install chromium` (binary not in Ansible's PATH) |

## RBAC API Reference (Validated)

| Operation | Method | Endpoint | Status |
|---|---|---|---|
| List policies | GET | `/api/permission/policies` | 200 |
| Create role | POST | `/api/permission/roles` | 201 |
| Create policy | POST | `/api/permission/policies` | 201 |
| Delete policy | DELETE | `/api/permission/policies/:kind/:ns/:name` (body) | 204 |
| Delete role | DELETE | `/api/permission/roles/:kind/:ns/:name` | 204 |

## Files Created

```
ansible.cfg
poc/oidc_browser_automation/test_browser_auth.py
poc/oidc_browser_automation/test_browser_auth.sh
poc/oidc_browser_automation/requirements.txt
poc/oidc_browser_automation/README.md
roles/rhdh_auth/defaults/main.yml
roles/rhdh_auth/library/rhdh_browser_auth.py
roles/rhdh_auth/meta/main.yml
roles/rhdh_auth/tasks/main.yml
playbooks/test_auth_role.yml
playbooks/examples/configure_rhdh_rbac.yml
execution-environment/execution-environment.yml
execution-environment/requirements.yml
execution-environment/requirements.txt
execution-environment/bindep.txt
docs/authentication/browser-automation-implementation.md
```

## Next Steps

1. **Build and test the AAP execution environment** - `ansible-builder build -t rhdh-automation-ee:latest`
2. **Create the `rhdh_rbac_automation` role** - Policy reconciliation logic using the bearer token
3. **Vault integration** - Store Keycloak credentials in Ansible Vault or AAP credential type
4. **Token refresh** - For playbooks exceeding 1 hour, re-invoke the auth role mid-run
