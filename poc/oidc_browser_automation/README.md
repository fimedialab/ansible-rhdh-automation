# RHDH Browser Authentication POC

Proof of concept for acquiring RHDH bearer tokens via browser automation using Playwright.

## Why Browser Automation?

RHDH's RBAC Backend API only allows write operations from `user:` type principals. Direct Grant tokens from Keycloak create `external:` principals which are limited to read-only operations. Browser authentication (OIDC Authorization Code flow) creates `user:` principals with full read+write access.

This POC automates the browser login flow to capture a valid bearer token.

## Prerequisites

- Python 3.8+
- RHDH instance running and accessible
- Keycloak configured as OIDC provider for RHDH
- Valid Keycloak user credentials

## Quick Start

```bash
cd poc/oidc_browser_automation

# Set environment variables
export RHDH_URL="http://localhost:7007"
export USERNAME="alice"
export PASSWORD="password123"
export HEADLESS="false"  # See the browser in action

# Run the POC (handles venv, dependencies, and browser install)
./test_browser_auth.sh
```

## Environment Variables

| Variable   | Default                  | Description                          |
|------------|--------------------------|--------------------------------------|
| `RHDH_URL` | `http://localhost:7007`  | RHDH instance URL                    |
| `USERNAME` | `alice`                  | Keycloak username                    |
| `PASSWORD` | `password123`            | Keycloak password                    |
| `HEADLESS` | `true`                   | Run browser headless (`true`/`false`)|
| `TIMEOUT`  | `30`                     | Authentication timeout (seconds)     |

## What It Does

1. Launches a Chromium browser (headless or visible)
2. Navigates to RHDH, which redirects to Keycloak login
3. Fills in username and password
4. Submits the login form
5. Waits for redirect back to RHDH
6. Intercepts API requests to capture the bearer token
7. Tests the token against the RBAC API
8. Saves the token to `/tmp/rhdh_bearer_token.txt`

## Files

- `test_browser_auth.sh` - Wrapper script (handles venv/deps setup)
- `test_browser_auth.py` - Python Playwright automation script
- `requirements.txt` - Python dependencies

## Troubleshooting

### Browser fails to launch
Ensure you have the required system dependencies:
```bash
playwright install --with-deps chromium
```

### Timeout during authentication
- Verify RHDH is running: `curl -s http://localhost:7007`
- Verify Keycloak is running: `curl -s http://keycloak.local:8080`
- Increase timeout: `export TIMEOUT=60`

### No token captured
- Try with `HEADLESS=false` to see what's happening
- Check RHDH logs: `docker logs rhdh --tail 50`
- Ensure the user exists in Keycloak and the RHDH catalog
