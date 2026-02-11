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


def acquire_token(rhdh_url, username, password, timeout=30):
    """
    Use Playwright to acquire bearer token via browser automation.

    RHDH uses a popup window for OIDC authentication:
    1. Navigate to RHDH, which shows a sign-in page
    2. Click sign-in button, which opens a Keycloak popup
    3. Fill credentials in the popup
    4. Popup closes after auth callback
    5. Capture bearer token from subsequent API requests

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
        browser = p.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )

        context = browser.new_context(
            viewport={'width': 1280, 'height': 720},
            ignore_https_errors=True,
            user_agent='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        )

        page = context.new_page()

        # Capture tokens from API requests
        captured_tokens = []

        def handle_request(request):
            auth_header = request.headers.get('authorization', '')
            if auth_header.lower().startswith('bearer '):
                token = auth_header.split(' ', 1)[1]
                if token not in captured_tokens:
                    captured_tokens.append(token)

        page.on("request", handle_request)

        try:
            # Navigate to RHDH
            page.goto(rhdh_url, timeout=timeout * 1000, wait_until='load')

            # Wait for React app to render sign-in UI or Keycloak redirect
            keycloak_username = page.locator('input[name="username"], input[id="username"]')
            sign_in_button = page.locator(
                'button:has-text("Sign In"), button:has-text("Log in"), '
                'a:has-text("Sign In")'
            )

            try:
                page.wait_for_function(
                    """() => {
                        return document.querySelector('input[name="username"]') !== null
                            || document.querySelector('input[id="username"]') !== null
                            || [...document.querySelectorAll('button, a')].some(
                                el => el.textContent?.includes('Sign In')
                                    || el.textContent?.includes('Log in')
                            )
                            || window.location.href.includes('keycloak');
                    }""",
                    timeout=timeout * 1000,
                )
            except PlaywrightTimeout:
                pass

            # Case 1: Direct redirect to Keycloak
            if keycloak_username.count() > 0:
                keycloak_username.first.fill(username)
                password_field = page.locator('input[name="password"], input[id="password"]').first
                password_field.fill(password)

                submit_button = page.locator('input[type="submit"], button[type="submit"]').first
                submit_button.click()

                page.wait_for_url(f"{rhdh_url}/**", timeout=timeout * 1000)

            # Case 2: RHDH sign-in page with popup
            elif sign_in_button.count() > 0:
                with page.expect_popup(timeout=timeout * 1000) as popup_info:
                    sign_in_button.first.click()

                popup = popup_info.value

                popup_username = popup.locator('input[name="username"], input[id="username"]')
                popup_username.first.wait_for(state="visible", timeout=timeout * 1000)
                popup_username.first.fill(username)

                popup_password = popup.locator('input[name="password"], input[id="password"]')
                popup_password.first.fill(password)

                popup_submit = popup.locator('input[type="submit"], button[type="submit"]')
                popup_submit.first.click()

                popup.wait_for_event("close", timeout=timeout * 1000)

            # Wait for authenticated API calls
            page.wait_for_timeout(5000)

            # Navigate to catalog to trigger more API calls if needed
            if not captured_tokens:
                try:
                    page.goto(f"{rhdh_url}/catalog", wait_until='networkidle', timeout=15000)
                    page.wait_for_timeout(3000)
                except Exception:
                    pass

            if captured_tokens:
                bearer_token = captured_tokens[0]
            else:
                raise Exception("No bearer token captured from API requests")

        except PlaywrightTimeout as e:
            raise Exception(f"Timeout during authentication: {str(e)}")
        except Exception as e:
            if "No bearer token" in str(e):
                raise
            raise Exception(f"Authentication failed: {str(e)}")
        finally:
            browser.close()

    return bearer_token


def decode_jwt_expiry(token):
    """Decode JWT token to extract expiry time."""
    try:
        import base64
        parts = token.split('.')
        if len(parts) != 3:
            return None

        payload = parts[1]
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += '=' * padding

        decoded = base64.urlsafe_b64decode(payload)
        payload_json = json.loads(decoded)

        return payload_json.get('exp')
    except Exception:
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
        token = acquire_token(
            module.params['rhdh_url'],
            module.params['username'],
            module.params['password'],
            module.params['timeout']
        )

        if not token:
            module.fail_json(msg='Failed to capture bearer token', **result)

        expiry = decode_jwt_expiry(token)
        if expiry:
            result['token_expiry'] = expiry
            result['expiry_seconds'] = max(0, expiry - int(time.time()))
        else:
            result['token_expiry'] = int(time.time()) + 3600
            result['expiry_seconds'] = 3600

        result['token'] = token
        result['changed'] = True

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=str(e), **result)


def main():
    run_module()


if __name__ == '__main__':
    main()
