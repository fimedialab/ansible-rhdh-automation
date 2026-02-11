#!/usr/bin/env python3
"""
RHDH Authentication POC - Browser Automation

Uses Playwright to automate the OIDC Authorization Code flow with Keycloak,
capturing the bearer token that RHDH issues to authenticated users.

This token creates a 'user:default/<username>' principal (not 'external:'),
which is required for RBAC write operations.

Environment variables:
    RHDH_URL       - RHDH instance URL (default: http://localhost:7007)
    RHDH_USERNAME  - Keycloak username (default: alice)
    RHDH_PASSWORD  - Keycloak password (default: password123)
    HEADLESS       - Run browser headless (default: true)
    TIMEOUT        - Authentication timeout in seconds (default: 30)
"""

import json
import os
import sys
import time
import base64

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout


def decode_jwt_payload(token):
    """Decode JWT payload to extract claims."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        # Add padding if needed
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def print_step(step_num, message):
    print(f"\nStep {step_num}: {message}")


def print_ok(message):
    print(f"  -> {message}")


def print_fail(message):
    print(f"  !! {message}")


def acquire_token(rhdh_url, username, password, headless=True, timeout=30):
    """
    Automate browser login to RHDH via Keycloak and capture the bearer token.

    Returns:
        str: Bearer token if successful, None otherwise
    """
    bearer_token = None

    with sync_playwright() as p:
        # Launch browser
        print_step(1, "Launching browser")
        browser = p.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        print_ok(f"Browser launched (headless={headless})")

        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        )
        page = context.new_page()

        # Set up request interception to capture bearer tokens
        captured_tokens = []

        def handle_request(request):
            """Capture Authorization headers from API requests."""
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ", 1)[1]
                if token not in captured_tokens:
                    captured_tokens.append(token)

        page.on("request", handle_request)

        try:
            # Navigate to RHDH
            print_step(2, "Navigating to RHDH")
            page.goto(rhdh_url, timeout=timeout * 1000, wait_until="load")
            print_ok(f"Loaded: {rhdh_url}")

            # RHDH is a React SPA - the OIDC sign-in page uses a POPUP window
            # for Keycloak authentication, not a same-page redirect.
            print_step(3, "Detecting authentication page")

            # Wait for the React app to render sign-in UI or redirect
            keycloak_username = page.locator('input[name="username"], input[id="username"]')
            sign_in_button = page.locator('button:has-text("Sign In"), button:has-text("Log in"), a:has-text("Sign In")')

            try:
                page.wait_for_function(
                    """() => {
                        return document.querySelector('input[name="username"]') !== null
                            || document.querySelector('input[id="username"]') !== null
                            || [...document.querySelectorAll('button, a')].some(
                                el => el.textContent?.includes('Sign In') || el.textContent?.includes('Log in')
                            )
                            || window.location.href.includes('keycloak');
                    }""",
                    timeout=timeout * 1000,
                )
            except PlaywrightTimeout:
                print_ok(f"Current URL: {page.url} (no login prompt detected)")

            current_url = page.url
            print_ok(f"Current URL: {current_url}")

            # Case 1: Already on Keycloak (direct redirect, not popup)
            if keycloak_username.count() > 0:
                print_step(4, "Filling login form (direct redirect)")

                keycloak_username.first.fill(username)
                print_ok("Entered username")

                password_field = page.locator('input[name="password"], input[id="password"]').first
                password_field.fill(password)
                print_ok("Entered password")

                print_step(5, "Submitting login")
                submit_button = page.locator('input[type="submit"], button[type="submit"]').first
                submit_button.click()
                print_ok("Clicked login button")

                print_ok("Waiting for authentication to complete...")
                page.wait_for_url(f"{rhdh_url}/**", timeout=timeout * 1000)
                print_ok(f"Redirected back to: {page.url}")

            # Case 2: RHDH sign-in page with button that opens popup
            elif sign_in_button.count() > 0:
                print_ok("Found sign-in button - RHDH uses popup for OIDC")

                # Listen for popup window BEFORE clicking the button
                print_step(4, "Clicking sign-in and handling popup")
                with page.expect_popup(timeout=timeout * 1000) as popup_info:
                    sign_in_button.first.click()

                popup = popup_info.value
                print_ok(f"Popup opened: {popup.url}")

                # Wait for Keycloak login form in the popup
                popup_username = popup.locator('input[name="username"], input[id="username"]')
                popup_username.first.wait_for(state="visible", timeout=timeout * 1000)

                popup_username.first.fill(username)
                print_ok("Entered username")

                popup_password = popup.locator('input[name="password"], input[id="password"]')
                popup_password.first.fill(password)
                print_ok("Entered password")

                print_step(5, "Submitting login in popup")
                popup_submit = popup.locator('input[type="submit"], button[type="submit"]')
                popup_submit.first.click()
                print_ok("Clicked login button")

                # Wait for popup to close (auth callback processed)
                print_ok("Waiting for authentication to complete...")
                popup.wait_for_event("close", timeout=timeout * 1000)
                print_ok("Popup closed - authentication complete")
                print_ok(f"Main page URL: {page.url}")

            else:
                print_step(4, "Already authenticated, skipping login")

            # Wait for RHDH to make authenticated API calls
            print_step(6, "Waiting for API calls with bearer token")
            page.wait_for_timeout(5000)

            # Navigate to catalog to trigger more API calls if needed
            if not captured_tokens:
                try:
                    page.goto(f"{rhdh_url}/catalog", wait_until="networkidle", timeout=15000)
                    page.wait_for_timeout(3000)
                except Exception:
                    pass  # Token may have been captured already

            if captured_tokens:
                bearer_token = captured_tokens[0]
                print_ok(f"Captured bearer token: {bearer_token[:50]}...")
            else:
                print_fail("No bearer token captured from API requests")

        except PlaywrightTimeout as e:
            print_fail(f"Timeout during authentication: {e}")
        except Exception as e:
            print_fail(f"Authentication failed: {e}")
        finally:
            browser.close()

    return bearer_token


def test_token(rhdh_url, token):
    """Test the captured token against the RHDH RBAC API."""
    import urllib.request
    import urllib.error

    print_step(7, "Testing token with RHDH API")

    # Test READ operation
    req = urllib.request.Request(
        f"{rhdh_url}/api/permission/policies",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            print_ok(f"Token works! Retrieved {len(data)} policies (HTTP {response.status})")
            return True
    except urllib.error.HTTPError as e:
        print_fail(f"Token test failed: HTTP {e.code} - {e.reason}")
        try:
            body = e.read().decode()
            print_fail(f"Response: {body}")
        except Exception:
            pass
        return False
    except Exception as e:
        print_fail(f"Token test error: {e}")
        return False


def main():
    # Read configuration from environment
    rhdh_url = os.environ.get("RHDH_URL", "http://localhost:7007")
    username = os.environ.get("RHDH_USERNAME", "alice")
    password = os.environ.get("RHDH_PASSWORD", "password123")
    headless = os.environ.get("HEADLESS", "true").lower() == "true"
    timeout = int(os.environ.get("TIMEOUT", "30"))

    print("=" * 50)
    print("RHDH Authentication POC - Browser Automation")
    print("=" * 50)
    print(f"\n  RHDH URL:  {rhdh_url}")
    print(f"  Username:  {username}")
    print(f"  Headless:  {headless}")
    print(f"  Timeout:   {timeout}s")

    # Acquire token
    token = acquire_token(rhdh_url, username, password, headless, timeout)

    if not token:
        print("\n" + "=" * 50)
        print("POC FAILED - Could not acquire token")
        print("=" * 50)
        sys.exit(1)

    # Decode and display token info
    payload = decode_jwt_payload(token)
    if payload:
        print(f"\n  Token claims:")
        print(f"    preferred_username: {payload.get('preferred_username', 'N/A')}")
        print(f"    email: {payload.get('email', 'N/A')}")
        print(f"    issuer: {payload.get('iss', 'N/A')}")
        exp = payload.get("exp")
        if exp:
            remaining = max(0, exp - int(time.time()))
            print(f"    expires_in: {remaining}s")

    # Test token
    success = test_token(rhdh_url, token)

    # Save token to file
    token_file = "/tmp/rhdh_bearer_token.txt"
    with open(token_file, "w") as f:
        f.write(token)

    print(f"\n  Token saved to: {token_file}")

    print("\n" + "=" * 50)
    if success:
        print("POC Complete - Token Successfully Acquired!")
    else:
        print("POC Partial - Token acquired but API test failed")
    print("=" * 50)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
