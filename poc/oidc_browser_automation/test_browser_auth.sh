#!/usr/bin/env bash
#
# RHDH Authentication POC - Browser Automation
#
# Wrapper script for test_browser_auth.py
# Sets up Python virtual environment and runs the Playwright-based POC.
#
# Environment variables:
#   RHDH_URL       - RHDH instance URL (default: http://localhost:7007)
#   RHDH_USERNAME  - Keycloak username (default: alice)
#   RHDH_PASSWORD  - Keycloak password (default: password123)
#   HEADLESS       - Run browser headless: true/false (default: true)
#   TIMEOUT        - Authentication timeout in seconds (default: 30)
#
# Usage:
#   export RHDH_URL="http://localhost:7007"
#   export RHDH_USERNAME="alice"
#   export RHDH_PASSWORD="password123"
#   export HEADLESS="false"   # Set to "true" for headless mode
#   ./test_browser_auth.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

# Defaults
export RHDH_URL="${RHDH_URL:-http://localhost:7007}"
export RHDH_USERNAME="${RHDH_USERNAME:-alice}"
export RHDH_PASSWORD="${RHDH_PASSWORD:-password123}"
export HEADLESS="${HEADLESS:-true}"
export TIMEOUT="${TIMEOUT:-30}"

# Create virtual environment if it doesn't exist
if [ ! -d "${VENV_DIR}" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "${VENV_DIR}"
fi

# Activate virtual environment
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# Install dependencies if needed
if ! python3 -c "import playwright" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -q -r "${SCRIPT_DIR}/requirements.txt"
fi

# Install Playwright browsers if needed
if ! playwright install --dry-run chromium 2>/dev/null | grep -q "already installed" 2>/dev/null; then
    echo "Installing Playwright Chromium browser (one-time download, ~500MB)..."
    playwright install chromium
fi

# Run the POC
python3 "${SCRIPT_DIR}/test_browser_auth.py"
