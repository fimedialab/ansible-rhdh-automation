# Ansible RHDH Automation

Ansible-based automation for configuring and managing Red Hat Developer Hub (RHDH) instances.

## Overview

This repository provides Ansible roles and playbooks for automating RHDH configuration tasks, including:
- Authentication and token management via Keycloak
- RBAC (Role-Based Access Control) policy management
- Multi-instance IDP deployment and configuration

## Project Structure
```
.
├── roles/              # Ansible roles
│   └── rhdh_auth/     # Keycloak authentication for RHDH API access
├── playbooks/         # Example playbooks
├── poc/               # Proof of concept scripts and tests
└── docs/              # Technical documentation
```

## Getting Started

See individual role READMEs for detailed usage instructions.

## Requirements

- Ansible 2.9+
- Red Hat Developer Hub instance
- Keycloak authentication provider
- Access to RHDH RBAC Backend API

## License

See LICENSE file for details.
