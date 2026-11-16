# Changelog

All notable changes to TeamsVoiceTool are recorded here. The project uses [Semantic Versioning](https://semver.org/). Each release is tagged `vX.Y.Z` in git.

## Unreleased

- JSON Analyzer now distinguishes usage records from detailed call records, provides expandable JSON-field navigation, and suggests possible usage-to-call matches based on timestamps and identity evidence.
- The SPN "Keep secret in memory (auto-renew)" option is on by default, so the API token renews itself without re-entering the secret. Untick it to keep the secret out of memory.
- Permission docs: added `Group.Read.All`, `Organization.Read.All`, `RoleManagement.Read.Directory`, and `TeamsPolicyUserAssign.ReadWrite.All` to the SPN list, and the Teams Administrator role must be assigned at Organization scope.

## 1.0.0

First versioned release.

- Enterprise Voice provisioning for users and resource accounts, with a Resource Accounts tab.
- Policy Manager for viewing and editing policies and their group assignments.
- Multiple telephone lines per user, for Calling Plan and Direct Routing.
- Configuration popup for tenants, PowerShell module import, and the Microsoft Teams module path. Teams 7.8 is the default.
- Call Record Analyzer.
- Window title shows the version.
