# TeamsVoiceTool

A PowerShell 7 WinForms toolkit for Microsoft Teams Enterprise Voice. It provisions and reads users and resource accounts, manages telephone lines and policies, and pulls call records, all from one window.

**Current version: 1.0.0.** See [CHANGELOG.md](CHANGELOG.md) for release history.

![Provisioning tab](Docs/screenshots/provisioning.png)

## Features

- **Unified Provisioning tab.** Read a user or resource account, see every assigned phone line, and edit and provision a number with its policies in one place. Read Settings fills the policy drop-downs with the values the user actually has.
- **Multiple phone lines.** Up to 11 lines per user (1 primary, 1 private, 9 alternate). Mix Calling Plan, Direct Routing, and Operator Connect. Alternate lines use the MicrosoftTeams module through RBAC.
- **Policy Manager.** Load any `Get-Cs*Policy` type, edit its settings, create or delete policies, and manage group assignments.
- **Resource Accounts.** Build and manage resource accounts with the same features as the Teams admin center.
- **Configuration popup.** Manage tenants, choose a Microsoft Teams module folder, import it, and copy it to a default location (current user Documents, or Program Files with admin rights).
- **Teams-first lookups.** When connected to RBAC, number, user, and group lookups use the MicrosoftTeams module (7.8 recommended) and fall back to Graph where the module lacks a cmdlet. This is controlled by a checkbox.
- **CDR, catalogs, SBC/Direct Routing, groups, bulk import, and a JSON analyzer** in the other tabs.

![Configuration popup](Docs/screenshots/configuration.png)

![Policy Manager](Docs/screenshots/policy-manager.png)

## Requirements

- Windows with **PowerShell 7** (`pwsh`). Windows PowerShell 5.1 is not supported.
- An Entra app registration (SPN) for the Graph API, with the permissions listed in the operator guide.
- For RBAC features: the **MicrosoftTeams** module, version **7.8** recommended. Install it with `Install-Module MicrosoftTeams -RequiredVersion 7.8.0`, or point the Configuration popup at a copy.

## Getting started

1. Clone the repo and open a PowerShell 7 window in the folder.
2. Launch the tool:

   ```powershell
   pwsh -NoProfile -ExecutionPolicy Bypass -File .\TeamsVoiceProvisioning.ps1
   ```

3. Click **Configuration** and add a tenant (label, tenant ID, client ID, and defaults). The tool stores no client secrets. Enter the secret in the SPN Secret box each session.
4. Click **Connect API**, then **Connect RBAC** if you need phone number and policy features.

The [operator guide](Docs/TeamsVoiceProvisioning_Instructions.md) covers setup, each tab, required permissions, licensing, and troubleshooting.

## Your data stays local

The tool writes tenant data beside the script. `.gitignore` excludes these files so they never reach the repo:

- `TeamsVoice_Tenants.csv` and `TeamsVoice_Environments.csv` (tenant and client IDs)
- `TeamsVoice_Settings.json`
- `Catalogs/` (location and policy catalogs)
- `TeamsVoice_Output/` (call records, reports, backups, and logs)

Without these files the tool starts with an empty tenant list and shows the Configuration prompt. Add a tenant to begin.

The screenshots in this README use demo data (a fictional "Contoso Demo" tenant and 555 numbers).

## Repository layout

| Path | Contents |
| --- | --- |
| `TeamsVoiceProvisioning.ps1` | The application |
| `Docs/` | Operator guide and screenshots |
| `Scripts/` | Helper scripts (for example, the socket trace) |

## License

Add a license before making the repo public.
