# Teams Voice Provisioning Test Utility — Operator Guide

A Windows PowerShell / WinForms tool for provisioning, validating, and auditing Microsoft Teams
Enterprise Voice across multiple tenants.

---

## Contents

1. [What the tool does](#1-what-the-tool-does)
2. [Requirements](#2-requirements)
3. [Launching](#3-launching)
4. [First-time setup: environments](#4-first-time-setup-environments)
5. [Connecting](#5-connecting)
6. [The Provisioning tab](#6-the-provisioning-tab)
7. [The CDR tab](#7-the-cdr-tab)
8. [The Catalogs tab](#8-the-catalogs-tab)
   - [Phone Lines panel](#8a-the-phone-lines-panel-multiple-lines-per-user) · [Resource Accounts](#8b-resource-accounts-provisioning-tab) · [Policy Manager tab](#8c-the-policy-manager-tab)
9. [Files the tool reads and writes](#9-files-the-tool-reads-and-writes)
10. [Permissions reference](#10-permissions-reference)
11. [Licensing model](#11-licensing-model)
12. [Troubleshooting](#12-troubleshooting)
13. [Known limitations](#13-known-limitations)

---

## 1. What the tool does

The utility performs Teams Enterprise Voice administration against one or more Microsoft 365
tenants from a single window. It covers four broad jobs:

**Provisioning** — assign a phone number, set an emergency location, and grant the nine Teams
voice policies to a user or resource account, with a pre-flight validation pass and a rollback.

**Auditing** — read a user's current voice configuration (identity, licensing, assigned number,
emergency location, effective policies) and inspect any number in the tenant's inventory.

**Call records** — pull Call Detail Records historically, or run a live engine that watches for
new and updated call telemetry and streams it to CSV.

**Catalog management** — download the tenant's emergency locations and voice policies to local
CSVs so the provisioning dropdowns are populated per environment.

### Two connection paths

The tool can talk to Microsoft two ways, and understanding the split explains most of its
behaviour:

| Path | How it authenticates | What it powers |
|---|---|---|
| **API** (primary) | Graph REST with an SPN client-credentials token | Everything except the items below |
| **RBAC** (optional) | `MicrosoftTeams` PowerShell module | Policy-grant fallback, full policy catalog download, full civic-address location download, DR number inventory |

API is required. RBAC is optional and stays dormant until connected — the features that need it
report that they need it rather than failing silently.

---

## 2. Requirements

- **Windows PowerShell 5.1** or **PowerShell 7** (the UI is WinForms, so Windows only). PowerShell 7 (`pwsh`) is recommended.
- **An Entra ID app registration (SPN)** per tenant, with a client secret
- **`MicrosoftTeams` PowerShell module** — only if you want the RBAC features
- Network access to `login.microsoftonline.com` and `graph.microsoft.com`

No proxy configuration is built in. If your network requires one, it must come from the machine's
system proxy settings.

---

## 3. Launching

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\TeamsVoiceProvisioning.ps1
```

If Windows flags the file as downloaded from the internet:

```powershell
Unblock-File .\TeamsVoiceProvisioning.ps1
```

To avoid passing the execution-policy switch every time (per-user, no admin required):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 4. First-time setup: environments

The tool ships with **no tenants configured**. On first launch it will say so and the dropdown
will be empty.

Click **Configuration** (top bar, beside the Environment dropdown) to open the **Configuration**
window (a popup, so the main window and any signed-in session are left alone), and add one entry per tenant:

| Field | What it is |
|---|---|
| **Label** | Display name in the dropdown (e.g. `Contoso Prod`) |
| **Tenant Id** | The tenant GUID |
| **Client Id** | The SPN's Application (client) ID GUID |
| **App name** | The SPN's display name — cosmetic, shown in the info bar |
| **Default UPN / number / CDR filter** | Optional pre-fills for the Provisioning and CDR tabs |

Tenant Id and Client Id are validated as GUIDs before saving. App name defaults to the Label if
left blank.

**Buttons in the Tenants box:**

- **Add / Update** — saves the form. If the Label matches an existing entry it updates in place
  (its defaults are kept); otherwise it creates a new one.
- **Clear Form** — blanks the fields to start a fresh entry.
- **Remove Selected** — deletes the highlighted environment (confirms first). Any catalog CSVs
  already saved for it are left on disk.
- **Use As Active** — selects the highlighted tenant in the Environment dropdown.

Everything is persisted to `TeamsVoice_Environments.csv` beside the script and reloaded on
startup. There is no cap on the number of environments.

> **Renaming:** changing the Label creates a *new* entry rather than renaming in place, because
> entries are keyed by Label. To rename, add under the new name then remove the old one.

**Client secrets are never stored.** They are typed into the SPN Secret box each session and
cleared from memory after use.

### Choosing the MicrosoftTeams module

**Recommended: MicrosoftTeams 7.8.** The tool is built and tested against 7.8. The Configuration
window shows a warning if an older version is loaded.

The **Microsoft Teams PowerShell module** box in the Configuration window lets you import the module
from a folder instead of the default install location.

1. Click **Browse...** and pick the folder containing `MicrosoftTeams.psd1`. A version folder
   (`...\MicrosoftTeams\7.8.0`), the `MicrosoftTeams` folder, or a `Modules` folder all work; when
   several versions are present the highest is used.
2. Click **Import Now**. If an RBAC session is connected, the import is refused so the session is
   kept. Disconnect RBAC first, or use **Copy Module and Import** and reconnect later.
3. Tick **Import this module path automatically** to load the chosen module at startup. The choice
   is saved in `TeamsVoice_Settings.json`. It is never swapped in while RBAC is connected.
4. **Use Default Module** clears the path and the checkbox (effective from the next launch).
5. Tick **Prefer the Teams module over Graph** (on by default) to use the Teams module cmdlets for
   number, user and group lookups when RBAC is connected. Graph remains the fallback, and is still
   used where 7.8 has no equivalent (for example deleting a resource account and changing a UPN).

#### Copying the module into a default location

To install the chosen module where PowerShell finds it by default, pick a **Copy to** target and
click **Copy Module and Import**:

- **My Documents module folder (current user):** `Documents\PowerShell\Modules` in PowerShell 7, or
  `Documents\WindowsPowerShell\Modules` in Windows PowerShell 5.1 (the edition running the tool).
  No admin rights needed.
- **Program Files (all users, needs admin):** `Program Files\PowerShell\Modules` or
  `Program Files\WindowsPowerShell\Modules`. The tool refuses this option unless it was started as
  administrator.

The module files are copied flat to `<Modules>\MicrosoftTeams\`, so `MicrosoftTeams.psd1` sits
directly in that folder. This matches the Microsoft Learn rule that the folder name must match the
manifest's base name. The copy then becomes the module path and is imported. Copying is refused
while a copy is already loaded in this session; close other PowerShell sessions that have the
module loaded, then copy again.

> The Teams module carries .NET assemblies that cannot be swapped inside a running process. If
> **Import Now** reports an assembly conflict after another version was already loaded, restart the
> tool and tick the automatic-import checkbox so the chosen module loads first.

---

## 5. Connecting

The top bar holds the connection controls.

### Connect API (required)

1. Select the environment in the dropdown.
2. Type the SPN client secret into **SPN Secret (API)**.
3. Click **Connect API**.

The label shows `API Token: acquired (<environment>)` in green on success. The secret box is
cleared immediately after the token is minted.

### Connect RBAC (optional)

Reuses the same secret from the box above — enter it again if you already connected API (the box
self-clears). Click **Connect RBAC**. This imports the `MicrosoftTeams` module and mints two
tokens (Graph + Teams admin resource).

### Test RBAC

Connecting proves the tokens are valid; it does **not** prove the SPN actually holds a Teams admin
role. **Test RBAC** runs `Get-CsTenant` and reports one of three states:

- `RBAC OK: role works (tenant <id>)` — fully functional
- `RBAC: connected but ROLE MISSING` — connected, but the directory role isn't assigned
- `RBAC test error: <message>` — something else went wrong

Run this before relying on any RBAC-only feature.

### Switching environments

Changing the dropdown clears the current token and RBAC session, reloads that environment's
catalogs, and prompts for the new secret. You cannot switch while the CDR engine is running —
stop it first.

---

## 6. The Provisioning tab

### Target selection

| Control | Purpose |
|---|---|
| **User / RA UPN** | The target user or resource account |
| **Target Type** | `Auto-detect`, `User`, or `Resource Account`. Auto-detect looks for an `MCOEV_VIRTUALUSER*` service plan |
| **Voice Type** | `directRouting`, `callingPlan`, or `operatorConnect` |

### Number and location

**Phone Number** takes E.164 format (`+15551234567`). The country code is detected from the
prefix and shown beside the field.

**Inspect** looks the number up in the tenant inventory and reports its type, source,
capabilities, assignment status, country, rate-center city, resolved emergency location, civic
address ID, and activation state — plus a plain-English verdict on whether it is a user-usage or
voice-app/conference-usage number.

**Location** and **Location ID** come from the emergency location catalog. When Voice Type is
`callingPlan`, location becomes mandatory and the list is filtered to locations in the same
country as the number.

Each row has an **On** checkbox (left) controlling whether that item is written, and a **RBAC**
checkbox (right) controlling whether that policy is granted via cmdlet instead of REST.
**All On** / **All Off** toggle everything.

### The nine policies

Dial Plan · Caller ID · Calling Policy · Call Park · Voice Routing · Emergency Calling ·
Emergency Routing · Mobility · Voicemail

Dropdown contents come from the policy catalog (see [Catalogs](#8-the-catalogs-tab)).

### Read Settings

Non-destructive. Produces a full report. After the lookup it fills the Phone Lines grid and the number box from the primary line, and sets the Voice Type to match the number (case-insensitive: `DirectRouting` → Direct Routing).

- **Identity** — display name, object ID, account enabled, detected target kind
- **Licensing** — SKUs held, Teams Phone plans, Virtual User plans, Calling Plan plans, and an
  overall voice-capable verdict
- **Number** — assigned number, type/source, usage capabilities, status, native city, emergency
  location, activation state
- **Policies / EV** — Enterprise Voice enabled/disabled, and the effective policy assignments
  (which are also pushed into the dropdowns so they reflect live config)

### Validate

Read-only pre-flight. Runs numbered checks and reports PASS / FAIL / N/A / SKIP:

| # | Check |
|---|---|
| 1 | Target exists |
| 2 | Target kind resolved |
| 3 | Voice-capable license present |
| 7 | Calling Plan license (only when Voice Type is `callingPlan`) |
| 9 | Number present in tenant inventory |
| 10 | Number usage matches target kind |

When Voice Type is `callingPlan` it also cross-checks that the number's country matches the
selected location's country.

### Provision

**This writes to the tenant.** A confirmation dialog lists exactly what will change — environment,
target, number, location update, and which policies are switched on — before anything happens.

Guard conditions that stop provisioning before any write:

- Calling Plan selected with no location chosen
- Number country and location country disagree
- Number's usage type is wrong for the target kind (user vs. resource account)
- Number is already assigned to a different object

After assigning a number the tool polls for up to ~40 seconds for the assignment to read back,
so a `PASS` means confirmed, not just accepted.

Every step is written to a timestamped CSV change report.

### Rollback

Restores the catalog default policy (the row flagged `IsDefault`) for each switched-on policy and
unassigns the number — but only if the number was assigned in *this session*. Requires a prior
Provision run in the same session.

### Remove Number

Unassigns the phone number only; leaves policies alone. If the number field is blank it looks up
the currently assigned number automatically. Confirms before acting.

### Deprovision User

**The most destructive action.** Removes the assigned number *and* resets every switched-on policy
to Global. Confirms with a full summary first.

---

## 7. The CDR tab

Two modes share the tab.

### Historical pull

Set **From date** and **To date**, optionally filter by **User (UPN or #)**, tick the record types,
then **Pull CDR**. Runs once and stops. No latency columns are recorded in this mode.

### Live engine

**Start Auto (live)** baselines everything that already exists today (silently), then watches for
new and updated telemetry, streaming rows to CSV as they arrive. **Stop** ends it cleanly after
the current record.

**Auto delay (s)** is the pause between cycles — `0` means back-to-back. Range 0–3600.

### Record types

| Checkbox | Source |
|---|---|
| **Direct Routing** | `getDirectRoutingCalls` |
| **Calling Plan (PSTN)** | `getPstnCalls` |
| **Full callRecords detail** | `callRecords` with sessions, segments, media, streams, and participants |

Full detail produces multiple row types per call — CallRecord, CallRecordParticipant,
CallRecordSession, CallRecordSegment, CallRecordMedia, CallRecordStream — including media quality
metrics (jitter, round-trip time, packet loss).

### Latency capture

In live mode only, each record carries how long after the call ended it became visible, and how
long after last modification. Microsoft enriches call records in phases, so the engine re-fetches
a record when its `version` increments, for up to 60 minutes after first sighting.

### Output

- **Open Report** — opens the most recent CDR CSV
- **Save Log** — exports the on-screen pull log
- Raw JSON for every record is written under `TeamsVoice_Output\CDR\RawJSON\<EnvKey>_<timestamp>\`

The engine runs in a background runspace, so the UI stays responsive. Closing the form stops it.

### JSON Analyzer

The JSON Analyzer opens files and folders starting in `TeamsVoice_Output\CDR\RawJSON`.
Calling Plan and Direct Routing usage records show the caller, callee, user, call type,
and duration when available. Direct Routing records also report whether the call was
established. Usage records do not contain session or media quality details; use
**Full callRecords detail** for that analysis.
The left tree provides session, segment, media and stream navigation for full
call records. Expand **JSON fields** on a record or section to inspect its fields,
including nested endpoints, networks, devices and arrays. Select any node to see
its JSON value in the bottom pane; possible matches can also be expanded this way.
Drag the vertical divider to resize the tree and the right-hand panes.
Possible matches between usage and full call records appear in the tree when both
start and end times are within one second. The analyzer also reports whether the
user ID and a phone number match, when available. These are suggestions, not
confirmed links. Loading a file searches its folder for other exported call JSON;
loading a folder matches records within each individual export folder.

---

## 8. The Catalogs tab

Catalogs are per-environment CSVs that populate the provisioning dropdowns.

### Emergency Locations

- **Download from Tenant** — with RBAC connected, pulls full civic addresses via
  `Get-CsOnlineLisLocation`. Without RBAC, falls back to REST, which only returns locations
  already in use by an assigned number and may leave street addresses blank.
- **Save to CSV** — persists to `Catalogs\TeamsVoice_LocationCatalog_Engineer_<EnvKey>.csv`
- **Reload from CSV** — re-reads from disk

### Voice Policies

- **Download (RBAC)** — enumerates all nine policy types via `Get-Cs*` cmdlets. **Requires RBAC** —
  REST cannot enumerate policies.
- **Refresh IDs (REST)** — resolves policy GUIDs for policy names already in the catalog, using
  the Graph `getPolicyId` endpoint. Useful when you have names but no IDs.
- **Save to CSV** — persists to `Catalogs\TeamsVoice_PolicyCatalog_Engineer_<EnvKey>.csv`
- **Reload from CSV** — re-reads from disk

> Downloads are held in memory until you click **Save to CSV**. Save if you want them to persist.

### Direct Routing Number Inventory

Requires RBAC. There is no Graph v1.0 equivalent for these operations.

- **Number(s) / range** accepts a single number, a comma-separated list, or a range as
  `+15551234500..+15551234510` (capped at 1000 numbers)
- **Add to Inventory** — submits an upload order
- **Check Last Order** — polls the order's status, returning success, warning, and error numbers
- **Release Number** — removes numbers from inventory (confirms first)

---

## 8a. The Phone Lines panel (multiple lines per user)

Gives one user more than one telephone line. Microsoft allows 11 per user: **1 primary + 1 private
+ up to 9 alternate**, in any mix of Calling Plan, Direct Routing and Operator Connect (max one
Teams Phone Mobile). The primary line is still provisioned on the Provisioning tab.

The Phone Lines panel sits in the right-hand pane of the **Provisioning** tab, above the status
log. It has no UPN box of its own: it works on the user in the UPN box on the left. The panel
resizes with the window, down to a 640 px minimum width. On short windows it may need the
scrollbar. Read Settings loads the lines grid, and the primary number goes into the number box.
Read Settings also refreshes the policy dropdowns to match the user's current assignments.

Alternate lines are **RBAC only** — Graph cannot manage them yet — and need MicrosoftTeams
**7.6.0 or later** (`-AssignmentCategory`); 7.8 is the recommended version. Point the tool at a newer module in the Configuration window
tab if the installed one is older. Users in India are not supported.

- **Read Settings** (left side) — fills the lines grid with every line (number, type, category,
  status, location). Without RBAC the grid falls back to Graph, which shows the primary line only.
- **Add Line** — number (E.164, optional `;ext=`), type, category, location (required for Calling
  Plan; must match the number's country), optional "email the user". Guards: user must already
  have a primary line, 11-line / 9-alternate / 1-private limits, no duplicate number. Waits for
  the assignment to read back.
- **Remove Selected** — unassigns the line. The primary cannot be removed while other lines exist.
- **Number-level policies** — set per alternate line via `Set-CsPhoneNumberPolicyAssignment`: tenant
  dial plan, voice routing, emergency call routing, emergency calling, caller ID, dial-out and
  shared calling routing policies. These do **not** fall back to the user's policies. A Direct
  Routing alternate line **requires** a voice routing policy and an emergency call routing policy;
  Add Line refuses without them. Blank = leave unchanged, `(none)` = clear. **Apply To Selected
  Line** changes policies on an existing alternate line; **Show Line Policies** reads them back.

Read Settings also lists a user's alternate and private lines in the status log when RBAC is
connected. Every change is logged to `TeamsVoice_Output\Reports\Changes\TeamsVoice_PhoneLines_*.csv`.

---

## 8b. Resource Accounts (Provisioning tab)

The Provisioning tab has two inner tabs: **User Provisioning** (the user workflow) and **Resource Accounts**.

- **List and search.** Refresh loads accounts with `Get-CsOnlineApplicationInstance`. The search box filters on display name or UPN. Selecting a row shows its current number (`Get-CsOnlineUser`) and association.
- **Create.** `New-CsOnlineApplicationInstance` with the auto attendant app ID (`ce933385-9390-45d1-9512-c8d228074e07`) or the call queue app ID (`11cd3e2e-fccb-42ad-ad00-878b93575e07`). The account also needs a Teams Phone Resource Account license and a usage location before a number can be assigned. The tool does not assign licenses.
- **Edit.** A display name change uses `Set-CsOnlineApplicationInstance`. A UPN change uses Graph `PATCH users/{id}`.
- **Delete.** Uses `Remove-CsOnlineApplicationInstance` when the loaded module has it. The installed MicrosoftTeams 6.9.0 does not, so the tool falls back to Graph `DELETE users/{id}`. Unassign the number first.
- **Associate.** `New-CsOnlineApplicationInstanceAssociation` links the account to an auto attendant or call queue picked from `Get-CsAutoAttendant` and `Get-CsCallQueue`.
- **Phone number.** Assign uses `Set-CsPhoneNumberAssignment`, and unassign uses `Remove-CsPhoneNumberAssignment`. Both take E.164 numbers and the number type (CallingPlan, DirectRouting, OperatorConnect).

All changes are written to the change log. Destructive actions ask for confirmation. These paths are not yet tested against a live tenant.

---

## 8c. The Policy Manager tab

Edits Teams policies and their group assignments. **Requires RBAC.**

1. Pick a **policy type** (about 40 are listed; type any other name that has `Get-Cs<Type>`) and
   click **Load Policies**.
2. **Settings** — select a policy to see its properties. Edit the Value column (arrays comma
   separated, booleans True/False) and **Save Changes**; only changed rows are sent through
   `Set-Cs<Type>`, after a confirmation that lists each old and new value. Nested objects show as
   read-only.
3. **New Policy...** creates a policy (optionally copying the selected one's settings).
   **Delete** removes it (the service refuses while it is assigned; Global cannot be deleted).
   **Assign To User...** grants the policy directly (`Grant-Cs<Type>`).
4. **Group Assignments** — lists `Get-CsGroupPolicyAssignment` for the type (or all types).
   **Assign Group**, **Update Selected** (policy and rank) and **Remove Selected** use
   `New-/Set-/Remove-CsGroupPolicyAssignment`. Find a group by name (needs the API token with
   `Group.Read.All`) or paste its GUID. Lowest rank wins; assignments cover direct members only.
   Types that do not support group assignment are skipped.

Every write asks for confirmation naming the tenant and is logged to
`TeamsVoice_Output\Reports\Changes\TeamsVoice_PolicyManager_*.csv`.

---

## 9. Files the tool reads and writes

All paths are relative to the script's own directory. The script, the tenant list and the settings
file stay in the project root; support files live in subfolders. Files an older build left in the
root are moved into the right folder automatically at startup.

| File | Direction | Purpose |
|---|---|---|
| `TeamsVoice_Environments.csv` (root) | read/write | Tenant definitions |
| `TeamsVoice_Settings.json` (root) | read/write | Teams module folder and auto-import choice |
| `Catalogs\TeamsVoice_LocationCatalog_Engineer_<Key>.csv` | read/write | Emergency locations per environment |
| `Catalogs\TeamsVoice_PolicyCatalog_Engineer_<Key>.csv` | read/write | Voice policies per environment |
| `TeamsVoice_Output\Reports\Changes\TeamsVoice_ChangeReport_<Kind>_<Key>_<timestamp>.csv` | write | Provision / Rollback / Remove / Deprovision audit trail |
| `TeamsVoice_Output\Reports\Changes\TeamsVoice_PolicyManager_<Key>_<date>.csv` | write | Policy Manager change log |
| `TeamsVoice_Output\Reports\Changes\TeamsVoice_PhoneLines_<Key>_<date>.csv` | write | Phone Lines change log |
| `TeamsVoice_Output\CDR\Reports\TeamsVoice_CDRReport_<Key>_<timestamp>.csv` | write | Call detail records |
| `TeamsVoice_Output\CDR\Logs\TeamsVoice_CDRPullLog_<Key>_<timestamp>.csv` | write | CDR pull log |
| `TeamsVoice_Output\CDR\RawJSON\<Key>_<timestamp>\*.json` | write | Raw call record JSON |
| `TeamsVoice_Output\Diagnostics\` | write | Traces and diagnostic captures |
| `Docs\`, `Scripts\` | — | This guide and helper scripts (`Trace-TeamsSockets.ps1`) |

Catalog files fall back to a name without the `_<Key>` suffix if the environment-specific one
doesn't exist, so a shared default catalog is possible.

---

## 10. Permissions reference

### Setting up the SPN (one per tenant)

1. **Create the app registration.** In the Entra admin center, go to *Entra ID > App registrations >
   New registration*. Use a name such as `TeamsVoiceTool`, single-tenant, and no redirect URI.
2. **Create a credential.** Under *Certificates & secrets*, add a client secret and copy the value
   right away. It is shown once. Note the expiry date, because an expired secret stops both API and
   RBAC sign-in. By default the tool keeps the secret in memory so the token renews itself. Untick
   *Keep secret in memory* to have it wiped after sign-in instead; the secret is never written to disk.
3. **Add API permissions.** Under *API permissions > Add a permission > Microsoft Graph >
   Application permissions*, add the permissions in the table below. Then click
   **Grant admin consent for <tenant>**. Application permissions do nothing until consent is granted.
4. **Assign the Teams Administrator directory role to the SPN at Organization scope.** Under *Entra ID >
   Roles and administrators > Teams Administrator > Add assignments*, select the app registration and
   set the scope to the whole organization (tenant-wide), not an Administrative Unit. This is the RBAC
   role. Skype for Business Administrator does not work for this.
5. **Copy the IDs into the Configuration window.** Tenant ID, client ID, and the secret (typed into
   the SPN Secret box each session).
6. **Click Test RBAC.** It should report `RBAC OK`. If it reports `ROLE MISSING`, step 4 is not done
   or has not finished propagating. Wait a few minutes and test again.

| Application permission | Used for | Dependency |
|---|---|---|
| `User.Read.All` | User lookups, license details | Needed by most Graph features |
| `TeamsTelephoneNumber.Read.All` | Listing number assignments, reading DR numbers | Graph number reads |
| `TeamsTelephoneNumber.ReadWrite.All` | Assigning, unassigning, and updating numbers | Needs the Read permission too |
| `TeamsPolicyUserAssign.ReadWrite.All` | Assigning and unassigning user policies through Graph (`/admin/teams/policy/userAssignments/assign`) | Least-privileged application permission on the v1.0 endpoint |
| `TeamsUserConfiguration.Read.All` | Reading effective policy assignments | Without it the Read report notes the gap and continues |
| `Group.Read.All` | Group lookups for policy group assignment and licensing groups | Without it, group search falls back to pasting a group GUID |
| `Organization.Read.All` | Reading tenant organization details and subscribed licenses | Read-only. Requested with the other tenant reads |
| `RoleManagement.Read.Directory` | Reading directory role assignments, including Administrative Unit scoped Teams Administrator | Required for AU-scoped roles (see the 40301 note below) |
| `CallRecords.Read.All` | Call records (`/communications/callRecords`) | Needed only for CDR reports. Microsoft advises granting it only to trusted apps, because call records are sensitive |

The app-only token is requested for `https://graph.microsoft.com/.default`, which means every
permission above must be consented before it takes effect. The RBAC token is requested for the
Teams resource (`48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default`), and the Teams Administrator role
covers that path.

### Who needs what

| Sign-in | Identity | Roles and permissions | Features that need it |
|---|---|---|---|
| **Connect API** | SPN (client credentials) | Graph application permissions above, admin-consented | Users, numbers, policy assignment (Graph), group lookups, CDR |
| **Connect RBAC / Test RBAC** | SPN | Teams Administrator directory role, Organization scope | Policy Manager, DR inventory, civic addresses, alternate lines, Route Simulator writes |
| **Interactive or device-code sign-in** | Your user account | Teams Administrator, or Teams Telephony Administrator for telephony-only writes. Trusted IP writes need Teams Administrator | Resource-account writes, which Microsoft does not allow under app-only auth |

The user account does not need Graph application permissions. Those belong to the SPN. A user
with only Teams Telephony Administrator gets "Denied" on Trusted IP writes, not on other telephony
writes.

### Dependencies at a glance

- **RBAC depends on the role, not the permissions.** Connecting succeeds with the secret alone.
  Without the Teams Administrator role, cmdlets connect and return empty results. An empty civic
  address export is a role problem, not an auth problem.
- **Graph writes depend on consent.** A permission that is added but not admin-consented fails with
  a 403.
- **Secret expiry breaks everything at once.** Both API and RBAC sign-in use the same secret.
- **Role scope matters.** The Teams Administrator role must be assigned at Organization scope. An
  Administrative Unit scoped assignment returns 40301 errors unless the SPN also has
  `RoleManagement.Read.Directory`, and for group cmdlets `GroupMember.Read.All`, then re-consent and
  reconnect.

### Graph API (application permissions on the SPN)

Endpoints used:

- `/users/{id}` and `/users/{id}/licenseDetails`
- `/admin/teams/telephoneNumberManagement/numberAssignments` — plus `assignNumber`,
  `unassignNumber`, `updateNumber`
- `/admin/teams/policy/userAssignments/assign` and `/unassign`
- `/admin/teams/policy/getPolicyId`
- `/admin/teams/userConfigurations`
- `/groups` — group lookups by ID or name (`Group.Read.All`)
- `/communications/callRecords` — including `getDirectRoutingCalls` and `getPstnCalls`

Reading effective policy assignments needs `TeamsUserConfiguration.Read.All`; without it the
Read report says so and continues.

### RBAC (Teams admin role on the SPN)

Cmdlets used: `Get-CsTenant`, the nine `Get-Cs*Policy` enumerators, the nine `Grant-Cs*` cmdlets,
`Get-CsOnlineLisLocation`, `New-CsOnlineDirectRoutingTelephoneNumberUploadOrder`,
`Get-CsOnlineTelephoneNumberOrder`, and `New-CsOnlineTelephoneNumberReleaseOrder`.

---

## 11. Licensing model

The tool follows Microsoft's documented rule: a Teams Phone license is **any service plan whose
name starts with `MCOEV`** — `MCOEV`, `MCOEV1`, and so on are all valid.

E5 is **not** required. It merely bundles Teams Phone Standard. The same capability arrives via
the standalone add-on on E1, E3, Business, F, EDU, and GOV plans, via Business Voice, and others.

- `MCOEV_VIRTUALUSER*` — the resource account variant, tracked separately
- `MCOPSTN*` — Microsoft Calling Plan (MCOPSTN1/2/5/6 and regional variants)

A plan that is assigned but not active reports as **"Found but NOT active"** rather than passing.

**Calling Plan is only required for Microsoft Calling Plan numbers.** Direct Routing, Operator
Connect, Teams Phone Mobile, and Shared Calling need no PSTN license, so their absence is reported
as N/A rather than a failure.

When no voice-capable license exists, both Read and Validate say so explicitly and list the SKUs
the account *does* hold, so you can see what's actually assigned.

---

## 12. Troubleshooting

**"No environment configured"** — open the Configuration tab and add a tenant.

**"No API token. Connect API first."** — enter the SPN secret and click Connect API. The secret
box clears after each use by design.

**RBAC fails with an assembly load error** (e.g. `Microsoft.IdentityModel.JsonWebTokens`) — this is
a `MicrosoftTeams` module problem, not a tool problem. Remove all versions and reinstall cleanly
from an elevated prompt:

```powershell
Uninstall-Module MicrosoftTeams -AllVersions -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files\WindowsPowerShell\Modules\MicrosoftTeams" -Recurse -Force -ErrorAction SilentlyContinue
Install-Module MicrosoftTeams -Scope AllUsers -Force -AllowClobber
```

Then use a fresh, non-elevated window.

**"Download needs RBAC"** on the policy catalog — expected. REST cannot enumerate policies. Either
connect RBAC, or use **Refresh IDs (REST)** if you already have policy names in the catalog.

**Policy dropdowns are empty** — the policy catalog hasn't been loaded for this environment.
Download it, then Save to CSV.

**"POST accepted but readback not confirmed within ~40s"** — the assignment was accepted but hadn't
propagated when the tool stopped polling. Usually it completes shortly after; re-run Read Settings
to confirm.

**Emergency locations have blank addresses** — they came from the REST fallback, which only sees
locations already in use. Connect RBAC and download again for full civic addresses.

**Can't switch environments** — the CDR engine is running. Stop it first.

---

## 13. Known limitations

- **Windows only** — WinForms UI.
- **No proxy support** — must come from system proxy settings.
- **Secrets are not stored** — re-entered each session by design.
- **Rollback is session-scoped** — it can only undo a number assignment made since the tool was
  opened.
- **DR inventory needs RBAC** — no Graph v1.0 equivalent exists.
- **Renaming an environment** creates a new entry rather than renaming in place.
- **Validate checks licensing and number state**, but does not test Enterprise Voice enablement or
  calling-policy private-calling — both are Microsoft dial-pad prerequisites. Read Settings does
  surface Enterprise Voice status.
- **The script is unsigned.** If your environment requires signed scripts, sign it with
  `Set-AuthenticodeSignature`.

---

*Document version 1.0 — covers the tool as of the current build.*
