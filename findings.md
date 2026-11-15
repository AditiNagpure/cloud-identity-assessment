# Cloud Identity & Security Posture Assessment — Findings Report

> **SIMULATED ASSESSMENT.** All weaknesses in this report were deliberately planted by the assessor in a personal Microsoft 365 E5 / Azure trial tenant (`AditiSecurityLab.onmicrosoft.com`) for training and portfolio purposes. No production systems, real users or real data were involved. The "HR export" file contains fake data only.

| | |
|---|---|
| **Assessor** | Aditi Nagpure |
| **Date** | 15 November 2026 |
| **Tenant** | AditiSecurityLab.onmicrosoft.com (Entra ID + Azure subscription "Azure subscription 1") |
| **Scope** | Entra ID app registrations, service principals, directory roles, Conditional Access, MFA registration; Azure RBAC at subscription level; resource group `rg-idaudit`; logging to Sentinel workspace `law-cyberrange` |
| **Out of scope** | Endpoint (WIN11-LAB01), Exchange mail flow, Intune, offensive exploitation of planted credentials |
| **Tooling** | Azure Cloud Shell (PowerShell), Microsoft Graph PowerShell SDK, Az PowerShell, Microsoft Defender XDR Advanced Hunting (KQL), Microsoft Sentinel |
| **Status** | Audit complete; F01–F05 remediated and verified; O1 open |

---

## 1. Rules of engagement

1. Testing limited to the assessor's own trial tenant; no third-party systems touched.
2. Planted secrets were never printed, stored or used outside the Cloud Shell session.
3. The break-glass account was never modified or excluded from monitoring.
4. All planted resources are tagged `type = simulated` and live in `rg-idaudit` where possible, to be deleted at the end of the engagement.

## 2. Methodology

**Plant → Audit → Report → Remediate → Verify.** Weaknesses were planted first (Stage 2). The audit (Stage 3) was then run as eight independent checks, using the same queries an assessor would run against an unknown tenant:

| Check | What it tests | Evidence |
|---|---|---|
| A01 | Directory (Entra) role holders, including service principals | `A01-directory-role-assignments.csv` |
| A02 | App Graph permissions, owners, secret lifetime, implicit grant, redirect URIs | `A02-app-permissions-credentials.png` |
| A03 | Privileged Azure RBAC at subscription scope | `A03-azure-rbac-privileged.png` |
| A04 | Conditional Access coverage and exclusions | `A04-conditional-access-coverage.png` |
| A05 | MFA registration per user | `A05-mfa-registration.png` |
| A06 | Storage account public access, shared key, network exposure | `A06-storage-exposure.png` |
| A07 | Diagnostic logging and log retention | `A07-logging-gaps.png` |
| A08 | Whether Sentinel recorded the privileged changes, and whether any alert fired | `A08-sentinel-audit-trail.png` |

## 3. Summary of findings

| ID | Title | Severity | Zero Trust principle broken | Status |
|---|---|---|---|---|
| F01 | Over-privileged service principal with standing Global Admin and subscription Owner | **Critical** | Least privilege; Assume breach | Remediated — verified |
| F02 | Unowned legacy app with tenant-wide mailbox read and insecure auth config | **High** | Least privilege; Verify explicitly | Retired — verified |
| F03 | Shared admin account excluded from MFA and not MFA-registered | **High** | Verify explicitly | Remediated — verified |
| F04 | Storage container readable anonymously from the internet | **High** | Verify explicitly; Assume breach | Remediated — verified |
| F05 | Logging gaps: no storage logs, Azure activity log not in SIEM, 30-day retention | **Medium-High** | Assume breach | Remediated — verified |
| O1 | Admin accounts use phishable MFA methods | **High** | Verify explicitly | Open (target 30 Nov 2026) |

**Reviewed and accepted (no action):**
- **MTP Unified RBAC** service principal holds *User Access Administrator* at resource-group scope. Microsoft first-party app created when Sentinel was onboarded to the Defender portal. Expected.
- **Break-glass account excluded from CA001.** Standard practice. Compensating control: Sentinel analytics rule alerting on any break-glass sign-in (see Detection-as-Code project).

---

## 4. Detailed findings

### F01 — Over-privileged service principal with standing Global Admin and subscription Owner
**Severity:** Critical  **Asset:** `app-backup-automation`  **ATT&CK:** T1098.003 (Additional Cloud Roles), T1098.001 (Additional Cloud Credentials), T1078.004 (Cloud Accounts)

**Evidence**
- A01: service principal `app-backup-automation` holds **Global Administrator** at directory scope `/`, permanently (no PIM).
- A02: Graph application permissions `Directory.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`; **0 owners**; client secret valid for **730 days**.
- A03: **Owner** on the entire subscription.
- A04: no Conditional Access policy targets workload identities, so the secret works from any IP.
- A08: creation, secret addition and Global Admin assignment were all logged in `AuditLogs` (4 events, 2:44–2:45 IST), but **no alert fired**. The subscription Owner assignment does not appear in Sentinel at all (see F05).

**Risk**
A "backup" workload needs neither directory write nor role management. Anyone who obtains the client secret (leaked in a repo, pipeline log or config file) gains non-interactive, MFA-free, location-unrestricted control of both the Entra tenant and the Azure subscription. `RoleManagement.ReadWrite.Directory` alone is a full tenant-takeover path even if Global Admin were removed. With no owner, nobody is accountable for rotating or retiring the secret.

**Correction**
1. Remove the Global Administrator directory role assignment.
2. Revoke `Directory.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`.
3. Replace subscription Owner with a narrowly scoped role (e.g. *Storage Blob Data Contributor* on the backup resource group only).
4. Delete the 2-year client secret; use a managed identity or federated credential instead. If a secret is unavoidable, cap it at 90 days.
5. Assign a named human owner.
6. Add a Sentinel analytics rule that alerts when any privileged directory role or high-risk Graph permission is granted to a service principal.

**Verification**
- Re-run A01: `app-backup-automation` no longer appears.
- Re-run A02: GraphAppPerms empty, Owners = 1, SecretDaysLeft empty.
- Re-run A03: no Owner/Contributor at subscription scope.
- Re-plant a test role assignment to a test service principal → the new Sentinel rule raises an incident → remove it.

---

### F02 — Unowned legacy app with tenant-wide mailbox read and insecure auth config
**Severity:** High  **Asset:** `app-legacy-integration`  **ATT&CK:** T1114.002 (Remote Email Collection), T1098.001

**Evidence**
- A02: Graph application permission `Mail.Read` (every mailbox in the tenant); **0 owners**; secret valid **1,825 days** (5 years); implicit grant enabled (`ImplicitGrant: True`); redirect URI uses `http://`.

**Risk**
A long-lived secret on an ownerless app is the classic forgotten integration. If the secret leaks, an attacker can silently read all mail. Implicit grant returns tokens in the URL fragment, where they can leak through browser history and referrer headers; an `http://` redirect sends tokens unencrypted.

**Correction**
Confirm whether the app is still in use. If not, delete it. If it is: assign an owner, revoke `Mail.Read` (or scope it with an Exchange application access policy / RBAC for Applications to specific mailboxes), disable implicit grant, change the redirect URI to `https://`, and rotate to a credential of 90 days or less.

**Verification**
Re-run A02: app absent, or Mail.Read gone, Owners ≥ 1, ImplicitGrant False, HttpRedirect False, SecretDaysLeft ≤ 90.

---

### F03 — Shared admin account excluded from MFA and not MFA-registered
**Severity:** High  **Asset:** `svc-reporting@AditiSecurityLab.onmicrosoft.com`  **ATT&CK:** T1110.003 (Password Spraying), T1078.004

**Evidence**
- A01: holds **User Administrator**.
- A04: explicitly excluded from `CA001 - Require MFA for all users`.
- A05: `IsAdmin: True`, `MfaRegistered: False`, no methods registered.

**Risk**
A password is the only barrier to an admin role that can reset passwords for non-admin users and create accounts. Because the account is shared, sign-in activity cannot be tied to a person. This is the most common real-world pattern behind password-spray compromises.

**Correction**
Remove the account from the CA001 exclusion list; remove the User Administrator role (or replace the shared account with named, individually assigned, PIM-eligible roles); if the account is a genuine automation, convert it to a workload identity. Block sign-in until resolved.

**Verification**
Re-run A04: CA001 excludes only the break-glass account. Re-run A01: svc-reporting holds no role. Sign-in attempt as svc-reporting is blocked or prompted for MFA (check Entra sign-in logs).

---

### F04 — Storage container readable anonymously from the internet
**Severity:** High  **Asset:** `stidaudit68750/hr-exports`  **ATT&CK:** T1530 (Data from Cloud Storage)

**Evidence**
- F04 screenshot: `hr-export-SAMPLE.csv` downloaded from an unauthenticated incognito browser via its public URL.
- A06: `AllowPublicBlob: True`, container access level `Blob`, `SharedKeyAllowed: True`, public network access at default (enabled, no firewall).

**Risk**
Anyone who discovers or guesses the URL can download the data with no identity and no trace (see F05). Shared key access lets anyone holding the account key bypass Entra ID entirely.

**Correction**
Set `AllowBlobPublicAccess = false` at account level; set the container to Private; disable shared key access (Entra ID auth only); restrict public network access or add firewall rules. Enforce tenant-wide with the Azure Policy "Storage account public access should be disallowed".

**Verification**
Re-run A06: AllowPublicBlob False, no public containers, SharedKeyAllowed False. The same URL in an incognito window returns `PublicAccessNotPermitted` / `ResourceNotFound`.

---

### F05 — Logging gaps: no storage logs, Azure activity log not in SIEM, 30-day retention
**Severity:** Medium-High  **Assets:** `stidaudit68750`, subscription activity log, `law-cyberrange`  **ATT&CK:** relates to T1562.008 (Impair Defenses: Disable or Modify Cloud Logs) — the gap gives an attacker the same outcome without having to act

**Evidence**
- A07: `StorageBlobLogging: NONE`; `ActivityLogExport: NONE`; `law-cyberrange` retention **30 days**.
- A08: the subscription Owner grant to `app-backup-automation` (F01) is absent from Sentinel; only Entra-side events were visible.

**Risk**
The anonymous download proven in F04 left no record. The single most dangerous Azure change in the tenant was invisible to the SIEM, so no detection could ever fire on it. 30-day retention is shorter than typical attacker dwell time, so evidence would expire before most investigations begin. Sentinel-enabled workspaces include 90 days of retention at no extra cost.

**Correction**
Enable diagnostic settings on the storage account (StorageRead / StorageWrite / StorageDelete to `law-cyberrange`); connect the Azure Activity data connector in Sentinel (subscription diagnostic setting → `law-cyberrange`); raise workspace retention to 90 days.

**Verification**
Re-run A07: all three show Configured / 90. Perform a test blob read and a test role assignment; both appear in Sentinel (`StorageBlobLogs`, `AzureActivity`).

---

### O1 — Admin accounts use phishable MFA methods
**Severity:** High  **Assets:** AditiNagpure@, breakglass@

**Evidence**
A05: both admin accounts are registered for `microsoftAuthenticatorPush` and `softwareOneTimePasscode` only. The non-admin test user already has passkeys, so phishing-resistant methods are available in the tenant but not applied to the highest-value accounts.

**Risk**
Push and OTP can be relayed by adversary-in-the-middle phishing kits (demonstrated in the assessor's Microsoft Cyber Range project).

**Correction**
Register passkeys/FIDO2 for both admins; extend the phishing-resistant authentication-strength policy (as used in CA002) to all directory roles. For break-glass, use a FIDO2 key stored physically secure.

**Verification**
Re-run A05: admins show `passKeyDeviceBound`. A CA policy requiring phishing-resistant MFA targets directory roles.

---

## 5. Remediation and verification results

Every fix was verified by re-running the **same audit check** that found the problem.

| Finding | Action taken | Verification | Result | Evidence |
|---|---|---|---|---|
| F01 | Removed Global Admin; revoked Directory.ReadWrite.All and RoleManagement.ReadWrite.Directory; replaced subscription Owner with Storage Blob Data Contributor on `rg-idaudit`; deleted the 730-day secret; assigned an owner | Re-ran A01, A02, A03 as a before/after table | 5/5 PASS | `V01-F01-verification.png` |
| F02 | App was created during this engagement and never put into use, so it was decommissioned rather than hardened (the sign-in activity check output was not retained as evidence) | Re-ran A02: app absent | PASS | `V02-F02-legacy-app-retired.png` |
| F03 | Removed svc-reporting from the CA001 exclusion; removed User Administrator; blocked sign-in | CA001 excludes only break-glass; svc-reporting accountEnabled = False; role assignments = 0 | PASS | `V03-F03-mfa-enforced.png` |
| F04 | Container set to Private; account-level public blob access off; shared key access off | Same public URL in an unauthenticated browser returns `PublicAccessNotPermitted` | PASS | `V04-F04-blob-blocked.png` |
| F05 | Storage diagnostic logs and subscription activity log sent to `law-cyberrange`; retention 30 → 90 days | Re-ran A07: Configured / Configured / 90 | PASS | `V05-F05-logging-enabled.png` |

## 6. Detection engineering (closing the "no alert fired" gap in F01)

**Rule:** *Privileged role or high-risk API permission granted to service principal* — Microsoft Sentinel scheduled analytics rule, severity High, MITRE T1098 (Account Manipulation), runs every 10 minutes over a 20-minute window. Alerts when (a) any Entra directory role is assigned to a service principal, or (b) a service principal is granted one of: `RoleManagement.ReadWrite.Directory`, `Directory.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Mail.Read`, `Mail.ReadWrite`, `Files.ReadWrite.All`.

| Test | Method | Result | Evidence |
|---|---|---|---|
| Backtest | Ran the rule query over the day's planted events | 4/4 malicious grants found (Global Admin, Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, Mail.Read); benign User.Read.All correctly ignored. Screenshot was re-captured after the live test, so it shows a 5th row (Directory Readers → app-detection-test) | `D01-detection-backtest.png` |
| Live test | Created `app-detection-test` and assigned it Directory Readers at 10:49 UTC | Incident #5 created 10 minutes after the activity (4:19 → 4:29 PM IST) | `D02-detection-live-incident.png` |
| Triage | Incident reviewed, documented and closed | Closed as **Benign Positive — security test**, closing notes recorded; test app deleted | `D03-incident-closed-classified.png` |

**Tuning notes (honest self-review):**
- **Duplicate alerts.** A 20-minute lookback on a 10-minute schedule saw the same event twice (2 alerts, 1 event). The overlap protects against late-arriving logs; the fix is to deduplicate on `CorrelationId` or align lookback with frequency.
- **No entity mapping.** The incident graph was empty. Mapping Actor → Account and ServicePrincipal → Cloud application would let analysts pivot directly.
- **Coverage gap.** The rule watches Entra roles and Graph permissions only. Azure RBAC grants (e.g. Owner to a service principal) now reach Sentinel via the activity log (F05 fix) but need a companion rule on `AzureActivity`.

## 7. Limitations

- Single-tenant trial environment; findings reflect planted conditions, not organic drift.
- Workload identity Conditional Access requires a Workload Identities Premium licence not present in this tenant; recommended but not tested.
- Planted credentials were not used to demonstrate impact; risk statements are based on documented permission capabilities.
- Defender for Cloud recommendations had not yet refreshed at the time of the audit; tool corroboration is recorded separately.
- O1 (phishing-resistant MFA for admins) is left open; it requires physical passkey enrolment and is tracked in the risk register.
- See `access-map.md` for before/after diagrams and `risk-register.md` for scoring against least privilege and Zero Trust.
