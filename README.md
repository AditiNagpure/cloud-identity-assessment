# Cloud Identity & Security Posture Assessment (Simulated)

> **SIMULATED ASSESSMENT.** Every weakness here was deliberately planted by me in my own Microsoft 365 E5 / Azure trial tenant (`AditiSecurityLab.onmicrosoft.com`), then audited, fixed and re-tested. No production systems, real users or real data were involved.

An end-to-end identity and cloud posture audit against a live Microsoft Entra ID and Azure control plane: plant realistic misconfigurations, find them the way an auditor would, fix them with least privilege, prove each fix, and build a detection so the worst one can't happen silently again.

## The loop on the headline finding (F01)

| Plant | Detect | Remediate | Verify |
|---|---|---|---|
| A "backup" app given **standing Global Admin**, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, **subscription Owner**, a 2-year secret and no owner | Graph + Az audit (A01–A03) found it; KQL showed the grants were logged but **no alert fired**, and the Owner grant never reached Sentinel at all | Removed GA and both Graph permissions; replaced Owner with *Storage Blob Data Contributor* on one resource group; deleted the secret; assigned an owner | Same checks re-run: **5/5 PASS**. New Sentinel rule backtested on the planted events, then fired on a live re-plant in **10 minutes**; incident triaged and closed |

## Results

| ID | Finding | Severity | Outcome |
|---|---|---|---|
| F01 | Over-privileged service principal (GA + directory/role write + subscription Owner) | Critical | Remediated, verified, detection built |
| F02 | Unowned legacy app with tenant-wide `Mail.Read`, 5-year secret, implicit grant, http redirect | High | Retired, verified |
| F03 | Shared admin account excluded from MFA and not MFA-registered | High | Remediated, verified |
| F04 | Storage container readable anonymously from the internet | High | Remediated, verified |
| F05 | No storage logs, Azure activity log not in SIEM, 30-day retention | Medium-High | Remediated, verified |
| O1 | Admins use phishable MFA (push/OTP); found, not planted | High | Open, tracked in risk register |

Inherent risk **1 Critical / 5 High** → residual **0 Critical / 1 High**.

## What's in this repo

| File | What it is |
|---|---|
| [`findings.md`](findings.md) | Full report: scope, rules of engagement, methodology, each finding with evidence / risk / correction / verification, remediation results, detection engineering and tuning notes, limitations |
| [`access-map.md`](access-map.md) | Before/after diagrams of which identity can reach which resource |
| [`risk-register.md`](risk-register.md) | 11 risks scored likelihood × impact, mapped to least privilege and Zero Trust, with inherent and residual ratings |
| [`evidence/`](evidence/) | Screenshots and exports referenced in the report (A = audit, V = verification, D = detection) |

## How the audit was done

Eight independent checks, run from Azure Cloud Shell and the Defender portal:

| Check | Tests | Tool |
|---|---|---|
| A01 | Who holds Entra directory roles, including apps | Microsoft Graph PowerShell |
| A02 | App permissions, owners, secret lifetime, implicit grant, redirect URIs | Microsoft Graph PowerShell |
| A03 | Privileged Azure RBAC at subscription scope | Az PowerShell |
| A04 | Conditional Access coverage and exclusions | Microsoft Graph |
| A05 | MFA registration per user | Microsoft Graph reports API |
| A06 | Storage public access, shared key, network exposure | Az PowerShell |
| A07 | Diagnostic logging and retention | Az PowerShell |
| A08 | Whether Sentinel recorded the privileged changes | KQL (Defender Advanced Hunting) |

## Skills demonstrated

- Entra ID app registration / service principal security: application permissions vs directory roles, credential hygiene, ownership
- Azure RBAC least-privilege design across the Entra and Azure permission planes
- Conditional Access and MFA coverage auditing
- Storage exposure assessment and hardening
- Logging architecture: diagnostic settings, activity log, retention
- Detection engineering in Microsoft Sentinel: KQL, backtest, live validation, incident triage, self-review of tuning
- Risk scoring against least privilege and Zero Trust (verify explicitly, least privilege, assume breach)

## Limitations

Single trial tenant with planted conditions. Workload-identity Conditional Access needs a licence the tenant doesn't have (accepted, with compensating controls). Planted credentials were never used to demonstrate impact. Details in [`findings.md`](findings.md#7-limitations).

## Related projects

- **Microsoft Cyber Range**: AiTM phishing → detect in Entra ID Protection / Sentinel → block with FIDO2 passkeys (same tenant)
- **[Detection-as-Code](https://github.com/AditiNagpure/detection-as-code)**: Sigma, Sentinel and YARA rules with CI testing; includes the break-glass sign-in rule cited as a compensating control here

---
*Author: Aditi Nagpure · November 2026*
