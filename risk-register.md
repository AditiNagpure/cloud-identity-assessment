# Risk Register — Cloud Identity & Security Posture Assessment

> **SIMULATED ASSESSMENT** — tenant `AditiSecurityLab.onmicrosoft.com`, 15 Nov 2026. Risk owner for all items: Aditi Nagpure (tenant administrator).

**Scoring:** Likelihood (L) and Impact (I) on a 1–5 scale; Score = L × I. **Rating:** 1–4 Low · 5–9 Medium · 10–15 High · 16–25 Critical.
**Zero Trust principles:** **VE** = Verify explicitly · **LP** = Use least-privilege access · **AB** = Assume breach.

| ID | Risk | Asset | ZT | Least-privilege / Zero Trust gap | Inherent L×I | Inherent | Control applied | Residual L×I | Residual | Status | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|
| R01 (F01) | Leaked client secret gives MFA-free takeover of tenant and subscription | app-backup-automation | LP, AB | Standing Global Admin + RoleManagement write + subscription Owner for a backup job; long-lived secret; no owner | 4×5 = 20 | Critical | GA removed; Graph permissions revoked; Owner replaced with Storage Blob Data Contributor on one RG; secret deleted; owner assigned; Sentinel rule alerts on any privileged role / high-risk permission granted to an SP | 1×2 = 2 | Low | **Closed — verified** | A01–A03, A08, V01, D01, D02, D03 |
| R02 (F02) | Forgotten integration silently reads all mail | app-legacy-integration | LP, VE | Tenant-wide Mail.Read; 5-year secret; no owner; implicit grant; http redirect | 3×4 = 12 | High | App confirmed unused and deleted (soft-deleted 30 days; credentials invalid immediately) | 0 | — | **Closed — verified** | A02, V02 |
| R03 (F03) | Password spray / phishing of shared admin account | svc-reporting | VE, LP | Admin role on a shared account; excluded from MFA; no MFA registered | 3×4 = 12 | High | Removed from CA001 exclusion; User Administrator removed; sign-in blocked | 1×1 = 1 | Low | **Closed — verified** | A01, A04, A05 |
| R04 (F04) | Anonymous download of data from storage | stidaudit68750 / hr-exports | VE, AB | Public blob access; shared key auth bypasses Entra ID | 3×4 = 12 | High | Container private; account-level public blob access off; shared key disabled | 1×2 = 2 | Low | **Closed — verified** | F04, A06, V04 |
| R05 (F05) | Attacks go unrecorded or evidence expires before investigation | Storage, subscription activity log, law-cyberrange | AB | No storage logs; Azure activity log not in SIEM; 30-day retention | 3×4 = 12 | High | Storage diagnostic logs and activity log sent to Sentinel; retention raised to 90 days | 2×2 = 4 | Low | **Closed — verified** | A07, A08, V05 |
| R06 (O1) | AiTM phishing of admin accounts | AditiNagpure@, breakglass@ | VE | Admins use push/OTP (phishable) while a normal user already has passkeys | 2×5 = 10 | High | Planned: register passkeys/FIDO2 for both admins; require phishing-resistant authentication strength for all directory roles | 2×5 = 10 | High | **Open** — target 30 Nov 2026 | A05 |
| R07 | Workload identities (apps) are not covered by Conditional Access | All service principals | VE, AB | No location or risk conditions on app sign-ins | 2×4 = 8 | Medium | Requires Workload Identities Premium licence (not in tenant). Compensating: no long-lived secrets; detection rule on privilege grants | 1×4 = 4 | Low | **Accepted** (licence) | A04 |
| R08 | Detection rule creates duplicate alerts and has no entities | Sentinel analytics rule | AB | 20-min lookback vs 10-min frequency; no entity mapping, so analysts can't pivot | 3×2 = 6 | Medium | Planned: align lookback with frequency or deduplicate on CorrelationId; map Account (Actor) and CloudApplication (ServicePrincipal) entities | 3×2 = 6 | Medium | **Open** — tuning | D02 |
| R09 | Storage account reachable from any network | stidaudit68750 | AB | Public network access enabled, no firewall rules | 2×2 = 4 | Low | Planned: restrict to selected networks / private endpoint, or delete at end of engagement | 2×2 = 4 | Low | **Open** — resolved by cleanup | A06 |
| R10 | Break-glass account is excluded from MFA policy | breakglass@ | VE | Intentional exclusion | 1×5 = 5 | Medium | Accepted by design. Compensating: Sentinel alert on every break-glass sign-in (Detection-as-Code project) | 1×5 = 5 | Medium | **Accepted** | A04 |
| R11 | First-party Microsoft SP holds User Access Administrator | MTP Unified RBAC | LP | Microsoft-managed; RG scope only | 1×3 = 3 | Low | Reviewed — created by Sentinel → Defender onboarding; expected | 1×3 = 3 | Low | **Accepted** | A03 |

## Summary

| | Critical | High | Medium | Low |
|---|---|---|---|---|
| **Inherent** (before) | 1 | 5 | 3 | 2 |
| **Residual** (after) | 0 | 1 (R06, open) | 2 (R08 open, R10 accepted) | 7 (R02 eliminated) |
