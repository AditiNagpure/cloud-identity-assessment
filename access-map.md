# Access Map — Before and After Remediation

> **SIMULATED ASSESSMENT** — tenant `AditiSecurityLab.onmicrosoft.com`. Red = finding, green = least-privilege / remediated, grey = accepted or reviewed.

## Before (as planted, 15 Nov 2026 — audit checks A01–A08)

```mermaid
flowchart LR
  subgraph ID[Identities]
    ADM[Aditi Nagpure<br/>admin user]
    BG[Break Glass<br/>emergency admin]
    GEET[Geetansh Chawla<br/>user · passkey]
    SVC[svc-reporting<br/>shared account<br/>NO MFA · excluded from CA001]
    APPB[app-backup-automation<br/>service principal<br/>secret 730 days · 0 owners]
    APPL[app-legacy-integration<br/>service principal<br/>secret 5 years · 0 owners<br/>implicit grant · http redirect]
    APPH[app-hr-reporting<br/>service principal<br/>no secret · 1 owner]
    ANON((Anonymous<br/>internet))
  end

  subgraph RES[Resources]
    DIR[(Entra ID directory)]
    MAIL[(All Exchange mailboxes)]
    SUB[(Azure subscription)]
    BLOB[(stidaudit68750<br/>hr-exports container)]
    SIEM[(Sentinel<br/>law-cyberrange · 30-day retention)]
  end

  ADM -- Global Administrator --> DIR
  ADM -- Owner --> SUB
  BG -- Global Administrator --> DIR
  SVC -- "User Administrator ⚠ F03" --> DIR
  APPB -- "Global Administrator ⚠ F01" --> DIR
  APPB -- "Directory.ReadWrite.All +<br/>RoleManagement.ReadWrite.Directory ⚠ F01" --> DIR
  APPB -- "Owner ⚠ F01" --> SUB
  APPL -- "Mail.Read (tenant-wide) ⚠ F02" --> MAIL
  APPH -- User.Read.All --> DIR
  ANON -- "anonymous read ⚠ F04" --> BLOB
  DIR -. Entra audit logs .-> SIEM
  SUB -. "activity log NOT exported ⚠ F05" .-x SIEM
  BLOB -. "no diagnostic logs ⚠ F05" .-x SIEM

  classDef risk fill:#fde2e1,stroke:#c0392b,color:#000
  classDef ok fill:#e3f4e8,stroke:#2e7d32,color:#000
  classDef neutral fill:#eeeeee,stroke:#777,color:#000
  class SVC,APPB,APPL,ANON risk
  class APPH,GEET ok
  class ADM,BG neutral
```

## After (remediated and verified, 15 Nov 2026 — checks V01–V05, D01–D03)

```mermaid
flowchart LR
  subgraph ID[Identities]
    ADM[Aditi Nagpure<br/>admin user<br/>O1 open: move to passkey]
    BG[Break Glass<br/>excluded from CA001<br/>sign-in alert in Sentinel]
    GEET[Geetansh Chawla<br/>user · passkey]
    SVC[svc-reporting<br/>sign-in BLOCKED · no role<br/>back under CA001]
    APPB[app-backup-automation<br/>no secret · 1 owner]
    APPL[app-legacy-integration<br/>DELETED]
    APPH[app-hr-reporting<br/>no secret · 1 owner]
    ANON((Anonymous<br/>internet))
  end

  subgraph RES[Resources]
    DIR[(Entra ID directory)]
    SUB[(Azure subscription)]
    RG[(rg-idaudit)]
    BLOB[(stidaudit68750<br/>private · shared key off)]
    SIEM[(Sentinel<br/>law-cyberrange · 90-day retention)]
    RULE{{Analytics rule:<br/>privileged role / high-risk<br/>permission granted to SP}}
  end

  ADM -- Global Administrator --> DIR
  ADM -- Owner --> SUB
  BG -- Global Administrator --> DIR
  APPB -- "Storage Blob Data Contributor<br/>(rg-idaudit only)" --> RG
  RG --- BLOB
  APPH -- User.Read.All --> DIR
  ANON -. "PublicAccessNotPermitted" .-x BLOB
  DIR -. Entra audit logs .-> SIEM
  SUB -. activity log .-> SIEM
  BLOB -. StorageRead/Write/Delete .-> SIEM
  SIEM --> RULE

  classDef ok fill:#e3f4e8,stroke:#2e7d32,color:#000
  classDef neutral fill:#eeeeee,stroke:#777,color:#000
  classDef gone fill:#ffffff,stroke:#bbb,color:#999,stroke-dasharray: 4 3
  class SVC,APPB,APPH,GEET,BLOB,RULE ok
  class ADM,BG neutral
  class APPL,ANON gone
```

## What changed

| Path | Before | After |
|---|---|---|
| app-backup-automation → Entra | Global Admin + directory and role write | none |
| app-backup-automation → Azure | Owner on whole subscription | Storage Blob Data Contributor on one resource group |
| app-backup-automation credential | 730-day secret, no owner | no secret, 1 named owner |
| app-legacy-integration → mailboxes | Mail.Read on every mailbox | app deleted |
| svc-reporting → Entra | User Administrator, no MFA | no role, sign-in blocked, MFA enforced |
| Internet → hr-exports | anonymous read | blocked (PublicAccessNotPermitted) |
| Azure + storage → Sentinel | not logged, 30-day retention | logged, 90-day retention, detection rule live |
