# PhantomLDAP — Detection & Blue Team Guide

> **Audience:** SOC analysts, Threat Hunters, and Detection Engineers.  
> This document covers Windows Event IDs, Sigma rules, network detection signatures, and SIEM queries for detecting PhantomLDAP activity.

---

## Table of Contents

1. [Host-Based Indicators](#1-host-based-indicators)
2. [Event ID Matrix](#2-event-id-matrix)
3. [Sigma Rules](#3-sigma-rules)
4. [Network Detection (NDR)](#4-network-detection-ndr)
5. [YARA Rules](#5-yara-rules)
6. [SIEM Queries](#6-siem-queries)
7. [Microsoft Defender for Identity Mappings](#7-microsoft-defender-for-identity-mappings)
8. [Hardening Recommendations](#8-hardening-recommendations)

---

## 1. Host-Based Indicators

### What PhantomLDAP Does (and Does Not Do)

| Action | PhantomLDAP | Detection Opportunity |
|:-------|:-----------:|:---------------------|
| Instantiate CLR | ❌ | Cannot detect via .NET/AMSI |
| Spawn child process | ❌ | No Event ID 4688 from BOF execution |
| Write temporary files | ❌ | No file creation artifacts |
| Load `wldap32.dll` | ✅ (if not already loaded) | Sysmon Event 7 (image load) |
| Access LDAP (port 389/636) | ✅ | Network monitoring, Sysmon 3 |
| Read `nTSecurityDescriptor` | ✅ | Event ID 4662 (if SACL audit enabled) |
| Execute from unusual process | Context-dependent | Sysmon 1 ancestry analysis |

### Strongest Detection Signal

The most reliable host-based signal is **Sysmon Event ID 7** (Image Load) for `wldap32.dll` being loaded by a process that has no legitimate reason to perform LDAP queries (e.g., `notepad.exe`, `calc.exe`, or any process not in the approved baseline).

---

## 2. Event ID Matrix

| Event ID | Source | Category | Description | Detection Value |
|:---------|:------:|:--------:|:------------|:--------------:|
| **1644** | Directory Service | LDAP | Expensive/slow LDAP search logged on DC (requires registry key) | 🔴 **High** |
| **4662** | Security | Object Access | AD object operation (read `nTSecurityDescriptor`) | 🟡 Medium |
| **4624** | Security | Logon | Successful logon (SSPI Kerberos bind) | 🟢 Low (noisy) |
| **4768** | Security | Kerberos | TGT request (pre-existing session, may not trigger) | 🟢 Low |
| **4769** | Security | Kerberos | TGS request (SPN enumeration correlation) | 🟡 Medium |
| **7** | Sysmon | Image Load | `wldap32.dll` loaded by unexpected process | 🔴 **High** |
| **3** | Sysmon | Network | Outbound TCP/389 or TCP/636 from workstation | 🟡 Medium |
| **1** | Sysmon | Process | Process creation (ancestry: beacon parent spawning mmc.exe) | 🟡 Medium |
| **8** | Sysmon | CreateRemoteThread | Injection detection (CS inject method-dependent) | 🔴 High |

### Enabling Event ID 1644 (LDAP Diagnostics)

```
# On each Domain Controller (requires reboot-free registry edit):
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "15 Field Engineering" /t REG_DWORD /d 5 /f

# This logs LDAP searches exceeding the cost threshold to Event ID 1644
# in the Directory Service event log.
```

---

## 3. Sigma Rules

### Rule 1 — Suspicious LDAP Enumeration from Workstation

```yaml
title: Suspicious LDAP Enumeration from Non-Server Process
id: a4f3c1e2-8b2d-4f1a-9c3e-2d7b5a9f8e6c
status: experimental
description: |
  Detects LDAP queries (port 389/636) initiated by processes that are not
  typical Active Directory administration tools. May indicate BOF-based
  AD enumeration tools like PhantomLDAP operating from an injected Beacon.
author: PhantomLDAP Detection Project
date: 2024-01-15
tags:
  - attack.discovery
  - attack.t1069.002
  - attack.t1087.002
  - attack.t1482
logsource:
  product: windows
  category: network_connection
  service: sysmon
detection:
  selection:
    EventID: 3
    DestinationPort:
      - 389
      - 636
  filter_legitimate:
    Image|contains:
      - '\mmc.exe'
      - '\LDP.exe'
      - '\dsa.msc'
      - '\powershell.exe'
      - '\outlook.exe'
      - '\svchost.exe'
      - '\lsass.exe'
      - '\ADWS.exe'
      - '\Microsoft.ActiveDirectory.WebServices.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Custom LDAP-capable applications
  - Administrative scripts using LDAP APIs
  - Legitimate management tools not in the filter list
level: medium
```

---

### Rule 2 — wldap32.dll Loaded in Unexpected Process

```yaml
title: wldap32.dll Image Load in Unexpected Process
id: b5e2d3f1-9c4a-4b2e-8d1f-3e8c6b7a2f1d
status: experimental
description: |
  Detects the loading of wldap32.dll (native Windows LDAP client library)
  into processes that have no business performing LDAP queries. BOF-based
  tools like PhantomLDAP may trigger wldap32.dll load if it is not already
  present in the process's module list.
author: PhantomLDAP Detection Project
date: 2024-01-15
tags:
  - attack.discovery
  - attack.t1087.002
  - attack.defense_evasion
  - attack.t1055
logsource:
  product: windows
  category: image_load
  service: sysmon
detection:
  selection:
    EventID: 7
    ImageLoaded|endswith: '\wldap32.dll'
  filter_known_legitimate:
    Image|contains:
      - '\mmc.exe'
      - '\explorer.exe'
      - '\outlook.exe'
      - '\ADWS.exe'
      - '\powershell.exe'
      - '\LDP.exe'
      - '\svchost.exe'
      - '\SearchHost.exe'
      - '\taskhostw.exe'
  condition: selection and not filter_known_legitimate
falsepositives:
  - LDAP-enabled third-party applications not in the filter list
  - Developer tools testing LDAP connectivity
level: high
```

---

### Rule 3 — AS-REP Roasting Adjacent LDAP Query

```yaml
title: AS-REP Roasting Target Enumeration via LDAP
id: c6f3e4a2-1d5b-4c3f-9e2a-4f9d7c8b3e2f
status: experimental
description: |
  Detects LDAP searches using the bit filter for userAccountControl flag
  0x400000 (DONT_REQUIRE_PREAUTH = 4194304), which is characteristic of
  AS-REP Roasting target enumeration. The OID 1.2.840.113556.1.4.803
  is the LDAP_MATCHING_RULE_BIT_AND extensible match.
author: PhantomLDAP Detection Project
date: 2024-01-15
references:
  - https://attack.mitre.org/techniques/T1558/004/
tags:
  - attack.credential_access
  - attack.t1558.004
logsource:
  product: windows
  service: ldap
  category: search
detection:
  selection:
    EventID: 1644
    SearchFilter|contains:
      - '1.2.840.113556.1.4.803:=4194304'
      - 'DONT_REQUIRE_PREAUTH'
      - 'userAccountControl:1.2.840.113556.1.4.803:=4194304'
  condition: selection
falsepositives:
  - Authorized security assessments
  - Vulnerability scanning tools
level: high
```

---

### Rule 4 — Kerberoasting SPN Enumeration via LDAP

```yaml
title: Kerberoasting SPN Enumeration via LDAP Filter
id: d7a4f5b3-2e6c-4d4g-af3b-5g0e8d9c4f3e
status: experimental
description: |
  Detects LDAP queries that specifically search for accounts with Service
  Principal Names (SPNs), which is the prerequisite step before Kerberoasting.
  The filter (servicePrincipalName=*) combined with user account filters is
  a strong indicator of Kerberoasting target reconnaissance.
author: PhantomLDAP Detection Project
date: 2024-01-15
references:
  - https://attack.mitre.org/techniques/T1558/003/
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  product: windows
  service: ldap
  category: search
detection:
  selection_filter:
    EventID: 1644
    SearchFilter|contains:
      - 'servicePrincipalName=*'
  selection_user_scope:
    SearchFilter|contains:
      - 'objectClass=user'
      - 'objectCategory=person'
  condition: selection_filter and selection_user_scope
falsepositives:
  - Authorized Red Team assessments
  - LDAP-based service management tools
  - Active Directory health check scripts
level: high
```

> [!NOTE]
> Save these rules as individual `.yml` files in `docs/detection/`. They require **Event ID 1644** enabled on Domain Controllers (see Section 2) and **Sysmon** deployed with an appropriate configuration.

---

## 4. Network Detection (NDR)

### Zeek/Suricata: LDAP Paging OID Signature

The paging control OID `1.2.840.113556.1.4.319` is embedded in the BER-encoded LDAP Extended Request and is visible in plaintext LDAP traffic.

**Zeek (zeek-ldap package):**
```zeek
# Detect LDAP Simple Paged Results control in search requests
event ldap_search_request(c: connection, msg_id: int, base_dn: string,
                           scope: int, deref: int, size_limit: int,
                           time_limit: int, filter: string)
{
    if (c$service$ldap$controls != T) return;
    # The paging OID in controls indicates automated enumeration
    for (ctrl in c$service$ldap$controls) {
        if (ctrl$control_type == "1.2.840.113556.1.4.319") {
            NOTICE([$note=LDAP::Paged_Enumeration,
                    $conn=c,
                    $msg=fmt("LDAP paged search from %s filter=%s", c$id$orig_h, filter),
                    $identifier=cat(c$id)]);
        }
    }
}
```

**Suricata rule:**
```
alert tcp any any -> any 389 (
    msg:"PhantomLDAP - LDAP Paging OID Detected (1.2.840.113556.1.4.319)";
    content:"|01 02 04 16|";
    content:"1.2.840.113556.1.4.319";
    within:50;
    classtype:policy-violation;
    sid:9000001;
    rev:1;
)
```

### Network Anomaly Signatures

| Anomaly | Threshold | Alert Priority |
|:--------|:---------:|:--------------:|
| Workstation → DC port 389 > 50 connections/hour | Variable | 🟡 Medium |
| Single source IP > 10,000 LDAP objects/session | Domain-dependent | 🔴 High |
| Paging OID from non-DC host | Any | 🟡 Medium |
| LDAP bind + paged search of `nTSecurityDescriptor` | Any | 🔴 High |

---

## 5. YARA Rules

### DJB2 Hash Pattern Detection

PhantomLDAP's compiled object files contain pre-computed DJB2 hash constants as DWORD literals. The following YARA rule matches the combination of the most distinctive hashes in a binary.

```yara
rule PhantomLDAP_DJB2_Hashes
{
    meta:
        description = "Detects PhantomLDAP BOF object files via pre-computed DJB2 hash constants"
        author      = "PhantomLDAP Detection Project"
        date        = "2024-01-15"
        reference   = "https://github.com/PhantomLDAP/PhantomLDAP"
        tlp         = "WHITE"
        severity    = "HIGH"

    strings:
        // PHANTOM_HASH_WLDAP32     = 0xEEE845E3
        $wldap32_hash   = { E3 45 E8 EE }

        // PHANTOM_HASH_KERNEL32    = 0x6DDB9555
        $kernel32_hash  = { 55 95 DB 6D }

        // PHANTOM_HASH_ldap_search_ext_sW = 0xC15A8F60
        $ldap_search_hash = { 60 8F 5A C1 }

        // PHANTOM_HASH_ldap_create_page_controlW = 0x78E2D50F
        $page_ctrl_hash = { 0F D5 E2 78 }

        // PHANTOM_HASH_ldap_parse_page_controlW = 0x59B4F83A
        $parse_page_hash = { 3A F8 B4 59 }

        // PHANTOM_HASH_HeapAlloc = 0x32C670D0
        $heapalloc_hash = { D0 70 C6 32 }

    condition:
        // Match if at least 4 of the 6 hash constants are present
        // (some may be absent in partially compiled objects)
        4 of them
}
```

**Deployment:**
```bash
# Scan a directory for PhantomLDAP BOF files:
yara -r phantom_ldap_djb2.yar /path/to/scan/

# Scan memory dump:
yara phantom_ldap_djb2.yar memory.dmp
```

---

## 6. SIEM Queries

### Splunk SPL

**Query 1: wldap32.dll loads from unexpected processes**
```spl
index=sysmon EventCode=7 ImageLoaded="*\\wldap32.dll"
| where NOT match(Image, "(?i)(mmc|explorer|outlook|svchost|ADWS|LDP|powershell|taskhostw)\.exe")
| stats count by Computer, Image, ImageLoaded, User
| where count > 0
| sort -count
```

**Query 2: High-volume LDAP from workstations (Event ID 1644)**
```spl
index=windows source="*Directory Service*" EventCode=1644
| rex field=Message "Filter: (?P<filter>[^\n]+)"
| rex field=Message "Client: (?P<client>[^\n]+)"
| stats count by client, filter, host
| where count > 5
| sort -count
```

**Query 3: AS-REP Roasting enumeration filter**
```spl
index=windows source="*Directory Service*" EventCode=1644
| rex field=Message "Filter: (?P<filter>[^\n]+)"
| where match(filter, "1\.2\.840\.113556\.1\.4\.803:=4194304|DONT_REQUIRE_PREAUTH")
| table _time, host, filter, Message
```

**Query 4: Kerberoasting TGS spike correlation**
```spl
index=windows EventCode=4769
| stats count by Account_Name, Service_Name, Client_Address
| where count > 5 AND NOT match(Service_Name, "(?i)(krbtgt|ldap|host|gc|cifs)\/")
| sort -count
```

---

## 7. Microsoft Defender for Identity Mappings

| MDI Alert | Correlation to PhantomLDAP | Likelihood |
|:----------|:--------------------------|:----------:|
| **Suspected AS-REP Roasting attack** | `bof_enum_asrep` + subsequent TGT requests | 🔴 High |
| **Suspected Kerberos SPNs exposure** | `bof_enum_spn` | 🟡 Medium |
| **LDAP enumeration** | All modules (high object count) | 🟡 Medium |
| **Active Directory attributes reconnaissance** | `bof_enum_acl` (`nTSecurityDescriptor` read) | 🔴 High |
| **Suspected account enumeration** | `bof_enum_admins`, `bof_enum_asrep` | 🟡 Medium |
| **Domain dominance** | Post-exploitation after DACL abuse | 🔴 High |

> [!WARNING]
> MDI's **LDAP enumeration** alert is triggered by volume-based heuristics. Using a smaller page size (100–200) may reduce the likelihood of triggering this alert.

---

## 8. Hardening Recommendations

### Reduce AS-REP Roasting Attack Surface
```powershell
# Identify accounts without Kerberos pre-auth (require it):
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} |
    Set-ADAccountControl -DoesNotRequirePreAuth $false
```

### Reduce Kerberoasting Attack Surface
```powershell
# Rotate SPN account passwords to 25+ char random strings:
$pass = -join ((65..90)+(97..122)+(48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
Set-ADAccountPassword -Identity sql_svc -NewPassword (ConvertTo-SecureString $pass -AsPlainText -Force)

# Better: Convert to Group Managed Service Accounts (GMSA):
New-ADServiceAccount -Name "sql_svc_gmsa" -DNSHostName "sql.corp.local" -ManagedPasswordIntervalInDays 30
```

### Restrict LDAP Read of `nTSecurityDescriptor`
```powershell
# Enable auditing of nTSecurityDescriptor reads (SACL):
# This generates Event ID 4662 for every security descriptor read
# Note: High volume — filter to sensitive objects only (DAs, Schema, Domain)
```

### Enable Event ID 1644 on All DCs
```powershell
# Enable LDAP diagnostics logging:
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics"
Set-ItemProperty -Path $key -Name "15 Field Engineering" -Value 5
```

### Deploy Protected Users Security Group
```powershell
# Add privileged accounts to Protected Users (disables NTLM, forces AES Kerberos):
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator","sql_svc"
```
