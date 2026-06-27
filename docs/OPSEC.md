# PhantomLDAP — OpSec Guide

> **Audience:** Red Team operators running PhantomLDAP during authorized engagements.  
> This document covers process selection, timing, LDAP vs. LDAPS trade-offs, module execution order, and TTP chaining for maximum stealth.

---

## Table of Contents

1. [Core OpSec Principles](#1-core-opsec-principles)
2. [Recommended Injection Targets](#2-recommended-injection-targets)
3. [Timing & Jitter Recommendations](#3-timing--jitter-recommendations)
4. [LDAP vs. LDAPS Trade-offs](#4-ldap-vs-ldaps-trade-offs)
5. [Network OpSec](#5-network-opsec)
6. [Tool Comparison Table](#6-tool-comparison-table)
7. [Optimal Module Execution Order](#7-optimal-module-execution-order)
8. [TTP Chaining — Attack Paths](#8-ttp-chaining--attack-paths)
9. [Defensive Evasion Checklist](#9-defensive-evasion-checklist)

---

## 1. Core OpSec Principles

PhantomLDAP was designed around five non-negotiable OpSec constraints:

| Constraint | Implementation |
|:-----------|:--------------|
| **No CLR loading** | Pure C BOF — .NET never initialized |
| **No child process** | Runs in Beacon thread; no `CreateProcess` |
| **No IAT imports for LDAP** | PEB walking + DJB2 resolution |
| **No disk writes** | All results via `BeaconPrintf` (C2 channel) |
| **No `VirtualAllocEx`** | BOF memory allocated by Cobalt Strike loader |

### What PhantomLDAP Does NOT Do

- ❌ Create temporary files in `%TEMP%`
- ❌ Create Windows Event Log entries for process creation
- ❌ Register Scheduled Tasks, Services, or WMI subscriptions
- ❌ Call `CreateRemoteThread`, `NtCreateThreadEx`, or `RtlCreateUserThread`
- ❌ Spawn `powershell.exe`, `cmd.exe`, or any interpreter

---

## 2. Recommended Injection Targets

The Beacon process context determines the risk profile of LDAP queries.

> [!IMPORTANT]
> Inject into a process that **legitimately performs LDAP queries** during normal operation. This makes PhantomLDAP's network traffic blend with expected process behavior.

### Process Selection Matrix

| Process | Risk Score | Legitimacy | Notes |
|:--------|:----------:|:----------:|:------|
| `explorer.exe` | 🟢 Low | Medium | Users' shell, LDAP queries expected for AD-integrated features |
| `mmc.exe` | 🟢 Low | **High** | Management Console natively queries LDAP — ideal host |
| `dsa.msc` / `AdsiEdit.msc` | 🟢 Low | **High** | AD management snap-ins — LDAP is their core function |
| `outlook.exe` | 🟡 Medium | High | GAL lookups use LDAP; large query volume may stand out |
| `lsass.exe` | 🔴 **AVOID** | — | Protected process; injection requires kernel access, extreme EDR trigger |
| `svchost.exe` | 🟡 Medium | Low | LDAP from svchost is unusual for most services |
| `taskmgr.exe` | 🟡 Medium | Low | Legitimate but short-lived process |
| `rundll32.exe` | 🔴 High | None | Heavy EDR monitoring; LDAP from rundll32 = instant alert |
| `notepad.exe` | 🔴 High | None | No LDAP behavior expected — behavioral anomaly |

**Optimal workflow:**
```
1. Check if mmc.exe is running on the compromised host
   ps | grep mmc

2. If mmc.exe exists: inject Beacon into it
   inject <pid> x64 LISTENER

3. Run PhantomLDAP modules from the mmc.exe Beacon
   bof_enum_spn
```

---

## 3. Timing & Jitter Recommendations

### Execution Windows

| Time | Risk | Reason |
|:-----|:----:|:-------|
| 08:00–09:30 | 🔴 Higher | SOC morning shift starting, alert review |
| 09:30–12:00 | 🟢 Low | Normal business hours — LDAP queries blend |
| 12:00–13:30 | 🟢 Low | Lunch hours — SOC attention reduced |
| 13:30–17:30 | 🟢 Low | Normal business hours |
| 17:30–22:00 | 🟡 Medium | After-hours, some SOC monitoring |
| 22:00–07:00 | 🟡 Medium | Overnight — anomalous if no AD replication traffic expected |

### Page Size Tuning

Smaller page sizes reduce per-query network burst, reducing NDR anomaly scores:

```
# Low-profile: 100 objects/page (slower, but smaller LDAP bursts)
# Default: 500 objects/page (reasonable balance)
# Fast (for large domains): 1000 objects/page (AD server default max)
```

Modify `PHANTOM_DEFAULT_PAGE_SIZE` in `phantom_ldap.h`, or pass at runtime via future argument extensions.

### Inter-Module Sleep

After each module, sleep the Beacon before running the next:

```
# Cobalt Strike console:
bof_enum_spn
sleep 300 30    ← 5 min sleep, 30% jitter

bof_enum_admins
sleep 180 50    ← 3 min sleep, 50% jitter
```

---

## 4. LDAP vs. LDAPS Trade-offs

### LDAP (Port 389)

| Property | Value |
|:---------|:------|
| Network visibility | **Cleartext** — all attributes visible to NDR/packet capture |
| EDR detection | Traffic pattern analysis still applies |
| Authentication | SASL/SSPI — Kerberos ticket still encrypted |
| Performance | Slightly faster (no TLS overhead) |
| Requirement | Default on all DCs |

### LDAPS (Port 636)

| Property | Value |
|:---------|:------|
| Network visibility | **Encrypted** — attribute names and values hidden from NDR |
| NDR detection | Only TLS metadata visible (hostname, cert, byte volumes) |
| Authentication | SASL over TLS — same Kerberos mechanism |
| Performance | ~5% overhead for TLS handshake + encryption |
| Requirement | Requires DC certificate (automatic with PKI, opt-in without) |

> [!TIP]
> For engagements where NDR (Zeek, Darktrace, Vectra) is deployed: use LDAPS.  
> The paging OID `1.2.840.113556.1.4.319` visible in plaintext LDAP traffic is a direct indicator.

### Enabling LDAPS in PhantomLDAP

```
# In CNA commands, pass DC with LDAPS flag:
# (modify phantom_ldap.cna if you add a -ssl flag, or directly:)
# Current implementation: use_ssl is hardcoded to FALSE
# Change in phantom_ldap_init() call in each module:
#   phantom_ldap_init(&ctx, dc_name, TRUE, 0)  ← TRUE = LDAPS
```

---

## 5. Network OpSec

### Traffic Profile Comparison

| Metric | SharpHound Full Run | PhantomLDAP Default |
|:-------|:-----------------:|:------------------:|
| Duration | 2–15 minutes | 5–60 minutes (paged) |
| Peak throughput | Very high (parallel) | Low-medium (sequential) |
| LDAP connections | Multiple | 1 per module |
| Paging OID in traffic | Sometimes | Always |
| Objects per burst | Up to server limit | 500 (configurable) |

### Indicators of Compromise (Network)

| Indicator | Protocol | Mitigation |
|:----------|:--------:|:-----------|
| Paging OID `1.2.840.113556.1.4.319` in LDAP Extended Request | LDAP/389 | Use LDAPS |
| High volume of `SearchResultEntry` PDUs from a workstation | LDAP/389 | Use LDAPS |
| Workstation connecting to DC on port 389 outside business hours | LDAP | Time operations appropriately |
| Unusual `BaseDN` (e.g., rootDSE query from workstation) | LDAP | Normal — rootDSE query is brief |

---

## 6. Tool Comparison Table

| Property | PhantomLDAP | SharpHound 2.x | PowerView | ADExplorer | BloodHound-CE |
|:---------|:-----------:|:--------------:|:---------:|:----------:|:-------------:|
| **Execution model** | BOF (in-thread) | Fork & Run | PowerShell | Native EXE | Native EXE |
| **CLR loaded** | ❌ | ✅ | ❌ | ❌ | ❌ |
| **AMSI bypass needed** | ❌ | ✅ | ✅ | ❌ | ❌ |
| **Static wldap32 IAT** | ❌ | N/A | N/A | ✅ | ✅ |
| **Dynamic API resolve** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Disk writes** | ❌ | ✅ (JSON) | ❌ | ✅ (ADS) | ✅ (zip/JSON) |
| **Results via C2** | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Binary DACL parse** | ✅ Full | Partial | ✅ | ❌ | ✅ |
| **Requires .NET** | ❌ | ✅ (4.6+) | ❌ | ❌ | ❌ |
| **Requires PowerShell** | ❌ | ❌ | ✅ | ❌ | ❌ |
| **ETW telemetry** | Minimal | High | Medium | Low | Low |
| **Event ID 4688 (new proc)** | ❌ | ✅ | ❌ | ✅ | ✅ |
| **Graph analysis** | ❌ | ✅ (BloodHound) | ❌ | ❌ | ✅ |

---

## 7. Optimal Module Execution Order

Execute modules in order of ascending risk and data value:

```
Phase 1 — Domain Reconnaissance (lowest risk)
─────────────────────────────────────────────
1. bof_enum_trusts      ← Map domain topology first
2. bof_enum_computers   ← Identify DCs, legacy hosts
3. bof_enum_gpo         ← Check for GPO-based persistence paths

Phase 2 — Credential Targets (medium risk)
──────────────────────────────────────────
4. bof_enum_spn         ← Kerberoasting candidates
5. bof_enum_asrep       ← AS-REP Roasting targets
6. bof_enum_admins      ← High-value admin accounts

Phase 3 — Privilege Escalation Paths (highest risk — more LDAP reads)
──────────────────────────────────────────────────────────────────────
7. bof_enum_acl <domain-root>         ← Domain object DACL
   bof_enum_acl <DA-group-dn>         ← Domain Admins DACL
   bof_enum_acl <schema-dn>           ← Schema DACL

Phase 4 — Custom Queries (as needed)
─────────────────────────────────────
8. bof_ldap_query ...   ← Targeted follow-up queries
```

---

## 8. TTP Chaining — Attack Paths

### Chain 1: Kerberoasting → Password Spray

```
bof_enum_spn
  → Identify service accounts with SPNs
  → Request TGS tickets (Rubeus / GetUserSPNs)
  → Crack with hashcat -m 13100
  → Validate with CrackMapExec / SMB spray

bof_enum_computers
  → Identify hosts where cracked account runs the service
  → Lateral movement via cracked credential
```

### Chain 2: DACL Abuse → Privilege Escalation

```
bof_enum_acl "DC=corp,DC=local"
  → Identify accounts with WriteDACL on domain object
  → Use WriteDACL to grant DCSync rights:
      Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" 
          -PrincipalIdentity attacker -Rights DCSync

bof_enum_acl "CN=Domain Admins,CN=Users,DC=corp,DC=local"
  → Identify accounts with GenericWrite on DA group
  → Add controlled account to Domain Admins:
      Add-DomainGroupMember -Identity "Domain Admins" -Members attacker
```

### Chain 3: AS-REP Roasting → Admin Account

```
bof_enum_asrep
  → Collect AS-REP hashes without credentials
  → Crack with hashcat -m 18200

bof_enum_admins
  → If cracked account has adminCount=1 → direct privileged access
```

### Chain 4: Trust Abuse → Cross-Forest

```
bof_enum_trusts
  → Identify bidirectional trust without SID filtering
  → Enumerate foreign domain via bof_ldap_query with alternate DC
  → If forest trust: SID History injection to access resources
```

---

## 9. Defensive Evasion Checklist

Before running PhantomLDAP in a sensitive engagement:

- [ ] **Confirm authorization scope** — explicit written permission
- [ ] **Check SOC schedule** — avoid peak monitoring windows
- [ ] **Identify EDR product** — know what's deployed before choosing injection target
- [ ] **Select injection target** — prefer `mmc.exe` or AD management processes
- [ ] **Configure sleep/jitter** — minimum 3 min between modules
- [ ] **Use LDAPS** if NDR (Zeek/Darktrace/Vectra) is deployed
- [ ] **Reduce page size** to 100–200 in environments with aggressive DLP/NDR
- [ ] **Avoid lsass.exe** — always
- [ ] **Test in lab first** — verify BOF runs cleanly before production engagement
- [ ] **Document all actions** — timestamped log for deconfliction
