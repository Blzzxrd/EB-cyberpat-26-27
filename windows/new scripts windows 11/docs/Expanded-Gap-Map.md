# Expanded source-to-gap map

This document maps previously identified high-priority gaps to what is **actually included** in this package. It distinguishes bundled code from optional upstream downloads.

| Gap | New native code | Optional selected external source |
|---|---|---|
| Password length, aging, lockout | `modules/35-PolicyChecks.ps1` (configuration comparisons) | HardeningKitty, BaselineAuditor |
| Advanced audit subcategory expectations | `modules/35-PolicyChecks.ps1` (English locale parsing; not comprehensive) | HardeningKitty, Windows-11-CIS-Audit (requires syver separately) |
| User rights and security options | `modules/35-PolicyChecks.ps1` (SID inclusions, registry targets) | HardeningKitty |
| Local users, local groups and required memberships | `modules/25-ScenarioChecks.ps1` | UserAudit snapshot/diff |
| Installed software versions and install paths | `modules/25-ScenarioChecks.ps1` plus existing `80-Software.ps1` | Fleschutz software list included in `third_party/CC0/` |
| Prohibited / required services | `modules/25-ScenarioChecks.ps1`, existing `10-System.ps1` | BaselineAuditor |
| RDP security policy | `modules/42-RdpChecks.ps1` | RdpDiagnostics (requires PowerShell 7+) |
| Prohibited files, portable programs, persistence | Extension expansion in `modules/90-Files.ps1`; existing `70-Persistence.ps1` | HostInventory (requires its accompanying CSV) |

## Source versions and licensing

- HardeningKitty — `0x6d69636b/windows_hardening@10c17aea783ab27fcea8c27c4c0dc3d3edf8bcca`, MIT, https://github.com/0x6d69636b/windows_hardening
- BaselineAuditor — `Coach40oz/Windows-SecurityBaselineAuditor@9f3373d9f5a882c1fa5db88da3a642e680c02331`, MIT stated in README, https://github.com/Coach40oz/Windows-SecurityBaselineAuditor
- UserAudit — `Nihar2520/Windows-User-Audit@3428fb6f9abaeef5aaf494dc1c566a59818d26c5`, no license identified, https://github.com/Nihar2520/Windows-User-Audit
- RdpDiagnostics — `paulmann/RDP-Diagnostic-Tool@8db4c169ec0de050fb48224db729fde66219671c`, PolyForm Noncommercial 1.0.0, https://github.com/paulmann/RDP-Diagnostic-Tool
- HostInventory — `emoghadamian/host-inventory@ae3a5a6cb7beb9e63c2f9ab46cbb2c6f2e42fc4a`, no license identified, https://github.com/emoghadamian/host-inventory
- Fleschutz list-installed-software — https://github.com/fleschutz/PowerShell/blob/main/scripts/list-installed-software.ps1 , CC0 (included directly)
- Ansible Lockdown Windows 11 CIS audit — https://github.com/ansible-lockdown/Windows-11-CIS-Audit , MIT; NOT included in downloader, because `run_audit.ps1` requires the separate Syver engine plus many per-control files.

## Scope and caution

A `WARN` or `REVIEW` is not a competition point. The tool does not inspect official scored images or answer keys and cannot infer scenario requirements. HardeningKitty/CIS baseline values may be unsuitable for a specific domain controller or application server. The current CP-19 competition rules restrict AI assistance during scored rounds. Use this work only in independent, authorized training.
