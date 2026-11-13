# Upstream security-audit scripts (separate, optional)

This folder contains one CC0-licensed upstream script **directly** and a version-pinned downloader for other reviewed tools. It does not silently invoke, install, or import any downloaded code. The main `Start-Audit.ps1` launcher does not invoke any upstream scripts.

## Included directly

- `CC0/list-installed-software.ps1` — Markus Fleschutz, CC0. Lists uninstall-registry software including names and versions. It does not include Store apps. Source: https://github.com/fleschutz/PowerShell/blob/main/scripts/list-installed-software.ps1

## Download manually on your own Windows training VM

Run from `third_party` **outside scored competition rounds**:

```powershell
.\Download-External-Audit-Tools.ps1 -Tool HardeningKitty
.\Download-External-Audit-Tools.ps1 -Tool BaselineAuditor,UserAudit,RdpDiagnostics,HostInventory
```

The downloader pins each file to an inspected upstream Git commit, saves it under `optional/<Tool>/`, produces a SHA-256 download log, and **does not execute it**. You must review the scripts before deciding whether to run them. A successful download does not establish safety or license permission.

| Tool | Selected files fetched | Purpose | License / constraints |
|---|---|---|---|
| HardeningKitty | `HardeningKitty.psm1`, `.psd1`, two baseline finding lists and signed manifest files | Policy-level auditing | MIT. Use `-Mode Audit`; avoid `HailMary` on critical hosts |
| BaselineAuditor | `script.ps1`, README | Password, audit, service, security options comparisons | MIT stated in README; no top-level LICENSE verified |
| UserAudit | `LocalUserSnapshot.ps1`, `diff_snapshots.ps1`, README | Snapshot and diff local users/groups | No explicit license found; verify permission before redistributing |
| RdpDiagnostics | `RDP-Tool.ps1`, LICENSE, README | Detailed RDP diagnostic | PolyForm Noncommercial 1.0.0; requires PowerShell 7+ according to current source; use diagnostic mode only |
| HostInventory | `host_inventory.ps1`, `windows_suspicious_tasks.csv`, README | Deep read-only persistence/system inventory | No explicit license found; verify permission before redistributing |

**Not bundled:** `ansible-lockdown/Windows-11-CIS-Audit` uses external `syver` binaries and per-control configuration trees; downloading `run_audit.ps1` alone will not make it work. Install it separately according to its README, with the appropriate Windows 11 benchmark rather than Server 2022: https://github.com/ansible-lockdown/Windows-11-CIS-Audit .

Do not redistribute files from unlicensed upstream repositories without permission. Make sure external programs and benchmark profiles are suitable for your own system and version. The project does not claim compatibility with official CyberPatriot scoring.
