# Windows Security Training Toolkit — README

A modular, **read-only Windows security auditing toolkit** written primarily in PowerShell 5.1 for **Windows 10/11 and Windows Server 2019/2022** practice virtual machines. It inventories security settings, compares selected settings with **your own lab requirements**, and exports reports for manual review.

> **Training use only.** This toolkit was created with AI assistance during CyberPatriot 19 Round 2 (November 12–15, 2026). Do **not** use AI-generated scripts or prohibited third-party assistance during scored competition rounds. Consult the current CyberPatriot Rules Book. The code has not been executed or validated on a Windows VM by its assembler; test it independently before relying on its output.

## Quick start — run the existing read-only audit

1. **Extract** `Windows-Security-Training-Toolkit-Expanded.zip` on a **personal practice VM**. The resulting folder should contain `Start-Audit.ps1`, `modules/`, and `config.example.json`.
2. **Open Windows PowerShell 5.1 as Administrator** (use the built-in **Windows PowerShell**, not PowerShell 7 for the primary launcher). Running without elevation may produce incomplete findings.
3. **Change directory** to the extracted project. For example, if it is in your Downloads folder:

   ```powershell
   cd "$env:USERPROFILE\Downloads\Windows-Security-Training-Toolkit-Expanded"
   ```

4. **Run the audit** with the provided empty configuration:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Audit.ps1
   ```

   This collects inventories and basic checks. **Empty configuration arrays do not mean everything is unauthorized.** The policy and scenario-comparison modules skip checks that need a custom baseline.

5. **Read the results** in `reports\audit-YYYYMMDD-HHMMSS\`. Open `Summary.txt` first, followed by `Findings.csv`, and then the corresponding files in `inventory\`.

**No internet connection is required for the built-in audit.** The `Start-Audit.ps1` launcher does **not** disable services, change passwords, delete files, update software, or change Windows security settings. It **does** create report files in its output directory.

## Better results — add your own lab configuration

Create a working copy so the original example remains untouched:

```powershell
Copy-Item .\config.example.json .\config.json
notepad .\config.json
```

Example of a minimal **fictional lab** configuration:

```json
{
  "AuthorizedLocalUsers": ["LabAdmin", "LabUser"],
  "ExpectedAdmins": ["LabAdmin"],
  "RequiredServices": ["EventLog"],
  "RequiredShares": [],
  "RequiredApplications": [],
  "RequiredGroups": {"LabOperators": ["LabUser"]},
  "ProhibitedServices": [],
  "RequiredApplicationDetails": [],
  "PolicyTargets": {
    "MinimumPasswordLength": {"Minimum": 14},
    "PasswordComplexity": {"Equals": 1}
  },
  "AuditSubcategoryTargets": [],
  "UserRightMustInclude": {},
  "RegistryPolicyTargets": [],
  "SearchFolders": []
}
```

Only include names and requirements actually appropriate for your own test VM. The bundled `config.lab-demo.json` intentionally has made-up users, groups, and software requirements; **do not run it as though it were a real machine's expected state**.

Run using your own configuration:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Audit.ps1 -ConfigPath .\config.json
```

### Configuration field meanings

| Field | What the toolkit checks |
|---|---|
| `AuthorizedLocalUsers` | Compares local accounts with your authorized list; also notes missing required users. Not applicable to domain controllers' local SAM. |
| `ExpectedAdmins` | Identifies unexpected local administrator group members. |
| `RequiredServices` | Inventories/reviews services that should be present or running. |
| `RequiredShares` | Identifies missing required SMB shares. |
| `RequiredApplications` | Compares installed application names with an allowed/expected list. |
| `RequiredGroups` | Checks named local groups and listed members. |
| `ProhibitedServices` | Flags listed services for review if present or running; does not disable them. |
| `RequiredApplicationDetails` | Checks approximate installed software name, minimum version, and optional install-path substring. Registry-based detection may miss portable apps. |
| `PolicyTargets` | Compares configured `secedit` account-policy values against `Minimum`, `Maximum`, or `Equals` targets. |
| `AuditSubcategoryTargets` | Verifies selected success/failure advanced audit subcategories. English audit-policy output is expected. |
| `UserRightMustInclude` | Tests named user-right assignments for required SIDs/principals. |
| `RegistryPolicyTargets` | Compares selected registry values to expected values. |
| `SearchFolders` | Enables a **filename-only** scan of specific directories for selected extensions. Empty means no file search. |

The benchmark and policy-comparison checks **do not automatically apply the uploaded CIS benchmark** or determine official CyberPatriot scoring. A setting can be appropriate for one system role and inappropriate for another.

## Run specific modules instead of all of them

These examples work from the extracted project folder:

```powershell
# Accounts, user/group requirements, and selected policy checks
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Audit.ps1 -ConfigPath .\config.json -Modules Accounts,ScenarioChecks,Policies,PolicyChecks

# Windows Server role inventory and networking
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Audit.ps1 -Modules Server,Network,RdpChecks

# Persistence and software inventory
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Audit.ps1 -Modules Persistence,Software,Files

# Save a run to a chosen output directory
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Start-Audit.ps1 -OutputDir .\reports\my-lab-run
```

Available module names: `System`, `Accounts`, `ScenarioChecks`, `Policies`, `PolicyChecks`, `Network`, `RdpChecks`, `Protection`, `Server`, `Persistence`, `Software`, `Files`.

## What's in the ZIP right now?

**25 files total, including 18 `.ps1` files.** The main audit runs 12 separate modules (the `00-Common.ps1` file is shared helper code, not its own audit).

| File | What it does |
|---|---|
| `Start-Audit.ps1` | Main read-only launcher; selects modules, loads config, writes CSV/JSON/text reports. |
| `modules/00-Common.ps1` | Shared reporting and helper functions. |
| `modules/10-System.ps1` | OS/build, role, admin permissions, services, Windows Time. |
| `modules/20-Accounts.ps1` | Local users, password-required flags, privileged local groups. |
| `modules/25-ScenarioChecks.ps1` | Required users, local groups/members, shares, prohibited services, software versions/paths. |
| `modules/30-Policies.ps1` | Local security policy export, password/lockout policy, advanced audit policy, GPO report. |
| `modules/35-PolicyChecks.ps1` | Per-setting comparisons for local policies, registry options, user rights, advanced audit settings. |
| `modules/40-Network.ps1` | Listening TCP ports, SMB configuration/shares/permissions, RDP and hosts file. |
| `modules/42-RdpChecks.ps1` | RDP NLA, security layer, encryption level, service and policy override review. |
| `modules/50-Protection.ps1` | Windows Firewall, Defender, event logs, BitLocker inventory. |
| `modules/60-Server.ps1` | Server roles, Active Directory, DNS zones, DHCP scopes, IIS sites and pools (when relevant). |
| `modules/70-Persistence.ps1` | Tasks, autoruns, startup folders, suspicious service paths, IFEO, WMI, BITS. |
| `modules/80-Software.ps1` | Installed applications, update/hotfix inventory, browser policy presence. |
| `modules/90-Files.ps1` | Optional scoped file-extension inventory; never deletes or reads file contents. |
| `Lab-Remediation-Examples.ps1` | **Separate, changes-settings** lab examples; not imported by the launcher. |
| `tests/Test-Syntax.ps1` | Checks PowerShell parser errors without running the audit. |
| `third_party/CC0/list-installed-software.ps1` | Directly included CC0 software-inventory script. |
| `third_party/Download-External-Audit-Tools.ps1` | Downloads selected upstream scripts to `third_party/optional/` and logs hashes; **never runs** the downloads. |
| `config.example.json` | Minimal config: inventories work, optional comparisons largely skipped. |
| `config.lab-demo.json` | Fictional example of advanced check configuration. |
| `third_party/README.md` | Upstream licenses, source links, optional tool details. |
| `docs/Source-Map.md` | Origins of design ideas from the original CyberPatriot repositories. |
| `docs/Expanded-Gap-Map.md` | How the expanded audit addresses previously identified gaps. |
| `docs/Training-Workflow.md` | Suggested safe test workflow and review process. |

## Understanding the output

Typical report directory:

```text
reports/
  audit-20261113-090000/
    Summary.txt
    Findings.csv
    Findings.json
    inventory/
      ...individual inventory CSV/TXT/INF files...
```

| Finding status | Interpretation |
|---|---|
| `PASS` | The particular implemented check met its configured condition. |
| `WARN` | A condition may not match a configured baseline or needs attention. |
| `REVIEW` | Manual interpretation is needed; not automatically a vulnerability. |
| `INFO` | Inventory/informational result, not a pass/fail score. |
| `SKIP` | Check was not applicable or no expected baseline was configured. |
| `ERROR` | Collection/check failed; review permissions, Windows edition, or module availability. |

Reports can contain usernames, IP addresses, paths, and configuration information. Treat them as private system information.

## Optional external auditors — not installed in the ZIP

The only complete vendored upstream script is `third_party/CC0/list-installed-software.ps1`. A **separate downloader** can retrieve selected, pinned-version files from **HardeningKitty**, **Windows Security Baseline Auditor**, **Windows User Audit**, **RDP Diagnostic Tool**, and **Host Inventory**:

```powershell
.\third_party\Download-External-Audit-Tools.ps1 -Tool All
```

The downloader needs internet access and writes files to `third_party/optional/`. It does **not** execute them, import them into `Start-Audit.ps1`, or make their findings part of the built-in report. Review their source, licensing, and any extra dependencies before deciding whether to use them independently in a training lab. The upstream RDP tool requires PowerShell 7 or newer; the **main toolkit** targets Windows PowerShell 5.1. Some upstream repositories do not have a verified distribution license, and the RDP tool is noncommercial licensed; do not redistribute those files without appropriate permission.

## Syntax check and limitations

Run this **before** your first full lab audit:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Syntax.ps1
```

This checks parsing only, not whether Windows API calls, permissions, or checks work correctly. The toolkit has **not been runtime-tested on Windows**. Server-specific commands require their respective Windows features and administration modules. Domain Group Policy can override local settings. The file search is deliberately limited; installed-software registry inventories can miss portable apps; and many policy targets must be supplied explicitly.

## Separate lab remediation examples — optional and not read-only

The audit never invokes `Lab-Remediation-Examples.ps1`. This separate script provides exactly four actions: `FirewallOn`, `DefenderRealtimeOn`, `DisableAutoRun`, `RequireNla`. Each requires an owned training VM, elevation, an explicit action, `-LabMode`, `-Apply`, and PowerShell confirmation. It refuses to run on domain controllers.

Only on a disposable **noncompetition training VM**, after reading the code and taking a VM snapshot, a representative example is:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Lab-Remediation-Examples.ps1 -LabMode -Apply -Action DisableAutoRun
```

Do not treat these example modifications as universally safe or as competition solutions. The primary recommendation is to run audits, review results, and change one approved setting at a time in a controlled lab.

## Troubleshooting

- **`Start-Audit.ps1` not found:** Check the extracted folder and run `Get-ChildItem` to locate it; do not run from the parent Downloads folder.
- **Script execution is disabled:** The commands above use a *process invocation* with `-ExecutionPolicy Bypass`. Use only where you are authorized; do not modify organization-managed execution policies.
- **An audit module reports `ERROR`:** Look at `Findings.csv`. Windows edition, elevation, permissions, installed roles, and localization can affect results. Other modules should still run.
- **Many expected checks show `SKIP`:** Your config is empty. Define appropriate values in `config.json`; do not use the fictional lab-demo expectations on a real machine.
- **No file findings:** The `SearchFolders` list defaults to empty.
- **External tools not present:** They are optional and not included as complete source scripts; run the pinned downloader only if you need them, outside scored rounds.
- **Need a stricter baseline:** Supply the appropriate expected values explicitly and validate applicability to the OS and role. The uploaded archived CIS Windows 11 benchmark is a reference, not an automatically enforced profile.

## Source and attribution

See `docs/Source-Map.md` and `third_party/README.md`. The core modules are originally assembled code inspired by public scripts; they are not verbatim copies of all five repositories. The directly included installed-software script is CC0. External tools retain their respective upstream terms.
