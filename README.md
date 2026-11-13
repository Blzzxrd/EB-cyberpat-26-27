# CyberPatriot Scripts

The Windows audit script is a defensive auditing assistant for an authorized Windows CyberPatriot competition image. It collects evidence and creates organized reports; it does not secure the computer automatically.

The separate `windows/server-2019/` folder contains the Windows 10/Server 2019 script bundle from [AwSkies/CPWindowsScripts](https://github.com/AwSkies/CPWindowsScripts), copied from commit `52db50457d21d1d7c8ddf121bc0a42fb0bc3457e`. It includes the supporting files needed by `secure.bat`. Unlike the audit script, `secure.bat` changes system settings and can disable services, delete accounts, and delete media files. Read its [usage guide](windows/server-2019/README.md) and [license](windows/server-2019/LICENSE.md), including the competition-use restriction, before using it. Check which services and accounts the server must keep before running it.

The `windows/new scripts windows 11/` folder contains the files from `Windows-Security-Training-Toolkit-Refactored.zip`. Its [README](windows/new%20scripts%20windows%2011/README.md) describes a separate modular audit toolkit for Windows 10/11 and Windows Server 2019/2022 practice VMs. The files are included with their original `docs/`, `modules/`, `tests/`, and `third_party/` layout.

Read the competition README before running the audit, and compare every result with that README before making a manual change.

## Project structure

```text
windows/
|-- CyberPatriot-Windows-Audit.ps1   Self-contained PowerShell 5.1 audit script
|-- server-2019/                     Third-party Windows 10/Server 2019 script bundle
|   |-- secure.bat                   Main script
|   |-- admins.bat, GetLocalUsers.vbs, admins.txt, authorizedusers.txt
|   |-- LGPO.exe, Policies/          Policy import dependencies
|   `-- README.md, LICENSE.md        Upstream documentation and license
`-- new scripts windows 11/          Modular training audit toolkit from the ZIP
    |-- Start-Audit.ps1              Main launcher
    |-- modules/, docs/, tests/, third_party/
    `-- README.md, config.*.json
linux/                              Linux audit scripts
README.md                           Audit safety, usage, report, workflow, and test guide
```

The script contains one function for each required audit module plus shared reporting and safety helpers. It has no external module, package, or Internet dependency.

## Read-only safety design

The toolkit is designed to separate collection from remediation:

- There is no remediation mode or remediation switch.
- Proposed manual commands are stored only as report text labeled `REFERENCE ONLY - NOT EXECUTED` (the report uses a Unicode em dash when supported).
- Every audit query goes through `Invoke-ReadOnlyCommand` before execution.
- The query safety gate parses the PowerShell abstract syntax tree, requires query commands to be on an allowlist, rejects dynamic command invocation, and rejects mutation patterns such as `Set-*`, `Remove-*`, service control, registry writes, event-log clearing, remote commands, and output redirection.
- External tools are restricted to query forms: `secedit /export`, `auditpol /get`, `netsh ... show`, and `wevtutil gl`. The current script uses the first three as needed.
- `secedit /export` reads security policy into `SecurityPolicy-ReadOnly-Export.inf` inside the audit results folder. It does not configure or import policy. Its log is also kept inside that folder.
- No remote computer is queried or scanned. Network commands inspect only the local machine's configuration, listeners, endpoints, and current connections.
- No Internet request, download, update search, exploitation, password attack, or credential test is performed.
- The suspicious-file module reads file metadata only. It does not open personal documents. Hashes are calculated only for already-flagged files and only when `-IncludeFileHashes` is explicitly used.
- Scoring-related path patterns are pruned and never reported, opened, hashed, or inspected. The script does not enumerate scoring processes, services, communications, or registry data.
- Each query has error isolation. A failed check is logged as `[ERROR]`, and the next check continues.
- Report writes are confined to a newly created timestamped audit folder. No existing file is overwritten, moved, renamed, quarantined, or deleted.
- At completion, the only process the script may launch is Notepad with `00-Audit-Summary.txt`; use `-DoNotOpenReport` to prevent that.

The phrase "no system changes" in reports means no accounts, policies, settings, services, tasks, applications, shares, permissions, security tools, or existing files are altered. The toolkit necessarily creates its new audit output files.

## Run as administrator

Administrative read access is recommended because Windows restricts local security policy, detailed firewall rules, Defender data, share permissions, and Security event-log metadata.

1. Read the CyberPatriot competition README completely.
2. Open the Start menu and search for **Windows PowerShell**.
3. Right-click **Windows PowerShell** and select **Run as administrator**.
4. Change to this project directory:

   ```powershell
   Set-Location 'C:\Users\anees\Documents\Cyberpatriot'
   ```

5. Run the script with one of the commands below.

The script does not require the execution policy to be changed permanently. `-ExecutionPolicy Bypass` applies only to that PowerShell process.

## Example commands

Default output: a timestamped folder on the current user's Desktop.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1
```

Create the timestamped results folder under a chosen parent directory:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1 -OutputPath 'C:\CyberAudit'
```

Review 14 days of events and hash only files already flagged by the metadata scan:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1 -EventLogDays 14 -IncludeFileHashes
```

Do not open Notepad at completion:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1 -DoNotOpenReport
```

Use selected local scan roots and add extensions:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1 `
  -ScanPath 'C:\Users\Public', 'C:\inetpub\wwwroot' `
  -ScanExtension '.config', '.psd1' `
  -ExcludePath 'C:\Users\Public\ApprovedMedia' `
  -DoNotOpenReport
```

`-OutputPath` is a parent folder. The script creates a new child such as `CyberPatriot-Audit-2026-07-12_231500` so an earlier audit is not overwritten.

## Reading the generated reports

Start in this order:

1. Open `00-Audit-Summary.txt` and note whether the audit was elevated and whether any queries failed.
2. Read `21-Manual-Review-Checklist.txt` alongside the competition README.
3. Open the detailed report named next to each ranked item.
4. Use `22-Audit-Errors.txt` to identify evidence that must be checked manually or collected again as administrator.
5. Use `23-Commands-Executed.txt` to verify what read-only query ran, when it ran, whether it succeeded, and any error it returned.
6. Use `Audit-Findings.csv` for filtering/sorting in a spreadsheet, or `Audit-Findings.json` for structured analysis.

The classifications mean:

- `[CRITICAL]`: strong evidence of a clearly insecure configuration.
- `[WARNING]`: evidence of a setting that may be insecure and still needs context.
- `[PASS]`: the inspected value appears securely configured.
- `[INFO]`: inventory or context, not a vulnerability decision.
- `[MANUAL REVIEW]`: authorization or need depends on the CyberPatriot README or system role.
- `[ERROR]`: evidence could not be collected; it is not a security conclusion.

An unusual user, service, file, application, extension, certificate, or task is not automatically unauthorized. Treat name/category matching as a prompt to investigate.

## Recommended manual-remediation workflow

1. Read the README and write down required users, administrators, services, applications, shares, and remote-access features.
2. Save the first audit folder as the baseline. Do not edit its reports.
3. Resolve `[ERROR]` items first by re-running elevated or checking the setting manually.
4. Verify every account and privileged group membership before changing users.
5. Review high-confidence controls in this order: password/account policy, Defender, firewall, remote access, insecure protocols, services, software/files, persistence, permissions/shares, logging, then updates.
6. Research one finding and its disruption risk. Confirm it is not required by the README.
7. Make one manual change using a normal Windows administration interface or a separately researched command. Never copy a reference command without understanding it.
8. Confirm sign-in and all README-required services still work.
9. Check the CyberPatriot score after that single carefully selected change.
10. Record what changed and the result. If behavior is wrong, manually reverse only that understood change.
11. Re-run this audit into a new timestamped folder and compare the structured findings.
12. Repeat one change at a time. Never clear logs, disable networking/security tools, or interfere with the scoring engine.

## Disposable Windows VM test checklist

Use a VM that contains no sensitive data and is not the live competition image.

- [ ] Take a VM snapshot before testing.
- [ ] Confirm Windows PowerShell 5.1 is available: `$PSVersionTable.PSVersion`.
- [ ] Copy only `CyberPatriot-Windows-Audit.ps1` and this guide into the VM.
- [ ] Read the script parameters with `Get-Help .\CyberPatriot-Windows-Audit.ps1 -Detailed`.
- [ ] Run once without elevation, with `-DoNotOpenReport`, and confirm failures are recorded without stopping the remaining modules.
- [ ] Confirm all 24 numbered text reports plus CSV and JSON are created.
- [ ] Confirm the text files open correctly in Notepad and the CSV imports with separate columns.
- [ ] Inspect `23-Commands-Executed.txt` and confirm it contains query-only commands.
- [ ] Run again as administrator into a different output parent and compare the error count.
- [ ] Test `-EventLogDays 1` and another allowed value such as `14`.
- [ ] Test a narrow `-ScanPath` and confirm personal document contents do not appear in reports.
- [ ] Test `-IncludeFileHashes` and confirm hashes appear only for already-flagged files.
- [ ] Test `-ExcludePath` and confirm excluded content is absent.
- [ ] Confirm the script never opens more than the summary, and that `-DoNotOpenReport` opens nothing.
- [ ] Compare users, services, firewall profiles, Defender state, shares, and installed software with Windows management consoles for spot-check accuracy.
- [ ] Confirm no service state/start type, account state, firewall rule, registry value, task, share, permission, installed program, existing file, or event log changed.
- [ ] Revert the VM snapshot after testing.

Some checks legitimately return `[ERROR]` without elevation or when a Windows edition lacks a cmdlet/provider. The correct response is manual verification or an elevated re-run, not automatic remediation.
