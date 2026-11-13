# Source ideas and locations

The bundled PowerShell is original, but its scope was inspired by the following public repositories reviewed November 12, 2026. These links let you inspect the actual scripts and any upstream licensing terms.

## 1. juxt-tech / cp19-kit
https://github.com/juxt-tech/cp19-kit

Source files to read:
- `windows/harden.ps1` - modular launcher, system role detection, audit-first default.
- `windows/lib/CpCommon.psm1` - shared checks, change tracking, configuration validation.
- `windows/modules/Users.ps1` - local/domain account comparison and service-identity safeguards.
- `windows/modules/Policies.ps1` - account policy, audit policy, security options.
- `windows/modules/System.ps1` - firewall, Defender, services, remote access, SMB, updates.
- `windows/modules/Server.ps1` - AD, DNS, IIS, role detection.
- `windows/modules/Reports.ps1` - read-only software, persistence, file findings.
- `windows/tests/` - Pester testing patterns.

Borrowed ideas: modular PowerShell architecture, non-destructive audits, service/README awareness, separate Server module, tests, evidence logs.

## 2. Sheeshkidayyy / Cypatmaterial
https://github.com/Sheeshkidayyy/Cypatmaterial

Source files to read:
- `Scripts/Windows/Windows 11/CypatScript.ps1` - compact workstation policy baseline.
- `Scripts/Windows/Server/2019/Version 3/Cypat Enforcer - Windows Server 2019 [V3].ps1` - older server check coverage.
- `Scripts/Windows/Server/2022/V4/Cypat Server 2022 Enforcer v4.ps1` - extensive checks, reports, service requirements, share ACLs, forensics and browser settings.

Borrowed ideas: status categories and readback verification, extensive process/listener/persistence inventories, share-protection checks, account and browser policy coverage. Deliberately excluded automatic password probing/resets and disruptive remediation.

## 3. aydenmikey / cyberpatriot-windows-toolkit
https://github.com/aydenmikey/cyberpatriot-windows-toolkit

Source files to read:
- `scenario-review.md` - required services, accounts, exceptions, prohibited changes.
- `accounts-and-passwords.md`, `network-and-smb.md`, `auditing-and-policy.md` - manual validation.
- `firewall-and-defender.md`, `software-and-files.md`, `services.md` - safe reviews.
- `change-log.md`, `final-verification.md` - before/after state, audit documentation.

Borrowed ideas: per-scenario allowlists, documentation-first workflow, visible verification reports.

## 4. Dudcom / Windows-Script-and-Resources-TroyHS
https://github.com/Dudcom/Windows-Script-and-Resources-TroyHS

Source files to read:
- `Troy-High-School-windows-harden-script--main/Main.ps1` - AD, roles, IIS, DNS/DHCP, file signatures, persistence, BITS, hidden tasks.
- `Troy-High-School-windows-harden-script--main/HardenAD/HardenAD.ps1` - AD infrastructure project.
- `Troy-High-School-windows-harden-script--main/new-hardeningkitty/README.md` - HardeningKitty reference.

Borrowed ideas: read-only persistence inspection and Server-specific coverage. Excluded blanket service disablement, GPO deletion, IIS LocalSystem pool identities, mass ACL rewrites, and automatic mass hardening.

## 5. BaiqingL / CyberPatriotScripts
https://github.com/BaiqingL/CyberPatriotScripts

Source files to read:
- `Windows/Main.bat`, `Windows/FirstRun.bat` - historic policy, account, networking and software-check categories.
- `Windows/resources/Check_Files.ps1` - older file search concept.
- `Windows/resources/usrList.ps1` - account inventory concept.

Borrowed ideas: broad legacy policy coverage and file/autorun inventories. Excluded the old DISM binaries, antivirus installers, mass service disabling, invasive user-rights rewrites and unsupported third-party tools.

## Licensing note

- `Sheeshkidayyy/Cypatmaterial` has an MIT license.
- `Dudcom/Windows-Script-and-Resources-TroyHS` has an MIT license, but bundled third-party projects may have different notices.
- `BaiqingL/CyberPatriotScripts` has an MPL 2.0 license.
- No repository-root license file was observed in `juxt-tech/cp19-kit` at review time; verify permissions before copying source text.
- Review each project's current license and attribution requirements before redistribution.
