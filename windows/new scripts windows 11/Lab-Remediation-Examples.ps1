<#
.SYNOPSIS
  OPTIONAL individual defensive setting examples for a personal training VM.
.DESCRIPTION
  Unlike Start-Audit.ps1, this file can change system settings.
  Every change requires -LabMode, -Apply, one explicit -Action, elevated rights,
  and PowerShell confirmation. No changes without ALL of those steps.
  NOT FOR SCORED CYBERPATRIOT ROUNDS. No system-wide auto-fix is provided.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$LabMode,
    [switch]$Apply,
    [ValidateSet('FirewallOn','DefenderRealtimeOn','DisableAutoRun','RequireNla')]
    [string]$Action
)
$ErrorActionPreference = 'Stop'
if (-not $LabMode -or -not $Apply -or -not $PSBoundParameters.ContainsKey('Action')) {
    throw 'No changes made. Explicit -LabMode -Apply -Action <name> are all required, and confirmation is still requested.'
}
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator in your own training VM.' }
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
if ($os.ProductType -eq 2) { throw 'Refusing remediation examples on domain controllers; consult domain policy and service dependencies.' }
$record = Join-Path $PSScriptRoot ('lab-change-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
"Training VM only; action: $Action; host: $env:COMPUTERNAME; before: $(Get-Date)" | Set-Content -LiteralPath $record -Encoding UTF8
switch ($Action) {
    'FirewallOn' {
        $before = @(Get-NetFirewallProfile | Select-Object Name,Enabled)
        $before | Out-String | Add-Content -LiteralPath $record
        if ($PSCmdlet.ShouldProcess('Domain, Private and Public profiles', 'Enable Windows Defender Firewall')) {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
            $after = @(Get-NetFirewallProfile | Select-Object Name,Enabled)
            $after | Out-String | Add-Content -LiteralPath $record
            Write-Host 'Firewall state verified; inspect access and required exceptions.'
        }
    }
    'DefenderRealtimeOn' {
        $before = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled
        $before | Out-String | Add-Content -LiteralPath $record
        if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Enable real-time protection')) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            $after = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled
            $after | Out-String | Add-Content -LiteralPath $record
            Write-Host 'Defender state verified; respect other antivirus products and existing legitimate exclusions.'
        }
    }
    'DisableAutoRun' {
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $before = Get-ItemProperty -Path $path -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
        if ($before) { "Before NoDriveTypeAutoRun=$($before.NoDriveTypeAutoRun)" | Add-Content -LiteralPath $record }
        if ($PSCmdlet.ShouldProcess($path, 'Set NoDriveTypeAutoRun to 255')) {
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name NoDriveTypeAutoRun -PropertyType DWord -Value 255 -Force -ErrorAction Stop | Out-Null
            $after = (Get-ItemProperty -Path $path -Name NoDriveTypeAutoRun -ErrorAction Stop).NoDriveTypeAutoRun
            "After NoDriveTypeAutoRun=$after" | Add-Content -LiteralPath $record
        }
    }
    'RequireNla' {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $term = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
        if ($term.fDenyTSConnections -ne 0) { throw 'RDP is already disabled; no change is needed.' }
        $before = (Get-ItemProperty -Path $path -Name UserAuthentication -ErrorAction Stop).UserAuthentication
        "Before NLA=$before" | Add-Content -LiteralPath $record
        if ($PSCmdlet.ShouldProcess('Remote Desktop', 'Require Network Level Authentication for an existing RDP service')) {
            Set-ItemProperty -Path $path -Name UserAuthentication -Value 1 -ErrorAction Stop
            $after = (Get-ItemProperty -Path $path -Name UserAuthentication -ErrorAction Stop).UserAuthentication
            "After NLA=$after" | Add-Content -LiteralPath $record
            Write-Host 'NLA state verified; ensure all authorized clients still support connection.'
        }
    }
}
Write-Host "Local change log: $record"
