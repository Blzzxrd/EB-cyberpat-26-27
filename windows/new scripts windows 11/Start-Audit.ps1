<#
.SYNOPSIS
  Windows defensive audit for personal lab / practice virtual machines.
.DESCRIPTION
  Read-only collection of Windows configuration, network and security posture.
  This tool does not harden, delete, disable, create, reset or reconfigure the machine.
  It DOES write reports to a designated local output folder.
  Not for use in any scored competition where AI-generated scripts are prohibited.
.EXAMPLE
  .\Start-Audit.ps1
.EXAMPLE
  .\Start-Audit.ps1 -ConfigPath .\config.example.json -Modules Accounts,Network,Server
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.example.json'),
    [string]$OutputDir = (Join-Path $PSScriptRoot ('reports\audit-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [ValidateSet('System','Accounts','ScenarioChecks','Policies','PolicyChecks','Network','RdpChecks','Protection','Server','Persistence','Software','Files')]
    [string[]]$Modules = @('System','Accounts','ScenarioChecks','Policies','PolicyChecks','Network','RdpChecks','Protection','Server','Persistence','Software','Files')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$moduleDir = Join-Path $PSScriptRoot 'modules'
foreach ($moduleFile in (Get-ChildItem -LiteralPath $moduleDir -Filter '*.ps1' -File | Sort-Object Name)) {
    . $moduleFile.FullName
}
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$inventoryDir = Join-Path $OutputDir 'inventory'
New-Item -ItemType Directory -Path $inventoryDir -Force | Out-Null
$findings = [System.Collections.Generic.List[object]]::new()

Add-Finding -Results $findings -Category 'Context' -Check 'Safety' -Status 'INFO' -Evidence 'Read-only local practice audit; findings are not competition scoring keys.' -Recommendation 'Inspect manually; preserve required services, accounts, and evidence.'
$moduleMap = [ordered]@{
    System         = 'Invoke-AuditSystem'
    Accounts       = 'Invoke-AuditAccounts'
    ScenarioChecks = 'Invoke-AuditScenarioChecks'
    Policies       = 'Invoke-AuditPolicies'
    PolicyChecks   = 'Invoke-AuditPolicyChecks'
    Network        = 'Invoke-AuditNetwork'
    RdpChecks      = 'Invoke-AuditRdpChecks'
    Protection     = 'Invoke-AuditProtection'
    Server         = 'Invoke-AuditServer'
    Persistence    = 'Invoke-AuditPersistence'
    Software       = 'Invoke-AuditSoftware'
    Files          = 'Invoke-AuditFiles'
}
foreach ($module in $Modules) {
    Write-Host ("[AUDIT] {0}" -f $module) -ForegroundColor Cyan
    try {
        & $moduleMap[$module] -Results $findings -Config $config -InventoryDir $inventoryDir
    } catch {
        Add-Finding -Results $findings -Category $module -Check 'Module execution' -Status 'ERROR' -Evidence $_.Exception.Message -Recommendation 'Inspect permissions, OS version, and module support.'
    }
}

$records = $findings.ToArray()
$records | Export-Csv -LiteralPath (Join-Path $OutputDir 'Findings.csv') -NoTypeInformation -Encoding UTF8
ConvertTo-Json -InputObject $records -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDir 'Findings.json') -Encoding UTF8
$groups = $records | Group-Object Status | Sort-Object Name
$summary = @(
    'WINDOWS SECURITY PRACTICE AUDIT (READ ONLY)'
    '==========================================='
    ('Time: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    ('Computer: ' + $env:COMPUTERNAME)
    ('Output: ' + $OutputDir)
    ('Modules: ' + ($Modules -join ', '))
    ''
    'FINDINGS BY STATUS'
)
$summary += @($groups | ForEach-Object { '{0,-12} {1,5}' -f $_.Name, $_.Count })
$summary += @('', 'Review the detailed Findings.csv and inventory files.', 'INFO and REVIEW are not necessarily vulnerabilities.', 'No system settings were changed by this script.')
$summary | Set-Content -LiteralPath (Join-Path $OutputDir 'Summary.txt') -Encoding UTF8
Write-Host ''
Write-Host ($summary -join [Environment]::NewLine)
Write-Host "Completed. Report folder: $OutputDir" -ForegroundColor Green
