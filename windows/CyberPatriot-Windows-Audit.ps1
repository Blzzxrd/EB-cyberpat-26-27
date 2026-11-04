#requires -Version 5.1
<#
.SYNOPSIS
    Creates a read-only Windows security audit for an authorized CyberPatriot image.

.DESCRIPTION
    Collects local security information and writes human-readable reports. The script
    does not remediate findings, change settings, remove files, alter accounts, control
    services, contact the Internet, inspect the CyberPatriot scoring engine, or scan
    another computer. Every finding must be checked against the competition README.

.PARAMETER OutputPath
    Parent directory for the timestamped audit results folder. The current user's
    Desktop is used when this parameter is omitted.

.PARAMETER EventLogDays
    Number of days of recent local security events to summarize. Default: 7.

.PARAMETER IncludeFileHashes
    Calculates SHA-256 hashes only for files already flagged by the metadata scan.

.PARAMETER ScanPath
    Optional local directories to scan instead of the conservative default locations.

.PARAMETER ScanExtension
    Optional file extensions to add to the suspicious-file metadata scan.

.PARAMETER ExcludePath
    Optional local paths to omit from file metadata scanning.

.PARAMETER DoNotOpenReport
    Prevents the summary report from being opened in Notepad at completion.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1 -EventLogDays 14 -IncludeFileHashes

.NOTES
    Audit-only. Proposed commands in reports are reference text and are never run.
    Windows PowerShell 5.1 compatible; no external modules or Internet access required.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$EventLogDays = 7,

    [Parameter()]
    [switch]$IncludeFileHashes,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ScanPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ScanExtension,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ExcludePath,

    [Parameter()]
    [switch]$DoNotOpenReport
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:AuditStart = Get-Date
$script:AuditComplete = $null
$script:AuditOutputFolder = $null
$script:IsAdministrator = $false
$script:Findings = New-Object System.Collections.ArrayList
$script:CommandLog = New-Object System.Collections.ArrayList
$script:ReportBuffers = @{}
$script:SecurityPolicy = @{}
$script:SecurityPolicyExportPath = $null
$script:SecurityPolicyExportAttempted = $false
$script:ServiceInventory = @()
$script:SoftwareInventory = @()
$script:StartupTargets = New-Object System.Collections.ArrayList
$script:PendingRestart = $false
$script:SystemSummary = @{}

$script:ReportFiles = @(
    '00-Audit-Summary.txt',
    '01-System-Information.txt',
    '02-Users-and-Groups.txt',
    '03-Password-and-Account-Policies.txt',
    '04-Local-Security-Policy.txt',
    '05-Firewall.txt',
    '06-Services.txt',
    '07-Remote-Access.txt',
    '08-Network-and-SMB.txt',
    '09-Windows-Defender.txt',
    '10-Windows-Update.txt',
    '11-Installed-Software.txt',
    '12-Startup-and-Scheduled-Tasks.txt',
    '13-Suspicious-Files.txt',
    '14-Permissions.txt',
    '15-Network-Shares.txt',
    '16-Registry-Security-Settings.txt',
    '17-Auditing-and-Logging.txt',
    '18-Browser-and-Proxy-Settings.txt',
    '19-Certificates-DNS-and-Hosts.txt',
    '20-Recent-Security-Events.txt',
    '21-Manual-Review-Checklist.txt',
    '22-Audit-Errors.txt',
    '23-Commands-Executed.txt'
)

$script:CategoryRank = @{
    'Users and Groups' = 1
    'Password and Account Policies' = 2
    'Windows Defender' = 3
    'Firewall' = 4
    'Remote Access' = 5
    'Network and SMB' = 6
    'Services' = 7
    'Installed Software' = 8
    'Suspicious Files' = 9
    'Startup and Scheduled Tasks' = 10
    'Permissions' = 11
    'Auditing and Logging' = 12
    'Windows Update' = 13
}

function Test-Administrator {
    [CmdletBinding()]
    param()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function New-AuditOutputFolder {
    [CmdletBinding()]
    param([string]$ParentPath)

    if ([string]::IsNullOrWhiteSpace($ParentPath)) {
        $ParentPath = [Environment]::GetFolderPath('Desktop')
    }

    $fullParent = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($ParentPath))
    if (-not (Test-Path -LiteralPath $fullParent -PathType Container)) {
        New-Item -ItemType Directory -Path $fullParent -Force -ErrorAction Stop | Out-Null
    }

    $folderName = 'CyberPatriot-Audit-{0}' -f (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    $candidate = Join-Path $fullParent $folderName
    $suffix = 1
    while (Test-Path -LiteralPath $candidate) {
        $candidate = Join-Path $fullParent ('{0}_{1}' -f $folderName, $suffix)
        $suffix++
    }

    New-Item -ItemType Directory -Path $candidate -ErrorAction Stop | Out-Null
    return [IO.Path]::GetFullPath($candidate)
}

function Test-IsPathInsideAuditOutput {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($script:AuditOutputFolder)) { return $false }
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [IO.Path]::GetFullPath($script:AuditOutputFolder).TrimEnd('\')
    return ($candidate -eq $root -or $candidate.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase))
}

function Initialize-AuditReportBuffers {
    [CmdletBinding()]
    param()

    foreach ($file in $script:ReportFiles) {
        $script:ReportBuffers[$file] = New-Object Text.StringBuilder
    }
}

function Add-ReportLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ReportFile,
        [AllowEmptyString()][string]$Text = ''
    )

    if (-not $script:ReportBuffers.ContainsKey($ReportFile)) {
        throw "Unknown audit report: $ReportFile"
    }
    [void]$script:ReportBuffers[$ReportFile].AppendLine($Text)
}

function Write-ModuleHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ReportFile,
        [Parameter(Mandatory = $true)][string]$Title,
        [string]$Purpose
    )

    Add-ReportLine $ReportFile ('=' * 78)
    Add-ReportLine $ReportFile $Title
    Add-ReportLine $ReportFile ('=' * 78)
    Add-ReportLine $ReportFile 'READ-ONLY AUDIT: No remediation commands were executed.'
    Add-ReportLine $ReportFile 'Compare every result with the CyberPatriot competition README.'
    if ($Purpose) { Add-ReportLine $ReportFile $Purpose }
    Add-ReportLine $ReportFile ('Collected: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
    Add-ReportLine $ReportFile ''
}

function ConvertTo-DisplayValue {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return '<not available>' }
    if ($Value -is [System.Array]) { return (($Value | ForEach-Object { [string]$_ }) -join '; ') }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return '<empty>' }
    return $text
}

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][bool]$Succeeded,
        [string]$ErrorMessage
    )

    $entry = [pscustomobject]@{
        Time = Get-Date
        AuditModule = $Module
        CommandOrQuery = $Command
        Succeeded = $Succeeded
        ErrorMessage = $ErrorMessage
    }
    [void]$script:CommandLog.Add($entry)
}

function Assert-ReadOnlyCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][string]$CommandText
    )

    # Transform/filter commands are allowed because they only shape data already read.
    $allowedCommands = @(
        'Get-CimInstance', 'Get-WmiObject', 'Get-Item', 'Get-ItemProperty',
        'Get-ItemPropertyValue', 'Get-ChildItem', 'Get-Content', 'Get-Acl',
        'Get-AuthenticodeSignature', 'Get-FileHash', 'Get-WinEvent', 'Get-HotFix',
        'Get-AppxPackage', 'Get-WindowsOptionalFeature', 'Get-NetAdapter', 'Get-NetConnectionProfile',
        'Get-NetFirewallProfile', 'Get-NetFirewallRule', 'Get-NetFirewallPortFilter',
        'Get-NetFirewallAddressFilter', 'Get-NetFirewallApplicationFilter',
        'Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Get-NetIPConfiguration',
        'Get-NetIPInterface', 'Get-DnsClientServerAddress', 'Get-DnsClientGlobalSetting',
        'Get-SmbServerConfiguration', 'Get-SmbClientConfiguration', 'Get-SmbShare',
        'Get-SmbShareAccess', 'Get-MpComputerStatus', 'Get-MpPreference',
        'Get-MpThreatDetection', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo',
        'Get-PSSessionConfiguration', 'Get-DnsClientNrptPolicy', 'Get-Command', 'Get-Service', 'Get-TimeZone', 'Get-Date',
        'Test-Path', 'Resolve-Path', 'Where-Object', 'Select-Object', 'Sort-Object',
        'Group-Object', 'Measure-Object', 'ForEach-Object', 'Write-Output',
        'Format-List', 'Format-Table', 'Out-String', 'auditpol.exe', 'secedit.exe',
        'netsh.exe', 'wevtutil.exe', 'ipconfig.exe'
    )

    # These words represent mutation capabilities. They are rejected even if a future
    # edit accidentally adds a dangerous command to the allowlist.
    $deniedPattern = '(?i)(\bSet-|\bRemove-|\bClear-|\bEnable-|\bDisable-|\bAdd-|\bInstall-|\bUninstall-|\bRename-|\bMove-|\bCopy-|\bStart-Service\b|\bStop-|\bRestart-|\bInvoke-Expression\b|\bInvoke-Command\b|\bEnter-PSSession\b|\bNew-PSSession\b|\breg(\.exe)?\s+(add|delete|copy|restore|load|unload)\b|\bnet(\.exe)?\s+(user|localgroup|share)\b|\bsc(\.exe)?\s+(create|delete|config|start|stop)\b|\bauditpol(\.exe)?\s+/set\b|\bwevtutil(\.exe)?\s+(cl|sl)\b|\bnetsh(\.exe)?.*\s(set|add|delete|reset)\b|\.Delete\s*\(|\.SetValue\s*\(|\.Put\s*\(|\.StartService\s*\(|\.StopService\s*\(|>|\bOut-File\b|\bSet-Content\b|\bAdd-Content\b)'
    if ($CommandText -match $deniedPattern -or $ScriptBlock.ToString() -match $deniedPattern) {
        throw 'Safety gate rejected a command containing a mutation pattern.'
    }

    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput(
        $ScriptBlock.ToString(), [ref]$tokens, [ref]$parseErrors
    )
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        throw ('Safety gate could not parse the query: {0}' -f $parseErrors[0].Message)
    }

    $commandAsts = $ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true)

    foreach ($commandAst in $commandAsts) {
        $name = $commandAst.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($name)) {
            throw 'Safety gate rejected a dynamically invoked command.'
        }
        if ($allowedCommands -notcontains $name) {
            throw ('Safety gate rejected non-allowlisted command: {0}' -f $name)
        }
    }

    $combined = $CommandText + ' ' + $ScriptBlock.ToString()
    if ($combined -match '(?i)secedit(\.exe)?' -and $combined -notmatch '(?i)/export\b') {
        throw 'Only secedit /export is permitted.'
    }
    if ($combined -match '(?i)auditpol(\.exe)?' -and $combined -notmatch '(?i)/get\b') {
        throw 'Only auditpol /get is permitted.'
    }
    if ($combined -match '(?i)netsh(\.exe)?' -and $combined -notmatch '(?i)\bshow\b') {
        throw 'Only netsh show queries are permitted.'
    }
    if ($combined -match '(?i)wevtutil(\.exe)?' -and $combined -notmatch '(?i)\bgl\b') {
        throw 'Only wevtutil get-log queries are permitted.'
    }
}

function Invoke-ReadOnlyCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$CommandText,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [switch]$SuppressErrorFinding
    )

    try {
        Assert-ReadOnlyCommand -ScriptBlock $ScriptBlock -CommandText $CommandText
        $result = & $ScriptBlock
        Write-AuditLog -Module $Module -Command $CommandText -Succeeded $true
        return $result
    }
    catch {
        $message = $_.Exception.Message
        Write-AuditLog -Module $Module -Command $CommandText -Succeeded $false -ErrorMessage $message
        if (-not $SuppressErrorFinding) {
            Add-AuditFinding -Severity INFO -Category $Module -Finding 'Audit query could not be completed' `
                -CurrentValue 'Unknown because the query failed' -ExpectedValue 'The read-only query should return data' `
                -Evidence ("Query: {0}; Error: {1}" -f $CommandText, $message) `
                -WhyThisMatters 'Incomplete evidence requires a human to verify the setting.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Review this setting manually after reading the README.' `
                -DisruptionRisk 'None from this audit; risk depends on any later manual action.' `
                -RestartRequired 'Unknown' -Confidence 'High that the query failed; no conclusion about security.' `
                -Status '[ERROR]' -ReportFile '22-Audit-Errors.txt'
        }
        return $null
    }
}

function Add-AuditFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'MANUAL REVIEW')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Finding,
        [Parameter(Mandatory = $true)]$CurrentValue,
        [Parameter(Mandatory = $true)]$ExpectedValue,
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)][string]$WhyThisMatters,
        [Parameter(Mandatory = $true)][ValidateSet('Yes', 'No')][string]$ReadmeRequired,
        [Parameter(Mandatory = $true)][string]$PossibleManualAction,
        [string]$PossibleCommand,
        [Parameter(Mandatory = $true)][string]$DisruptionRisk,
        [Parameter(Mandatory = $true)][string]$RestartRequired,
        [Parameter(Mandatory = $true)][string]$Confidence,
        [Parameter(Mandatory = $true)][ValidateSet('[CRITICAL]', '[WARNING]', '[PASS]', '[INFO]', '[MANUAL REVIEW]', '[ERROR]')][string]$Status,
        [Parameter(Mandatory = $true)][string]$ReportFile
    )

    $referenceOnly = 'REFERENCE ONLY {0} NOT EXECUTED' -f [char]0x2014
    if ([string]::IsNullOrWhiteSpace($PossibleCommand)) {
        $commandText = 'Research and correct manually after checking the README.'
    }
    else {
        $commandText = '{0}: {1}' -f $referenceOnly, $PossibleCommand
    }

    $findingObject = [pscustomobject][ordered]@{
        Severity = $Severity
        Category = $Category
        Finding = $Finding
        CurrentValue = ConvertTo-DisplayValue $CurrentValue
        ExpectedOrRecommendedValue = ConvertTo-DisplayValue $ExpectedValue
        Evidence = ConvertTo-DisplayValue $Evidence
        WhyThisMatters = $WhyThisMatters
        READMEVerificationRequired = $ReadmeRequired
        PossibleManualAction = $PossibleManualAction
        PossibleCommandForManualUse = $commandText
        DisruptionRisk = $DisruptionRisk
        RestartPotentiallyRequired = $RestartRequired
        Confidence = $Confidence
        Status = $Status
        ReportFile = $ReportFile
    }
    [void]$script:Findings.Add($findingObject)
}

function Add-FormattedFindingsToReports {
    [CmdletBinding()]
    param()

    foreach ($report in $script:ReportFiles) {
        $items = @($script:Findings | Where-Object { $_.ReportFile -eq $report })
        if ($items.Count -eq 0) { continue }
        Add-ReportLine $report ''
        Add-ReportLine $report 'STRUCTURED FINDINGS'
        Add-ReportLine $report '-------------------'
        foreach ($item in $items) {
            Add-ReportLine $report '---'
            Add-ReportLine $report ('Severity: {0}' -f $item.Severity)
            Add-ReportLine $report ('Category: {0}' -f $item.Category)
            Add-ReportLine $report ('Finding: {0}' -f $item.Finding)
            Add-ReportLine $report ('Current Value: {0}' -f $item.CurrentValue)
            Add-ReportLine $report ('Expected or Recommended Value: {0}' -f $item.ExpectedOrRecommendedValue)
            Add-ReportLine $report ('Evidence: {0}' -f $item.Evidence)
            Add-ReportLine $report ('Why This Matters: {0}' -f $item.WhyThisMatters)
            Add-ReportLine $report ('README Verification Required: {0}' -f $item.READMEVerificationRequired)
            Add-ReportLine $report ('Possible Manual Action: {0}' -f $item.PossibleManualAction)
            Add-ReportLine $report ('Possible Command for Manual Use: {0}' -f $item.PossibleCommandForManualUse)
            Add-ReportLine $report ('Disruption Risk: {0}' -f $item.DisruptionRisk)
            Add-ReportLine $report ('Restart Potentially Required: {0}' -f $item.RestartPotentiallyRequired)
            Add-ReportLine $report ('Confidence: {0}' -f $item.Confidence)
            Add-ReportLine $report ('Status: {0}' -f $item.Status)
            Add-ReportLine $report '-------'
        }
    }
}

function Get-AuditSeverityCount {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Status)

    return @($script:Findings | Where-Object { $_.Status -eq $Status }).Count
}

function Get-RegistryAuditValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $query = {
        if (Test-Path -LiteralPath $Path) {
            $property = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
            return $property.$Name
        }
        return $null
    }.GetNewClosure()
    return Invoke-ReadOnlyCommand -Module $Module -CommandText ("Get registry value: {0}\{1}" -f $Path, $Name) `
        -ScriptBlock $query -SuppressErrorFinding
}

function Get-RegistryAuditProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $query = {
        if (Test-Path -LiteralPath $Path) {
            return Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        }
        return $null
    }.GetNewClosure()
    return Invoke-ReadOnlyCommand -Module $Module -CommandText ("Get registry properties: {0}" -f $Path) `
        -ScriptBlock $query -SuppressErrorFinding
}

function Test-WeakWriteAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Acl)

    $weakIdentities = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users')
    foreach ($rule in $Acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($weakIdentities -notcontains $rule.IdentityReference.Value) { continue }
        $rights = $rule.FileSystemRights
        if (($rights -band [Security.AccessControl.FileSystemRights]::WriteData) -ne 0 -or
            ($rights -band [Security.AccessControl.FileSystemRights]::AppendData) -ne 0 -or
            ($rights -band [Security.AccessControl.FileSystemRights]::Delete) -ne 0 -or
            ($rights -band [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -ne 0 -or
            ($rights -band [Security.AccessControl.FileSystemRights]::ChangePermissions) -ne 0 -or
            ($rights -band [Security.AccessControl.FileSystemRights]::TakeOwnership) -ne 0) { return $true }
    }
    return $false
}

function Test-WeakReadAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Acl)

    $weakIdentities = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users')
    foreach ($rule in $Acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if ($weakIdentities -notcontains $rule.IdentityReference.Value) { continue }
        if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0) { return $true }
    }
    return $false
}

function Get-ObjectPropertyValue {
    [CmdletBinding()]
    param(
        $InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-AuditPathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$SuppressErrorFinding
    )

    $query = {
        if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
            return Get-Acl -LiteralPath $Path -ErrorAction Stop
        }
        return $null
    }.GetNewClosure()
    return Invoke-ReadOnlyCommand -Module $Module -CommandText ("Get-Acl -LiteralPath '{0}'" -f $Path) `
        -ScriptBlock $query -SuppressErrorFinding:$SuppressErrorFinding
}

function Test-AuditPathExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Module,
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('Any', 'Leaf', 'Container')][string]$PathType = 'Any'
    )

    $query = {
        if ($PathType -eq 'Leaf') { return Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction Stop }
        if ($PathType -eq 'Container') { return Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop }
        return Test-Path -LiteralPath $Path -ErrorAction Stop
    }.GetNewClosure()
    $result = Invoke-ReadOnlyCommand -Module $Module -CommandText 'Test whether one local audit target path exists' `
        -ScriptBlock $query -SuppressErrorFinding
    if ($null -eq $result) { return $null }
    return [bool]$result
}

function Get-ExecutablePathFromCommandLine {
    [CmdletBinding()]
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($expanded.StartsWith('"')) {
        $endQuote = $expanded.IndexOf('"', 1)
        if ($endQuote -gt 1) { return $expanded.Substring(1, $endQuote - 1) }
    }
    $match = [regex]::Match($expanded, '^(?<exe>.+?\.exe)(?:\s|$)', 'IgnoreCase')
    if ($match.Success) { return $match.Groups['exe'].Value }
    $first = $expanded.Split(' ')[0].Trim('"')
    return $first
}

function Test-IsProhibitedScoringPath {
    [CmdletBinding()]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    # This is an exclusion guard only. The script never searches for, reports on, or
    # opens matching content.
    return ($Path -match '(?i)(scorebot|scoring[ _-]?engine|cyberpatriot[ _-]?scor|ccsclient)')
}

function Invoke-AuditModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $true)][int]$Number,
        [Parameter(Mandatory = $true)][int]$Total
    )

    $percent = [int](($Number - 1) * 100 / $Total)
    Write-Progress -Activity 'CyberPatriot read-only Windows audit' -Status $Name -PercentComplete $percent
    Write-Host ('[{0}/{1}] {2}' -f $Number, $Total, $Name) -ForegroundColor Cyan
    try {
        & $ScriptBlock
    }
    catch {
        $message = $_.Exception.Message
        Write-AuditLog -Module $Name -Command 'Audit module execution' -Succeeded $false -ErrorMessage $message
        Add-AuditFinding -Severity INFO -Category $Name -Finding 'Audit module encountered an unexpected error' `
            -CurrentValue 'Module did not complete all checks' -ExpectedValue 'Module should complete read-only checks' `
            -Evidence $message -WhyThisMatters 'Some settings may require separate human review.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Review the associated report and verify missing checks manually.' `
            -DisruptionRisk 'None from this audit.' -RestartRequired 'No' -Confidence 'High' `
            -Status '[ERROR]' -ReportFile '22-Audit-Errors.txt'
    }
}

function Invoke-SystemInformationAudit {
    [CmdletBinding()]
    param()

    $report = '01-System-Information.txt'
    $module = 'System Information'
    Write-ModuleHeader $report $module 'Basic host, operating system, boot, memory, and local network context.'

    $os = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_OperatingSystem' `
        -ScriptBlock { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
    $computer = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_ComputerSystem' `
        -ScriptBlock { Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop }
    $adapters = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get active physical network adapters' -ScriptBlock {
        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
            Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        }
    }
    $profiles = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-NetConnectionProfile' -ScriptBlock {
        if (Get-Command Get-NetConnectionProfile -ErrorAction SilentlyContinue) {
            Get-NetConnectionProfile -ErrorAction Stop
        }
    }
    $timeZone = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-TimeZone' -ScriptBlock {
        if (Get-Command Get-TimeZone -ErrorAction SilentlyContinue) { Get-TimeZone -ErrorAction Stop }
    } -SuppressErrorFinding

    $pendingChecks = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    $pendingKeys = Invoke-ReadOnlyCommand -Module $module -CommandText 'Test known pending-restart registry keys' -ScriptBlock {
        foreach ($key in $pendingChecks) {
            if (Test-Path -LiteralPath $key) { Write-Output $key }
        }
    }.GetNewClosure() -SuppressErrorFinding
    $pendingRename = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    $script:PendingRestart = (@($pendingKeys).Count -gt 0 -or $null -ne $pendingRename)

    $windowsEdition = if ($os) { $os.Caption } else { '<not available>' }
    $windowsVersion = if ($os) { '{0} (build {1})' -f $os.Version, $os.BuildNumber } else { '<not available>' }
    $domainWorkgroup = if ($computer) {
        if ($computer.PartOfDomain) { 'Domain: {0}' -f $computer.Domain } else { 'Workgroup: {0}' -f $computer.Workgroup }
    } else { '<not available>' }
    $lastBoot = if ($os) { $os.LastBootUpTime } else { $null }
    $memoryGb = if ($computer) { [math]::Round($computer.TotalPhysicalMemory / 1GB, 2) } else { $null }
    $zoneText = if ($timeZone) { '{0} ({1})' -f $timeZone.DisplayName, $timeZone.Id } else { [TimeZoneInfo]::Local.DisplayName }

    $details = [ordered]@{
        'Computer name' = $env:COMPUTERNAME
        'Windows edition' = $windowsEdition
        'Windows version/build' = $windowsVersion
        'Current user' = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        'Ran as administrator' = $script:IsAdministrator
        'Domain or workgroup' = $domainWorkgroup
        'PowerShell version' = $PSVersionTable.PSVersion.ToString()
        'System architecture' = if ($computer) { $computer.SystemType } else { $env:PROCESSOR_ARCHITECTURE }
        'Operating-system architecture' = if ($os) { $os.OSArchitecture } else { '<not available>' }
        'Last boot time' = ConvertTo-DisplayValue $lastBoot
        'Current time zone' = $zoneText
        'Installed memory (GB)' = ConvertTo-DisplayValue $memoryGb
        'Pending restart indicated' = $script:PendingRestart
    }
    foreach ($item in $details.GetEnumerator()) {
        Add-ReportLine $report ('{0}: {1}' -f $item.Key, (ConvertTo-DisplayValue $item.Value))
    }
    $script:SystemSummary = @{
        ComputerName = $env:COMPUTERNAME
        WindowsEdition = $windowsEdition
        WindowsVersion = $windowsVersion
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'ACTIVE NETWORK ADAPTERS'
    foreach ($adapter in @($adapters)) {
        Add-ReportLine $report ('Name={0}; InterfaceDescription={1}; LinkSpeed={2}; MAC={3}' -f `
            $adapter.Name, $adapter.InterfaceDescription, $adapter.LinkSpeed, $adapter.MacAddress)
    }
    if (@($adapters).Count -eq 0) { Add-ReportLine $report '<none returned>' }

    Add-ReportLine $report ''
    Add-ReportLine $report 'CURRENT NETWORK PROFILES'
    foreach ($profile in @($profiles)) {
        Add-ReportLine $report ('Name={0}; Interface={1}; Category={2}; IPv4={3}; IPv6={4}' -f `
            $profile.Name, $profile.InterfaceAlias, $profile.NetworkCategory, $profile.IPv4Connectivity, $profile.IPv6Connectivity)
    }
    if (@($profiles).Count -eq 0) { Add-ReportLine $report '<none returned>' }

    Add-AuditFinding -Severity INFO -Category $module -Finding 'Audit execution context recorded' `
        -CurrentValue ("Windows={0}; Elevated={1}; PowerShell={2}" -f $windowsVersion, $script:IsAdministrator, $PSVersionTable.PSVersion) `
        -ExpectedValue 'Run elevated for the most complete read-only evidence; elevation does not authorize remediation.' `
        -Evidence 'Operating-system and token information collected locally.' `
        -WhyThisMatters 'Some local policy, event log, Defender, and share queries require administrative read access.' `
        -ReadmeRequired 'No' -PossibleManualAction 'If important queries fail, re-run the audit as administrator.' `
        -PossibleCommand 'powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1 -DoNotOpenReport' `
        -DisruptionRisk 'Low; this launches the same read-only audit.' -RestartRequired 'No' -Confidence 'High' `
        -Status '[INFO]' -ReportFile $report

    if ($script:PendingRestart) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Pending restart indicators are present' `
            -CurrentValue 'One or more Windows pending-restart indicators were found.' `
            -ExpectedValue 'No unexplained pending restart; first determine why a restart is pending.' `
            -Evidence ((@($pendingKeys) + @('PendingFileRenameOperations=' + (ConvertTo-DisplayValue $pendingRename))) -join '; ') `
            -WhyThisMatters 'A restart may complete updates or configuration changes, but it may also disrupt required services.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Review update history and required services before deciding whether to restart.' `
            -DisruptionRisk 'High if the image has required active services.' -RestartRequired 'Yes, only if manually chosen.' `
            -Confidence 'Medium; these indicators can remain after completed work.' -Status '[MANUAL REVIEW]' -ReportFile $report
    }
    else {
        Add-AuditFinding -Severity INFO -Category $module -Finding 'No common pending restart indicator detected' `
            -CurrentValue 'No common indicator found' -ExpectedValue 'No pending restart' `
            -Evidence 'Checked Component Based Servicing, Windows Update, and pending file rename indicators.' `
            -WhyThisMatters 'Unfinished servicing can affect update and security state.' -ReadmeRequired 'No' `
            -PossibleManualAction 'No action suggested.' -DisruptionRisk 'None' -RestartRequired 'No' `
            -Confidence 'Medium; not every product uses these indicators.' -Status '[PASS]' -ReportFile $report
    }
}

function Invoke-UsersAndGroupsAudit {
    [CmdletBinding()]
    param()

    $report = '02-Users-and-Groups.txt'
    $module = 'Users and Groups'
    Write-ModuleHeader $report $module 'Local account authorization always requires comparison with the README.'

    $users = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_UserAccount where LocalAccount=True' -ScriptBlock {
        Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | Sort-Object Name
    }
    $groupLinks = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_GroupUser local memberships' -ScriptBlock {
        Get-CimInstance -ClassName Win32_GroupUser -ErrorAction Stop
    }
    $recentCreates = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get recent local Security event 4720 account-creation records (30 days, maximum 100)' -ScriptBlock {
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = (Get-Date).AddDays(-30) } `
            -MaxEvents 100 -ErrorAction Stop
    } -SuppressErrorFinding

    Add-ReportLine $report 'LOCAL USERS'
    foreach ($user in @($users)) {
        $lastLogon = Get-ObjectPropertyValue $user 'LastLogon'
        $accountExpires = Get-ObjectPropertyValue $user 'AccountExpires'
        $description = Get-ObjectPropertyValue $user 'Description'
        Add-ReportLine $report (('Name={0}; SID={1}; Disabled={2}; Lockout={3}; PasswordRequired={4}; PasswordExpires={5}; ' +
            'LastLogon={6}; AccountExpires={7}; Description={8}') -f $user.Name, $user.SID, $user.Disabled, `
            $user.Lockout, $user.PasswordRequired, $user.PasswordExpires, (ConvertTo-DisplayValue $lastLogon), `
            (ConvertTo-DisplayValue $accountExpires), (ConvertTo-DisplayValue $description))

        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Verify local user authorization: {0}" -f $user.Name) `
            -CurrentValue ("Enabled={0}; SID={1}; LastLogon={2}" -f (-not $user.Disabled), $user.SID, (ConvertTo-DisplayValue $lastLogon)) `
            -ExpectedValue 'Only users explicitly authorized by the CyberPatriot README should exist and be enabled.' `
            -Evidence ("Win32_UserAccount record; Description={0}" -f (ConvertTo-DisplayValue $description)) `
            -WhyThisMatters 'The script cannot know which competition users are authorized.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the account, its role, and enabled state against the README before changing anything.' `
            -DisruptionRisk 'High; changing a required account can break access or scoring.' -RestartRequired 'No' `
            -Confidence 'High that the account exists; authorization is unknown.' -Status '[MANUAL REVIEW]' -ReportFile $report

        if (-not $user.PasswordRequired -and -not $user.Disabled) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Enabled account does not require a password: {0}" -f $user.Name) `
                -CurrentValue 'PasswordRequired=False' -ExpectedValue 'PasswordRequired=True for interactive accounts unless the README explicitly requires otherwise.' `
                -Evidence 'Win32_UserAccount.PasswordRequired' -WhyThisMatters 'Accounts without required passwords can permit trivial access.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the account purpose and configure it manually only if authorized.' `
                -DisruptionRisk 'High for service or required accounts.' -RestartRequired 'No' -Confidence 'Medium; provider values should be verified locally.' `
                -Status '[WARNING]' -ReportFile $report
        }
        if ($null -eq $lastLogon) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Account has no recorded last logon: {0}" -f $user.Name) `
                -CurrentValue 'LastLogon not recorded' -ExpectedValue 'Account purpose and use should be understood.' `
                -Evidence 'Win32_UserAccount.LastLogon was empty.' -WhyThisMatters 'Unused or newly created accounts require authorization review.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the account against the README and with the team.' `
                -DisruptionRisk 'High if a required account is changed.' -RestartRequired 'No' `
                -Confidence 'Low; Windows may not populate this provider field consistently.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
        if ($user.Name -match '(?i)^(admin(istrator)?[0-9_-]+|guest[0-9_-]+|test|temp|support|backup)$') {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Account name warrants authorization review: {0}" -f $user.Name) `
                -CurrentValue $user.Name -ExpectedValue 'Account names and purposes should match the README.' `
                -Evidence 'Name resembles a built-in, temporary, support, or backup account pattern.' `
                -WhyThisMatters 'A name alone is not proof of an unauthorized account.' -ReadmeRequired 'Yes' `
                -PossibleManualAction 'Verify ownership and required purpose; do not remove based only on the name.' `
                -DisruptionRisk 'High if incorrectly changed.' -RestartRequired 'No' -Confidence 'Low; this is only a naming heuristic.' `
                -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }
    if (@($users).Count -eq 0) { Add-ReportLine $report '<no local-user data returned>' }

    $targetGroups = @('Administrators', 'Remote Desktop Users', 'Remote Management Users', 'Backup Operators', 'Guests')
    Add-ReportLine $report ''
    Add-ReportLine $report 'SELECTED LOCAL GROUP MEMBERSHIPS'
    foreach ($groupName in $targetGroups) {
        $members = New-Object System.Collections.ArrayList
        foreach ($link in @($groupLinks)) {
            $groupObject = Get-ObjectPropertyValue $link 'GroupComponent'
            $memberObject = Get-ObjectPropertyValue $link 'PartComponent'
            $groupObjectName = Get-ObjectPropertyValue $groupObject 'Name'
            $resolvedGroup = if ($groupObjectName) { $groupObjectName } else { [string]$groupObject }
            if ($resolvedGroup -notmatch ('(?i)(^|Name=")' + [regex]::Escape($groupName) + '("|$)')) { continue }
            $memberObjectName = Get-ObjectPropertyValue $memberObject 'Name'
            $memberObjectDomain = Get-ObjectPropertyValue $memberObject 'Domain'
            $memberName = if ($memberObjectName) {
                if ($memberObjectDomain) { '{0}\{1}' -f $memberObjectDomain, $memberObjectName } else { $memberObjectName }
            } else { [string]$memberObject }
            [void]$members.Add($memberName)
        }
        Add-ReportLine $report ("{0}: {1}" -f $groupName, (ConvertTo-DisplayValue @($members)))
        foreach ($member in @($members)) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Verify membership in {0}: {1}" -f $groupName, $member) `
                -CurrentValue ("Member of {0}" -f $groupName) -ExpectedValue 'Every privileged or remote-access membership must be explicitly authorized.' `
                -Evidence 'Win32_GroupUser association' -WhyThisMatters 'Privileged groups grant powerful access, but required members depend on the README.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Compare this membership with the README before making any change.' `
                -DisruptionRisk 'High; changing required group memberships can block access or services.' -RestartRequired 'Usually no' `
                -Confidence 'High for membership; authorization unknown.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }

    $guest = @($users | Where-Object { $_.SID -match '-501$' }) | Select-Object -First 1
    $admin = @($users | Where-Object { $_.SID -match '-500$' }) | Select-Object -First 1
    Add-ReportLine $report ''
    Add-ReportLine $report ('Built-in Guest status: {0}' -f $(if ($guest) { if ($guest.Disabled) { 'Disabled' } else { 'Enabled' } } else { 'Not returned' }))
    Add-ReportLine $report ('Built-in Administrator status: {0}' -f $(if ($admin) { if ($admin.Disabled) { 'Disabled' } else { 'Enabled' } } else { 'Not returned' }))
    if ($guest -and -not $guest.Disabled) {
        Add-AuditFinding -Severity HIGH -Category $module -Finding 'Built-in Guest account is enabled' `
            -CurrentValue ("{0} is enabled" -f $guest.Name) -ExpectedValue 'Built-in Guest is commonly disabled unless explicitly required.' `
            -Evidence ("SID ending -501: {0}" -f $guest.SID) -WhyThisMatters 'Guest access can reduce accountability and expose resources.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the README, then review the account manually.' `
            -DisruptionRisk 'Medium; required guest workflows could break.' -RestartRequired 'No' -Confidence 'High' `
            -Status '[WARNING]' -ReportFile $report
    }
    if ($admin) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Built-in Administrator account status requires review' `
            -CurrentValue ("Name={0}; Enabled={1}" -f $admin.Name, (-not $admin.Disabled)) `
            -ExpectedValue 'Status and name must follow the competition README and local access plan.' `
            -Evidence ("SID ending -500: {0}" -f $admin.SID) -WhyThisMatters 'This is a powerful recovery and administration account.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify required status and credentials manually.' `
            -DisruptionRisk 'High; mistakes can remove administrative access.' -RestartRequired 'No' -Confidence 'High' `
            -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'RECENT ACCOUNT-CREATION EVENTS (LAST 30 DAYS, IF ACCESSIBLE)'
    foreach ($event in @($recentCreates)) {
        $eventId = Get-ObjectPropertyValue $event 'Id'
        if ($null -eq $eventId) { continue }
        Add-ReportLine $report ('{0:u}; EventId={1}; RecordId={2}; Provider={3}' -f `
            (Get-ObjectPropertyValue $event 'TimeCreated'), $eventId, `
            (Get-ObjectPropertyValue $event 'RecordId'), (Get-ObjectPropertyValue $event 'ProviderName'))
    }
    if (@($recentCreates).Count -eq 0) { Add-ReportLine $report '<none returned or Security log unavailable>' }
}

function Get-ReadOnlySecurityPolicyExport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Module)

    if ($script:SecurityPolicy.Count -gt 0 -or $script:SecurityPolicyExportAttempted) { return }
    $script:SecurityPolicyExportAttempted = $true
    if (-not $script:IsAdministrator) {
        Add-AuditFinding -Severity INFO -Category $Module -Finding 'Security policy export skipped because the audit is not elevated' `
            -CurrentValue 'RanAsAdministrator=False' -ExpectedValue 'Run the read-only audit as administrator for local security policy evidence.' `
            -Evidence 'The script did not invoke secedit because the current token lacks the required read/export privilege.' `
            -WhyThisMatters 'Password policy and user-right values cannot be fully exported without elevation.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Re-run this audit as administrator; do not change policy until the README is reviewed.' `
            -PossibleCommand 'powershell.exe -ExecutionPolicy Bypass -File .\CyberPatriot-Windows-Audit.ps1 -DoNotOpenReport' `
            -DisruptionRisk 'Low; this re-runs read-only collection.' -RestartRequired 'No' -Confidence 'High' `
            -Status '[ERROR]' -ReportFile '22-Audit-Errors.txt'
        return
    }
    $exportPath = Join-Path $script:AuditOutputFolder 'SecurityPolicy-ReadOnly-Export.inf'
    $logPath = Join-Path $script:AuditOutputFolder 'SecurityPolicy-ReadOnly-Export.log'
    if (-not (Test-IsPathInsideAuditOutput $exportPath) -or -not (Test-IsPathInsideAuditOutput $logPath)) {
        throw 'Security-policy export path is outside the audit output folder.'
    }

    $exportResult = Invoke-ReadOnlyCommand -Module $Module `
        -CommandText ("secedit.exe /export /cfg '{0}' /areas SECURITYPOLICY USER_RIGHTS /log '{1}' /quiet" -f $exportPath, $logPath) `
        -ScriptBlock {
            $nativeOutput = secedit.exe /export /cfg $exportPath /areas SECURITYPOLICY USER_RIGHTS /log $logPath /quiet
            if ($LASTEXITCODE -ne 0) { throw ("secedit /export failed with exit code {0}: {1}" -f $LASTEXITCODE, (@($nativeOutput) -join ' ')) }
            Write-Output $nativeOutput
        }.GetNewClosure()
    if (-not (Test-Path -LiteralPath $exportPath)) { return }

    $script:SecurityPolicyExportPath = $exportPath
    $lines = Invoke-ReadOnlyCommand -Module $Module -CommandText ("Get-Content '{0}'" -f $exportPath) `
        -ScriptBlock { Get-Content -LiteralPath $exportPath -ErrorAction Stop }.GetNewClosure()
    $section = ''
    foreach ($line in @($lines)) {
        if ($line -match '^\s*\[(.+)\]\s*$') {
            $section = $Matches[1]
            continue
        }
        if ($line -match '^\s*([^;][^=]+?)\s*=\s*(.*)$') {
            $key = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            $script:SecurityPolicy[$key] = $value
            $script:SecurityPolicy[('{0}\{1}' -f $section, $key)] = $value
        }
    }
}

function Invoke-PasswordPolicyAudit {
    [CmdletBinding()]
    param()

    $report = '03-Password-and-Account-Policies.txt'
    $module = 'Password and Account Policies'
    Write-ModuleHeader $report $module 'Common defensive baselines are guidance only; the competition README controls.'
    Get-ReadOnlySecurityPolicyExport -Module $module

    Add-ReportLine $report ('Security policy support export: {0}' -f (ConvertTo-DisplayValue $script:SecurityPolicyExportPath))
    Add-ReportLine $report 'PASSWORD AND LOCKOUT VALUES'
    $settings = @(
        @{ Key = 'MinimumPasswordLength'; Label = 'Minimum password length'; Recommended = 'At least 12 characters (or README requirement)' },
        @{ Key = 'PasswordHistorySize'; Label = 'Password history'; Recommended = '24 remembered passwords (or README requirement)' },
        @{ Key = 'MaximumPasswordAge'; Label = 'Maximum password age'; Recommended = '1-90 days where rotation is required by the README' },
        @{ Key = 'MinimumPasswordAge'; Label = 'Minimum password age'; Recommended = 'At least 1 day to prevent cycling' },
        @{ Key = 'PasswordComplexity'; Label = 'Password complexity'; Recommended = 'Enabled (1)' },
        @{ Key = 'ClearTextPassword'; Label = 'Reversible password encryption'; Recommended = 'Disabled (0)' },
        @{ Key = 'LockoutBadCount'; Label = 'Account lockout threshold'; Recommended = 'A finite threshold such as 5 attempts, unless README differs' },
        @{ Key = 'LockoutDuration'; Label = 'Account lockout duration'; Recommended = 'At least 15 minutes, unless README differs' },
        @{ Key = 'ResetLockoutCount'; Label = 'Reset lockout counter'; Recommended = 'At least 15 minutes, unless README differs' }
    )
    foreach ($setting in $settings) {
        $value = if ($script:SecurityPolicy.ContainsKey($setting.Key)) { $script:SecurityPolicy[$setting.Key] } else { $null }
        Add-ReportLine $report ('{0}: {1}; Common recommendation: {2}' -f $setting.Label, (ConvertTo-DisplayValue $value), $setting.Recommended)
    }

    $limitBlank = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse'
    $noLmHash = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash'
    $restrictAnon = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous'
    Add-ReportLine $report ('Blank-password remote-use restriction (LimitBlankPasswordUse): {0}' -f (ConvertTo-DisplayValue $limitBlank))
    Add-ReportLine $report ('LAN Manager hash storage prevention (NoLMHash): {0}' -f (ConvertTo-DisplayValue $noLmHash))
    Add-ReportLine $report ('Anonymous enumeration restriction (RestrictAnonymous): {0}' -f (ConvertTo-DisplayValue $restrictAnon))

    $policyTests = @(
        @{ Key='MinimumPasswordLength'; Bad={ param($v) ([int]$v -lt 8) }; Severity='HIGH'; Name='Minimum password length is weak'; Expected='At least 12 characters or the README requirement' },
        @{ Key='PasswordHistorySize'; Bad={ param($v) ([int]$v -lt 5) }; Severity='MEDIUM'; Name='Password history is weak'; Expected='24 remembered passwords or the README requirement' },
        @{ Key='MaximumPasswordAge'; Bad={ param($v) ([int]$v -eq 0 -or [int]$v -gt 90) }; Severity='MEDIUM'; Name='Maximum password age is weak or unlimited'; Expected='A finite value no greater than 90 days when the README requires rotation' },
        @{ Key='MinimumPasswordAge'; Bad={ param($v) ([int]$v -lt 1) }; Severity='LOW'; Name='Minimum password age allows rapid password cycling'; Expected='At least 1 day or the README requirement' },
        @{ Key='PasswordComplexity'; Bad={ param($v) ([int]$v -ne 1) }; Severity='HIGH'; Name='Password complexity is disabled'; Expected='Enabled (1)' },
        @{ Key='ClearTextPassword'; Bad={ param($v) ([int]$v -ne 0) }; Severity='CRITICAL'; Name='Reversible password encryption is enabled'; Expected='Disabled (0)' },
        @{ Key='LockoutBadCount'; Bad={ param($v) ([int]$v -eq 0 -or [int]$v -gt 10) }; Severity='HIGH'; Name='Account lockout threshold is weak or disabled'; Expected='A finite threshold such as 5 attempts, unless the README differs' },
        @{ Key='LockoutDuration'; Bad={ param($v) ([int]$v -gt 0 -and [int]$v -lt 15) }; Severity='MEDIUM'; Name='Account lockout duration is short'; Expected='At least 15 minutes or the README requirement' },
        @{ Key='ResetLockoutCount'; Bad={ param($v) ([int]$v -lt 15) }; Severity='MEDIUM'; Name='Lockout counter reset time is short'; Expected='At least 15 minutes or the README requirement' }
    )
    foreach ($test in $policyTests) {
        if (-not $script:SecurityPolicy.ContainsKey($test.Key)) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Could not evaluate {0}" -f $test.Key) `
                -CurrentValue 'Not returned' -ExpectedValue $test.Expected -Evidence 'Security policy export did not contain this value.' `
                -WhyThisMatters 'The policy must be verified manually.' -ReadmeRequired 'Yes' `
                -PossibleManualAction 'Open Local Security Policy and inspect the value without changing it until the README is checked.' `
                -DisruptionRisk 'None for inspection.' -RestartRequired 'No' -Confidence 'High that export lacked the value.' `
                -Status '[MANUAL REVIEW]' -ReportFile $report
            continue
        }
        $value = $script:SecurityPolicy[$test.Key]
        $isBad = & $test.Bad $value
        if ($isBad) {
            Add-AuditFinding -Severity $test.Severity -Category $module -Finding $test.Name `
                -CurrentValue $value -ExpectedValue $test.Expected -Evidence ("secedit read-only export key {0}" -f $test.Key) `
                -WhyThisMatters 'Weak password or lockout policy can make account compromise easier.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Compare with the README, then change manually through approved Windows policy tools if needed.' `
                -DisruptionRisk 'Medium; overly strict values can lock out users.' -RestartRequired 'Usually no' -Confidence 'High' `
                -Status $(if ($test.Severity -eq 'CRITICAL') { '[CRITICAL]' } else { '[WARNING]' }) -ReportFile $report
        }
        else {
            Add-AuditFinding -Severity INFO -Category $module -Finding ("{0} meets the common baseline" -f $test.Key) `
                -CurrentValue $value -ExpectedValue $test.Expected -Evidence ("secedit export key {0}" -f $test.Key) `
                -WhyThisMatters 'Strong account policy reduces password and guessing risk.' -ReadmeRequired 'Yes' `
                -PossibleManualAction 'Confirm the value matches the README; no automatic action is taken.' `
                -DisruptionRisk 'None from review.' -RestartRequired 'No' -Confidence 'High' -Status '[PASS]' -ReportFile $report
        }
    }

    $registryPolicy = @(
        @{ Name='Blank-password remote-use restriction'; Value=$limitBlank; Good=1; Severity='HIGH'; Expected='Enabled (1)'; Evidence='HKLM SYSTEM CurrentControlSet Control Lsa LimitBlankPasswordUse' },
        @{ Name='LAN Manager hash storage prevention'; Value=$noLmHash; Good=1; Severity='HIGH'; Expected='Enabled (1)'; Evidence='HKLM SYSTEM CurrentControlSet Control Lsa NoLMHash' }
    )
    foreach ($item in $registryPolicy) {
        if ($null -eq $item.Value) {
            $status = '[MANUAL REVIEW]'; $severity = 'MANUAL REVIEW'
        } elseif ([int]$item.Value -eq $item.Good) {
            $status = '[PASS]'; $severity = 'INFO'
        } else {
            $status = '[WARNING]'; $severity = $item.Severity
        }
        Add-AuditFinding -Severity $severity -Category $module -Finding $item.Name `
            -CurrentValue (ConvertTo-DisplayValue $item.Value) -ExpectedValue $item.Expected -Evidence $item.Evidence `
            -WhyThisMatters 'This setting limits weak or blank-password authentication behavior.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the value and any application dependency before changing it manually.' `
            -DisruptionRisk 'Medium; legacy authentication may break.' -RestartRequired 'Possibly' `
            -Confidence $(if ($null -eq $item.Value) { 'Low; value not present.' } else { 'High' }) -Status $status -ReportFile $report
    }
}

function Invoke-LocalSecurityPolicyAudit {
    [CmdletBinding()]
    param()

    $report = '04-Local-Security-Policy.txt'
    $module = 'Local Security Policy'
    Write-ModuleHeader $report $module 'Security options and user rights from registry queries and a read-only secedit export.'
    Get-ReadOnlySecurityPolicyExport -Module $module

    $privileges = @(
        'SeRemoteShutdownPrivilege', 'SeDebugPrivilege', 'SeTcbPrivilege', 'SeBackupPrivilege',
        'SeRestorePrivilege', 'SeInteractiveLogonRight', 'SeDenyInteractiveLogonRight',
        'SeRemoteInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
        'SeNetworkLogonRight', 'SeDenyNetworkLogonRight', 'SeServiceLogonRight',
        'SeBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyBatchLogonRight'
    )
    Add-ReportLine $report 'USER RIGHTS ASSIGNMENTS'
    foreach ($name in $privileges) {
        $value = if ($script:SecurityPolicy.ContainsKey($name)) { $script:SecurityPolicy[$name] } else { $null }
        Add-ReportLine $report ('{0}: {1}' -f $name, (ConvertTo-DisplayValue $value))
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Verify user right assignment: {0}" -f $name) `
            -CurrentValue (ConvertTo-DisplayValue $value) -ExpectedValue 'Only accounts and groups explicitly required by Windows roles and the README.' `
            -Evidence 'Read-only local security policy export' -WhyThisMatters 'User rights can grant remote, debug, backup, restore, or logon capability.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Resolve SIDs and compare each assignment with required roles before changing policy.' `
            -DisruptionRisk 'High; changing rights can break sign-in, services, backup, or administration.' -RestartRequired 'Possibly' `
            -Confidence 'High for exported values; authorization requires human judgment.' -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    $registrySettings = @(
        @{ Label='Anonymous SID/name translation restriction'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LSAAnonymousNameLookup'; Expected='Disabled (0)' },
        @{ Label='Anonymous account enumeration restriction'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Expected='1 or stronger where compatible' },
        @{ Label='Anonymous SAM enumeration restriction'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Expected='Enabled (1)' },
        @{ Label='Anonymous shares'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='NullSessionShares'; Expected='Empty unless explicitly required' },
        @{ Label='UAC enabled'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Expected='Enabled (1)' },
        @{ Label='UAC administrator consent behavior'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Expected='Prompt (nonzero), with README compatibility' },
        @{ Label='UAC secure desktop'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop'; Expected='Enabled (1)' },
        @{ Label='Machine inactivity timeout'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='InactivityTimeoutSecs'; Expected='A reasonable nonzero timeout, commonly 900 seconds or less' },
        @{ Label='Cached interactive logons'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='CachedLogonsCount'; Expected='A limited value appropriate for the image' },
        @{ Label='Ctrl+Alt+Delete requirement (DisableCAD)'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableCAD'; Expected='0 to require secure attention sequence' },
        @{ Label='Interactive logon banner title'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='LegalNoticeCaption'; Expected='README/organization-approved text where required' },
        @{ Label='Interactive logon banner text'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='LegalNoticeText'; Expected='README/organization-approved text where required' },
        @{ Label='Always install elevated (machine)'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Expected='Disabled or absent (0)' },
        @{ Label='Always install elevated (user)'; Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Expected='Disabled or absent (0)' }
    )
    Add-ReportLine $report ''
    Add-ReportLine $report 'SECURITY OPTIONS'
    foreach ($setting in $registrySettings) {
        $value = Get-RegistryAuditValue -Module $module -Path $setting.Path -Name $setting.Name
        Add-ReportLine $report ('{0}: {1}; Recommended: {2}' -f $setting.Label, (ConvertTo-DisplayValue $value), $setting.Expected)
    }

    $uac = Get-RegistryAuditValue -Module $module -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    if ($null -ne $uac -and [int]$uac -eq 0) {
        Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'User Account Control is disabled' `
            -CurrentValue 'EnableLUA=0' -ExpectedValue 'EnableLUA=1' -Evidence 'HKLM Policies System EnableLUA' `
            -WhyThisMatters 'UAC helps limit silent elevation and separates standard from administrative actions.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify application requirements and enable UAC manually if the README allows.' `
            -DisruptionRisk 'High; applications and logon behavior can change.' -RestartRequired 'Yes' -Confidence 'High' `
            -Status '[CRITICAL]' -ReportFile $report
    }
    elseif ($null -ne $uac) {
        Add-AuditFinding -Severity INFO -Category $module -Finding 'User Account Control is enabled' `
            -CurrentValue ("EnableLUA={0}" -f $uac) -ExpectedValue 'EnableLUA=1' -Evidence 'HKLM Policies System EnableLUA' `
            -WhyThisMatters 'UAC helps contain administrative actions.' -ReadmeRequired 'No' -PossibleManualAction 'No action suggested.' `
            -DisruptionRisk 'None' -RestartRequired 'No' -Confidence 'High' -Status '[PASS]' -ReportFile $report
    }

    $secureDesktop = Get-RegistryAuditValue -Module $module -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop'
    if ($null -ne $secureDesktop -and [int]$secureDesktop -eq 0) {
        Add-AuditFinding -Severity MEDIUM -Category $module -Finding 'UAC prompts do not use the secure desktop' `
            -CurrentValue 'PromptOnSecureDesktop=0' -ExpectedValue 'PromptOnSecureDesktop=1' `
            -Evidence 'HKLM Policies System PromptOnSecureDesktop' -WhyThisMatters 'The secure desktop makes prompt spoofing and interference harder.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify and change the UAC prompt setting manually if appropriate.' `
            -DisruptionRisk 'Low to medium.' -RestartRequired 'Possibly' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
    }

    $allElevatedMachine = Get-RegistryAuditValue -Module $module -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    $allElevatedUser = Get-RegistryAuditValue -Module $module -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated'
    if (($null -ne $allElevatedMachine -and [int]$allElevatedMachine -eq 1) -and
        ($null -ne $allElevatedUser -and [int]$allElevatedUser -eq 1)) {
        Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'Windows Installer AlwaysInstallElevated is enabled for machine and user' `
            -CurrentValue 'HKLM=1 and HKCU=1' -ExpectedValue 'Both disabled or absent' `
            -Evidence 'Windows Installer policy registry values' -WhyThisMatters 'A standard user may be able to install a crafted MSI with elevated privileges.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Disable both policy values manually after verifying the README.' `
            -DisruptionRisk 'Medium; deployment workflows may depend on policy.' -RestartRequired 'Possibly' -Confidence 'High' `
            -Status '[CRITICAL]' -ReportFile $report
    }
}

function Invoke-FirewallAudit {
    [CmdletBinding()]
    param()

    $report = '05-Firewall.txt'
    $module = 'Firewall'
    Write-ModuleHeader $report $module 'Local Windows Firewall profiles and enabled allow rules; no rule is changed.'

    $profiles = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-NetFirewallProfile' -ScriptBlock {
        if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            Get-NetFirewallProfile -ErrorAction Stop
        }
    }
    if (@($profiles).Count -eq 0) {
        $fallback = Invoke-ReadOnlyCommand -Module $module -CommandText 'netsh.exe advfirewall show allprofiles' `
            -ScriptBlock { netsh.exe advfirewall show allprofiles } -SuppressErrorFinding
        Add-ReportLine $report 'NETSH FALLBACK OUTPUT'
        foreach ($line in @($fallback)) { Add-ReportLine $report ([string]$line) }
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Structured firewall profile query unavailable' `
            -CurrentValue 'See netsh fallback output' -ExpectedValue 'Domain, Private, and Public profiles enabled with inbound blocking.' `
            -Evidence 'Get-NetFirewallProfile returned no data.' -WhyThisMatters 'Firewall status must be verified for every profile.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Review Windows Defender Firewall with Advanced Security manually.' `
            -DisruptionRisk 'None for review; high if rules are changed incorrectly.' -RestartRequired 'No' -Confidence 'Low' `
            -Status '[MANUAL REVIEW]' -ReportFile $report
    }
    else {
        Add-ReportLine $report 'FIREWALL PROFILES'
        foreach ($profile in @($profiles)) {
            Add-ReportLine $report ('Name={0}; Enabled={1}; DefaultInbound={2}; DefaultOutbound={3}; LogFile={4}' -f `
                $profile.Name, $profile.Enabled, $profile.DefaultInboundAction, $profile.DefaultOutboundAction, $profile.LogFileName)
            if (-not $profile.Enabled) {
                Add-AuditFinding -Severity CRITICAL -Category $module -Finding ("Firewall profile is disabled: {0}" -f $profile.Name) `
                    -CurrentValue 'Enabled=False' -ExpectedValue 'Enabled=True unless the README explicitly requires otherwise.' `
                    -Evidence 'Get-NetFirewallProfile' -WhyThisMatters 'An inactive profile does not enforce its inbound rules.' `
                    -ReadmeRequired 'Yes' -PossibleManualAction 'Confirm the active network profile and enable the firewall manually if authorized.' `
                    -DisruptionRisk 'High; enabling a firewall can interrupt required traffic.' -RestartRequired 'No' -Confidence 'High' `
                    -Status '[CRITICAL]' -ReportFile $report
            }
            else {
                Add-AuditFinding -Severity INFO -Category $module -Finding ("Firewall profile enabled: {0}" -f $profile.Name) `
                    -CurrentValue ("Enabled=True; DefaultInbound={0}; DefaultOutbound={1}" -f $profile.DefaultInboundAction, $profile.DefaultOutboundAction) `
                    -ExpectedValue 'Enabled with inbound blocking and only required allow rules.' -Evidence 'Get-NetFirewallProfile' `
                    -WhyThisMatters 'Host firewall profiles reduce exposed attack surface.' -ReadmeRequired 'Yes' `
                    -PossibleManualAction 'Confirm defaults and required exceptions against the README.' `
                    -DisruptionRisk 'None from review.' -RestartRequired 'No' -Confidence 'High' -Status '[PASS]' -ReportFile $report
            }
            if ([string]$profile.DefaultInboundAction -eq 'Allow') {
                Add-AuditFinding -Severity HIGH -Category $module -Finding ("Default inbound action allows traffic: {0}" -f $profile.Name) `
                    -CurrentValue 'DefaultInboundAction=Allow' -ExpectedValue 'Block' -Evidence 'Get-NetFirewallProfile' `
                    -WhyThisMatters 'Default allow exposes services unless every unwanted path is explicitly blocked.' `
                    -ReadmeRequired 'Yes' -PossibleManualAction 'Review required services, then change the default manually if permitted.' `
                    -DisruptionRisk 'High; required network services may be interrupted.' -RestartRequired 'No' -Confidence 'High' `
                    -Status '[WARNING]' -ReportFile $report
            }
        }
    }

    $ruleDetails = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get enabled Windows Firewall allow rules and associated port/address/application filters' -ScriptBlock {
        if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) { return }
        $enabledRules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Allow' }
        foreach ($rule in $enabledRules) {
            $port = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $address = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
            $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Name = $rule.DisplayName
                Direction = $rule.Direction
                Profile = $rule.Profile
                Protocol = $port.Protocol
                LocalPort = $port.LocalPort
                RemotePort = $port.RemotePort
                RemoteAddress = $address.RemoteAddress
                Program = $application.Program
                Service = $rule.Service
                Group = $rule.DisplayGroup
            }
        }
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'ENABLED ALLOW RULES'
    foreach ($rule in @($ruleDetails)) {
        $ruleName = Get-ObjectPropertyValue $rule 'Name'
        if ([string]::IsNullOrWhiteSpace([string]$ruleName)) { continue }
        $ruleDirection = Get-ObjectPropertyValue $rule 'Direction'
        $ruleProfile = Get-ObjectPropertyValue $rule 'Profile'
        $ruleProtocol = Get-ObjectPropertyValue $rule 'Protocol'
        $ruleLocalPort = Get-ObjectPropertyValue $rule 'LocalPort'
        $ruleRemotePort = Get-ObjectPropertyValue $rule 'RemotePort'
        $ruleRemoteAddress = Get-ObjectPropertyValue $rule 'RemoteAddress'
        $ruleProgram = Get-ObjectPropertyValue $rule 'Program'
        $ruleService = Get-ObjectPropertyValue $rule 'Service'
        $ruleGroup = Get-ObjectPropertyValue $rule 'Group'
        Add-ReportLine $report (('Name={0}; Direction={1}; Profile={2}; Protocol={3}; LocalPort={4}; RemotePort={5}; ' +
            'RemoteAddress={6}; Program={7}; Service={8}; Group={9}') -f $ruleName, $ruleDirection, $ruleProfile, `
            (ConvertTo-DisplayValue $ruleProtocol), (ConvertTo-DisplayValue $ruleLocalPort), `
            (ConvertTo-DisplayValue $ruleRemotePort), (ConvertTo-DisplayValue $ruleRemoteAddress), `
            (ConvertTo-DisplayValue $ruleProgram), (ConvertTo-DisplayValue $ruleService), (ConvertTo-DisplayValue $ruleGroup))

        $remoteAny = (@($ruleRemoteAddress) -contains 'Any' -or @($ruleRemoteAddress).Count -eq 0)
        $portAny = (@($ruleLocalPort) -contains 'Any' -or @($ruleLocalPort).Count -eq 0)
        $broadRange = ([string]$ruleLocalPort -match '\d+\s*-\s*\d+')
        $sensitive = (('{0} {1} {2}' -f $ruleName, $ruleGroup, $ruleService) -match `
            '(?i)(remote|desktop|winrm|ssh|telnet|ftp|file.*printer|network discovery|smb|rpc|management)')
        $programTargetExists = $true
        if ($ruleProgram -and [string]$ruleProgram -notin @('Any', 'System')) {
            $programTargetExists = Test-AuditPathExists -Module $module `
                -Path ([Environment]::ExpandEnvironmentVariables([string]$ruleProgram)) -PathType Leaf
        }
        $missingProgram = ($ruleProgram -and [string]$ruleProgram -notin @('Any', 'System') -and $programTargetExists -eq $false)

        if ($ruleDirection -eq 'Inbound' -and $remoteAny -and ($portAny -or $broadRange)) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Broad inbound allow rule: {0}" -f $ruleName) `
                -CurrentValue ("Port={0}; RemoteAddress={1}; Profile={2}" -f (ConvertTo-DisplayValue $ruleLocalPort), (ConvertTo-DisplayValue $ruleRemoteAddress), $ruleProfile) `
                -ExpectedValue 'Inbound rules limited to required ports, programs, profiles, and remote addresses.' `
                -Evidence 'Enabled Windows Firewall allow rule and associated filters' `
                -WhyThisMatters 'Broad inbound rules can expose local services to untrusted systems.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the dependent service and narrow or disable the rule manually only if the README permits.' `
                -DisruptionRisk 'High; changing rules can break required connectivity.' -RestartRequired 'No' -Confidence 'Medium; service context still matters.' `
                -Status '[WARNING]' -ReportFile $report
        }
        elseif ($ruleDirection -eq 'Inbound' -and $sensitive) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Remote administration or sharing firewall rule enabled: {0}" -f $ruleName) `
                -CurrentValue ("Port={0}; RemoteAddress={1}; Profile={2}" -f (ConvertTo-DisplayValue $ruleLocalPort), (ConvertTo-DisplayValue $ruleRemoteAddress), $ruleProfile) `
                -ExpectedValue 'Enabled only when the README requires the related service.' -Evidence 'Enabled inbound allow rule' `
                -WhyThisMatters 'Remote access and sharing rules expose services over the network.' -ReadmeRequired 'Yes' `
                -PossibleManualAction 'Confirm service necessity and source scope before manually changing the rule.' `
                -DisruptionRisk 'High' -RestartRequired 'No' -Confidence 'Medium' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
        if ($missingProgram) {
            Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Firewall rule points to a missing program: {0}" -f $ruleName) `
                -CurrentValue $ruleProgram -ExpectedValue 'Existing, authorized executable or no stale rule.' `
                -Evidence 'Application filter target does not exist.' -WhyThisMatters 'Stale or hijackable paths can make rules misleading.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the application was intentionally removed before deleting any rule manually.' `
                -DisruptionRisk 'Medium' -RestartRequired 'No' -Confidence 'Medium; environment variables and protected paths can affect detection.' `
                -Status '[WARNING]' -ReportFile $report
        }
    }
    Add-ReportLine $report ('Total enabled allow rules returned: {0}' -f @($ruleDetails).Count)
}

function Invoke-ServicesAudit {
    [CmdletBinding()]
    param()

    $report = '06-Services.txt'
    $module = 'Services'
    Write-ModuleHeader $report $module 'Service configuration, executable metadata, ACLs, and signatures. Services are never controlled.'

    $services = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_Service' -ScriptBlock {
        Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Sort-Object DisplayName
    }
    $inventory = New-Object System.Collections.ArrayList
    Add-ReportLine $report 'SERVICE INVENTORY'
    foreach ($service in @($services)) {
        $exePath = Get-ExecutablePathFromCommandLine -CommandLine $service.PathName
        $metadata = $null
        if ($exePath) {
            $metadata = Invoke-ReadOnlyCommand -Module $module -CommandText 'Inspect one service executable with Test-Path, Get-Acl, and Get-AuthenticodeSignature' -ScriptBlock {
                if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
                    return [pscustomobject]@{ Exists = $false; Signature = 'NotChecked'; Signer = $null; DirectoryWritable = $null; Acl = $null }
                }
                $signature = Get-AuthenticodeSignature -LiteralPath $exePath -ErrorAction SilentlyContinue
                $directory = [IO.Path]::GetDirectoryName($exePath)
                $directoryAcl = if ($directory -and (Test-Path -LiteralPath $directory)) { Get-Acl -LiteralPath $directory -ErrorAction SilentlyContinue } else { $null }
                return [pscustomobject]@{
                    Exists = $true
                    Signature = if ($signature) { [string]$signature.Status } else { 'NotChecked' }
                    Signer = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
                    DirectoryWritable = $null
                    Acl = $directoryAcl
                }
            }.GetNewClosure() -SuppressErrorFinding
        }

        # Test-WeakWriteAcl is a local analysis helper. The query safety gate does not
        # permit custom commands inside query blocks, so compute this result afterward.
        $exists = if ($metadata) { Get-ObjectPropertyValue $metadata 'Exists' } else { $null }
        $directoryWritable = $null
        if ($metadata) {
            $aclFromMetadata = Get-ObjectPropertyValue $metadata 'Acl'
            if ($aclFromMetadata) { $directoryWritable = Test-WeakWriteAcl -Acl $aclFromMetadata }
        }
        $signatureStatus = if ($metadata) { Get-ObjectPropertyValue $metadata 'Signature' } else { 'NotChecked' }
        $signer = if ($metadata) { Get-ObjectPropertyValue $metadata 'Signer' } else { $null }
        $unquoted = $false
        if ($service.PathName -and $service.PathName -notmatch '^\s*"' -and $exePath -match '\s') { $unquoted = $true }

        $record = [pscustomobject]@{
            Name = $service.Name
            DisplayName = $service.DisplayName
            State = $service.State
            StartMode = $service.StartMode
            PathName = $service.PathName
            ExecutablePath = $exePath
            StartName = $service.StartName
            ProcessId = $service.ProcessId
            ExecutableExists = $exists
            PathQuoted = -not $unquoted
            DirectoryWritableByStandardUsers = $directoryWritable
            SignatureStatus = $signatureStatus
            Signer = $signer
            Description = $service.Description
        }
        [void]$inventory.Add($record)
        Add-ReportLine $report (('Name={0}; DisplayName={1}; State={2}; StartMode={3}; Account={4}; PID={5}; ' +
            'Path={6}; ExecutableExists={7}; PathQuoted={8}; DirectoryWritableByStandardUsers={9}; Signature={10}; Signer={11}') -f `
            $record.Name, $record.DisplayName, $record.State, $record.StartMode, $record.StartName, $record.ProcessId, `
            (ConvertTo-DisplayValue $record.PathName), (ConvertTo-DisplayValue $record.ExecutableExists), $record.PathQuoted, `
            (ConvertTo-DisplayValue $record.DirectoryWritableByStandardUsers), (ConvertTo-DisplayValue $record.SignatureStatus), `
            (ConvertTo-DisplayValue $record.Signer))

        $serviceText = '{0} {1} {2}' -f $record.Name, $record.DisplayName, $record.PathName
        $isReviewService = $serviceText -match '(?i)(telnet|\bftp\b|iis|world wide web|remote registry|snmp|simple tcp|routing and remote access|remote desktop|openssh|\bsshd\b|winrm|spooler|teamviewer|anydesk|vnc|screenconnect|connectwise|splashtop|logmein|rustdesk|dwservice)'
        $userLocation = $exePath -and $exePath -match '(?i)\\Users\\|\\AppData\\|\\Downloads\\|\\Desktop\\'
        $tempLocation = $exePath -and $exePath -match '(?i)\\Temp\\|\\TMP\\'

        if ($isReviewService) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Review potentially exposed or remote-capable service: {0}" -f $record.DisplayName) `
                -CurrentValue ("State={0}; StartMode={1}; Path={2}" -f $record.State, $record.StartMode, $record.PathName) `
                -ExpectedValue 'Installed and enabled only when explicitly required by the README or image role.' `
                -Evidence 'Service name/display name/path matched a review category.' `
                -WhyThisMatters 'Remote access, web, printing, routing, management, and legacy services can increase attack surface.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Confirm the service purpose and dependencies before manually changing it.' `
                -PossibleCommand ("Get-CimInstance Win32_Service | Where-Object Name -eq '{0}'" -f $record.Name) `
                -DisruptionRisk 'High; required services and scoring can depend on it.' -RestartRequired 'Possibly' `
                -Confidence 'Medium; category matching does not prove the service is unauthorized.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
        if ($userLocation -or $tempLocation) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Service executable runs from a user-writable location: {0}" -f $record.DisplayName) `
                -CurrentValue $exePath -ExpectedValue 'Service executables stored in protected system or application directories.' `
                -Evidence 'Executable path contains a user profile, Downloads, Desktop, AppData, or temporary directory.' `
                -WhyThisMatters 'A privileged service executable in a writable location may be replaceable by a lower-privileged user.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify publisher, ACLs, and required purpose before manually correcting the installation.' `
                -DisruptionRisk 'High' -RestartRequired 'Likely if the service installation is later corrected.' `
                -Confidence 'High for location; authorization unknown.' -Status '[WARNING]' -ReportFile $report
        }
        if ($exists -eq $false) {
            Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Service executable target is missing: {0}" -f $record.DisplayName) `
                -CurrentValue $exePath -ExpectedValue 'Existing authorized executable or intentionally removed service registration.' `
                -Evidence 'Test-Path returned False for extracted executable path.' `
                -WhyThisMatters 'Stale services can indicate incomplete uninstallation or a hijackable path.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify path parsing and product purpose before manually removing any stale registration.' `
                -DisruptionRisk 'High if the path was parsed incorrectly or the service is required.' -RestartRequired 'Possibly' `
                -Confidence 'Medium; complex service command lines can be parsed imperfectly.' -Status '[WARNING]' -ReportFile $report
        }
        if ($unquoted) {
            Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Unquoted service executable path contains spaces: {0}" -f $record.DisplayName) `
                -CurrentValue $record.PathName -ExpectedValue 'Executable path enclosed in quotes when it contains spaces.' `
                -Evidence 'Service PathName begins without a quote and extracted executable path contains spaces.' `
                -WhyThisMatters 'Windows path parsing can permit an earlier executable in the path to run.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the exact ImagePath and service behavior before manually quoting it.' `
                -DisruptionRisk 'High; an incorrect path edit can prevent service startup.' -RestartRequired 'Service restart or reboot may be needed later.' `
                -Confidence 'Medium; verify command-line parsing and ACLs.' -Status '[WARNING]' -ReportFile $report
        }
        if ($directoryWritable -eq $true) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Service executable directory appears writable by ordinary users: {0}" -f $record.DisplayName) `
                -CurrentValue ([IO.Path]::GetDirectoryName($exePath)) -ExpectedValue 'No write/modify/full-control grant to Everyone, Users, or Authenticated Users.' `
                -Evidence 'Directory ACL contains an allow rule with write-like rights for a broad identity.' `
                -WhyThisMatters 'Writable service directories can allow executable or dependency replacement.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Review inherited and effective permissions before manually correcting ACLs.' `
                -DisruptionRisk 'High; ACL changes can break updates or applications.' -RestartRequired 'No' -Confidence 'Medium; effective access can differ from explicit ACL analysis.' `
                -Status '[WARNING]' -ReportFile $report
        }
    }
    $script:ServiceInventory = @($inventory)
    Add-ReportLine $report ''
    Add-ReportLine $report ('Total services inventoried: {0}' -f $script:ServiceInventory.Count)
    Add-AuditFinding -Severity INFO -Category $module -Finding 'Service inventory completed' `
        -CurrentValue ("{0} services inventoried" -f $script:ServiceInventory.Count) `
        -ExpectedValue 'Every service reviewed in context; unusual does not mean unauthorized.' `
        -Evidence 'Win32_Service plus local file metadata.' -WhyThisMatters 'Services are major privilege and persistence boundaries.' `
        -ReadmeRequired 'Yes' -PossibleManualAction 'Review highlighted and unfamiliar services against the README and installed roles.' `
        -DisruptionRisk 'None from review.' -RestartRequired 'No' -Confidence 'High' -Status '[INFO]' -ReportFile $report
}

function Invoke-RemoteAccessAudit {
    [CmdletBinding()]
    param()

    $report = '07-Remote-Access.txt'
    $module = 'Remote Access'
    Write-ModuleHeader $report $module 'RDP, assistance, remoting, SSH, remote services, listeners, and related firewall rules.'

    $rdpDeny = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    $nla = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
    $assistance = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp'
    Add-ReportLine $report ('Remote Desktop denied (fDenyTSConnections): {0}' -f (ConvertTo-DisplayValue $rdpDeny))
    Add-ReportLine $report ('Network Level Authentication (UserAuthentication): {0}' -f (ConvertTo-DisplayValue $nla))
    Add-ReportLine $report ('Remote Assistance allowed (fAllowToGetHelp): {0}' -f (ConvertTo-DisplayValue $assistance))

    if ($null -ne $rdpDeny -and [int]$rdpDeny -eq 0) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Remote Desktop is allowed' `
            -CurrentValue 'fDenyTSConnections=0' -ExpectedValue 'Disabled unless required by the README; if required, use NLA and tightly scoped firewall rules.' `
            -Evidence 'Terminal Server registry setting' -WhyThisMatters 'RDP exposes remote interactive logon.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Confirm RDP is required and review authorized users, NLA, and firewall scope.' `
            -DisruptionRisk 'High; disabling required RDP can remove access.' -RestartRequired 'No' -Confidence 'High' `
            -Status '[MANUAL REVIEW]' -ReportFile $report
        if ($null -ne $nla -and [int]$nla -eq 0) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding 'Remote Desktop is allowed without Network Level Authentication' `
                -CurrentValue 'RDP allowed; UserAuthentication=0' -ExpectedValue 'NLA enabled (1) when RDP is required.' `
                -Evidence 'Terminal Server and RDP-Tcp registry values' `
                -WhyThisMatters 'NLA authenticates before establishing a full remote desktop session.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify client compatibility and enable NLA manually if RDP is required.' `
                -DisruptionRisk 'High; older clients may lose access.' -RestartRequired 'Possibly' -Confidence 'High' `
                -Status '[WARNING]' -ReportFile $report
        }
    }
    else {
        Add-AuditFinding -Severity INFO -Category $module -Finding 'Remote Desktop is not enabled by the local setting' `
            -CurrentValue (ConvertTo-DisplayValue $rdpDeny) -ExpectedValue 'Disabled unless required.' `
            -Evidence 'Terminal Server fDenyTSConnections' -WhyThisMatters 'Disabled RDP reduces remote attack surface.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Confirm the README does not require RDP.' `
            -DisruptionRisk 'None from review.' -RestartRequired 'No' -Confidence 'Medium; policy can override local values.' `
            -Status '[PASS]' -ReportFile $report
    }

    if ($null -ne $assistance -and [int]$assistance -eq 1) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Remote Assistance is allowed' `
            -CurrentValue 'fAllowToGetHelp=1' -ExpectedValue 'Disabled unless explicitly required.' `
            -Evidence 'Remote Assistance registry setting' -WhyThisMatters 'Remote Assistance can provide interactive access.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify requirements before changing the setting manually.' `
            -DisruptionRisk 'Medium' -RestartRequired 'Possibly' -Confidence 'High' -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    if ($script:ServiceInventory.Count -eq 0) {
        $script:ServiceInventory = @(Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_Service for remote-access status' `
            -ScriptBlock { Get-CimInstance -ClassName Win32_Service -ErrorAction Stop })
    }
    $remoteNames = @('WinRM', 'sshd', 'RemoteRegistry', 'TermService', 'LanmanServer')
    Add-ReportLine $report ''
    Add-ReportLine $report 'REMOTE-ACCESS RELATED SERVICES'
    foreach ($name in $remoteNames) {
        $service = @($script:ServiceInventory | Where-Object { (Get-ObjectPropertyValue $_ 'Name') -eq $name }) | Select-Object -First 1
        if ($service) {
            $serviceState = Get-ObjectPropertyValue $service 'State'
            $serviceStartMode = Get-ObjectPropertyValue $service 'StartMode'
            $servicePathName = Get-ObjectPropertyValue $service 'PathName'
            Add-ReportLine $report ('Name={0}; State={1}; StartMode={2}; Path={3}' -f $name, $serviceState, $serviceStartMode, (ConvertTo-DisplayValue $servicePathName))
            if ($serviceState -eq 'Running' -or $serviceStartMode -eq 'Auto') {
                Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Remote-capable service active or automatic: {0}" -f $name) `
                    -CurrentValue ("State={0}; StartMode={1}" -f $serviceState, $serviceStartMode) `
                    -ExpectedValue 'Active only when required by the README and protected by authentication and firewall controls.' `
                    -Evidence 'Win32_Service inventory' -WhyThisMatters 'The service can support remote access or remote file operations.' `
                    -ReadmeRequired 'Yes' -PossibleManualAction 'Confirm dependencies and requirements before manually changing service configuration.' `
                    -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'High for service state; necessity unknown.' `
                    -Status '[MANUAL REVIEW]' -ReportFile $report
            }
        }
        else { Add-ReportLine $report ("{0}: not installed or not returned" -f $name) }
    }

    $psEndpoints = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-PSSessionConfiguration (read-only endpoint listing)' -ScriptBlock {
        Get-PSSessionConfiguration -ErrorAction Stop
    } -SuppressErrorFinding
    Add-ReportLine $report ''
    Add-ReportLine $report 'POWERSHELL REMOTING ENDPOINTS'
    foreach ($endpoint in @($psEndpoints)) {
        $endpointName = Get-ObjectPropertyValue $endpoint 'Name'
        if ($endpointName) {
            Add-ReportLine $report ('Name={0}; Permission={1}' -f $endpointName, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $endpoint 'Permission')))
        }
    }
    if (@($psEndpoints).Count -eq 0) { Add-ReportLine $report '<none returned or access denied>' }

    $listeners = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get local TCP listening ports related to remote access' -ScriptBlock {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            Get-NetTCPConnection -State Listen -ErrorAction Stop |
                Where-Object { $_.LocalPort -in @(21, 22, 23, 80, 443, 445, 3389, 5985, 5986, 5900, 5901) }
        }
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'RELATED LOCAL LISTENING PORTS'
    foreach ($listener in @($listeners)) {
        $listenerPort = Get-ObjectPropertyValue $listener 'LocalPort'
        if ($null -eq $listenerPort) { continue }
        $listenerAddress = Get-ObjectPropertyValue $listener 'LocalAddress'
        $listenerPid = Get-ObjectPropertyValue $listener 'OwningProcess'
        Add-ReportLine $report ('Address={0}; Port={1}; PID={2}' -f $listenerAddress, $listenerPort, $listenerPid)
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Remote-access related port is listening locally: {0}" -f $listenerPort) `
            -CurrentValue ("{0}:{1}; PID={2}" -f $listenerAddress, $listenerPort, $listenerPid) `
            -ExpectedValue 'Listening only when the associated service is authorized.' -Evidence 'Get-NetTCPConnection local listener' `
            -WhyThisMatters 'A listening port is reachable according to binding and firewall scope.' -ReadmeRequired 'Yes' `
            -PossibleManualAction 'Identify the associated authorized service and review its firewall exposure.' `
            -DisruptionRisk 'High if a required listener is changed.' -RestartRequired 'Possibly' `
            -Confidence 'High that the port is listening; accessibility from a network was not tested.' -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    $remoteRules = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get enabled firewall rules related to remote access' -ScriptBlock {
        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.Enabled -eq 'True' -and ('{0} {1}' -f $_.DisplayName, $_.DisplayGroup) -match '(?i)(remote|winrm|ssh|desktop|management|file.*printer)' } |
                Select-Object DisplayName, DisplayGroup, Direction, Action, Profile
        }
    } -SuppressErrorFinding
    Add-ReportLine $report ''
    Add-ReportLine $report 'RELATED ENABLED FIREWALL RULES'
    foreach ($rule in @($remoteRules)) {
        $displayName = Get-ObjectPropertyValue $rule 'DisplayName'
        if ($displayName) {
            Add-ReportLine $report ('Name={0}; Group={1}; Direction={2}; Action={3}; Profile={4}' -f `
                $displayName, (Get-ObjectPropertyValue $rule 'DisplayGroup'), (Get-ObjectPropertyValue $rule 'Direction'), `
                (Get-ObjectPropertyValue $rule 'Action'), (Get-ObjectPropertyValue $rule 'Profile'))
        }
    }
}

function Invoke-NetworkAndSmbAudit {
    [CmdletBinding()]
    param()

    $report = '08-Network-and-SMB.txt'
    $module = 'Network and SMB'
    Write-ModuleHeader $report $module 'Local-only protocol, name-resolution, listener, connection, DNS, forwarding, and TLS inspection.'

    $smbServer = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-SmbServerConfiguration' -ScriptBlock {
        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) { Get-SmbServerConfiguration -ErrorAction Stop }
    }
    $smbClient = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-SmbClientConfiguration' -ScriptBlock {
        if (Get-Command Get-SmbClientConfiguration -ErrorAction SilentlyContinue) { Get-SmbClientConfiguration -ErrorAction Stop }
    }
    $smb1Features = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-WindowsOptionalFeature SMB1Protocol feature states' -ScriptBlock {
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol*' -ErrorAction Stop
        }
    } -SuppressErrorFinding

    Add-ReportLine $report 'SMB CONFIGURATION'
    if ($smbServer) {
        Add-ReportLine $report ('Server: EnableSMB1Protocol={0}; EnableSMB2Protocol={1}; RequireSecuritySignature={2}; EnableSecuritySignature={3}; EncryptData={4}; RejectUnencryptedAccess={5}' -f `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbServer 'EnableSMB1Protocol')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbServer 'EnableSMB2Protocol')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbServer 'RequireSecuritySignature')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbServer 'EnableSecuritySignature')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbServer 'EncryptData')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbServer 'RejectUnencryptedAccess')))
    }
    if ($smbClient) {
        Add-ReportLine $report ('Client: RequireSecuritySignature={0}; EnableSecuritySignature={1}; EnableInsecureGuestLogons={2}' -f `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbClient 'RequireSecuritySignature')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbClient 'EnableSecuritySignature')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $smbClient 'EnableInsecureGuestLogons')))
    }
    foreach ($feature in @($smb1Features)) {
        $featureName = Get-ObjectPropertyValue $feature 'FeatureName'
        if ($featureName) {
            Add-ReportLine $report ('OptionalFeature={0}; State={1}' -f $featureName, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $feature 'State')))
        }
    }

    $smb1Enabled = $false
    if ($smbServer -and (Get-ObjectPropertyValue $smbServer 'EnableSMB1Protocol') -eq $true) { $smb1Enabled = $true }
    if (@($smb1Features | Where-Object { (Get-ObjectPropertyValue $_ 'State') -eq 'Enabled' }).Count -gt 0) { $smb1Enabled = $true }
    if ($smb1Enabled) {
        Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'SMBv1 is enabled' `
            -CurrentValue 'SMBv1 server or optional feature is enabled.' -ExpectedValue 'SMBv1 disabled unless an explicit, documented legacy requirement exists.' `
            -Evidence 'Get-SmbServerConfiguration and Windows optional-feature state' `
            -WhyThisMatters 'SMBv1 is obsolete and lacks modern protocol protections.' -ReadmeRequired 'Yes' `
            -PossibleManualAction 'Confirm no required legacy dependency, then disable SMBv1 manually using approved Windows features/policy tools.' `
            -DisruptionRisk 'High; legacy file-sharing devices may stop working.' -RestartRequired 'Yes' -Confidence 'High' `
            -Status '[CRITICAL]' -ReportFile $report
    }
    else {
        Add-AuditFinding -Severity INFO -Category $module -Finding 'SMBv1 does not appear enabled' `
            -CurrentValue 'No enabled SMBv1 state returned.' -ExpectedValue 'Disabled' -Evidence 'SMB server configuration and optional features' `
            -WhyThisMatters 'Removing SMBv1 reduces exposure to legacy protocol attacks.' -ReadmeRequired 'No' `
            -PossibleManualAction 'No action suggested; verify any unavailable client component separately.' `
            -DisruptionRisk 'None' -RestartRequired 'No' -Confidence 'Medium' -Status '[PASS]' -ReportFile $report
    }

    $serverSigning = Get-ObjectPropertyValue $smbServer 'RequireSecuritySignature'
    $clientSigning = Get-ObjectPropertyValue $smbClient 'RequireSecuritySignature'
    if ($serverSigning -eq $false -or $clientSigning -eq $false) {
        Add-AuditFinding -Severity MEDIUM -Category $module -Finding 'SMB signing is not required in all returned roles' `
            -CurrentValue ("ServerRequire={0}; ClientRequire={1}" -f (ConvertTo-DisplayValue $serverSigning), (ConvertTo-DisplayValue $clientSigning)) `
            -ExpectedValue 'SMB signing required where compatible with image requirements.' -Evidence 'SMB client/server configuration' `
            -WhyThisMatters 'Signing helps prevent tampering and relay-style abuse of SMB sessions.' -ReadmeRequired 'Yes' `
            -PossibleManualAction 'Check compatibility and README requirements before requiring SMB signing manually.' `
            -DisruptionRisk 'High; legacy SMB peers may fail.' -RestartRequired 'Possibly' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
    }
    $insecureGuest = Get-ObjectPropertyValue $smbClient 'EnableInsecureGuestLogons'
    if ($insecureGuest -eq $true) {
        Add-AuditFinding -Severity HIGH -Category $module -Finding 'Insecure SMB guest logons are enabled' `
            -CurrentValue 'EnableInsecureGuestLogons=True' -ExpectedValue 'False' -Evidence 'Get-SmbClientConfiguration' `
            -WhyThisMatters 'Unauthenticated guest sessions reduce accountability and protocol protections.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify required shares and disable insecure guest logons manually if safe.' `
            -DisruptionRisk 'High; guest-only shares may become inaccessible.' -RestartRequired 'Possibly' -Confidence 'High' `
            -Status '[WARNING]' -ReportFile $report
    }

    $lmLevel = Get-RegistryAuditValue -Module $module -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
    $llmnr = Get-RegistryAuditValue -Module $module -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    $wpad = Get-RegistryAuditValue -Module $module -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name 'WpadOverride'
    Add-ReportLine $report ('LAN Manager authentication level: {0}' -f (ConvertTo-DisplayValue $lmLevel))
    Add-ReportLine $report ('LLMNR EnableMulticast: {0}' -f (ConvertTo-DisplayValue $llmnr))
    Add-ReportLine $report ('WPAD override: {0}' -f (ConvertTo-DisplayValue $wpad))
    if ($null -eq $lmLevel -or [int]$lmLevel -lt 5) {
        Add-AuditFinding -Severity MEDIUM -Category $module -Finding 'LAN Manager/NTLM authentication level may permit legacy responses' `
            -CurrentValue (ConvertTo-DisplayValue $lmLevel) -ExpectedValue 'Common hardened value 5, subject to compatibility and README.' `
            -Evidence 'HKLM Lsa LmCompatibilityLevel' -WhyThisMatters 'Legacy LM/NTLM modes provide weaker authentication and negotiation.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify domain/application compatibility before manually changing authentication policy.' `
            -DisruptionRisk 'High; legacy clients or servers can lose authentication.' -RestartRequired 'Possibly' `
            -Confidence $(if ($null -eq $lmLevel) { 'Low; absent values use OS defaults.' } else { 'High' }) -Status '[WARNING]' -ReportFile $report
    }
    if ($null -eq $llmnr -or [int]$llmnr -ne 0) {
        Add-AuditFinding -Severity MEDIUM -Category $module -Finding 'LLMNR is not explicitly disabled by policy' `
            -CurrentValue (ConvertTo-DisplayValue $llmnr) -ExpectedValue 'EnableMulticast=0 where the README and network design allow.' `
            -Evidence 'DNSClient policy EnableMulticast' -WhyThisMatters 'Multicast name resolution can permit local-network spoofing.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Confirm name-resolution requirements before disabling LLMNR manually.' `
            -DisruptionRisk 'Medium; name resolution for some local resources may change.' -RestartRequired 'Possibly' `
            -Confidence 'Medium; absence usually means the feature is available.' -Status '[WARNING]' -ReportFile $report
    }

    $sharingRules = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get enabled Network Discovery and File and Printer Sharing firewall rules' -ScriptBlock {
        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.Enabled -eq 'True' -and $_.DisplayGroup -match '(?i)(Network Discovery|File and Printer Sharing)' } |
                Select-Object DisplayName, DisplayGroup, Direction, Action, Profile
        }
    } -SuppressErrorFinding
    Add-ReportLine $report ''
    Add-ReportLine $report 'NETWORK DISCOVERY AND FILE/PRINTER SHARING FIREWALL RULES'
    foreach ($rule in @($sharingRules)) {
        $displayName = Get-ObjectPropertyValue $rule 'DisplayName'
        if (-not $displayName) { continue }
        Add-ReportLine $report ('Name={0}; Group={1}; Direction={2}; Action={3}; Profile={4}' -f `
            $displayName, (Get-ObjectPropertyValue $rule 'DisplayGroup'), (Get-ObjectPropertyValue $rule 'Direction'), `
            (Get-ObjectPropertyValue $rule 'Action'), (Get-ObjectPropertyValue $rule 'Profile'))
        if ((Get-ObjectPropertyValue $rule 'Direction') -eq 'Inbound' -and (Get-ObjectPropertyValue $rule 'Action') -eq 'Allow') {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Discovery or file-sharing inbound rule enabled: {0}" -f $displayName) `
                -CurrentValue ("Group={0}; Profile={1}" -f (Get-ObjectPropertyValue $rule 'DisplayGroup'), (Get-ObjectPropertyValue $rule 'Profile')) `
                -ExpectedValue 'Enabled only on required profiles when the README/image role needs discovery or sharing.' `
                -Evidence 'Enabled Windows Firewall rule' `
                -WhyThisMatters 'Discovery and sharing rules can expose local services and resources to nearby systems.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify required shares/devices and profile scope before changing the rule manually.' `
                -DisruptionRisk 'High; required discovery or file/print access may stop.' -RestartRequired 'No' `
                -Confidence 'High for rule state; service necessity is unknown.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }

    $netbios = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_NetworkAdapterConfiguration IPEnabled adapters' -ScriptBlock {
        Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'ACTIVE IP ADAPTER SETTINGS'
    foreach ($adapter in @($netbios)) {
        Add-ReportLine $report ('Description={0}; IP={1}; DNS={2}; DNSDomain={3}; NetBIOSOption={4}; IPForwarding={5}' -f `
            $adapter.Description, (ConvertTo-DisplayValue $adapter.IPAddress), (ConvertTo-DisplayValue $adapter.DNSServerSearchOrder), `
            (ConvertTo-DisplayValue $adapter.DNSDomain), (ConvertTo-DisplayValue $adapter.TcpipNetbiosOptions), $adapter.IPEnabled)
        if ($adapter.TcpipNetbiosOptions -ne 2) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("NetBIOS over TCP/IP is enabled or DHCP-controlled: {0}" -f $adapter.Description) `
                -CurrentValue ("TcpipNetbiosOptions={0}" -f (ConvertTo-DisplayValue $adapter.TcpipNetbiosOptions)) `
                -ExpectedValue 'Disabled (2) where legacy name resolution/file sharing is not required.' `
                -Evidence 'Win32_NetworkAdapterConfiguration' -WhyThisMatters 'NetBIOS increases legacy local-network name-resolution and sharing exposure.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify adapter and legacy dependencies before manually disabling NetBIOS.' `
                -DisruptionRisk 'High for legacy applications.' -RestartRequired 'Possibly' -Confidence 'Medium' `
                -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }

    $tcpListeners = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get all local TCP listeners' -ScriptBlock {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort, LocalAddress
        }
    }
    $udpListeners = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get all local UDP endpoints' -ScriptBlock {
        if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
            Get-NetUDPEndpoint -ErrorAction Stop | Sort-Object LocalPort, LocalAddress
        }
    }
    $activeTcp = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get active established local TCP connections' -ScriptBlock {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            Get-NetTCPConnection -State Established -ErrorAction Stop | Sort-Object RemoteAddress, RemotePort
        }
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'LISTENING TCP PORTS'
    foreach ($item in @($tcpListeners)) { Add-ReportLine $report ('{0}:{1}; PID={2}' -f $item.LocalAddress, $item.LocalPort, $item.OwningProcess) }
    Add-ReportLine $report ''
    Add-ReportLine $report 'LISTENING UDP PORTS'
    foreach ($item in @($udpListeners)) { Add-ReportLine $report ('{0}:{1}; PID={2}' -f $item.LocalAddress, $item.LocalPort, $item.OwningProcess) }
    Add-ReportLine $report ''
    Add-ReportLine $report 'ACTIVE ESTABLISHED TCP CONNECTIONS (LOCAL OBSERVATION ONLY)'
    foreach ($item in @($activeTcp)) {
        Add-ReportLine $report ('Local={0}:{1}; Remote={2}:{3}; PID={4}' -f $item.LocalAddress, $item.LocalPort, $item.RemoteAddress, $item.RemotePort, $item.OwningProcess)
    }

    $ipForward = Get-RegistryAuditValue -Module $module -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter'
    $sharedAccess = @($script:ServiceInventory | Where-Object { $_.Name -eq 'SharedAccess' }) | Select-Object -First 1
    Add-ReportLine $report ('IP forwarding (IPEnableRouter): {0}' -f (ConvertTo-DisplayValue $ipForward))
    Add-ReportLine $report ('Internet Connection Sharing service: {0}' -f $(if ($sharedAccess) { "State=$($sharedAccess.State); StartMode=$($sharedAccess.StartMode)" } else { 'Not returned' }))
    if ($null -ne $ipForward -and [int]$ipForward -eq 1) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'IP forwarding is enabled' `
            -CurrentValue 'IPEnableRouter=1' -ExpectedValue 'Disabled unless the computer is intentionally a router.' `
            -Evidence 'TCP/IP Parameters registry value' -WhyThisMatters 'Forwarding changes the host into a traffic path between networks.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the assigned server/network role before changing routing manually.' `
            -DisruptionRisk 'High' -RestartRequired 'Yes' -Confidence 'High' -Status '[MANUAL REVIEW]' -ReportFile $report
    }
    if ($sharedAccess -and ($sharedAccess.State -eq 'Running' -or $sharedAccess.StartMode -eq 'Auto')) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Internet Connection Sharing service is active or automatic' `
            -CurrentValue ("State={0}; StartMode={1}" -f $sharedAccess.State, $sharedAccess.StartMode) `
            -ExpectedValue 'Active only if the README requires connection sharing.' -Evidence 'SharedAccess service configuration' `
            -WhyThisMatters 'ICS can alter routing, addressing, and firewall behavior.' -ReadmeRequired 'Yes' `
            -PossibleManualAction 'Verify required network topology before changing the service manually.' `
            -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'High' -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'SCHANNEL SSL/TLS PROTOCOL SETTINGS'
    foreach ($protocol in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')) {
        foreach ($role in @('Client', 'Server')) {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\{1}' -f $protocol, $role
            $enabled = Get-RegistryAuditValue -Module $module -Path $path -Name 'Enabled'
            $disabledByDefault = Get-RegistryAuditValue -Module $module -Path $path -Name 'DisabledByDefault'
            Add-ReportLine $report ('{0} {1}: Enabled={2}; DisabledByDefault={3}' -f $protocol, $role, `
                (ConvertTo-DisplayValue $enabled), (ConvertTo-DisplayValue $disabledByDefault))
            if ($protocol -in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') -and $null -ne $enabled -and [int]$enabled -ne 0) {
                Add-AuditFinding -Severity HIGH -Category $module -Finding ("Legacy protocol explicitly enabled: {0} {1}" -f $protocol, $role) `
                    -CurrentValue ("Enabled={0}; DisabledByDefault={1}" -f $enabled, (ConvertTo-DisplayValue $disabledByDefault)) `
                    -ExpectedValue 'Legacy SSL/TLS disabled unless a documented requirement exists.' -Evidence $path `
                    -WhyThisMatters 'Legacy protocol versions have known cryptographic weaknesses.' -ReadmeRequired 'Yes' `
                    -PossibleManualAction 'Inventory application dependencies before disabling the protocol manually.' `
                    -DisruptionRisk 'High; legacy clients or servers may fail.' -RestartRequired 'Usually yes' -Confidence 'High' `
                    -Status '[WARNING]' -ReportFile $report
            }
        }
    }
}

function Invoke-WindowsDefenderAudit {
    [CmdletBinding()]
    param()

    $report = '09-Windows-Defender.txt'
    $module = 'Windows Defender'
    Write-ModuleHeader $report $module 'Microsoft Defender status, preferences, exclusions, detections, and registered antivirus products.'

    $status = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-MpComputerStatus' -ScriptBlock {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { Get-MpComputerStatus -ErrorAction Stop }
    }
    $preference = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-MpPreference' -ScriptBlock {
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) { Get-MpPreference -ErrorAction Stop }
    }
    $detections = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-MpThreatDetection recent records' -ScriptBlock {
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) { Get-MpThreatDetection -ErrorAction Stop }
    } -SuppressErrorFinding
    $securityProducts = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance root/SecurityCenter2 AntiVirusProduct' -ScriptBlock {
        Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    } -SuppressErrorFinding

    Add-ReportLine $report 'DEFENDER STATUS'
    $statusProperties = @(
        'AMServiceEnabled', 'AntivirusEnabled', 'AntispywareEnabled', 'RealTimeProtectionEnabled',
        'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled',
        'NISEnabled', 'AntivirusSignatureLastUpdated', 'AntivirusSignatureAge',
        'AntispywareSignatureLastUpdated', 'IsTamperProtected', 'DefenderSignaturesOutOfDate',
        'FullScanAge', 'QuickScanAge'
    )
    foreach ($name in $statusProperties) {
        Add-ReportLine $report ('{0}: {1}' -f $name, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $status $name)))
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'DEFENDER PREFERENCES'
    $preferenceProperties = @(
        'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection',
        'MAPSReporting', 'SubmitSamplesConsent', 'PUAProtection', 'EnableControlledFolderAccess',
        'EnableNetworkProtection', 'DisableBlockAtFirstSeen', 'CloudBlockLevel',
        'SignatureUpdateInterval', 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress'
    )
    foreach ($name in $preferenceProperties) {
        Add-ReportLine $report ('{0}: {1}' -f $name, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $preference $name)))
    }

    if ($null -eq $status) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Microsoft Defender status could not be read' `
            -CurrentValue 'No Get-MpComputerStatus result' -ExpectedValue 'An active, healthy antivirus product required by the README.' `
            -Evidence 'Defender cmdlet unavailable or query failed; see errors/command log.' `
            -WhyThisMatters 'Antivirus state needs direct verification.' -ReadmeRequired 'Yes' `
            -PossibleManualAction 'Open Windows Security and review registered security providers.' `
            -DisruptionRisk 'None for review.' -RestartRequired 'No' -Confidence 'Low' -Status '[MANUAL REVIEW]' -ReportFile $report
    }
    else {
        $avEnabled = Get-ObjectPropertyValue $status 'AntivirusEnabled'
        $rtEnabled = Get-ObjectPropertyValue $status 'RealTimeProtectionEnabled'
        if ($avEnabled -ne $true) {
            Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'Microsoft Defender antivirus is not enabled' `
                -CurrentValue ("AntivirusEnabled={0}" -f (ConvertTo-DisplayValue $avEnabled)) `
                -ExpectedValue 'An authorized antivirus product actively protecting the system.' -Evidence 'Get-MpComputerStatus' `
                -WhyThisMatters 'Inactive antivirus reduces detection and prevention of malicious software.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Check for an authorized third-party antivirus and review Windows Security manually.' `
                -DisruptionRisk 'High; enabling or replacing security software can affect performance and compatibility.' `
                -RestartRequired 'Possibly' -Confidence 'High for Defender; another product may be active.' -Status '[CRITICAL]' -ReportFile $report
        }
        elseif ($rtEnabled -ne $true) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding 'Defender real-time protection is not enabled' `
                -CurrentValue ("RealTimeProtectionEnabled={0}" -f (ConvertTo-DisplayValue $rtEnabled)) `
                -ExpectedValue 'True unless an authorized product is providing equivalent protection.' -Evidence 'Get-MpComputerStatus' `
                -WhyThisMatters 'Without real-time scanning, threats may execute before scheduled scans.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Review Windows Security and policy sources before enabling protection manually.' `
                -DisruptionRisk 'Medium' -RestartRequired 'Possibly' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
        }
        else {
            Add-AuditFinding -Severity INFO -Category $module -Finding 'Defender antivirus and real-time protection are enabled' `
                -CurrentValue 'AntivirusEnabled=True; RealTimeProtectionEnabled=True' `
                -ExpectedValue 'Enabled' -Evidence 'Get-MpComputerStatus' -WhyThisMatters 'Real-time antivirus is a central endpoint defense.' `
                -ReadmeRequired 'No' -PossibleManualAction 'Continue reviewing exclusions, signatures, and detections.' `
                -DisruptionRisk 'None' -RestartRequired 'No' -Confidence 'High' -Status '[PASS]' -ReportFile $report
        }
        $signatureAge = Get-ObjectPropertyValue $status 'AntivirusSignatureAge'
        if ($null -ne $signatureAge -and [int]$signatureAge -gt 7) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding 'Defender signatures are older than seven days' `
                -CurrentValue ("AntivirusSignatureAge={0} days" -f $signatureAge) -ExpectedValue 'Current signatures, normally less than one day old when update access is available.' `
                -Evidence 'Get-MpComputerStatus' -WhyThisMatters 'Older signatures may miss recently identified threats.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Review network/update constraints, then update signatures manually if permitted.' `
                -DisruptionRisk 'Low to medium.' -RestartRequired 'No' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
        }
    }

    $exclusionKinds = @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress')
    foreach ($kind in $exclusionKinds) {
        $values = @(Get-ObjectPropertyValue $preference $kind)
        $values = @($values | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
        foreach ($value in $values) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Defender exclusion requires prominent review: {0}" -f $kind) `
                -CurrentValue $value -ExpectedValue 'No exclusion unless narrowly scoped, documented, and required by the README/application.' `
                -Evidence ("Get-MpPreference.{0}" -f $kind) -WhyThisMatters 'Excluded content can evade antivirus inspection.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the exact business/competition need before manually removing or narrowing any exclusion.' `
                -DisruptionRisk 'High; removing legitimate exclusions can break or slow applications.' -RestartRequired 'No' `
                -Confidence 'High that the exclusion is configured; maliciousness is not inferred.' -Status '[WARNING]' -ReportFile $report
        }
    }

    $cloud = Get-ObjectPropertyValue $preference 'MAPSReporting'
    $samples = Get-ObjectPropertyValue $preference 'SubmitSamplesConsent'
    $pua = Get-ObjectPropertyValue $preference 'PUAProtection'
    $cfa = Get-ObjectPropertyValue $preference 'EnableControlledFolderAccess'
    $networkProtection = Get-ObjectPropertyValue $preference 'EnableNetworkProtection'
    Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Review Defender advanced protection settings' `
        -CurrentValue ("Cloud/MAPS={0}; SampleSubmission={1}; PUA={2}; ControlledFolderAccess={3}; NetworkProtection={4}" -f `
            (ConvertTo-DisplayValue $cloud), (ConvertTo-DisplayValue $samples), (ConvertTo-DisplayValue $pua), `
            (ConvertTo-DisplayValue $cfa), (ConvertTo-DisplayValue $networkProtection)) `
        -ExpectedValue 'Protection enabled according to privacy, compatibility, and README requirements.' `
        -Evidence 'Get-MpPreference' -WhyThisMatters 'These controls extend detection and blocking but can affect applications or data handling.' `
        -ReadmeRequired 'Yes' -PossibleManualAction 'Research numeric modes and verify application impact before changing any setting manually.' `
        -DisruptionRisk 'Medium to high.' -RestartRequired 'Possibly' -Confidence 'High for returned values.' `
        -Status '[MANUAL REVIEW]' -ReportFile $report

    Add-ReportLine $report ''
    Add-ReportLine $report 'RECENT DEFENDER DETECTIONS'
    foreach ($detection in @($detections | Sort-Object InitialDetectionTime -Descending | Select-Object -First 50)) {
        Add-ReportLine $report ('ThreatID={0}; InitialDetection={1}; ActionSuccess={2}; Resources={3}' -f `
            $detection.ThreatID, $detection.InitialDetectionTime, $detection.ActionSuccess, (ConvertTo-DisplayValue $detection.Resources))
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Review Defender detection: ThreatID {0}" -f $detection.ThreatID) `
            -CurrentValue ("InitialDetection={0}; ActionSuccess={1}" -f $detection.InitialDetectionTime, $detection.ActionSuccess) `
            -ExpectedValue 'Every detection investigated and resolved without removing required competition files.' `
            -Evidence (ConvertTo-DisplayValue $detection.Resources) -WhyThisMatters 'Detections can indicate malicious or unwanted content, but context matters.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Review Windows Security detection details; do not automatically quarantine or delete anything.' `
            -DisruptionRisk 'High if a required file is removed.' -RestartRequired 'Possibly' -Confidence 'High that Defender recorded a detection.' `
            -Status '[MANUAL REVIEW]' -ReportFile $report
    }
    if (@($detections).Count -eq 0) { Add-ReportLine $report '<none returned>' }

    Add-ReportLine $report ''
    Add-ReportLine $report 'REGISTERED ANTIVIRUS PRODUCTS'
    foreach ($product in @($securityProducts)) {
        Add-ReportLine $report ('Name={0}; State={1}; Executable={2}; ReportingExe={3}' -f `
            $product.displayName, $product.productState, $product.pathToSignedProductExe, $product.pathToSignedReportingExe)
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Verify registered antivirus product: {0}" -f $product.displayName) `
            -CurrentValue ("ProductState={0}" -f $product.productState) -ExpectedValue 'Only authorized, healthy security products required for the image.' `
            -Evidence 'SecurityCenter2 AntiVirusProduct registration' -WhyThisMatters 'Multiple or inactive products can conflict or create gaps.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify product health and authorization in Windows Security and the README.' `
            -DisruptionRisk 'High if security software is changed.' -RestartRequired 'Possibly' -Confidence 'Medium; Security Center states are encoded.' `
            -Status '[MANUAL REVIEW]' -ReportFile $report
    }
}

function Invoke-WindowsUpdateAudit {
    [CmdletBinding()]
    param()

    $report = '10-Windows-Update.txt'
    $module = 'Windows Update'
    Write-ModuleHeader $report $module 'Update services, policy, installed updates, last success indicators, and pending restart. No updates are searched online or installed.'

    if ($script:ServiceInventory.Count -eq 0) {
        $script:ServiceInventory = @(Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_Service for update service state' `
            -ScriptBlock { Get-CimInstance -ClassName Win32_Service -ErrorAction Stop })
    }
    $updateServiceNames = @('wuauserv', 'BITS', 'UsoSvc', 'WaaSMedicSvc')
    Add-ReportLine $report 'UPDATE-RELATED SERVICES'
    foreach ($name in $updateServiceNames) {
        $service = @($script:ServiceInventory | Where-Object { $_.Name -eq $name }) | Select-Object -First 1
        if ($service) {
            Add-ReportLine $report ('Name={0}; State={1}; StartMode={2}; Account={3}' -f $name, $service.State, $service.StartMode, $service.StartName)
            if ($service.StartMode -eq 'Disabled') {
                Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Update-related service is disabled: {0}" -f $name) `
                    -CurrentValue ("State={0}; StartMode=Disabled" -f $service.State) `
                    -ExpectedValue 'Configured according to supported Windows defaults and the README, not permanently disabled without reason.' `
                    -Evidence 'Win32_Service' -WhyThisMatters 'Disabled update components can prevent security maintenance.' `
                    -ReadmeRequired 'Yes' -PossibleManualAction 'Verify Windows edition, policy, and README before changing service startup manually.' `
                    -DisruptionRisk 'Medium to high.' -RestartRequired 'Possibly' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
            }
        }
        else { Add-ReportLine $report ("{0}: not installed or not returned" -f $name) }
    }

    $auOptions = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions'
    $noAuto = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate'
    $useWuServer = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWUServer'
    $wuServer = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'WUServer'
    $lastSuccess = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -Name 'LastSuccessTime'
    Add-ReportLine $report ''
    Add-ReportLine $report ('AUOptions: {0}' -f (ConvertTo-DisplayValue $auOptions))
    Add-ReportLine $report ('NoAutoUpdate: {0}' -f (ConvertTo-DisplayValue $noAuto))
    Add-ReportLine $report ('UseWUServer: {0}' -f (ConvertTo-DisplayValue $useWuServer))
    Add-ReportLine $report ('WUServer: {0}' -f (ConvertTo-DisplayValue $wuServer))
    Add-ReportLine $report ('Last successful install indicator: {0}' -f (ConvertTo-DisplayValue $lastSuccess))
    Add-ReportLine $report ('Pending restart: {0}' -f $script:PendingRestart)

    if ($null -ne $noAuto -and [int]$noAuto -eq 1) {
        Add-AuditFinding -Severity HIGH -Category $module -Finding 'Automatic Windows Update is disabled by policy' `
            -CurrentValue 'NoAutoUpdate=1' -ExpectedValue 'Updates managed through an authorized automatic or centrally managed process.' `
            -Evidence 'Windows Update AU policy registry value' -WhyThisMatters 'Disabled update delivery can leave known vulnerabilities unpatched.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Determine whether WSUS or another approved mechanism is required before changing policy manually.' `
            -DisruptionRisk 'High; updates can restart or alter required applications.' -RestartRequired 'Potentially' -Confidence 'High' `
            -Status '[WARNING]' -ReportFile $report
    }

    $hotfixes = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-HotFix sorted by InstalledOn' -ScriptBlock {
        Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'RECENTLY INSTALLED UPDATES (LATEST 100)'
    foreach ($hotfix in @($hotfixes | Select-Object -First 100)) {
        Add-ReportLine $report ('HotFixID={0}; InstalledOn={1}; Description={2}; InstalledBy={3}' -f `
            $hotfix.HotFixID, (ConvertTo-DisplayValue $hotfix.InstalledOn), $hotfix.Description, (ConvertTo-DisplayValue $hotfix.InstalledBy))
    }
    if (@($hotfixes).Count -eq 0) { Add-ReportLine $report '<none returned>' }

    Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Missing updates require manual verification' `
        -CurrentValue ("Installed hotfix records returned={0}; LastSuccess={1}; PendingRestart={2}" -f @($hotfixes).Count, (ConvertTo-DisplayValue $lastSuccess), $script:PendingRestart) `
        -ExpectedValue 'All README-required and applicable security updates installed through an authorized workflow.' `
        -Evidence 'Local installed-update history only; the script intentionally performs no online search.' `
        -WhyThisMatters 'An offline local inventory cannot prove that no applicable update is missing.' `
        -ReadmeRequired 'Yes' -PossibleManualAction 'Use the approved Windows Update interface and README guidance to check manually when permitted.' `
        -DisruptionRisk 'High; installation or restart can affect services.' -RestartRequired 'Potentially' `
        -Confidence 'High that this audit did not contact an update source; missing-update status remains unknown.' `
        -Status '[MANUAL REVIEW]' -ReportFile $report
}

function Invoke-InstalledSoftwareAudit {
    [CmdletBinding()]
    param()

    $report = '11-Installed-Software.txt'
    $module = 'Installed Software'
    Write-ModuleHeader $report $module 'Desktop programs and Appx packages. Categories are review prompts, never authorization decisions.'

    $machinePaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $desktopSoftware = Invoke-ReadOnlyCommand -Module $module -CommandText 'Read 64-bit, 32-bit, and current-user uninstall registry entries' -ScriptBlock {
        foreach ($path in $machinePaths) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        }
        $userRoots = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' }
        foreach ($userRoot in $userRoots) {
            $userPath = 'Registry::HKEY_USERS\' + $userRoot.PSChildName + '\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
            Get-ItemProperty -Path $userPath -ErrorAction SilentlyContinue
        }
    }.GetNewClosure()
    $appx = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-AppxPackage -AllUsers' -ScriptBlock {
        if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
            Get-AppxPackage -AllUsers -ErrorAction Stop
        }
    } -SuppressErrorFinding

    $inventory = New-Object System.Collections.ArrayList
    foreach ($program in @($desktopSoftware)) {
        $name = Get-ObjectPropertyValue $program 'DisplayName'
        if ([string]::IsNullOrWhiteSpace([string]$name)) { continue }
        $record = [pscustomobject]@{
            Type = 'Desktop'
            Name = [string]$name
            Version = Get-ObjectPropertyValue $program 'DisplayVersion'
            Publisher = Get-ObjectPropertyValue $program 'Publisher'
            InstallDate = Get-ObjectPropertyValue $program 'InstallDate'
            InstallLocation = Get-ObjectPropertyValue $program 'InstallLocation'
            UninstallString = Get-ObjectPropertyValue $program 'UninstallString'
            PackageFullName = $null
        }
        [void]$inventory.Add($record)
    }
    foreach ($package in @($appx)) {
        $packageName = Get-ObjectPropertyValue $package 'Name'
        if ([string]::IsNullOrWhiteSpace([string]$packageName)) { continue }
        $record = [pscustomobject]@{
            Type = 'Appx'
            Name = $packageName
            Version = Get-ObjectPropertyValue $package 'Version'
            Publisher = Get-ObjectPropertyValue $package 'Publisher'
            InstallDate = $null
            InstallLocation = Get-ObjectPropertyValue $package 'InstallLocation'
            UninstallString = $null
            PackageFullName = Get-ObjectPropertyValue $package 'PackageFullName'
        }
        [void]$inventory.Add($record)
    }
    $script:SoftwareInventory = @($inventory | Sort-Object Type, Name, Version -Unique)

    Add-ReportLine $report 'SOFTWARE INVENTORY'
    foreach ($program in $script:SoftwareInventory) {
        Add-ReportLine $report (('Type={0}; Name={1}; Version={2}; Publisher={3}; InstallDate={4}; Location={5}; ' +
            'UninstallString(REFERENCE ONLY - NOT EXECUTED)={6}; PackageFullName={7}') -f `
            $program.Type, $program.Name, (ConvertTo-DisplayValue $program.Version), (ConvertTo-DisplayValue $program.Publisher), `
            (ConvertTo-DisplayValue $program.InstallDate), (ConvertTo-DisplayValue $program.InstallLocation), `
            (ConvertTo-DisplayValue $program.UninstallString), (ConvertTo-DisplayValue $program.PackageFullName))

        $text = '{0} {1} {2}' -f $program.Name, $program.Publisher, $program.InstallLocation
        $categories = New-Object System.Collections.ArrayList
        $categoryRules = @(
            @{ Pattern='(?i)(steam|epic games|gog galaxy|minecraft|roblox|battle\.net|origin|ubisoft|game)'; Label='Game or game platform' },
            @{ Pattern='(?i)(bittorrent|utorrent|qbittorrent|deluge|transmission|torrent)'; Label='Peer-to-peer or torrent software' },
            @{ Pattern='(?i)(john the ripper|hashcat|ophcrack|mimikatz|l0phtcrack|password recovery|password reset|chntpw)'; Label='Password-recovery or password-cracking tool' },
            @{ Pattern='(?i)(wireshark|winpcap|npcap|tcpdump|packet capture)'; Label='Packet-capture software' },
            @{ Pattern='(?i)(nmap|zenmap|advanced ip scanner|masscan|network scanner|angry ip)'; Label='Network scanner' },
            @{ Pattern='(?i)(teamviewer|anydesk|realvnc|tightvnc|ultravnc|screenconnect|connectwise|splashtop|logmein|rustdesk|remote utilities|dwservice)'; Label='Third-party remote-access software' },
            @{ Pattern='(?i)(apache|nginx|xampp|wamp|iis express|tomcat|lighttpd)'; Label='Web server' },
            @{ Pattern='(?i)(filezilla server|serv-u|freeftpd|core ftp server|ftp server)'; Label='FTP server' },
            @{ Pattern='(?i)(mysql|mariadb|postgresql|mongodb|sql server|oracle database)'; Label='Database server' },
            @{ Pattern='(?i)(xmrig|minergate|nicehash|crypto miner|coinminer)'; Label='Cryptocurrency mining software' },
            @{ Pattern='(?i)(toolbar|search protect|browser helper)'; Label='Browser toolbar or helper' },
            @{ Pattern='(?i)(java\s*(runtime|se)?\s*[67]\b|python\s*2\.|\.net framework\s*[123]\.|visual c\+\+\s*2005)'; Label='Potentially outdated runtime' }
        )
        foreach ($rule in $categoryRules) {
            if ($text -match $rule.Pattern) { [void]$categories.Add($rule.Label) }
        }
        if ($program.Type -eq 'Desktop' -and [string]::IsNullOrWhiteSpace([string]$program.Publisher)) {
            [void]$categories.Add('Unknown or missing publisher')
        }
        foreach ($category in @($categories | Sort-Object -Unique)) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Review software category ({0}): {1}" -f $category, $program.Name) `
                -CurrentValue ("Version={0}; Publisher={1}; Location={2}" -f (ConvertTo-DisplayValue $program.Version), (ConvertTo-DisplayValue $program.Publisher), (ConvertTo-DisplayValue $program.InstallLocation)) `
                -ExpectedValue 'Installed only when explicitly authorized or required by the README and image role.' `
                -Evidence ("Name/publisher/location matched review category: {0}" -f $category) `
                -WhyThisMatters 'The category can increase attack surface or violate competition requirements, but the name alone is not proof.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the exact product, publisher, use, dependencies, and README authorization before uninstalling anything.' `
                -DisruptionRisk 'High; uninstalling required software can break services or scoring.' -RestartRequired 'Possibly' `
                -Confidence 'Low to medium; this is a name-based review heuristic.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }
    Add-ReportLine $report ''
    Add-ReportLine $report ('Total unique software records: {0}' -f $script:SoftwareInventory.Count)
}

function Add-StartupTargetRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Command,
        [string]$RunAs,
        [string]$Trigger,
        [bool]$Hidden = $false,
        [string]$ReportFile = '12-Startup-and-Scheduled-Tasks.txt'
    )

    $target = Get-ExecutablePathFromCommandLine -CommandLine $Command
    $record = [pscustomobject]@{
        Source = $Source
        Name = $Name
        Command = $Command
        Target = $target
        RunAs = $RunAs
        Trigger = $Trigger
        Hidden = $Hidden
    }
    [void]$script:StartupTargets.Add($record)
    Add-ReportLine $ReportFile (('Source={0}; Name={1}; Command={2}; Target={3}; RunAs={4}; Trigger={5}; Hidden={6}') -f `
        $Source, $Name, (ConvertTo-DisplayValue $Command), (ConvertTo-DisplayValue $target), `
        (ConvertTo-DisplayValue $RunAs), (ConvertTo-DisplayValue $Trigger), $Hidden)
}

function Invoke-StartupAndScheduledTasksAudit {
    [CmdletBinding()]
    param()

    $report = '12-Startup-and-Scheduled-Tasks.txt'
    $module = 'Startup and Scheduled Tasks'
    Write-ModuleHeader $report $module 'Startup folders, Run keys, scheduled tasks, profiles, logon configuration, services, AppInit, and WMI subscriptions.'

    Add-ReportLine $report 'STARTUP FOLDERS'
    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($folder in $startupFolders) {
        $files = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get startup-folder file metadata' -ScriptBlock {
            if (Test-Path -LiteralPath $folder) { Get-ChildItem -LiteralPath $folder -Force -File -ErrorAction Stop }
        }.GetNewClosure() -SuppressErrorFinding
        foreach ($file in @($files)) {
            Add-StartupTargetRecord -Source 'Startup folder' -Name $file.Name -Command $file.FullName -Trigger 'User logon' -ReportFile $report
        }
        if (@($files).Count -eq 0) { Add-ReportLine $report ("Folder={0}; <no files returned>" -f $folder) }
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'REGISTRY RUN AND RUNONCE ENTRIES'
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        $values = Get-RegistryAuditProperties -Module $module -Path $key
        if ($values) {
            foreach ($property in $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
                Add-StartupTargetRecord -Source $key -Name $property.Name -Command ([string]$property.Value) -Trigger 'User logon' -ReportFile $report
            }
        }
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'SCHEDULED TASKS'
    $tasks = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-ScheduledTask with current task information' -ScriptBlock {
        if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) { return }
        foreach ($task in (Get-ScheduledTask -ErrorAction Stop)) {
            $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction SilentlyContinue
            [pscustomobject]@{
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Hidden = $task.Settings.Hidden
                UserId = $task.Principal.UserId
                RunLevel = $task.Principal.RunLevel
                Actions = $task.Actions
                Triggers = $task.Triggers
                LastRunTime = if ($info) { $info.LastRunTime } else { $null }
                NextRunTime = if ($info) { $info.NextRunTime } else { $null }
                LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
            }
        }
    }
    foreach ($task in @($tasks)) {
        $taskTriggers = @(Get-ObjectPropertyValue $task 'Triggers')
        $taskActions = @(Get-ObjectPropertyValue $task 'Actions')
        $triggerNames = foreach ($trigger in $taskTriggers) {
            if ($null -eq $trigger) { continue }
            $cimClass = Get-ObjectPropertyValue $trigger 'CimClass'
            $cimName = Get-ObjectPropertyValue $cimClass 'CimClassName'
            if ($cimName) { $cimName } else { $trigger.GetType().Name }
        }
        $triggerText = @($triggerNames) -join ', '
        if ([string]::IsNullOrWhiteSpace($triggerText)) { $triggerText = '<not available>' }
        $taskPath = Get-ObjectPropertyValue $task 'TaskPath'
        $taskName = Get-ObjectPropertyValue $task 'TaskName'
        foreach ($action in $taskActions) {
            $command = ('{0} {1}' -f (Get-ObjectPropertyValue $action 'Execute'), (Get-ObjectPropertyValue $action 'Arguments')).Trim()
            Add-StartupTargetRecord -Source ("Scheduled task {0}{1}" -f $taskPath, $taskName) `
                -Name ([string]$taskName) -Command $command -RunAs (Get-ObjectPropertyValue $task 'UserId') `
                -Trigger $triggerText -Hidden ([bool](Get-ObjectPropertyValue $task 'Hidden')) -ReportFile $report
        }
        Add-ReportLine $report ('TaskState={0}; RunLevel={1}; LastRun={2}; NextRun={3}; LastResult={4}' -f `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $task 'State')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $task 'RunLevel')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $task 'LastRunTime')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $task 'NextRunTime')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $task 'LastTaskResult')))
        if ($taskName -and $triggerText -match '(?i)(EventTrigger|BootTrigger|RegistrationTrigger|SessionStateChangeTrigger)') {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Scheduled task has a trigger requiring context review: {0}" -f $taskName) `
                -CurrentValue ("TaskPath={0}; Triggers={1}" -f $taskPath, $triggerText) `
                -ExpectedValue 'Trigger type and timing are required by Windows, an authorized application, or the README.' `
                -Evidence 'Get-ScheduledTask trigger class metadata' `
                -WhyThisMatters 'Event, boot, registration, and session triggers can execute code outside an obvious daily schedule.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Review the full trigger, action, author, and task history before changing the task manually.' `
                -DisruptionRisk 'High; Windows and applications rely on these trigger types.' -RestartRequired 'Possibly' `
                -Confidence 'Low for security impact; this is a review heuristic.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'POWERSHELL PROFILES'
    $profilePaths = @(
        $PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost,
        $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost
    ) | Sort-Object -Unique
    foreach ($path in $profilePaths) {
        $profileInfo = Invoke-ReadOnlyCommand -Module $module -CommandText 'Inspect PowerShell profile metadata and content' -ScriptBlock {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                [pscustomobject]@{
                    File = Get-Item -LiteralPath $path -ErrorAction Stop
                    Content = Get-Content -LiteralPath $path -ErrorAction SilentlyContinue
                }
            }
        }.GetNewClosure() -SuppressErrorFinding
        if ($profileInfo) {
            Add-ReportLine $report ('Path={0}; Length={1}; Modified={2}' -f $path, $profileInfo.File.Length, $profileInfo.File.LastWriteTime)
            Add-StartupTargetRecord -Source 'PowerShell profile' -Name ([IO.Path]::GetFileName($path)) -Command $path -Trigger 'PowerShell startup' -ReportFile $report
            if ((@($profileInfo.Content) -join ' ') -match '(?i)(-enc(odedcommand)?\b|frombase64string|downloadstring|invoke-webrequest|invoke-expression)') {
                Add-AuditFinding -Severity HIGH -Category $module -Finding ("PowerShell profile contains a suspicious execution pattern: {0}" -f $path) `
                    -CurrentValue 'Encoded, download, or dynamic-execution keyword detected; content is not reproduced.' `
                    -ExpectedValue 'Profiles contain only understood, authorized commands.' -Evidence 'Read-only keyword review of the PowerShell profile.' `
                    -WhyThisMatters 'Profiles execute automatically when PowerShell starts.' -ReadmeRequired 'Yes' `
                    -PossibleManualAction 'Open the profile manually and review every line before deciding whether to edit it.' `
                    -DisruptionRisk 'High; profiles may be required for administration.' -RestartRequired 'No' `
                    -Confidence 'Medium; keywords can have legitimate uses.' -Status '[WARNING]' -ReportFile $report
            }
        }
        else { Add-ReportLine $report ("Path={0}; Not present" -f $path) }
    }

    $winlogon = Get-RegistryAuditProperties -Module $module -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $appInit = Get-RegistryAuditProperties -Module $module -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    Add-ReportLine $report ''
    Add-ReportLine $report 'WINLOGON AND APPINIT'
    foreach ($name in @('Shell', 'Userinit', 'VmApplet', 'Taskman')) {
        $value = Get-ObjectPropertyValue $winlogon $name
        Add-ReportLine $report ('Winlogon {0}: {1}' -f $name, (ConvertTo-DisplayValue $value))
        if ($value) { Add-StartupTargetRecord -Source 'Winlogon' -Name $name -Command ([string]$value) -Trigger 'User logon' -ReportFile $report }
    }
    foreach ($name in @('LoadAppInit_DLLs', 'AppInit_DLLs', 'RequireSignedAppInit_DLLs')) {
        Add-ReportLine $report ('AppInit {0}: {1}' -f $name, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $appInit $name)))
    }
    $loadAppInit = Get-ObjectPropertyValue $appInit 'LoadAppInit_DLLs'
    $appInitDlls = Get-ObjectPropertyValue $appInit 'AppInit_DLLs'
    if ($loadAppInit -eq 1 -and -not [string]::IsNullOrWhiteSpace([string]$appInitDlls)) {
        Add-AuditFinding -Severity HIGH -Category $module -Finding 'AppInit DLL loading is enabled with configured DLLs' `
            -CurrentValue $appInitDlls -ExpectedValue 'Disabled/empty unless explicitly required and every DLL is trusted.' `
            -Evidence 'Win32 AppInit registry values' -WhyThisMatters 'AppInit can load DLLs into many user-mode processes.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify each DLL signature, path, and application dependency before manually changing the setting.' `
            -DisruptionRisk 'High' -RestartRequired 'Yes' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
    }

    $logonScripts = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get local/network login profile ScriptPath values' -ScriptBlock {
        Get-CimInstance -ClassName Win32_NetworkLoginProfile -ErrorAction Stop |
            Where-Object { $_.PSObject.Properties['ScriptPath'] -and -not [string]::IsNullOrWhiteSpace([string]$_.PSObject.Properties['ScriptPath'].Value) } |
            Select-Object Name, ScriptPath
    } -SuppressErrorFinding
    Add-ReportLine $report ''
    Add-ReportLine $report 'LOCAL USER LOGON SCRIPTS'
    foreach ($entry in @($logonScripts)) {
        $entryName = Get-ObjectPropertyValue $entry 'Name'
        $entryScriptPath = Get-ObjectPropertyValue $entry 'ScriptPath'
        if ($entryName -and $entryScriptPath) {
            Add-StartupTargetRecord -Source 'Login profile ScriptPath' -Name $entryName -Command $entryScriptPath -RunAs $entryName -Trigger 'User logon' -ReportFile $report
        }
    }
    if (@($logonScripts).Count -eq 0) { Add-ReportLine $report '<none returned>' }

    $wmiSubscriptions = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get WMI permanent event filters, consumers, and bindings from root/subscription' -ScriptBlock {
        Get-CimInstance -Namespace 'root/subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace 'root/subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace 'root/subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace 'root/subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue
    } -SuppressErrorFinding
    Add-ReportLine $report ''
    Add-ReportLine $report 'WMI PERMANENT EVENT SUBSCRIPTIONS'
    foreach ($item in @($wmiSubscriptions)) {
        $itemCimClass = Get-ObjectPropertyValue $item 'CimClass'
        $className = Get-ObjectPropertyValue $itemCimClass 'CimClassName'
        if (-not $className) { continue }
        Add-ReportLine $report ('Class={0}; Name={1}; CommandLineTemplate={2}; ScriptFileName={3}; Filter={4}; Consumer={5}' -f `
            $className, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $item 'Name')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $item 'CommandLineTemplate')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $item 'ScriptFileName')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $item 'Filter')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $item 'Consumer')))
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Review WMI permanent subscription object: {0}" -f $className) `
            -CurrentValue (ConvertTo-DisplayValue (Get-ObjectPropertyValue $item 'Name')) `
            -ExpectedValue 'Only subscriptions required by authorized management software.' -Evidence 'root/subscription CIM inventory' `
            -WhyThisMatters 'Permanent WMI subscriptions can execute persistently without a visible scheduled task.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Identify the owning product before removing any WMI object manually.' `
            -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'Medium; legitimate management software uses WMI subscriptions.' `
            -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'SERVICE-BASED PERSISTENCE'
    Add-ReportLine $report ('See 06-Services.txt; service inventory count={0}.' -f $script:ServiceInventory.Count)

    foreach ($entry in @($script:StartupTargets)) {
        $command = [string]$entry.Command
        $target = [string]$entry.Target
        $inUserLocation = $command -match '(?i)\\(AppData|Downloads|Desktop|Temp)\\'
        $encoded = $command -match '(?i)(powershell(\.exe)?.*(-enc(odedcommand)?\b|frombase64string)|invoke-expression|downloadstring)'
        $targetExists = if ($target -and $target -match '(?i)\.(exe|com|bat|cmd|ps1|vbs|js|dll)$') {
            Test-AuditPathExists -Module $module -Path $target -PathType Leaf
        } else { $null }
        $missing = $target -and $target -match '(?i)\.(exe|com|bat|cmd|ps1|vbs|js|dll)$' -and $targetExists -eq $false
        if ($inUserLocation -or $encoded -or $missing) {
            $reasons = @()
            if ($inUserLocation) { $reasons += 'user-writable location' }
            if ($encoded) { $reasons += 'encoded/dynamic PowerShell pattern' }
            if ($missing) { $reasons += 'missing target' }
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Persistence entry needs review: {0}" -f $entry.Name) `
                -CurrentValue $command -ExpectedValue 'Existing, authorized, understandable target in a protected location.' `
                -Evidence ("Source={0}; Reasons={1}" -f $entry.Source, ($reasons -join ', ')) `
                -WhyThisMatters 'Startup entries execute automatically and can provide persistence.' -ReadmeRequired 'Yes' `
                -PossibleManualAction 'Inspect the target, publisher, trigger, owner, and application purpose before changing the entry manually.' `
                -DisruptionRisk 'High; required logon/application behavior may break.' -RestartRequired 'Possibly' `
                -Confidence 'Medium; heuristics can flag legitimate updaters and scripts.' -Status '[WARNING]' -ReportFile $report
        }
        elseif ($entry.Hidden -or $entry.RunAs -match '(?i)(SYSTEM|S-1-5-18)') {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Privileged or hidden scheduled/startup entry: {0}" -f $entry.Name) `
                -CurrentValue ("RunAs={0}; Hidden={1}; Command={2}" -f (ConvertTo-DisplayValue $entry.RunAs), $entry.Hidden, $command) `
                -ExpectedValue 'Documented, authorized operating-system or application task.' -Evidence $entry.Source `
                -WhyThisMatters 'Hidden or SYSTEM execution is powerful but common for legitimate Windows tasks.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify publisher, task path, trigger, and owning component; do not disable based on privilege alone.' `
                -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'Low for security judgment.' `
                -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }
}

function Invoke-SuspiciousFilesAudit {
    [CmdletBinding()]
    param()

    $report = '13-Suspicious-Files.txt'
    $module = 'Suspicious Files'
    Write-ModuleHeader $report $module 'Metadata-only search of conservative local paths. Personal-document contents are never opened.'

    $defaultExtensions = @(
        '.mp3', '.wav', '.flac', '.aac', '.m4a', '.mp4', '.avi', '.mkv', '.mov', '.wmv',
        '.torrent', '.pcap', '.pcapng', '.cap', '.dmp', '.iso', '.rom', '.nes', '.gba',
        '.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse',
        '.wsf', '.hta', '.jar', '.py', '.pl', '.rb', '.sh'
    )
    $customExtensions = @()
    if ($ScanExtension) {
        foreach ($item in $ScanExtension) {
            if ([string]::IsNullOrWhiteSpace($item)) { continue }
            if ($item.StartsWith('.')) { $customExtensions += $item.ToLowerInvariant() } else { $customExtensions += ('.' + $item.ToLowerInvariant()) }
        }
    }
    $extensions = @($defaultExtensions + $customExtensions | Sort-Object -Unique)

    $paths = New-Object System.Collections.ArrayList
    if ($ScanPath -and $ScanPath.Count -gt 0) {
        foreach ($path in $ScanPath) { [void]$paths.Add([Environment]::ExpandEnvironmentVariables($path)) }
    }
    else {
        $profileRoots = Invoke-ReadOnlyCommand -Module $module -CommandText 'List local user profile directories for conservative metadata scan roots' -ScriptBlock {
            if (Test-Path -LiteralPath ($env:SystemDrive + '\Users')) {
                Get-ChildItem -LiteralPath ($env:SystemDrive + '\Users') -Directory -Force -ErrorAction Stop
            }
        } -SuppressErrorFinding
        foreach ($profileRoot in @($profileRoots)) {
            foreach ($child in @('Desktop', 'Documents', 'Downloads', 'Music', 'Videos', 'Pictures', 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')) {
                [void]$paths.Add((Join-Path $profileRoot.FullName $child))
            }
        }
        foreach ($path in @(
            $env:TEMP,
            (Join-Path $env:WINDIR 'Temp'),
            (Join-Path $env:SystemDrive 'inetpub\wwwroot'),
            (Join-Path $env:SystemDrive 'inetpub\ftproot'),
            (Join-Path $env:SystemDrive 'ftproot')
        )) { if ($path) { [void]$paths.Add($path) } }
    }

    $excludedRoots = @()
    if ($ExcludePath) {
        foreach ($item in $ExcludePath) {
            if ([string]::IsNullOrWhiteSpace($item)) { continue }
            $excludedRoots += [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($item)).TrimEnd('\')
        }
    }
    Add-ReportLine $report ('Include file hashes: {0}' -f [bool]$IncludeFileHashes)
    Add-ReportLine $report ('Extensions reviewed: {0}' -f ($extensions -join ', '))
    Add-ReportLine $report 'Scan roots (nonexistent roots are skipped):'
    foreach ($path in @($paths | Sort-Object -Unique)) { Add-ReportLine $report ('  ' + $path) }
    Add-ReportLine $report ''
    Add-ReportLine $report 'FLAGGED FILE METADATA'

    $flaggedCount = 0
    foreach ($root in @($paths | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace([string]$root)) { continue }
        if (Test-IsProhibitedScoringPath $root) {
            Add-ReportLine $report 'A configured root was skipped by the scoring-system exclusion guard.'
            continue
        }
        $fullRoot = $null
        try { $fullRoot = [IO.Path]::GetFullPath($root).TrimEnd('\') } catch { continue }
        if (Test-IsPathInsideAuditOutput $fullRoot) { continue }
        $skipRoot = $false
        foreach ($excluded in $excludedRoots) {
            if ($fullRoot -eq $excluded -or $fullRoot.StartsWith($excluded + '\', [StringComparison]::OrdinalIgnoreCase)) { $skipRoot = $true; break }
        }
        if ($skipRoot) { continue }

        $outputGuard = $script:AuditOutputFolder
        $exclusionGuard = @($excludedRoots)
        $files = Invoke-ReadOnlyCommand -Module $module -CommandText 'Enumerate file metadata under one approved local scan root with protected-path pruning' -ScriptBlock {
            if (-not (Test-Path -LiteralPath $fullRoot -PathType Container)) { return }
            $queue = @($fullRoot)
            $index = 0
            $seenFiles = 0
            while ($index -lt $queue.Count -and $seenFiles -lt 100000) {
                $current = $queue[$index]
                $index++
                if ($current -match '(?i)(scorebot|scoring[ _-]?engine|cyberpatriot[ _-]?scor|ccsclient)') { continue }
                if ($current -eq $outputGuard -or $current.StartsWith($outputGuard + '\', [StringComparison]::OrdinalIgnoreCase)) { continue }
                $excluded = $false
                foreach ($excludedPath in $exclusionGuard) {
                    if ($current -eq $excludedPath -or $current.StartsWith($excludedPath + '\', [StringComparison]::OrdinalIgnoreCase)) { $excluded = $true; break }
                }
                if ($excluded) { continue }
                $children = Get-ChildItem -LiteralPath $current -Force -ErrorAction SilentlyContinue
                foreach ($child in $children) {
                    if ($child.PSIsContainer) {
                        if ($child.FullName -notmatch '(?i)(scorebot|scoring[ _-]?engine|cyberpatriot[ _-]?scor|ccsclient)') { $queue += $child.FullName }
                    }
                    else {
                        $seenFiles++
                        Write-Output $child
                        if ($seenFiles -ge 100000) { break }
                    }
                }
            }
        }.GetNewClosure() -SuppressErrorFinding

        foreach ($file in @($files)) {
            $fileFullName = Get-ObjectPropertyValue $file 'FullName'
            if ([string]::IsNullOrWhiteSpace([string]$fileFullName)) { continue }
            if (Test-IsProhibitedScoringPath $fileFullName) { continue }
            $extension = [string]$file.Extension
            $nameText = [string]$file.Name
            $reasons = New-Object System.Collections.ArrayList
            if ($extensions -contains $extension.ToLowerInvariant()) {
                if ($extension -match '(?i)^\.(mp3|wav|flac|aac|m4a|mp4|avi|mkv|mov|wmv)$') { [void]$reasons.Add('media file') }
                elseif ($extension -eq '.torrent') { [void]$reasons.Add('torrent file') }
                elseif ($extension -match '(?i)^\.(pcap|pcapng|cap)$') { [void]$reasons.Add('packet-capture file') }
                elseif ($extension -match '(?i)^\.(exe|com|scr|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|jar|py|pl|rb|sh)$' -and `
                    $fileFullName -match '(?i)\\(Users|Temp|Downloads|Desktop|AppData)\\') { [void]$reasons.Add('executable or script in a user-writable location') }
                elseif ($extension -match '(?i)^\.(iso|rom|nes|gba)$') { [void]$reasons.Add('disk/game image') }
            }
            $nameRules = @(
                @{ Pattern='(?i)(passwords?|passwd|wordlist|rockyou|credentials?|hashes)'; Reason='password or credential-list filename' },
                @{ Pattern='(?i)(mimikatz|hashcat|john(\.exe)?|ophcrack|l0pht|chntpw)'; Reason='password-recovery/cracking tool name' },
                @{ Pattern='(?i)(nmap|masscan|zenmap|angry.?ip|netscan)'; Reason='network-scanner tool name' },
                @{ Pattern='(?i)(teamviewer|anydesk|tightvnc|ultravnc|realvnc|rustdesk|xmrig|coinminer|nicehash)'; Reason='remote-access or miner tool name' },
                @{ Pattern='(?i)(keylog|reverse.?shell|payload|backdoor|rat\.exe|hacktool)'; Reason='suspicious utility/script filename' }
            )
            foreach ($rule in $nameRules) { if ($nameText -match $rule.Pattern) { [void]$reasons.Add($rule.Reason) } }
            if ($reasons.Count -eq 0) { continue }

            $filePath = $fileFullName
            $metadata = Invoke-ReadOnlyCommand -Module $module -CommandText 'Read ACL owner, signature, and optional hash for one already-flagged file' -ScriptBlock {
                $acl = Get-Acl -LiteralPath $filePath -ErrorAction SilentlyContinue
                $signature = if ($filePath -match '(?i)\.(exe|dll|sys|ps1|psm1|cat|msi)$') {
                    Get-AuthenticodeSignature -LiteralPath $filePath -ErrorAction SilentlyContinue
                } else { $null }
                $hash = if ($IncludeFileHashes) { Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue } else { $null }
                [pscustomobject]@{
                    Owner = if ($acl) { $acl.Owner } else { $null }
                    Signature = if ($signature) { $signature.Status } else { $null }
                    Signer = if ($signature -and $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
                    SHA256 = if ($hash) { $hash.Hash } else { $null }
                }
            }.GetNewClosure() -SuppressErrorFinding
            $flaggedCount++
            Add-ReportLine $report (('Path={0}; Name={1}; Extension={2}; Size={3}; Owner={4}; Created={5}; Modified={6}; ' +
                'Signature={7}; Signer={8}; SHA256={9}; Reason={10}') -f $fileFullName, $file.Name, $file.Extension, `
                $file.Length, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $metadata 'Owner')), $file.CreationTime, $file.LastWriteTime, `
                (ConvertTo-DisplayValue (Get-ObjectPropertyValue $metadata 'Signature')), `
                (ConvertTo-DisplayValue (Get-ObjectPropertyValue $metadata 'Signer')), `
                (ConvertTo-DisplayValue (Get-ObjectPropertyValue $metadata 'SHA256')), (@($reasons | Sort-Object -Unique) -join ', '))
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Review flagged file: {0}" -f $file.Name) `
                -CurrentValue $fileFullName -ExpectedValue 'Present only when authorized or required by the README and image role.' `
                -Evidence ("Reasons={0}; Size={1}; Modified={2}; Signature={3}" -f (@($reasons | Sort-Object -Unique) -join ', '), $file.Length, $file.LastWriteTime, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $metadata 'Signature'))) `
                -WhyThisMatters 'The metadata pattern can indicate unwanted content or user-writable execution, but it does not prove maliciousness.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify ownership, purpose, publisher, and README authorization; do not open personal documents or delete automatically.' `
                -DisruptionRisk 'High if the file is required.' -RestartRequired 'Possibly, depending on later manual action.' `
                -Confidence 'Low to medium; metadata and filename heuristic only.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }
    if ($flaggedCount -eq 0) { Add-ReportLine $report '<no files matched the configured metadata patterns>' }
    Add-ReportLine $report ('Total flagged files: {0}' -f $flaggedCount)
}

function Invoke-PermissionsAudit {
    [CmdletBinding()]
    param()

    $report = '14-Permissions.txt'
    $module = 'Permissions'
    Write-ModuleHeader $report $module 'Broad write/read grants on sensitive, service, startup, web, FTP, and task target paths.'

    $paths = New-Object System.Collections.ArrayList
    foreach ($path in @(
        $env:WINDIR,
        (Join-Path $env:WINDIR 'System32'),
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        [Environment]::GetFolderPath('CommonStartup'),
        (Join-Path $env:SystemDrive 'inetpub\wwwroot'),
        (Join-Path $env:SystemDrive 'inetpub\ftproot'),
        (Join-Path $env:SystemDrive 'ftproot')
    )) { if ($path) { [void]$paths.Add($path) } }
    foreach ($service in @($script:ServiceInventory)) {
        $serviceExecutable = Get-ObjectPropertyValue $service 'ExecutablePath'
        if (-not $serviceExecutable) { $serviceExecutable = Get-ExecutablePathFromCommandLine (Get-ObjectPropertyValue $service 'PathName') }
        if ($serviceExecutable) { [void]$paths.Add([IO.Path]::GetDirectoryName([string]$serviceExecutable)) }
    }
    foreach ($entry in @($script:StartupTargets)) {
        if ($entry.Target) { [void]$paths.Add([IO.Path]::GetDirectoryName([string]$entry.Target)) }
    }

    Add-ReportLine $report 'DIRECTORY ACL REVIEW'
    foreach ($path in @($paths | Where-Object { $_ } | Sort-Object -Unique)) {
        if (Test-IsProhibitedScoringPath $path) { continue }
        $acl = Get-AuditPathAcl -Module $module -Path $path -SuppressErrorFinding
        if (-not $acl) { continue }
        Add-ReportLine $report ('Path={0}; Owner={1}; Protected={2}' -f $path, $acl.Owner, $acl.AreAccessRulesProtected)
        foreach ($rule in $acl.Access) {
            if ($rule.IdentityReference.Value -in @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users') -or `
                (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)) {
                Add-ReportLine $report ('  Identity={0}; Type={1}; Rights={2}; Inherited={3}' -f `
                    $rule.IdentityReference.Value, $rule.AccessControlType, $rule.FileSystemRights, $rule.IsInherited)
            }
        }
        if (Test-WeakWriteAcl -Acl $acl) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Sensitive or executable directory appears broadly writable: {0}" -f $path) `
                -CurrentValue 'Write-like allow right for Everyone, Users, or Authenticated Users.' `
                -ExpectedValue 'Only required administrators, system, installers, or application identities can modify protected executable/configuration directories.' `
                -Evidence 'Get-Acl explicit/inherited access rules; see report lines.' `
                -WhyThisMatters 'Broad write access can permit executable replacement, persistence, or configuration tampering.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Calculate effective access and application requirements before manually changing inherited or explicit ACLs.' `
                -DisruptionRisk 'High; incorrect ACLs can break Windows, updates, services, or applications.' -RestartRequired 'Possibly' `
                -Confidence 'Medium; group nesting, deny rules, ownership, and privileges affect effective access.' -Status '[WARNING]' -ReportFile $report
        }
    }

    $sensitiveFiles = @(
        (Join-Path $env:WINDIR 'System32\config\SAM'),
        (Join-Path $env:WINDIR 'System32\config\SYSTEM'),
        (Join-Path $env:WINDIR 'System32\config\SECURITY'),
        (Join-Path $env:WINDIR 'Panther\Unattend.xml'),
        (Join-Path $env:WINDIR 'Panther\Unattend\Unattend.xml'),
        (Join-Path $env:WINDIR 'System32\Sysprep\Unattend.xml')
    )
    Add-ReportLine $report ''
    Add-ReportLine $report 'SENSITIVE FILE ACL REVIEW (CONTENTS NOT OPENED)'
    foreach ($path in $sensitiveFiles) {
        $acl = Get-AuditPathAcl -Module $module -Path $path -SuppressErrorFinding
        if (-not $acl) { continue }
        Add-ReportLine $report ('Path={0}; Owner={1}' -f $path, $acl.Owner)
        foreach ($rule in $acl.Access) {
            Add-ReportLine $report ('  Identity={0}; Type={1}; Rights={2}; Inherited={3}' -f `
                $rule.IdentityReference.Value, $rule.AccessControlType, $rule.FileSystemRights, $rule.IsInherited)
        }
        if (Test-WeakReadAcl -Acl $acl) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Sensitive file may be readable by ordinary users: {0}" -f $path) `
                -CurrentValue 'Read-like allow right for Everyone, Users, or Authenticated Users.' `
                -ExpectedValue 'Sensitive credential/configuration files readable only by specifically required identities.' `
                -Evidence 'Get-Acl only; file contents were not opened.' `
                -WhyThisMatters 'Readable credential hives or unattended configuration can expose secrets.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify effective access, inherited ACLs, and file purpose before manually changing permissions.' `
                -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'Medium' -Status '[WARNING]' -ReportFile $report
        }
    }
}

function Invoke-NetworkSharesAudit {
    [CmdletBinding()]
    param()

    $report = '15-Network-Shares.txt'
    $module = 'Network Shares'
    Write-ModuleHeader $report $module 'Local SMB shares, share permissions, target existence, and NTFS permissions.'

    $shares = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-SmbShare with Get-SmbShareAccess' -ScriptBlock {
        if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { return }
        foreach ($share in (Get-SmbShare -ErrorAction Stop)) {
            [pscustomobject]@{
                Name = $share.Name
                Path = $share.Path
                Description = $share.Description
                Special = $share.Special
                Temporary = $share.Temporary
                ScopeName = $share.ScopeName
                Permissions = @(Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue)
            }
        }
    }
    if (@($shares).Count -eq 0) {
        $shares = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_Share fallback' -ScriptBlock {
            Get-CimInstance -ClassName Win32_Share -ErrorAction Stop
        } -SuppressErrorFinding
    }

    Add-ReportLine $report 'LOCAL SMB SHARES'
    foreach ($share in @($shares)) {
        $isAdministrative = ([bool](Get-ObjectPropertyValue $share 'Special')) -or $share.Name -match '^(ADMIN\$|IPC\$|[A-Z]\$)$'
        $path = [string]$share.Path
        $exists = if ([string]::IsNullOrWhiteSpace($path)) { $null } else { Test-AuditPathExists -Module $module -Path $path }
        Add-ReportLine $report ('Name={0}; Path={1}; Description={2}; Special/Admin={3}; Temporary={4}; TargetExists={5}' -f `
            $share.Name, (ConvertTo-DisplayValue $path), (ConvertTo-DisplayValue $share.Description), $isAdministrative, `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $share 'Temporary')), (ConvertTo-DisplayValue $exists))
        $everyoneAccess = $false
        foreach ($permission in @(Get-ObjectPropertyValue $share 'Permissions')) {
            Add-ReportLine $report ('  SharePermission: Account={0}; Type={1}; Right={2}' -f `
                $permission.AccountName, $permission.AccessControlType, $permission.AccessRight)
            if ($permission.AccountName -match '(?i)(^|\\)Everyone$' -and $permission.AccessControlType -eq 'Allow') { $everyoneAccess = $true }
        }
        $acl = if ($exists) { Get-AuditPathAcl -Module $module -Path $path -SuppressErrorFinding } else { $null }
        if ($acl) {
            Add-ReportLine $report ('  NTFS Owner={0}' -f $acl.Owner)
            foreach ($rule in $acl.Access) {
                if ($rule.IdentityReference.Value -in @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users')) {
                    Add-ReportLine $report ('  NTFS Permission: Identity={0}; Type={1}; Rights={2}; Inherited={3}' -f `
                        $rule.IdentityReference.Value, $rule.AccessControlType, $rule.FileSystemRights, $rule.IsInherited)
                }
            }
        }

        if ($isAdministrative) {
            Add-AuditFinding -Severity INFO -Category $module -Finding ("Standard administrative share present: {0}" -f $share.Name) `
                -CurrentValue (ConvertTo-DisplayValue $path) -ExpectedValue 'Standard administrative shares are not automatically vulnerabilities.' `
                -Evidence 'Share name/special flag' -WhyThisMatters 'These shares support normal Windows administration and require authenticated administrative access.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify standard behavior; do not remove solely because the share exists.' `
                -DisruptionRisk 'High if removed.' -RestartRequired 'Possibly' -Confidence 'High' -Status '[INFO]' -ReportFile $report
        }
        else {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Verify non-administrative share: {0}" -f $share.Name) `
                -CurrentValue ("Path={0}; EveryoneAllow={1}; TargetExists={2}" -f (ConvertTo-DisplayValue $path), $everyoneAccess, (ConvertTo-DisplayValue $exists)) `
                -ExpectedValue 'Only README-authorized shares with least-privilege share and NTFS permissions.' `
                -Evidence 'Get-SmbShare, Get-SmbShareAccess, and Get-Acl' `
                -WhyThisMatters 'Shares can expose local files to remote users.' -ReadmeRequired 'Yes' `
                -PossibleManualAction 'Verify the share purpose, authorized users, and both permission layers before changing it manually.' `
                -DisruptionRisk 'High' -RestartRequired 'No' -Confidence 'High for configuration; authorization unknown.' `
                -Status '[MANUAL REVIEW]' -ReportFile $report
        }
        if ($everyoneAccess) {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Share grants access to Everyone: {0}" -f $share.Name) `
                -CurrentValue 'Share-level Allow permission for Everyone' -ExpectedValue 'Specific authorized users/groups with least privilege.' `
                -Evidence 'Get-SmbShareAccess' -WhyThisMatters 'Broad share permissions can expose data, subject to NTFS permissions.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Review effective access and required clients before manually narrowing share permissions.' `
                -DisruptionRisk 'High' -RestartRequired 'No' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
        }
        if ($exists -eq $false) {
            Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Share target is missing: {0}" -f $share.Name) `
                -CurrentValue $path -ExpectedValue 'Existing authorized target or no stale share.' -Evidence 'Test-Path returned False.' `
                -WhyThisMatters 'Stale shares are confusing and can expose a path if it is recreated later.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify expected storage before manually removing the stale share.' `
                -DisruptionRisk 'Medium' -RestartRequired 'No' -Confidence 'High' -Status '[WARNING]' -ReportFile $report
        }
    }
}

function Invoke-RegistrySecuritySettingsAudit {
    [CmdletBinding()]
    param()

    $report = '16-Registry-Security-Settings.txt'
    $module = 'Registry Security Settings'
    Write-ModuleHeader $report $module 'Targeted security-related registry values only. No unrelated registry export and no writes.'

    $settings = @(
        @{ Area='AutoRun/AutoPlay'; Label='Disable AutoRun'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'; Recommended='255 or organization/README baseline' },
        @{ Area='AutoRun/AutoPlay'; Label='Disable AutoPlay'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutoplayfornonVolume'; Recommended='1' },
        @{ Area='UAC'; Label='UAC enabled'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Recommended='1' },
        @{ Area='UAC'; Label='Secure desktop'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop'; Recommended='1' },
        @{ Area='Remote Desktop'; Label='Deny RDP connections'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; Name='fDenyTSConnections'; Recommended='1 unless required' },
        @{ Area='Remote Desktop'; Label='RDP NLA'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name='UserAuthentication'; Recommended='1 when RDP is required' },
        @{ Area='Remote Assistance'; Label='Remote Assistance'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Name='fAllowToGetHelp'; Recommended='0 unless required' },
        @{ Area='Anonymous access'; Label='Restrict anonymous'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Recommended='1 or stronger where compatible' },
        @{ Area='Anonymous access'; Label='Restrict anonymous SAM'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Recommended='1' },
        @{ Area='LAN Manager'; Label='Authentication level'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Recommended='5 where compatible' },
        @{ Area='LAN Manager'; Label='Do not store LM hash'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash'; Recommended='1' },
        @{ Area='SMB'; Label='SMB1 server driver'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1'; Recommended='0/absent where supported default disables it' },
        @{ Area='SMB'; Label='Require server signing'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='RequireSecuritySignature'; Recommended='1 where compatible' },
        @{ Area='SMB'; Label='Require client signing'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Recommended='1 where compatible' },
        @{ Area='LLMNR'; Label='Enable multicast DNS client resolution'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMulticast'; Recommended='0 where compatible' },
        @{ Area='Windows Script Host'; Label='Machine WSH enabled'; Path='HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; Name='Enabled'; Recommended='Disabled only when README/application requirements allow' },
        @{ Area='Windows Script Host'; Label='User WSH enabled'; Path='HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings'; Name='Enabled'; Recommended='Disabled only when README/application requirements allow' },
        @{ Area='PowerShell logging'; Label='Module logging'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name='EnableModuleLogging'; Recommended='1' },
        @{ Area='PowerShell logging'; Label='Script block logging'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Recommended='1' },
        @{ Area='Process auditing'; Label='Include command line'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Recommended='1 with privacy/README review' },
        @{ Area='Credential storage'; Label='WDigest cached cleartext credential behavior'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name='UseLogonCredential'; Recommended='0/absent on supported Windows' },
        @{ Area='Credential storage'; Label='Cached interactive logons'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='CachedLogonsCount'; Recommended='Limited value appropriate to role' },
        @{ Area='Windows Installer'; Label='Always install elevated machine'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Recommended='0/absent' },
        @{ Area='Windows Installer'; Label='Always install elevated user'; Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Recommended='0/absent' },
        @{ Area='Screen lock'; Label='Screen saver active'; Path='HKCU:\Control Panel\Desktop'; Name='ScreenSaveActive'; Recommended='1 where a screen lock is required' },
        @{ Area='Screen lock'; Label='Screen saver secure'; Path='HKCU:\Control Panel\Desktop'; Name='ScreenSaverIsSecure'; Recommended='1' },
        @{ Area='Screen lock'; Label='Screen saver timeout'; Path='HKCU:\Control Panel\Desktop'; Name='ScreenSaveTimeOut'; Recommended='900 seconds or less where required' },
        @{ Area='Defender'; Label='Disable antispyware policy'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name='DisableAntiSpyware'; Recommended='0/absent' },
        @{ Area='Defender'; Label='Disable real-time monitoring policy'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableRealtimeMonitoring'; Recommended='0/absent' },
        @{ Area='Windows Update'; Label='Disable automatic updates'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='NoAutoUpdate'; Recommended='0/absent or authorized central management' },
        @{ Area='Proxy'; Label='Per-user proxy enabled'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'; Name='ProxyEnable'; Recommended='0 unless an authorized proxy is required' },
        @{ Area='Proxy'; Label='Per-user proxy server'; Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'; Name='ProxyServer'; Recommended='Authorized proxy only' },
        @{ Area='Credential storage'; Label='Automatic administrator logon'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='AutoAdminLogon'; Recommended='0/absent' },
        @{ Area='Credential storage'; Label='Default password value'; Path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='DefaultPassword'; Recommended='Absent' }
    )

    $collected = @{}
    Add-ReportLine $report 'TARGETED REGISTRY VALUES'
    foreach ($setting in $settings) {
        $value = Get-RegistryAuditValue -Module $module -Path $setting.Path -Name $setting.Name
        $key = '{0}|{1}' -f $setting.Path, $setting.Name
        $collected[$key] = $value
        $display = if ($setting.Name -eq 'DefaultPassword') {
            if ($null -eq $value) { '<absent>' } else { '<present; value deliberately not displayed>' }
        } else { ConvertTo-DisplayValue $value }
        Add-ReportLine $report ('Area={0}; Setting={1}; Current={2}; Recommended={3}; Registry={4}\{5}' -f `
            $setting.Area, $setting.Label, $display, $setting.Recommended, $setting.Path, $setting.Name)
    }

    $autoAdmin = $collected['HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|AutoAdminLogon']
    $defaultPassword = $collected['HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|DefaultPassword']
    if ([string]$autoAdmin -eq '1' -or $null -ne $defaultPassword) {
        Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'Automatic logon or stored default password is configured' `
            -CurrentValue ("AutoAdminLogon={0}; DefaultPasswordPresent={1}" -f (ConvertTo-DisplayValue $autoAdmin), ($null -ne $defaultPassword)) `
            -ExpectedValue 'Automatic logon disabled and no DefaultPassword value.' `
            -Evidence 'Winlogon registry values; password value was deliberately not displayed.' `
            -WhyThisMatters 'Automatic logon can store reusable credentials and bypass normal interactive authentication.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify required kiosk/service behavior and remove automatic logon manually only after securing access.' `
            -DisruptionRisk 'High; required unattended logon may stop.' -RestartRequired 'Yes' -Confidence 'High' `
            -Status '[CRITICAL]' -ReportFile $report
    }
    $wdigest = $collected['HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest|UseLogonCredential']
    if ($null -ne $wdigest -and [int]$wdigest -eq 1) {
        Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'WDigest credential caching is explicitly enabled' `
            -CurrentValue 'UseLogonCredential=1' -ExpectedValue '0 or absent on supported Windows.' `
            -Evidence 'WDigest security provider registry value' -WhyThisMatters 'The setting can keep reusable logon credentials in memory.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Check application/OS compatibility before disabling the setting manually.' `
            -DisruptionRisk 'Medium' -RestartRequired 'Yes' -Confidence 'High' -Status '[CRITICAL]' -ReportFile $report
    }
    $noDriveAutoRun = $collected['HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoDriveTypeAutoRun']
    if ($null -eq $noDriveAutoRun -or [int]$noDriveAutoRun -ne 255) {
        Add-AuditFinding -Severity MEDIUM -Category $module -Finding 'AutoRun is not disabled for all drive types by the inspected machine policy' `
            -CurrentValue (ConvertTo-DisplayValue $noDriveAutoRun) -ExpectedValue 'Common hardened value 255, subject to README requirements.' `
            -Evidence 'Explorer policy NoDriveTypeAutoRun' -WhyThisMatters 'Automatic media actions can launch unwanted content.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Check effective policy and required removable-media behavior before changing AutoRun manually.' `
            -DisruptionRisk 'Low to medium.' -RestartRequired 'Possibly' -Confidence 'Medium; user policy and OS defaults may also apply.' `
            -Status '[WARNING]' -ReportFile $report
    }
    $disableDefender = $collected['HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender|DisableAntiSpyware']
    $disableRealtime = $collected['HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection|DisableRealtimeMonitoring']
    if (($null -ne $disableDefender -and [int]$disableDefender -eq 1) -or ($null -ne $disableRealtime -and [int]$disableRealtime -eq 1)) {
        Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'Defender is disabled by an inspected policy value' `
            -CurrentValue ("DisableAntiSpyware={0}; DisableRealtimeMonitoring={1}" -f (ConvertTo-DisplayValue $disableDefender), (ConvertTo-DisplayValue $disableRealtime)) `
            -ExpectedValue 'No disabling policy unless an authorized third-party product requires it.' `
            -Evidence 'Windows Defender policy registry values' -WhyThisMatters 'A disabling policy can prevent endpoint protection.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify third-party antivirus and policy source before removing the policy manually.' `
            -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'High' -Status '[CRITICAL]' -ReportFile $report
    }

    Add-ReportLine $report ''
    Add-ReportLine $report 'SCHANNEL PROTOCOL SETTINGS'
    foreach ($protocol in @('SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')) {
        foreach ($role in @('Client', 'Server')) {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\{1}' -f $protocol, $role
            $enabled = Get-RegistryAuditValue -Module $module -Path $path -Name 'Enabled'
            $disabled = Get-RegistryAuditValue -Module $module -Path $path -Name 'DisabledByDefault'
            Add-ReportLine $report ('Protocol={0}; Role={1}; Enabled={2}; DisabledByDefault={3}' -f `
                $protocol, $role, (ConvertTo-DisplayValue $enabled), (ConvertTo-DisplayValue $disabled))
        }
    }
}

function Invoke-AuditingAndLoggingAudit {
    [CmdletBinding()]
    param()

    $report = '17-Auditing-and-Logging.txt'
    $module = 'Auditing and Logging'
    Write-ModuleHeader $report $module 'Event Log service, advanced audit policy, command-line/PowerShell logging, and log capacity/retention.'

    if ($script:ServiceInventory.Count -eq 0) {
        $script:ServiceInventory = @(Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-CimInstance Win32_Service for Event Log state' `
            -ScriptBlock { Get-CimInstance -ClassName Win32_Service -ErrorAction Stop })
    }
    $eventLogService = @($script:ServiceInventory | Where-Object { (Get-ObjectPropertyValue $_ 'Name') -eq 'EventLog' }) | Select-Object -First 1
    $eventLogState = Get-ObjectPropertyValue $eventLogService 'State'
    $eventLogStartMode = Get-ObjectPropertyValue $eventLogService 'StartMode'
    Add-ReportLine $report ('Windows Event Log service: {0}' -f $(if ($eventLogService) { "State=$eventLogState; StartMode=$eventLogStartMode" } else { 'Not returned' }))
    if ($eventLogService -and ($eventLogState -ne 'Running' -or $eventLogStartMode -eq 'Disabled')) {
        Add-AuditFinding -Severity CRITICAL -Category $module -Finding 'Windows Event Log service is not running normally' `
            -CurrentValue ("State={0}; StartMode={1}" -f $eventLogState, $eventLogStartMode) `
            -ExpectedValue 'Running and configured according to supported Windows defaults.' -Evidence 'Win32_Service EventLog' `
            -WhyThisMatters 'Security monitoring and incident evidence depend on event logging.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Investigate service dependencies and policy before manually correcting it.' `
            -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'High' -Status '[CRITICAL]' -ReportFile $report
    }

    $auditPolicy = @()
    if ($script:IsAdministrator) {
        $auditPolicy = @(Invoke-ReadOnlyCommand -Module $module -CommandText 'auditpol.exe /get /category:* /r' `
            -ScriptBlock {
                $nativeOutput = auditpol.exe /get '/category:*' /r
                if ($LASTEXITCODE -ne 0) { throw ("auditpol /get failed with exit code {0}" -f $LASTEXITCODE) }
                Write-Output $nativeOutput
            })
    }
    else {
        Add-ReportLine $report 'Advanced audit policy query skipped because this run is not elevated.'
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'ADVANCED AUDIT POLICY (CSV-FORMATTED AUDITPOL OUTPUT)'
    foreach ($line in @($auditPolicy)) { Add-ReportLine $report ([string]$line) }
    $auditText = @($auditPolicy) -join "`n"
    $requiredAuditTerms = @('Logon', 'Account Logon', 'Account Management', 'Policy Change', 'Privilege Use', 'Process Creation')
    foreach ($term in $requiredAuditTerms) {
        $matching = @($auditPolicy | Where-Object { [string]$_ -match [regex]::Escape($term) })
        if ($matching.Count -eq 0) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Could not locate audit policy area: {0}" -f $term) `
                -CurrentValue 'No matching auditpol output line' -ExpectedValue 'Relevant success/failure auditing configured according to the README.' `
                -Evidence 'Localized or unavailable auditpol output.' -WhyThisMatters 'Important security actions may not be recorded.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Open Advanced Audit Policy and verify the category manually.' `
                -DisruptionRisk 'None for review; enabling auditing can increase log volume.' -RestartRequired 'No' `
                -Confidence 'Low due to localization/output parsing.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
        elseif ((@($matching) -join ' ') -match '(?i)No Auditing') {
            Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Important audit policy area may have no auditing: {0}" -f $term) `
                -CurrentValue (@($matching) -join ' | ') -ExpectedValue 'Success and/or Failure auditing appropriate to the category and README.' `
                -Evidence 'auditpol /get read-only output' -WhyThisMatters 'Missing audit records reduce detection and accountability.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify exact subcategories and log capacity before enabling auditing manually.' `
                -DisruptionRisk 'Medium; audit volume can be substantial.' -RestartRequired 'No' -Confidence 'Medium; text matching is locale-sensitive.' `
                -Status '[WARNING]' -ReportFile $report
        }
    }

    $cmdLine = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled'
    $moduleLogging = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging'
    $scriptBlockLogging = Get-RegistryAuditValue -Module $module `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging'
    Add-ReportLine $report ''
    Add-ReportLine $report ('Process command-line auditing: {0}' -f (ConvertTo-DisplayValue $cmdLine))
    Add-ReportLine $report ('PowerShell module logging: {0}' -f (ConvertTo-DisplayValue $moduleLogging))
    Add-ReportLine $report ('PowerShell script-block logging: {0}' -f (ConvertTo-DisplayValue $scriptBlockLogging))
    foreach ($setting in @(
        @{ Name='Process command-line auditing'; Value=$cmdLine },
        @{ Name='PowerShell module logging'; Value=$moduleLogging },
        @{ Name='PowerShell script-block logging'; Value=$scriptBlockLogging }
    )) {
        if ($null -eq $setting.Value -or [int]$setting.Value -ne 1) {
            Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Logging control is not explicitly enabled: {0}" -f $setting.Name) `
                -CurrentValue (ConvertTo-DisplayValue $setting.Value) -ExpectedValue 'Enabled (1), after privacy, capacity, and README review.' `
                -Evidence 'Targeted policy registry query' -WhyThisMatters 'Command/script logging improves investigation of administrative and malicious activity.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Review privacy and log-size impact before enabling the policy manually.' `
                -DisruptionRisk 'Medium; logs may contain sensitive command arguments and consume storage.' -RestartRequired 'Possibly' `
                -Confidence 'Medium; absence can mean not configured rather than forcibly disabled.' -Status '[WARNING]' -ReportFile $report
        }
    }

    $logs = New-Object System.Collections.ArrayList
    foreach ($logToRead in @('Security', 'Application', 'System')) {
        $oneLog = Invoke-ReadOnlyCommand -Module $module -CommandText ("Get-WinEvent -ListLog {0}" -f $logToRead) -ScriptBlock {
            Get-WinEvent -ListLog $logToRead -ErrorAction Stop
        }.GetNewClosure()
        foreach ($item in @($oneLog)) { [void]$logs.Add($item) }
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'EVENT LOG CAPACITY AND RETENTION'
    foreach ($log in @($logs)) {
        $logName = Get-ObjectPropertyValue $log 'LogName'
        if ([string]::IsNullOrWhiteSpace([string]$logName)) { continue }
        $maximumSize = Get-ObjectPropertyValue $log 'MaximumSizeInBytes'
        Add-ReportLine $report ('Name={0}; Enabled={1}; RecordCount={2}; MaximumSizeBytes={3}; LogMode={4}; IsLogFull={5}' -f `
            $logName, (Get-ObjectPropertyValue $log 'IsEnabled'), (Get-ObjectPropertyValue $log 'RecordCount'), `
            $maximumSize, (Get-ObjectPropertyValue $log 'LogMode'), (Get-ObjectPropertyValue $log 'IsLogFull'))
        if ($null -ne $maximumSize -and [long]$maximumSize -lt 20MB) {
            Add-AuditFinding -Severity MEDIUM -Category $module -Finding ("Event log has a small maximum size: {0}" -f $logName) `
                -CurrentValue ("{0} bytes; Mode={1}" -f $maximumSize, (Get-ObjectPropertyValue $log 'LogMode')) `
                -ExpectedValue 'Sufficient capacity for the image activity and retention needs; commonly at least 20 MB for core logs.' `
                -Evidence 'Get-WinEvent -ListLog' -WhyThisMatters 'Small logs can overwrite useful security evidence quickly.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Estimate event volume and free disk space before increasing log size manually.' `
                -DisruptionRisk 'Low to medium; larger logs consume disk.' -RestartRequired 'No' -Confidence 'Medium; appropriate size depends on activity.' `
                -Status '[WARNING]' -ReportFile $report
        }
    }
}

function Invoke-BrowserAndProxyAudit {
    [CmdletBinding()]
    param()

    $report = '18-Browser-and-Proxy-Settings.txt'
    $module = 'Browser and Proxy Settings'
    Write-ModuleHeader $report $module 'Installed browser versions, extension metadata, proxy, homepage, certificate-warning, password, and download policies.'

    Add-ReportLine $report 'INSTALLED BROWSERS FROM SOFTWARE INVENTORY'
    $browserSoftware = @($script:SoftwareInventory | Where-Object { $_.Name -match '(?i)(Microsoft Edge|Google Chrome|Mozilla Firefox|Brave|Opera|Vivaldi)' })
    foreach ($browser in $browserSoftware) {
        Add-ReportLine $report ('Name={0}; Version={1}; Publisher={2}; Location={3}' -f `
            $browser.Name, (ConvertTo-DisplayValue $browser.Version), (ConvertTo-DisplayValue $browser.Publisher), (ConvertTo-DisplayValue $browser.InstallLocation))
    }
    $knownExecutables = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
        (Join-Path $env:ProgramFiles 'Mozilla Firefox\firefox.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Mozilla Firefox\firefox.exe')
    ) | Where-Object { $_ }
    foreach ($exe in $knownExecutables | Sort-Object -Unique) {
        $item = Invoke-ReadOnlyCommand -Module $module -CommandText 'Read known browser executable version metadata' -ScriptBlock {
            if (Test-Path -LiteralPath $exe -PathType Leaf) { Get-Item -LiteralPath $exe -ErrorAction Stop }
        }.GetNewClosure() -SuppressErrorFinding
        if ($item) { Add-ReportLine $report ('Executable={0}; Version={1}' -f $exe, $item.VersionInfo.ProductVersion) }
    }

    $extensionRoots = @(
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'),
        (Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles')
    ) | Where-Object { $_ }
    Add-ReportLine $report ''
    Add-ReportLine $report 'BROWSER EXTENSION METADATA'
    foreach ($root in $extensionRoots) {
        if (Test-IsProhibitedScoringPath $root) { continue }
        $manifests = Invoke-ReadOnlyCommand -Module $module -CommandText 'Enumerate browser extension manifest metadata under current user profile' -ScriptBlock {
            if (Test-Path -LiteralPath $root -PathType Container) {
                Get-ChildItem -LiteralPath $root -Filter 'manifest.json' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000
            }
        }.GetNewClosure() -SuppressErrorFinding
        foreach ($manifest in @($manifests)) {
            if (Test-IsProhibitedScoringPath $manifest.FullName) { continue }
            $content = Invoke-ReadOnlyCommand -Module $module -CommandText 'Read one browser extension manifest file' -ScriptBlock {
                Get-Content -LiteralPath $manifest.FullName -Raw -ErrorAction Stop
            }.GetNewClosure() -SuppressErrorFinding
            $extensionName = '<not parsed>'
            $extensionVersion = '<not parsed>'
            try {
                $json = $content | ConvertFrom-Json -ErrorAction Stop
                $extensionName = ConvertTo-DisplayValue $json.name
                $extensionVersion = ConvertTo-DisplayValue $json.version
            } catch { }
            Add-ReportLine $report ('Manifest={0}; Name={1}; Version={2}; Modified={3}' -f `
                $manifest.FullName, $extensionName, $extensionVersion, $manifest.LastWriteTime)
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Verify browser extension: {0}" -f $extensionName) `
                -CurrentValue ("Version={0}; Manifest={1}" -f $extensionVersion, $manifest.FullName) `
                -ExpectedValue 'Only extensions explicitly authorized or required by the README/user role.' `
                -Evidence 'Extension manifest metadata; no browsing history or personal content inspected.' `
                -WhyThisMatters 'Extensions can read or change browser data according to granted permissions.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Open the browser extension manager and verify ID, source, permissions, and need before manual removal.' `
                -DisruptionRisk 'Medium; required browser workflows may break.' -RestartRequired 'No' `
                -Confidence 'High that the manifest exists; authorization unknown.' -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }

    $proxyMachine = Get-RegistryAuditProperties -Module $module `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxyUser = Get-RegistryAuditProperties -Module $module `
        -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxyPolicy = Get-RegistryAuditProperties -Module $module `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    Add-ReportLine $report ''
    Add-ReportLine $report 'PROXY SETTINGS'
    foreach ($entry in @(
        @{ Scope='Machine'; Object=$proxyMachine }, @{ Scope='Current user'; Object=$proxyUser }, @{ Scope='Policy'; Object=$proxyPolicy }
    )) {
        Add-ReportLine $report ('Scope={0}; ProxyEnable={1}; ProxyServer={2}; AutoConfigURL={3}; ProxyOverride={4}' -f `
            $entry.Scope, (ConvertTo-DisplayValue (Get-ObjectPropertyValue $entry.Object 'ProxyEnable')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $entry.Object 'ProxyServer')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $entry.Object 'AutoConfigURL')), `
            (ConvertTo-DisplayValue (Get-ObjectPropertyValue $entry.Object 'ProxyOverride')))
    }
    $userProxyEnabled = Get-ObjectPropertyValue $proxyUser 'ProxyEnable'
    $userProxyServer = Get-ObjectPropertyValue $proxyUser 'ProxyServer'
    $autoConfigUrl = Get-ObjectPropertyValue $proxyUser 'AutoConfigURL'
    if (($userProxyEnabled -eq 1 -and $userProxyServer) -or $autoConfigUrl) {
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Per-user proxy or automatic configuration is active' `
            -CurrentValue ("ProxyEnabled={0}; ProxyServer={1}; AutoConfigURL={2}" -f (ConvertTo-DisplayValue $userProxyEnabled), (ConvertTo-DisplayValue $userProxyServer), (ConvertTo-DisplayValue $autoConfigUrl)) `
            -ExpectedValue 'Only an authorized proxy/PAC configuration required by the README or network.' `
            -Evidence 'Current-user Internet Settings registry values' -WhyThisMatters 'A proxy can observe or redirect browser and system traffic.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify the server/URL with the README and network design before manually clearing or changing it.' `
            -DisruptionRisk 'High; required network access may fail.' -RestartRequired 'No' -Confidence 'High' `
            -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    $policyPaths = @(
        'HKLM:\SOFTWARE\Policies\Google\Chrome', 'HKCU:\SOFTWARE\Policies\Google\Chrome',
        'HKLM:\SOFTWARE\Policies\Microsoft\Edge', 'HKCU:\SOFTWARE\Policies\Microsoft\Edge',
        'HKLM:\SOFTWARE\Policies\Mozilla\Firefox', 'HKCU:\SOFTWARE\Policies\Mozilla\Firefox',
        'HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main'
    )
    $policyNames = @(
        'HomepageLocation', 'HomepageIsNewTabPage', 'RestoreOnStartupURLs', 'DefaultDownloadDirectory',
        'DownloadRestrictions', 'PasswordManagerEnabled', 'PasswordManagerSavingEnabled',
        'SSLErrorOverrideAllowed', 'DisableSecuritySettingsCheck', 'Start Page', 'Search Page'
    )
    Add-ReportLine $report ''
    Add-ReportLine $report 'BROWSER HOMEPAGE, CERTIFICATE-WARNING, PASSWORD, AND DOWNLOAD POLICIES'
    foreach ($path in $policyPaths) {
        $policyObject = Get-RegistryAuditProperties -Module $module -Path $path
        if (-not $policyObject) { continue }
        foreach ($name in $policyNames) {
            $value = Get-ObjectPropertyValue $policyObject $name
            if ($null -ne $value) {
                Add-ReportLine $report ('Registry={0}; Setting={1}; Value={2}' -f $path, $name, (ConvertTo-DisplayValue $value))
                Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Verify browser policy: {0}" -f $name) `
                    -CurrentValue (ConvertTo-DisplayValue $value) -ExpectedValue 'Authorized setting consistent with the README and safe browsing requirements.' `
                    -Evidence $path -WhyThisMatters 'Managed browser policies can force homepages, weaken warnings, affect passwords, or control downloads.' `
                    -ReadmeRequired 'Yes' -PossibleManualAction 'Verify policy source and intent before changing it manually.' `
                    -DisruptionRisk 'Medium to high.' -RestartRequired 'Browser restart may be required.' -Confidence 'High' `
                    -Status '[MANUAL REVIEW]' -ReportFile $report
            }
        }
    }
}

function Invoke-CertificatesDnsHostsAudit {
    [CmdletBinding()]
    param()

    $report = '19-Certificates-DNS-and-Hosts.txt'
    $module = 'Certificates DNS and Hosts'
    Write-ModuleHeader $report $module 'Trusted roots, expiration/recent issuance heuristics, hosts entries, DNS, suffixes, NRPT, and proxy context.'

    $certificates = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get trusted root certificates from LocalMachine and CurrentUser stores' -ScriptBlock {
        Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction Stop
        Get-ChildItem -Path 'Cert:\CurrentUser\Root' -ErrorAction Stop
    }
    Add-ReportLine $report 'TRUSTED ROOT CERTIFICATES'
    $now = Get-Date
    foreach ($certificate in @($certificates | Sort-Object Subject, Thumbprint -Unique)) {
        Add-ReportLine $report ('Subject={0}; Issuer={1}; NotBefore={2}; NotAfter={3}; Thumbprint={4}; HasPrivateKey={5}' -f `
            $certificate.Subject, $certificate.Issuer, $certificate.NotBefore, $certificate.NotAfter, $certificate.Thumbprint, $certificate.HasPrivateKey)
        if ($certificate.NotAfter -lt $now) {
            Add-AuditFinding -Severity LOW -Category $module -Finding ("Expired certificate remains in a trusted root store: {0}" -f $certificate.Subject) `
                -CurrentValue ("Expired={0}; Thumbprint={1}" -f $certificate.NotAfter, $certificate.Thumbprint) `
                -ExpectedValue 'Trusted roots maintained according to Windows/vendor requirements; expiration reviewed in context.' `
                -Evidence 'Local trusted-root certificate metadata' -WhyThisMatters 'Expired roots can be obsolete, but some remain for historic signature validation.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Research the exact root and Windows trust behavior before manually removing any certificate.' `
                -DisruptionRisk 'High; certificate removal can break TLS, software validation, or updates.' -RestartRequired 'Possibly' `
                -Confidence 'High for expiration; low for security impact.' -Status '[WARNING]' -ReportFile $report
        }
        if ($certificate.NotBefore -ge $now.AddDays(-90)) {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding ("Recently issued trusted root certificate: {0}" -f $certificate.Subject) `
                -CurrentValue ("NotBefore={0}; Issuer={1}; Thumbprint={2}" -f $certificate.NotBefore, $certificate.Issuer, $certificate.Thumbprint) `
                -ExpectedValue 'Known vendor/organization root required by the image.' `
                -Evidence 'Certificate NotBefore is within 90 days; Windows does not expose installation time here.' `
                -WhyThisMatters 'A newly issued root can expand who may issue trusted certificates, but NotBefore is not installation time.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify issuer, thumbprint, deployment source, and purpose before removal.' `
                -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'Low for recent installation; high for certificate dates.' `
                -Status '[MANUAL REVIEW]' -ReportFile $report
        }
        if (('{0} {1}' -f $certificate.Subject, $certificate.Issuer) -match '(?i)(DO_NOT_TRUST|fiddler|burp|charles|mitm|intercept|test root|proxy root)') {
            Add-AuditFinding -Severity HIGH -Category $module -Finding ("Trusted root issuer name warrants review: {0}" -f $certificate.Subject) `
                -CurrentValue ("Issuer={0}; Thumbprint={1}" -f $certificate.Issuer, $certificate.Thumbprint) `
                -ExpectedValue 'Only authorized trust anchors.' -Evidence 'Issuer/subject keyword heuristic' `
                -WhyThisMatters 'Interception/testing roots can permit trusted TLS interception when their private key is controlled.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Confirm exact product and thumbprint; never remove a root based on name alone.' `
                -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'Medium; names can be legitimate.' -Status '[WARNING]' -ReportFile $report
        }
    }

    $hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    $hostsLines = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get hosts file non-comment lines' -ScriptBlock {
        Get-Content -LiteralPath $hostsPath -ErrorAction Stop |
            Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }
    }.GetNewClosure()
    Add-ReportLine $report ''
    Add-ReportLine $report 'WINDOWS HOSTS FILE ACTIVE ENTRIES'
    foreach ($line in @($hostsLines)) { Add-ReportLine $report ([string]$line) }
    if (@($hostsLines).Count -eq 0) { Add-ReportLine $report '<no active entries>' }
    foreach ($line in @($hostsLines)) {
        if ([string]$line -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost(\s|$)') {
            Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Non-default hosts file entry requires review' `
                -CurrentValue ([string]$line) -ExpectedValue 'Only explicitly required local name mappings.' `
                -Evidence $hostsPath -WhyThisMatters 'Hosts entries override normal DNS and can redirect services or updates.' `
                -ReadmeRequired 'Yes' -PossibleManualAction 'Verify every hostname and address before editing the hosts file manually.' `
                -DisruptionRisk 'High; name resolution can break.' -RestartRequired 'No' -Confidence 'High for entry; intent unknown.' `
                -Status '[MANUAL REVIEW]' -ReportFile $report
        }
    }

    $dnsServers = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-DnsClientServerAddress for active address families' -ScriptBlock {
        if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
            Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { @($_.ServerAddresses).Count -gt 0 }
        }
    }
    $dnsGlobal = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-DnsClientGlobalSetting' -ScriptBlock {
        if (Get-Command Get-DnsClientGlobalSetting -ErrorAction SilentlyContinue) { Get-DnsClientGlobalSetting -ErrorAction Stop }
    }
    $nrpt = Invoke-ReadOnlyCommand -Module $module -CommandText 'Get-DnsClientNrptPolicy' -ScriptBlock {
        if (Get-Command Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue) { Get-DnsClientNrptPolicy -ErrorAction Stop }
    } -SuppressErrorFinding
    Add-ReportLine $report ''
    Add-ReportLine $report 'DNS SERVERS AND SUFFIXES'
    foreach ($entry in @($dnsServers)) {
        Add-ReportLine $report ('Interface={0}; Family={1}; Servers={2}' -f $entry.InterfaceAlias, $entry.AddressFamily, (ConvertTo-DisplayValue $entry.ServerAddresses))
    }
    if ($dnsGlobal) {
        Add-ReportLine $report ('SuffixSearchList={0}; UseSuffixSearchList={1}; UseDevolution={2}' -f `
            (ConvertTo-DisplayValue $dnsGlobal.SuffixSearchList), $dnsGlobal.UseSuffixSearchList, $dnsGlobal.UseDevolution)
    }
    Add-ReportLine $report ''
    Add-ReportLine $report 'NAME RESOLUTION POLICY TABLE'
    foreach ($policy in @($nrpt)) {
        Add-ReportLine $report ('Namespace={0}; NameServers={1}; DnsSecValidationRequired={2}; DirectAccess={3}' -f `
            (ConvertTo-DisplayValue $policy.Namespace), (ConvertTo-DisplayValue $policy.NameServers), `
            (ConvertTo-DisplayValue $policy.DnsSecValidationRequired), (ConvertTo-DisplayValue $policy.DirectAccessEnabled))
        Add-AuditFinding -Severity 'MANUAL REVIEW' -Category $module -Finding 'Name Resolution Policy Table entry requires review' `
            -CurrentValue ("Namespace={0}; Servers={1}" -f (ConvertTo-DisplayValue $policy.Namespace), (ConvertTo-DisplayValue $policy.NameServers)) `
            -ExpectedValue 'Only policies required by authorized domain, VPN, or DirectAccess configuration.' `
            -Evidence 'Get-DnsClientNrptPolicy' -WhyThisMatters 'NRPT can redirect or constrain DNS resolution for selected namespaces.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Verify domain/VPN requirements before changing any name-resolution policy.' `
            -DisruptionRisk 'High' -RestartRequired 'Possibly' -Confidence 'High' -Status '[MANUAL REVIEW]' -ReportFile $report
    }

    $proxy = Get-RegistryAuditProperties -Module $module -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
    Add-ReportLine $report ''
    Add-ReportLine $report ('ProxyEnable={0}; ProxyServer={1}; AutoConfigURL={2}' -f `
        (ConvertTo-DisplayValue (Get-ObjectPropertyValue $proxy 'ProxyEnable')), `
        (ConvertTo-DisplayValue (Get-ObjectPropertyValue $proxy 'ProxyServer')), `
        (ConvertTo-DisplayValue (Get-ObjectPropertyValue $proxy 'AutoConfigURL')))
}

function Invoke-RecentSecurityEventsAudit {
    [CmdletBinding()]
    param()

    $report = '20-Recent-Security-Events.txt'
    $module = 'Recent Security Events'
    Write-ModuleHeader $report $module ("Local event summaries for the last {0} day(s). Counts are capped at 200 per event query." -f $EventLogDays)

    $startTime = (Get-Date).AddDays(-$EventLogDays)
    $eventQueries = @(
        @{ Label='Failed logons'; Log='Security'; Ids=@(4625); Severity='MEDIUM' },
        @{ Label='Successful privileged logons (special privileges assigned)'; Log='Security'; Ids=@(4672); Severity='MANUAL REVIEW' },
        @{ Label='Account creation'; Log='Security'; Ids=@(4720); Severity='HIGH' },
        @{ Label='Account deletion'; Log='Security'; Ids=@(4726); Severity='HIGH' },
        @{ Label='Security group membership changes'; Log='Security'; Ids=@(4728, 4729, 4732, 4733, 4756, 4757); Severity='HIGH' },
        @{ Label='Service installation'; Log='System'; Ids=@(7045); Severity='HIGH' },
        @{ Label='Scheduled task creation'; Log='Security'; Ids=@(4698); Severity='HIGH' },
        @{ Label='Defender detections'; Log='Microsoft-Windows-Windows Defender/Operational'; Ids=@(1116, 1117); Severity='HIGH' },
        @{ Label='Audit log clearing'; Log='Security'; Ids=@(1102); Severity='CRITICAL' },
        @{ Label='Firewall rule/profile changes'; Log='Security'; Ids=@(4946, 4947, 4948, 4950); Severity='MEDIUM' },
        @{ Label='PowerShell script-block execution'; Log='Microsoft-Windows-PowerShell/Operational'; Ids=@(4104); Severity='MANUAL REVIEW' },
        @{ Label='System shutdown initiated'; Log='System'; Ids=@(1074); Severity='INFO' },
        @{ Label='Unexpected shutdown'; Log='System'; Ids=@(6008); Severity='HIGH' },
        @{ Label='Unexpected restart/kernel power'; Log='System'; Ids=@(41); Severity='HIGH' }
    )

    foreach ($queryDefinition in $eventQueries) {
        $logName = $queryDefinition.Log
        $ids = $queryDefinition.Ids
        $events = Invoke-ReadOnlyCommand -Module $module `
            -CommandText ("Get-WinEvent Log={0}; Id={1}; Start={2:u}; MaxEvents=200" -f $logName, ($ids -join ','), $startTime) `
            -ScriptBlock {
                Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $ids; StartTime = $startTime } `
                    -MaxEvents 200 -ErrorAction Stop
            }.GetNewClosure() -SuppressErrorFinding
        $safeEvents = New-Object System.Collections.ArrayList
        foreach ($event in @($events)) {
            $eventId = Get-ObjectPropertyValue $event 'Id'
            if ($null -eq $eventId) { continue }
            $message = [string](Get-ObjectPropertyValue $event 'Message')
            if ($message -match '(?i)(scorebot|scoring[ _-]?engine|cyberpatriot[ _-]?scor|ccsclient)') { continue }
            [void]$safeEvents.Add($event)
        }
        Add-ReportLine $report ('{0}: CountReturned={1}; QueryCap=200; Log={2}; IDs={3}' -f `
            $queryDefinition.Label, $safeEvents.Count, $logName, ($ids -join ','))
        foreach ($event in @($safeEvents | Select-Object -First 5)) {
            $message = ([string](Get-ObjectPropertyValue $event 'Message') -replace '\s+', ' ').Trim()
            if ($message.Length -gt 500) { $message = $message.Substring(0, 500) + ' [truncated]' }
            # Script-block event content is deliberately not reproduced. It can contain
            # sensitive commands; the report records metadata only.
            if ((Get-ObjectPropertyValue $event 'Id') -eq 4104) { $message = '<script-block content deliberately omitted>' }
            Add-ReportLine $report ('  Time={0:u}; Id={1}; RecordId={2}; Provider={3}; Message={4}' -f `
                (Get-ObjectPropertyValue $event 'TimeCreated'), (Get-ObjectPropertyValue $event 'Id'), `
                (Get-ObjectPropertyValue $event 'RecordId'), (Get-ObjectPropertyValue $event 'ProviderName'), `
                (ConvertTo-DisplayValue $message))
        }
        if ($safeEvents.Count -eq 0) { continue }

        $status = if ($queryDefinition.Severity -eq 'CRITICAL') { '[CRITICAL]' } elseif ($queryDefinition.Severity -eq 'MANUAL REVIEW' -or $queryDefinition.Severity -eq 'INFO') { '[MANUAL REVIEW]' } else { '[WARNING]' }
        $severity = if ($queryDefinition.Severity -eq 'INFO') { 'MANUAL REVIEW' } else { $queryDefinition.Severity }
        Add-AuditFinding -Severity $severity -Category $module -Finding ("Recent event activity: {0}" -f $queryDefinition.Label) `
            -CurrentValue ("{0} event(s) returned in last {1} day(s), capped at 200" -f $safeEvents.Count, $EventLogDays) `
            -ExpectedValue 'Every security-relevant event understood in system and README context.' `
            -Evidence ("Log={0}; IDs={1}; most recent RecordId={2}" -f $logName, ($ids -join ','), (Get-ObjectPropertyValue $safeEvents[0] 'RecordId')) `
            -WhyThisMatters 'These events can indicate attacks, administrative changes, maintenance, or normal activity.' `
            -ReadmeRequired 'Yes' -PossibleManualAction 'Review the event examples and full Event Viewer context; do not clear logs.' `
            -DisruptionRisk 'None for review.' -RestartRequired 'No' `
            -Confidence 'High for returned events; intent and completeness require review.' -Status $status -ReportFile $report
    }
}

function Build-ManualReviewChecklist {
    [CmdletBinding()]
    param()

    $report = '21-Manual-Review-Checklist.txt'
    Write-ModuleHeader $report 'Manual Review Checklist' 'Work through this list slowly. This report never authorizes a change.'
    $standardItems = @(
        'Read the CyberPatriot README completely.',
        'Verify every local user.',
        'Verify every administrator.',
        'Review password policy findings.',
        'Review Defender findings and exclusions.',
        'Review firewall profiles and allow rules.',
        'Review remote-access services and listeners.',
        'Review installed software.',
        'Review suspicious-file metadata without opening personal documents.',
        'Review scheduled tasks.',
        'Review startup entries and PowerShell profiles.',
        'Review shares and permissions.',
        'Review insecure protocols and legacy name resolution.',
        'Review Windows Update findings.',
        'Review logging configuration and recent events.',
        'Make only one carefully selected manual change at a time.',
        'Confirm required services still work after each manual change.',
        'Check the CyberPatriot score after each carefully selected manual change.',
        'Re-run this audit after manual changes.'
    )
    Add-ReportLine $report 'BASE CHECKLIST'
    foreach ($item in $standardItems) { Add-ReportLine $report ('[ ] ' + $item) }

    Add-ReportLine $report ''
    Add-ReportLine $report 'CHECKLIST GENERATED FROM THIS AUDIT'
    $reviewItems = @($script:Findings | Where-Object {
        $_.Status -in @('[CRITICAL]', '[WARNING]', '[MANUAL REVIEW]', '[ERROR]')
    } | Sort-Object ReportFile, Finding -Unique)
    foreach ($item in $reviewItems) {
        Add-ReportLine $report ('[ ] {0} [{1}] - See {2}' -f $item.Finding, $item.Status.Trim('[', ']'), $item.ReportFile)
    }
    if ($reviewItems.Count -eq 0) {
        Add-ReportLine $report '[ ] No generated issue items; still complete every base checklist item and read the README.'
    }
}

function Build-CommandLogReport {
    [CmdletBinding()]
    param()

    $report = '23-Commands-Executed.txt'
    Write-ModuleHeader $report 'Commands and Queries Executed' 'Every listed audit command/query passed the read-only safety gate before execution.'
    Add-ReportLine $report ('Total logged audit queries: {0}' -f $script:CommandLog.Count)
    Add-ReportLine $report ''
    foreach ($entry in $script:CommandLog) {
        Add-ReportLine $report '---'
        Add-ReportLine $report ('Time: {0}' -f $entry.Time.ToString('yyyy-MM-dd HH:mm:ss.fff zzz'))
        Add-ReportLine $report ('Audit module: {0}' -f $entry.AuditModule)
        Add-ReportLine $report ('Command or query: {0}' -f $entry.CommandOrQuery)
        Add-ReportLine $report ('Succeeded: {0}' -f $entry.Succeeded)
        Add-ReportLine $report ('Error message: {0}' -f (ConvertTo-DisplayValue $entry.ErrorMessage))
    }
}

function Build-AuditSummary {
    [CmdletBinding()]
    param()

    $report = '00-Audit-Summary.txt'
    Write-ModuleHeader $report 'CyberPatriot Windows Read-Only Audit Summary' 'Start with the competition README, then use this ranked summary to choose manual review work.'

    $criticalCount = Get-AuditSeverityCount '[CRITICAL]'
    $warningCount = Get-AuditSeverityCount '[WARNING]'
    $manualCount = Get-AuditSeverityCount '[MANUAL REVIEW]'
    $passCount = Get-AuditSeverityCount '[PASS]'
    $errorCount = Get-AuditSeverityCount '[ERROR]'
    $edition = if ($script:SystemSummary.ContainsKey('WindowsEdition')) { $script:SystemSummary.WindowsEdition } else { '<not available>' }
    $version = if ($script:SystemSummary.ContainsKey('WindowsVersion')) { $script:SystemSummary.WindowsVersion } else { '<not available>' }
    $computer = if ($script:SystemSummary.ContainsKey('ComputerName')) { $script:SystemSummary.ComputerName } else { $env:COMPUTERNAME }

    Add-ReportLine $report ('Computer name: {0}' -f $computer)
    Add-ReportLine $report ('Windows edition: {0}' -f $edition)
    Add-ReportLine $report ('Windows version: {0}' -f $version)
    Add-ReportLine $report ('Audit start time: {0}' -f $script:AuditStart.ToString('yyyy-MM-dd HH:mm:ss zzz'))
    Add-ReportLine $report ('Audit completion time: {0}' -f $script:AuditComplete.ToString('yyyy-MM-dd HH:mm:ss zzz'))
    Add-ReportLine $report ('Ran as administrator: {0}' -f $script:IsAdministrator)
    Add-ReportLine $report ('Total checks/findings recorded: {0}' -f $script:Findings.Count)
    Add-ReportLine $report ('Critical findings: {0}' -f $criticalCount)
    Add-ReportLine $report ('Warnings: {0}' -f $warningCount)
    Add-ReportLine $report ('Manual-review items: {0}' -f $manualCount)
    Add-ReportLine $report ('Passed checks: {0}' -f $passCount)
    Add-ReportLine $report ('Errors: {0}' -f $errorCount)
    Add-ReportLine $report ('Output folder: {0}' -f $script:AuditOutputFolder)
    Add-ReportLine $report ''
    Add-ReportLine $report 'IMPORTANT: NO SECURITY SETTINGS, USERS, SERVICES, TASKS, FILES, SHARES, SOFTWARE, OR REGISTRY VALUES WERE CHANGED.'
    Add-ReportLine $report 'The only files created are audit output/support files inside the output folder.'
    Add-ReportLine $report 'READ THE CYBERPATRIOT README BEFORE MAKING ANY MANUAL CHANGE.'

    $severityRank = @{ '[CRITICAL]'=1; '[WARNING]'=2; '[MANUAL REVIEW]'=3; '[ERROR]'=4 }
    $ranked = foreach ($finding in @($script:Findings | Where-Object {
        $_.Status -in @('[CRITICAL]', '[WARNING]', '[MANUAL REVIEW]', '[ERROR]')
    })) {
        $categoryOrder = if ($script:CategoryRank.ContainsKey($finding.Category)) { $script:CategoryRank[$finding.Category] } else { 14 }
        [pscustomobject]@{
            CategoryOrder = $categoryOrder
            SeverityOrder = $severityRank[$finding.Status]
            Item = $finding
        }
    }
    $ranked = @($ranked | Sort-Object CategoryOrder, SeverityOrder, @{ Expression = { $_.Item.Finding } })
    Add-ReportLine $report ''
    Add-ReportLine $report 'RANKED IMPORTANT FINDINGS (TOP 40)'
    $position = 1
    foreach ($entry in @($ranked | Select-Object -First 40)) {
        Add-ReportLine $report ('{0}. {1} {2} - {3} (See {4})' -f `
            $position, $entry.Item.Status, $entry.Item.Category, $entry.Item.Finding, $entry.Item.ReportFile)
        $position++
    }
    if ($ranked.Count -eq 0) { Add-ReportLine $report '<no critical, warning, manual-review, or error items recorded>' }

    Add-ReportLine $report ''
    Add-ReportLine $report 'REPORT FILE CHECKLIST'
    foreach ($file in $script:ReportFiles) { Add-ReportLine $report ('[x] ' + $file) }
    Add-ReportLine $report '[x] Audit-Findings.csv'
    Add-ReportLine $report '[x] Audit-Findings.json'
    if ($script:SecurityPolicyExportPath) {
        Add-ReportLine $report '[x] SecurityPolicy-ReadOnly-Export.inf (read-only support export; not a policy change)'
        Add-ReportLine $report '[x] SecurityPolicy-ReadOnly-Export.log (secedit export log)'
    }
}

function Export-AuditReports {
    [CmdletBinding()]
    param()

    Add-FormattedFindingsToReports
    $utf8Bom = New-Object Text.UTF8Encoding($true)
    foreach ($file in $script:ReportFiles) {
        $path = Join-Path $script:AuditOutputFolder $file
        if (-not (Test-IsPathInsideAuditOutput $path)) { throw "Refusing to write outside audit output: $path" }
        [IO.File]::WriteAllText($path, $script:ReportBuffers[$file].ToString(), $utf8Bom)
    }

    $csvPath = Join-Path $script:AuditOutputFolder 'Audit-Findings.csv'
    $jsonPath = Join-Path $script:AuditOutputFolder 'Audit-Findings.json'
    if (-not (Test-IsPathInsideAuditOutput $csvPath) -or -not (Test-IsPathInsideAuditOutput $jsonPath)) {
        throw 'Refusing to export findings outside the audit output folder.'
    }
    $script:Findings | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    $json = if ($script:Findings.Count -eq 0) { '[]' } else { $script:Findings | ConvertTo-Json -Depth 6 }
    [IO.File]::WriteAllText($jsonPath, [string]$json, $utf8Bom)
}

# -----------------------------------------------------------------------------
# Main execution
# -----------------------------------------------------------------------------
$startupMessage = 'This is a read-only auditing tool. It will not secure, modify, delete, disable, or patch anything. Review every finding against the CyberPatriot README before manually changing the system. This tool must not interact with the CyberPatriot scoring engine.'
Write-Host $startupMessage -ForegroundColor Yellow
Write-Host ''

$script:IsAdministrator = Test-Administrator
try {
    $script:AuditOutputFolder = New-AuditOutputFolder -ParentPath $OutputPath
}
catch {
    throw ('Could not create the audit output folder: {0}' -f $_.Exception.Message)
}
Initialize-AuditReportBuffers
Write-ModuleHeader '22-Audit-Errors.txt' 'Audit Errors' 'A failed query does not stop the remaining audit modules.'

$modules = @(
    @{ Name='System Information'; Action={ Invoke-SystemInformationAudit } },
    @{ Name='Users and Groups'; Action={ Invoke-UsersAndGroupsAudit } },
    @{ Name='Password and Account Policies'; Action={ Invoke-PasswordPolicyAudit } },
    @{ Name='Local Security Policy'; Action={ Invoke-LocalSecurityPolicyAudit } },
    @{ Name='Firewall'; Action={ Invoke-FirewallAudit } },
    @{ Name='Services'; Action={ Invoke-ServicesAudit } },
    @{ Name='Remote Access'; Action={ Invoke-RemoteAccessAudit } },
    @{ Name='Network and SMB'; Action={ Invoke-NetworkAndSmbAudit } },
    @{ Name='Windows Defender'; Action={ Invoke-WindowsDefenderAudit } },
    @{ Name='Windows Update'; Action={ Invoke-WindowsUpdateAudit } },
    @{ Name='Installed Software'; Action={ Invoke-InstalledSoftwareAudit } },
    @{ Name='Startup and Scheduled Tasks'; Action={ Invoke-StartupAndScheduledTasksAudit } },
    @{ Name='Suspicious Files'; Action={ Invoke-SuspiciousFilesAudit } },
    @{ Name='Permissions'; Action={ Invoke-PermissionsAudit } },
    @{ Name='Network Shares'; Action={ Invoke-NetworkSharesAudit } },
    @{ Name='Registry Security Settings'; Action={ Invoke-RegistrySecuritySettingsAudit } },
    @{ Name='Auditing and Logging'; Action={ Invoke-AuditingAndLoggingAudit } },
    @{ Name='Browser and Proxy Settings'; Action={ Invoke-BrowserAndProxyAudit } },
    @{ Name='Certificates DNS and Hosts'; Action={ Invoke-CertificatesDnsHostsAudit } },
    @{ Name='Recent Security Events'; Action={ Invoke-RecentSecurityEventsAudit } }
)

$moduleNumber = 0
foreach ($moduleDefinition in $modules) {
    $moduleNumber++
    Invoke-AuditModule -Name $moduleDefinition.Name -ScriptBlock $moduleDefinition.Action `
        -Number $moduleNumber -Total $modules.Count
}
Write-Progress -Activity 'CyberPatriot read-only Windows audit' -Completed

$script:AuditComplete = Get-Date
Build-ManualReviewChecklist
Build-CommandLogReport
Build-AuditSummary
Export-AuditReports

$criticalCount = Get-AuditSeverityCount '[CRITICAL]'
$warningCount = Get-AuditSeverityCount '[WARNING]'
$manualCount = Get-AuditSeverityCount '[MANUAL REVIEW]'
$errorCount = Get-AuditSeverityCount '[ERROR]'
$summaryPath = Join-Path $script:AuditOutputFolder '00-Audit-Summary.txt'

Write-Host ''
Write-Host 'Audit completed' -ForegroundColor Green
Write-Host 'No system changes were made.' -ForegroundColor Green
Write-Host ('Output folder: {0}' -f $script:AuditOutputFolder)
Write-Host ('Total findings/checks: {0}' -f $script:Findings.Count)
Write-Host ('Critical findings: {0}' -f $criticalCount)
Write-Host ('Warnings: {0}' -f $warningCount)
Write-Host ('Manual-review findings: {0}' -f $manualCount)
Write-Host ('Errors: {0}' -f $errorCount)
Write-Host ('Summary report: {0}' -f $summaryPath)
Write-Host 'Read the CyberPatriot README before making any change.' -ForegroundColor Yellow
Write-Host 'Make changes manually and one at a time, checking required services and the score after each.' -ForegroundColor Yellow
Write-Host 'Re-run the audit after manual remediation.' -ForegroundColor Yellow

if (-not $DoNotOpenReport) {
    try {
        # This launches Notepad only; it does not run any proposed remediation command.
        Start-Process -FilePath (Join-Path $env:WINDIR 'System32\notepad.exe') -ArgumentList ('"{0}"' -f $summaryPath) -ErrorAction Stop
    }
    catch {
        Write-Warning ('The summary was created but Notepad could not be opened: {0}' -f $_.Exception.Message)
    }
}
