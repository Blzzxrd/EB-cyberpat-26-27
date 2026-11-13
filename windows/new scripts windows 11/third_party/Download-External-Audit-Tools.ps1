<#
.SYNOPSIS
    Download selected public Windows security auditing tools for lab review only.
.DESCRIPTION
    This downloader NEVER executes downloaded code and does not change Windows security settings.
    Files are pinned to published Git commits so upstream changes cannot silently replace them.
    Fetching a tool does not grant permissions beyond its license: inspect each source LICENSE.
    Use outside CyberPatriot scored rounds and on devices you own or are authorized to administer.
.EXAMPLE
    .\Download-External-Audit-Tools.ps1 -Tool HardeningKitty
.EXAMPLE
    .\Download-External-Audit-Tools.ps1 -Tool All
#>
[CmdletBinding()]
param(
    [ValidateSet('All','HardeningKitty','BaselineAuditor','UserAudit','RdpDiagnostics','HostInventory')]
    [string[]]$Tool = @('HardeningKitty'),
    [string]$Destination = (Join-Path $PSScriptRoot 'optional')
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Pinned commits keep downloads reproducible; downloaded code is never executed here.
$catalog = [ordered]@{
    HardeningKitty = @{
        Repo='0x6d69636b/windows_hardening'; Commit='10c17aea783ab27fcea8c27c4c0dc3d3edf8bcca'; License='MIT';
        Files=@('HardeningKitty.psm1','HardeningKitty.psd1','LICENSE','lists/finding_list_0x6d69636b_machine.csv','lists/finding_list_0x6d69636b_user.csv','lists/hardeningkitty_lists_manifest.psd1','lists/hardeningkitty_lists_manifest.psd1.p7s')
    }
    BaselineAuditor = @{
        Repo='Coach40oz/Windows-SecurityBaselineAuditor'; Commit='9f3373d9f5a882c1fa5db88da3a642e680c02331'; License='MIT claimed in README; no root LICENSE observed';
        Files=@('script.ps1','README.md')
    }
    UserAudit = @{
        Repo='Nihar2520/Windows-User-Audit'; Commit='3428fb6f9abaeef5aaf494dc1c566a59818d26c5'; License='No license identified; use subject to permission';
        Files=@('LocalUserSnapshot.ps1','diff_snapshots.ps1','README.md')
    }
    RdpDiagnostics = @{
        Repo='paulmann/RDP-Diagnostic-Tool'; Commit='8db4c169ec0de050fb48224db729fde66219671c'; License='PolyForm Noncommercial 1.0.0';
        Files=@('RDP-Tool.ps1','LICENSE','README.md')
    }
    HostInventory = @{
        Repo='emoghadamian/host-inventory'; Commit='ae3a5a6cb7beb9e63c2f9ab46cbb2c6f2e42fc4a'; License='No license identified; use subject to permission';
        Files=@('host_inventory.ps1','windows_suspicious_tasks.csv','README.md')
    }
}
$selection = if ($Tool -contains 'All') { @($catalog.Keys) } else { @($Tool | Select-Object -Unique) }
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$report = [System.Collections.Generic.List[object]]::new()
foreach ($name in $selection) {
    $item = $catalog[$name]
    Write-Host "Downloading $name from $($item.Repo)@$($item.Commit)" -ForegroundColor Cyan
    foreach ($relative in $item.Files) {
        # Reject path traversals even if the manifest changes in a future revision.
        if ($relative -match '(^/|^\\|\.\.)') { throw "Unsafe file path in catalog: $relative" }
        $rel = $relative -replace '\\','/'
        $escapedPath = (($rel -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
        $url = 'https://raw.githubusercontent.com/{0}/{1}/{2}' -f $item.Repo,$item.Commit,$escapedPath
        $file = Join-Path (Join-Path $Destination $name) ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
        $dir = Split-Path -Parent $file
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $file -ErrorAction Stop
            $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
            [void]$report.Add([pscustomobject]@{Tool=$name;Repo=$item.Repo;Commit=$item.Commit;File=$relative;SHA256=$hash;License=$item.License;Download='OK'})
            Write-Host "  OK $relative"
        } catch {
            [void]$report.Add([pscustomobject]@{Tool=$name;Repo=$item.Repo;Commit=$item.Commit;File=$relative;SHA256='';License=$item.License;Download=$_.Exception.Message})
            Write-Warning "Failed $relative : $($_.Exception.Message)"
        }
    }
}
$manifest = Join-Path $Destination 'downloads.csv'
$report | Export-Csv -LiteralPath $manifest -NoTypeInformation -Encoding UTF8
Write-Host "Files downloaded only; NONE have been executed. Verify contents and license. Manifest: $manifest" -ForegroundColor Green
