function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Results,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [ValidateSet('INFO','PASS','REVIEW','WARN','ERROR','SKIP')][string]$Status = 'INFO',
        [string]$Evidence = '',
        [string]$Recommendation = ''
    )
    [void]$Results.Add([pscustomobject]@{
        Category = $Category
        Check = $Check
        Status = $Status
        Evidence = $Evidence
        Recommendation = $Recommendation
    })
}
function Export-Inventory {
    param([string]$Name, [object[]]$Items, [string]$InventoryDir)
    $path = Join-Path $InventoryDir ($Name + '.csv')
    if ($null -eq $Items -or $Items.Count -eq 0) {
        'No items returned.' | Set-Content -LiteralPath ($path -replace '\.csv$','.txt') -Encoding UTF8
        return
    }
    $Items | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
}
function Get-ConfigValues {
    param([object]$Config, [string]$Name)
    if (-not $Config) { return @() }
    $p = $Config.PSObject.Properties[$Name]
    if (-not $p -or $null -eq $p.Value) { return @() }
    @($p.Value | Where-Object { $null -ne $_ -and ("$_").Trim() })
}
function Invoke-SafeProbe {
    param([System.Collections.Generic.List[object]]$Results, [string]$Category, [string]$Check, [scriptblock]$Probe)
    try {
        & $Probe
    } catch {
        Add-Finding -Results $Results -Category $Category -Check $Check -Status 'ERROR' -Evidence $_.Exception.Message -Recommendation 'Inspect manually or rerun with sufficient read permissions.'
    }
}
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}
function Test-IsServer {
    try { return (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType -ne 1 }
    catch { return $false }
}
function Test-IsDC {
    try { return (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType -eq 2 }
    catch { return $false }
}
function Test-SuspiciousPath {
    param([string]$Path)
    return ($Path -match '(?i)\\Users\\[^\\]+\\(AppData|Downloads|Desktop)\\|\\Windows\\Temp\\|\\Temp\\|\\Users\\Public\\')
}
