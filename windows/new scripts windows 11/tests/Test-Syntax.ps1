[CmdletBinding()]
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
$files = @(Get-ChildItem -LiteralPath $Root -Filter '*.ps1' -File -Recurse)
$fail = 0
foreach ($file in $files) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        Write-Host "FAIL $($file.FullName)" -ForegroundColor Red
        $parseErrors | ForEach-Object { Write-Host "  $($_.Message) at $($_.Extent.StartLineNumber)" }
        $fail++
    } else {
        Write-Host "OK   $($file.FullName)" -ForegroundColor Green
    }
}
if ($fail) { throw "$fail PowerShell files failed parsing." }
Write-Host "Passed syntax check: $($files.Count) PowerShell files."
