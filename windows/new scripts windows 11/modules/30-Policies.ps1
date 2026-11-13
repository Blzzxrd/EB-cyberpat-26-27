function Invoke-AuditPolicies {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'Policies' 'Local password policy' {
        $path = Join-Path $InventoryDir 'local-security-policy.inf'
        & secedit.exe /export /cfg $path /quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $path)) { throw "secedit export failed: exit code $LASTEXITCODE" }
        $settings = @{}
        Get-Content -LiteralPath $path | ForEach-Object {
            if ($_ -match '^\s*([^;#=\[][^=]*)\s*=\s*(.*?)\s*$') { $settings[$matches[1].Trim()] = $matches[2].Trim() }
        }
        foreach ($k in @('MinimumPasswordLength','PasswordComplexity','PasswordHistorySize','MaximumPasswordAge','MinimumPasswordAge','ClearTextPassword','LockoutBadCount','ResetLockoutCount','LockoutDuration')) {
            if ($settings.ContainsKey($k)) {
                Add-Finding $Results 'Policies' $k 'INFO' $settings[$k] 'Compare with the lab baseline and domain policy if domain joined.'
            } else {
                Add-Finding $Results 'Policies' $k 'REVIEW' 'Not present in export' 'Use effective account policy and domain/GPO inspection.'
            }
        }
        if ($settings.ContainsKey('ClearTextPassword') -and $settings['ClearTextPassword'] -eq '1') {
            Add-Finding $Results 'Policies' 'Reversible password storage' 'WARN' 'Enabled' 'Review reversible-encryption requirement; prefer disabled.'
        }
    }
    Invoke-SafeProbe $Results 'Policies' 'Advanced audit policy' {
        $path = Join-Path $InventoryDir 'advanced-audit-policy.txt'
        $audit = & auditpol.exe /get /category:* 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol failed with exit code $LASTEXITCODE" }
        $audit | Out-File -LiteralPath $path -Encoding UTF8
        Add-Finding $Results 'Policies' 'Advanced audit policy' 'INFO' ('Report: ' + $path) 'Review success/failure settings and applicability for the system role.'
    }
    Invoke-SafeProbe $Results 'Policies' 'Group Policy' {
        $path = Join-Path $InventoryDir 'computer-gpo.txt'
        & gpresult.exe /scope computer /r 2>&1 | Out-File -LiteralPath $path -Encoding UTF8
        Add-Finding $Results 'Policies' 'Effective Group Policy' 'INFO' ('Report: ' + $path) 'Domain GPO may override local policy settings.'
    }
}
