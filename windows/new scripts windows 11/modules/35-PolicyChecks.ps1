function Invoke-AuditPolicyChecks {
    param($Results, $Config, [string]$InventoryDir)
    $targetProp = $Config.PSObject.Properties['PolicyTargets']
    $auditProp = $Config.PSObject.Properties['AuditSubcategoryTargets']
    $rightsProp = $Config.PSObject.Properties['UserRightMustInclude']
    $registryProp = $Config.PSObject.Properties['RegistryPolicyTargets']
    if ((-not $targetProp -or -not $targetProp.Value) -and (-not $auditProp -or -not $auditProp.Value) -and (-not $rightsProp -or -not $rightsProp.Value) -and (-not $registryProp -or -not $registryProp.Value)) {
        Add-Finding $Results 'PolicyChecks' 'Baseline comparison' 'SKIP' 'No expected policy values configured.' 'Add a lab baseline; do not assume a particular CIS benchmark fits every server role.'
        return
    }
    Invoke-SafeProbe $Results 'PolicyChecks' 'Secedit policy' {
        $policy = Join-Path $InventoryDir 'policy-checks-export.inf'
        & secedit.exe /export /cfg $policy /quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $policy)) { throw 'secedit export failed' }
        # Secedit typically uses UTF-16LE and can emit BOM-less UTF-16. Detect both.
        $bytes = [IO.File]::ReadAllBytes($policy)
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) { $raw = [Text.Encoding]::Unicode.GetString($bytes,2,$bytes.Length-2) }
        elseif ($bytes.Length -ge 4 -and $bytes[1] -eq 0 -and $bytes[3] -eq 0) { $raw = [Text.Encoding]::Unicode.GetString($bytes) }
        else { $raw = [Text.Encoding]::UTF8.GetString($bytes) }
        $values = @{}
        $section = ''
        foreach ($line in ($raw -split "`r?`n")) {
            if ($line -match '^\s*\[(.+)\]\s*$') { $section=$matches[1]; continue }
            if ($line -match '^\s*([^#;=][^=]*?)\s*=\s*(.*?)\s*$') { $values["$section|$($matches[1].Trim())"]=$matches[2].Trim() }
        }
        if ($targetProp -and $targetProp.Value) {
            foreach ($p in $targetProp.Value.PSObject.Properties) {
                $key='System Access|' + $p.Name
                $actual = if ($values.ContainsKey($key)) { $values[$key] } else { $null }
                if ($null -eq $actual) { Add-Finding $Results 'PolicyChecks' $p.Name 'REVIEW' 'Setting not found in security-policy export.' 'Check domain policy/effective policy.'; continue }
                $desired = $p.Value
                $min = $desired.PSObject.Properties['Minimum']
                $max = $desired.PSObject.Properties['Maximum']
                $eq  = $desired.PSObject.Properties['Equals']
                $ok = $false
                if ($min) { try { $ok = [double]$actual -ge [double]$min.Value } catch {} }
                elseif ($max) { try { $ok = [double]$actual -le [double]$max.Value } catch {} }
                elseif ($eq) { $ok = "$actual" -eq "$($eq.Value)" }
                else { $ok = "$actual" -eq "$desired" }
                Add-Finding $Results 'PolicyChecks' $p.Name $(if ($ok) {'PASS'} else {'WARN'}) "Actual=$actual; Target=$($desired | ConvertTo-Json -Compress)" 'Baseline values are role-dependent; do not auto-remediate.'
            }
        }
        if ($rightsProp -and $rightsProp.Value) {
            foreach ($p in $rightsProp.Value.PSObject.Properties) {
                $key='Privilege Rights|' + $p.Name
                if (-not $values.ContainsKey($key)) { Add-Finding $Results 'PolicyChecks' "User right: $($p.Name)" 'REVIEW' 'Not specified in export' ''; continue }
                $actual = @($values[$key] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') })
                foreach ($principal in @($p.Value)) {
                    $expect = "$principal".TrimStart('*')
                    Add-Finding $Results 'PolicyChecks' "User right: $($p.Name) / $principal" $(if ($actual -contains $expect) {'PASS'} else {'WARN'}) "Current: $($actual -join ', ')" 'Verify SID mapping and required service identities before changes.'
                }
            }
        }
    }
    if ($registryProp -and $registryProp.Value) {
        Invoke-SafeProbe $Results 'PolicyChecks' 'Registry-based security options' {
            foreach ($p in @($registryProp.Value)) {
                $path = [string]$p.Path
                $name = [string]$p.Name
                $expected = "$($p.Equals)"
                try {
                    $actual = Get-ItemPropertyValue -LiteralPath $path -Name $name -ErrorAction Stop
                    Add-Finding $Results 'PolicyChecks' "Registry: $path / $name" $(if ("$actual" -eq $expected) {'PASS'} else {'WARN'}) "Actual=$actual; Expected=$expected" 'Registry policy can be overridden by effective domain Group Policy.'
                } catch { Add-Finding $Results 'PolicyChecks' "Registry: $path / $name" 'REVIEW' $_.Exception.Message 'Absent value is not automatically noncompliant: verify effective policy.' }
            }
        }
    }
    if ($auditProp -and $auditProp.Value) {
        Invoke-SafeProbe $Results 'PolicyChecks' 'Advanced audit subcategory' {
            foreach ($a in @($auditProp.Value)) {
                $name = [string]$a.Name
                if (-not $name) { continue }
                $output = @(& auditpol.exe /get "/subcategory:$name" 2>&1)
                if ($LASTEXITCODE -ne 0) { Add-Finding $Results 'PolicyChecks' "Audit: $name" 'REVIEW' ($output -join ' ') 'Auditpol output may be localized or the subcategory absent.'; continue }
                $joined = $output -join ' '
                $status = if ($joined -match 'Success and Failure') {'both'} elseif ($joined -match 'Success') {'success'} elseif ($joined -match 'Failure') {'failure'} elseif ($joined -match 'No Auditing') {'none'} else {'unknown'}
                $ok = (-not $a.RequireSuccess -or $status -in @('success','both')) -and (-not $a.RequireFailure -or $status -in @('failure','both'))
                Add-Finding $Results 'PolicyChecks' "Audit: $name" $(if ($status -eq 'unknown') {'REVIEW'} elseif ($ok) {'PASS'} else {'WARN'}) "Read=$status; NeedSuccess=$($a.RequireSuccess); NeedFailure=$($a.RequireFailure)" 'Auditpol parsing assumes an English Windows locale; inspect raw auditpol report as necessary.'
            }
        }
    }
}
