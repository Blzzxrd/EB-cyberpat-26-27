function Invoke-AuditScenarioChecks {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'ScenarioChecks' 'Required local users and groups' {
        if (Test-IsDC) { Add-Finding $Results 'ScenarioChecks' 'Local SAM' 'SKIP' 'Domain controller; use AD role-specific inventory.' ''; return }
        $actual = @(Get-LocalUser -ErrorAction Stop | Select-Object -ExpandProperty Name)
        foreach ($expected in @(Get-ConfigValues $Config 'AuthorizedLocalUsers')) {
            Add-Finding $Results 'ScenarioChecks' "Authorized user: $expected" $(if ($actual -contains $expected) {'PASS'} else {'WARN'}) $(if ($actual -contains $expected) {'Present'} else {'Missing'}) 'Inspect the scenario before creating or changing a local user.'
        }
        $list = @()
        $groupMap = $Config.PSObject.Properties['RequiredGroups']
        if ($groupMap -and $groupMap.Value) {
            foreach ($entry in $groupMap.Value.PSObject.Properties) {
                $name = [string]$entry.Name
                $expectedMembers = @($entry.Value)
                try {
                    $group = Get-LocalGroup -Name $name -ErrorAction Stop
                    Add-Finding $Results 'ScenarioChecks' "Required group: $name" 'PASS' 'Group exists.' ''
                    $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop | ForEach-Object Name)
                    foreach ($member in $expectedMembers) {
                        $shortName = "$member".Split([char]92)[-1]
                        $found = @($members | Where-Object { $_ -ieq $member -or $_.Split([char]92)[-1] -ieq $shortName }).Count -gt 0
                        Add-Finding $Results 'ScenarioChecks' "Group $name / member $member" $(if ($found) {'PASS'} else {'WARN'}) $(if ($found) {'Present'} else {'Not found'}) 'Check expected scope/domain before changing membership.'
                    }
                    $list += @($members | ForEach-Object { [pscustomobject]@{Group=$name;Member=$_} })
                } catch { Add-Finding $Results 'ScenarioChecks' "Required group: $name" 'REVIEW' $_.Exception.Message 'Check local vs domain group naming and permissions.' }
            }
        }
        Export-Inventory 'scenario-groups' @($list) $InventoryDir
    }
    Invoke-SafeProbe $Results 'ScenarioChecks' 'Required shares and service restrictions' {
        foreach ($name in @(Get-ConfigValues $Config 'RequiredShares')) {
            try {
                $s = Get-SmbShare -Name $name -ErrorAction Stop
                Add-Finding $Results 'ScenarioChecks' "Required share: $name" 'PASS' "Path=$($s.Path)" ''
            } catch { Add-Finding $Results 'ScenarioChecks' "Required share: $name" 'WARN' 'Not found, or SMB management unavailable.' 'Check the scenario and Server service requirements.' }
        }
        foreach ($name in @(Get-ConfigValues $Config 'ProhibitedServices')) {
            try {
                $service = Get-Service -Name $name -ErrorAction Stop
                Add-Finding $Results 'ScenarioChecks' "Prohibited service: $name" $(if ($service.Status -eq 'Running') {'WARN'} else {'REVIEW'}) "Status=$($service.Status); Startup=$($service.StartType)" 'Check dependencies and policy before any changes.'
            } catch { Add-Finding $Results 'ScenarioChecks' "Prohibited service: $name" 'PASS' 'Not installed (or unavailable).' '' }
        }
    }
    Invoke-SafeProbe $Results 'ScenarioChecks' 'Application versions and paths' {
        $prop = $Config.PSObject.Properties['RequiredApplicationDetails']
        if (-not $prop -or -not $prop.Value) { Add-Finding $Results 'ScenarioChecks' 'Application requirements' 'SKIP' 'No RequiredApplicationDetails configured.' ''; return }
        $registry = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $apps = @(Get-ItemProperty -Path $registry -ErrorAction SilentlyContinue | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,InstallLocation,Publisher)
        $output = @()
        foreach ($requirement in @($prop.Value)) {
            $name = [string]$requirement.Name
            if (-not $name) { continue }
            # Literal substring; avoid pattern metacharacters in application names.
            $matches = @($apps | Where-Object { $_.DisplayName.IndexOf($name,[StringComparison]::OrdinalIgnoreCase) -ge 0 })
            $output += $matches
            if ($matches.Count -eq 0) { Add-Finding $Results 'ScenarioChecks' "Required software: $name" 'REVIEW' 'No matching uninstall-registry entry' 'Portable applications and per-user installations may not appear here.'; continue }
            $minVersion = [string]$requirement.MinimumVersion
            $requiredPath = [string]$requirement.InstallPathContains
            $versionMatch = $false
            $pathMatch = $false
            foreach ($app in $matches) {
                if (-not $minVersion) {
                    $versionMatch = $true
                } else {
                    try {
                        if ([version]$app.DisplayVersion -ge [version]$minVersion) { $versionMatch = $true }
                    } catch {
                        Add-Finding $Results 'ScenarioChecks' "Version parse: $name" 'REVIEW' $app.DisplayVersion 'Check vendor version convention manually.'
                    }
                }
                if (-not $requiredPath -or ($app.InstallLocation -and $app.InstallLocation.IndexOf($requiredPath,[StringComparison]::OrdinalIgnoreCase) -ge 0)) { $pathMatch = $true }
            }
            Add-Finding $Results 'ScenarioChecks' "Application version: $name" $(if ($versionMatch) {'PASS'} else {'WARN'}) "Detected=$(@($matches | ForEach-Object DisplayVersion) -join ', '); Minimum=$minVersion" 'Review precise vendor version requirements.'
            Add-Finding $Results 'ScenarioChecks' "Application location: $name" $(if ($pathMatch) {'PASS'} else {'REVIEW'}) "Expected substring=$requiredPath; Detected=$(@($matches | ForEach-Object InstallLocation) -join ', ')" 'A blank InstallLocation registry field does not prove a missing app.'
        }
        Export-Inventory 'scenario-required-applications' @($output) $InventoryDir
    }
}
