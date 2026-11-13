function Invoke-AuditSoftware {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'Software' 'Installed program inventory' {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $apps = @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object DisplayName |
            Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation,InstallDate | Sort-Object DisplayName,DisplayVersion -Unique)
        Export-Inventory 'installed-programs' $apps $InventoryDir
        Add-Finding $Results 'Software' 'Installed applications' 'INFO' "$($apps.Count) registry entries enumerated" 'Includes only installed-program registry entries; portable apps may be missed.'
        $approved = @(Get-ConfigValues $Config 'RequiredApplications')
        foreach ($name in $approved) {
            $found = @($apps | Where-Object { $_.DisplayName -like "*$name*" })
            Add-Finding $Results 'Software' "Required application: $name" $(if ($found.Count) {'PASS'} else {'REVIEW'}) $(if ($found.Count) { ($found.DisplayName -join ', ') } else { 'Not found in uninstall registry' }) 'Check alternate install locations, versions and app dependencies.'
        }
    }
    Invoke-SafeProbe $Results 'Software' 'Installed Windows updates' {
        $hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 75 HotFixID,Description,InstalledOn,InstalledBy)
        Export-Inventory 'hotfixes' $hotfixes $InventoryDir
        Add-Finding $Results 'Software' 'Hotfix inventory' 'INFO' "$($hotfixes.Count) records exported" 'A hotfix list alone does not prove the system is fully patched.'
    }
    Invoke-SafeProbe $Results 'Software' 'Windows Update service' {
        $service = Get-Service wuauserv -ErrorAction Stop
        Add-Finding $Results 'Software' 'Windows Update service' 'INFO' "Status=$($service.Status); Startup=$($service.StartType)" 'Manual or Trigger Start can be normal on modern Windows. Review effective update policy.'
    }
    Invoke-SafeProbe $Results 'Software' 'Browser policy keys' {
        $policies = @(
            [pscustomobject]@{Browser='Chrome'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'},
            [pscustomobject]@{Browser='Edge'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'},
            [pscustomobject]@{Browser='Firefox'; Path='HKLM:\SOFTWARE\Policies\Mozilla\Firefox'}
        )
        foreach ($policy in $policies) {
            if (Test-Path -LiteralPath $policy.Path) {
                Add-Finding $Results 'Software' "Browser machine policy: $($policy.Browser)" 'INFO' 'Policy registry key exists.' 'Verify effective policies inside browser management UI.'
            } else {
                Add-Finding $Results 'Software' "Browser machine policy: $($policy.Browser)" 'INFO' 'Policy registry key absent.' 'Not necessarily a vulnerability if that browser is not installed.'
            }
        }
    }
}
