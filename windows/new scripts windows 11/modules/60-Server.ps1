function Invoke-AuditServer {
    param($Results, $Config, [string]$InventoryDir)
    if (-not (Test-IsServer)) {
        Add-Finding $Results 'Server' 'Windows Server checks' 'SKIP' 'Detected workstation operating system.' 'Run on a Server practice VM to inspect server roles.'
        return
    }
    Invoke-SafeProbe $Results 'Server' 'Windows roles' {
        if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) { throw 'ServerManager cmdlets unavailable.' }
        $roles = @(Get-WindowsFeature | Where-Object Installed | Select-Object Name,DisplayName,FeatureType,InstallState)
        Export-Inventory 'installed-server-roles' $roles $InventoryDir
        Add-Finding $Results 'Server' 'Installed roles and features' 'INFO' "$($roles.Count) entries exported" 'Verify each role against required workloads.'
    }
    if (Test-IsDC) {
        Invoke-SafeProbe $Results 'Server' 'Active Directory users' {
            Import-Module ActiveDirectory -ErrorAction Stop
            $users = @(Get-ADUser -Filter * -ResultSetSize 500 -Properties Enabled,PasswordNotRequired,PasswordNeverExpires,DoesNotRequirePreAuth,ServicePrincipalName |
                Select-Object SamAccountName,Enabled,PasswordNotRequired,PasswordNeverExpires,DoesNotRequirePreAuth,@{Name='HasSPN';Expression={@($_.ServicePrincipalName).Count -gt 0}})
            Export-Inventory 'ad-users' $users $InventoryDir
            foreach ($u in $users) {
                if ($u.PasswordNotRequired -or $u.DoesNotRequirePreAuth -or $u.PasswordNeverExpires) {
                    Add-Finding $Results 'Server' "AD account flags: $($u.SamAccountName)" 'REVIEW' "PasswordNotRequired=$($u.PasswordNotRequired); NeverExpires=$($u.PasswordNeverExpires); NoKerberosPreAuth=$($u.DoesNotRequirePreAuth); HasSPN=$($u.HasSPN)" 'Investigate legitimate service principals and account requirements.'
                }
            }
            $admins = @(Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction Stop | Select-Object Name,SamAccountName,ObjectClass)
            Export-Inventory 'domain-admins' $admins $InventoryDir
            Add-Finding $Results 'Server' 'Domain Admins' 'INFO' "$($admins.Count) members enumerated" 'Compare with approved administrative roles.'
        }
        Invoke-SafeProbe $Results 'Server' 'Domain password policy' {
            $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop | Select-Object MinPasswordLength,ComplexityEnabled,PasswordHistoryCount,LockoutThreshold,MaxPasswordAge,MinPasswordAge,ReversibleEncryptionEnabled
            Export-Inventory 'domain-password-policy' @($policy) $InventoryDir
            Add-Finding $Results 'Server' 'AD domain password policy' 'INFO' 'Policy exported to inventory.' 'Domain Group Policy can supersede local security settings.'
        }
    }
    Invoke-SafeProbe $Results 'Server' 'DNS zones' {
        if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { return }
        $zones = @(Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName,ZoneType,IsDsIntegrated,DynamicUpdate,SecureSecondaries)
        Export-Inventory 'dns-zones' $zones $InventoryDir
        foreach ($z in $zones) {
            if ("$($z.SecureSecondaries)" -eq 'TransferAnyServer' -or
                "$($z.DynamicUpdate)" -eq 'NonsecureAndSecure') {
                Add-Finding $Results 'Server' "DNS zone: $($z.ZoneName)" 'REVIEW' "Transfer=$($z.SecureSecondaries); Updates=$($z.DynamicUpdate)" 'Review zone transfers and dynamic updates against DNS architecture.'
            }
        }
    }
    Invoke-SafeProbe $Results 'Server' 'DHCP scopes' {
        if (-not (Get-Command Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) { return }
        $scopes = @(Get-DhcpServerv4Scope -ErrorAction Stop | Select-Object ScopeId,Name,StartRange,EndRange,State)
        Export-Inventory 'dhcp-scopes' $scopes $InventoryDir
        Add-Finding $Results 'Server' 'DHCP scopes' 'INFO' "$($scopes.Count) scopes enumerated" 'Review scope ranges and required operation.'
    }
    Invoke-SafeProbe $Results 'Server' 'IIS websites and app pools' {
        if (-not (Get-Command Get-Website -ErrorAction SilentlyContinue)) { Import-Module WebAdministration -ErrorAction Stop }
        $sites = @(Get-Website -ErrorAction Stop | Select-Object Name,State,PhysicalPath,@{Name='Bindings';Expression={($_.Bindings.Collection | ForEach-Object bindingInformation) -join ';'}})
        Export-Inventory 'iis-websites' $sites $InventoryDir
        $pools = @(Get-ChildItem IIS:\AppPools | Select-Object Name,State,@{Name='IdentityType';Expression={$_.processModel.identityType}})
        Export-Inventory 'iis-app-pools' $pools $InventoryDir
        Add-Finding $Results 'Server' 'IIS sites and pools' 'INFO' "$($sites.Count) sites, $($pools.Count) pools" 'Inspect authentication, HTTPS, directory browsing, and app pool identities; never elevate app pools to LocalSystem as a blanket fix.'
    }
}
