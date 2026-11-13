function Invoke-AuditAccounts {
    param($Results, $Config, [string]$InventoryDir)
    if (Test-IsDC) {
        Add-Finding $Results 'Accounts' 'Local account inspection' 'SKIP' 'Domain controller detected; local SAM operations are not applicable.' 'Review AD inventory in Server module.'
        return
    }
    Invoke-SafeProbe $Results 'Accounts' 'Local account inventory' {
        if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) { throw 'Get-LocalUser unavailable.' }
        $accounts = @(Get-LocalUser | Select-Object Name,Enabled,Description,PasswordRequired,PasswordExpires,PasswordLastSet,LastLogon,SID)
        Export-Inventory 'local-users' $accounts $InventoryDir
        $authorized = @(Get-ConfigValues $Config 'AuthorizedLocalUsers')
        foreach ($user in $accounts) {
            if ($authorized.Count -gt 0 -and $authorized -notcontains $user.Name -and $user.Name -notin @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')) {
                Add-Finding $Results 'Accounts' "Unlisted account: $($user.Name)" 'REVIEW' "Enabled=$($user.Enabled)" 'Determine purpose, service dependencies, and ownership before taking action.'
            }
            if ($user.PasswordRequired -eq $false -and $user.Enabled) {
                Add-Finding $Results 'Accounts' "Password requirement: $($user.Name)" 'REVIEW' 'Enabled account does not require a password.' 'Investigate account policy and exceptions.'
            }
        }
        Add-Finding $Results 'Accounts' 'Local accounts' 'INFO' "$($accounts.Count) accounts enumerated" 'Check authorized and service identities against the lab scenario.'
    }
    Invoke-SafeProbe $Results 'Accounts' 'Local groups' {
        $output = @()
        foreach ($group in @('Administrators','Remote Desktop Users','Backup Operators','Power Users')) {
            try {
                $members = @(Get-LocalGroupMember -Group $group -ErrorAction Stop)
                foreach ($member in $members) {
                    $output += [pscustomobject]@{
                        Group       = $group
                        Member      = $member.Name
                        ObjectClass = $member.ObjectClass
                        Source      = $member.PrincipalSource
                    }
                }
            } catch {
                Add-Finding $Results 'Accounts' "Group $group" 'REVIEW' $_.Exception.Message 'Use localized group name or inspect membership with system administration tools.'
            }
        }
        Export-Inventory 'local-group-members' $output $InventoryDir
        $expectedAdmins = @(Get-ConfigValues $Config 'ExpectedAdmins')
        foreach ($member in ($output | Where-Object Group -eq 'Administrators')) {
            if ($expectedAdmins.Count -gt 0 -and $expectedAdmins -notcontains $member.Member) {
                Add-Finding $Results 'Accounts' 'Administrator group member' 'REVIEW' $member.Member 'Investigate membership; do not remove service or built-in principals automatically.'
            }
        }
    }
}
