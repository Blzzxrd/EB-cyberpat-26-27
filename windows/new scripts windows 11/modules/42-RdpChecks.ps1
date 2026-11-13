function Invoke-AuditRdpChecks {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'RdpChecks' 'RDP configuration' {
        $locations = @(
            [pscustomobject]@{Kind='Local';Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';Properties=@('fDenyTSConnections')},
            [pscustomobject]@{Kind='Local listener';Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp';Properties=@('UserAuthentication','SecurityLayer','MinEncryptionLevel','PortNumber')},
            [pscustomobject]@{Kind='Group Policy';Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services';Properties=@('fDenyTSConnections','UserAuthentication','SecurityLayer','MinEncryptionLevel')}
        )
        $list = @()
        foreach ($location in $locations) {
            foreach ($name in $location.Properties) {
                try {
                    $value = Get-ItemPropertyValue -LiteralPath $location.Path -Name $name -ErrorAction Stop
                    $list += [pscustomobject]@{Source=$location.Kind;Setting=$name;Value=$value;Path=$location.Path}
                    Add-Finding $Results 'RdpChecks' "$($location.Kind) $name" 'INFO' "$value" 'A Group Policy value may override the local listener configuration.'
                } catch { Add-Finding $Results 'RdpChecks' "$($location.Kind) $name" 'INFO' 'Not configured or not accessible' '' }
            }
        }
        Export-Inventory 'rdp-policy-values' @($list) $InventoryDir
        $localNla = $list | Where-Object { $_.Source -eq 'Local listener' -and $_.Setting -eq 'UserAuthentication' } | Select-Object -First 1
        $gpNla = $list | Where-Object { $_.Source -eq 'Group Policy' -and $_.Setting -eq 'UserAuthentication' } | Select-Object -First 1
        $effectiveNla = if ($gpNla) { $gpNla.Value } elseif ($localNla) { $localNla.Value } else { $null }
        if ($null -ne $effectiveNla -and [int]$effectiveNla -ne 1) {
            Add-Finding $Results 'RdpChecks' 'Network Level Authentication' 'REVIEW' "Effective NLA may be disabled: $effectiveNla" 'Review if RDP is enabled or required; do not disable critical remote access.'
        }
        $rdp = Get-Service -Name TermService -ErrorAction SilentlyContinue
        if ($rdp) { Add-Finding $Results 'RdpChecks' 'Remote Desktop Services status' 'INFO' "Status=$($rdp.Status); Startup=$($rdp.StartType)" '' }
    }
}
