function Invoke-AuditNetwork {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'Network' 'Listening TCP ports' {
        if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { throw 'Get-NetTCPConnection unavailable.' }
        $processes = @(Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath)
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $items = @($listeners | ForEach-Object {
            $port = $_
            $owner = $processes | Where-Object ProcessId -eq $port.OwningProcess | Select-Object -First 1
            [pscustomobject]@{
                Address    = $port.LocalAddress
                Port       = $port.LocalPort
                Pid        = $port.OwningProcess
                Process    = $(if ($owner) { $owner.Name } else { '' })
                Executable = $(if ($owner) { $owner.ExecutablePath } else { '' })
            }
        })
        Export-Inventory 'listening-tcp' $items $InventoryDir
        foreach ($item in $items) {
            if (Test-SuspiciousPath $item.Executable) { Add-Finding $Results 'Network' 'Listener in user-writable path' 'REVIEW' "$($item.Process) $($item.Address):$($item.Port) $($item.Executable)" 'Investigate publisher and purpose before taking action.' }
        }
        Add-Finding $Results 'Network' 'Listening ports' 'INFO' "$($items.Count) TCP listeners enumerated" 'Review exposed services and expected ports.'
    }
    Invoke-SafeProbe $Results 'Network' 'SMB server settings' {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        Export-Inventory 'smb-server-config' @($smb | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,EncryptData,RejectUnencryptedAccess) $InventoryDir
        Add-Finding $Results 'Network' 'SMBv1 server support' $(if ($smb.EnableSMB1Protocol) { 'REVIEW' } else { 'PASS' }) "Enabled=$($smb.EnableSMB1Protocol)" 'Legacy applications may depend on SMBv1; evaluate upgrade and dependencies.'
        Add-Finding $Results 'Network' 'SMB server signing' 'INFO' "Required=$($smb.RequireSecuritySignature)" 'Review server/client and domain policy expectations.'
    }
    Invoke-SafeProbe $Results 'Network' 'SMB shares and permissions' {
        $shares = @(Get-SmbShare -ErrorAction Stop)
        Export-Inventory 'smb-shares' @($shares | Select-Object Name,Path,Description,Special,CurrentUsers) $InventoryDir
        $access = @()
        foreach ($share in $shares) {
            try {
                foreach ($entry in @(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop)) {
                    $access += [pscustomobject]@{Share=$share.Name; Account=$entry.AccountName; AccessRight=$entry.AccessRight; AccessControlType=$entry.AccessControlType}
                }
            } catch {
                Add-Finding $Results 'Network' "Share permissions: $($share.Name)" 'REVIEW' $_.Exception.Message 'Inspect share and filesystem ACLs manually.'
            }
        }
        Export-Inventory 'smb-share-acls' $access $InventoryDir
        $required = @(Get-ConfigValues $Config 'RequiredShares')
        foreach ($share in $shares) {
            if ($required.Count -gt 0 -and $required -notcontains $share.Name -and -not $share.Special) {
                Add-Finding $Results 'Network' 'Unlisted non-system share' 'REVIEW' "$($share.Name) => $($share.Path)" 'Check share purpose and connected users; preserve data.'
            }
        }
    }
    Invoke-SafeProbe $Results 'Network' 'Remote access configuration' {
        $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
        $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
        if ($ts) {
            $enabled = $ts.fDenyTSConnections -eq 0
            $nla = if ($rdp) { $rdp.UserAuthentication } else { 'unknown' }
            Add-Finding $Results 'Network' 'Remote Desktop' 'INFO' "Enabled=$enabled; NLA=$nla" 'Match remote access to scenario requirements; do not cut off remote administration.'
        }
        $assistance = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue
        if ($assistance) { Add-Finding $Results 'Network' 'Remote Assistance' 'INFO' "Allow connections=$($assistance.fAllowToGetHelp)" 'Review whether assistance is required.' }
    }
    Invoke-SafeProbe $Results 'Network' 'Hosts file' {
        $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        $custom = @(Get-Content -LiteralPath $path -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*(#.*)?$' })
        if ($custom.Count) { Add-Finding $Results 'Network' 'Custom hosts entries' 'REVIEW' ($custom -join '; ') 'Verify against legitimate local overrides; do not reset blindly.' }
    }
}
