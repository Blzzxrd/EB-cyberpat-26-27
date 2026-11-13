function Invoke-AuditProtection {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'Protection' 'Firewall' {
        if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { throw 'Firewall PowerShell cmdlets unavailable.' }
        $profiles = @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked,LogAllowed,LogMaxSizeKilobytes)
        Export-Inventory 'firewall-profiles' $profiles $InventoryDir
        foreach ($p in $profiles) {
            Add-Finding $Results 'Protection' "Firewall profile: $($p.Name)" $(if ($p.Enabled) { 'PASS' } else { 'WARN' }) "Enabled=$($p.Enabled); In=$($p.DefaultInboundAction); Out=$($p.DefaultOutboundAction)" 'Review effective Group Policy and required application rules.'
        }
        $allow = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop | Select-Object Name,DisplayName,Profile,PolicyStoreSourceType)
        Export-Inventory 'enabled-inbound-allow-rules' $allow $InventoryDir
        Add-Finding $Results 'Protection' 'Inbound allow rules' 'INFO' "$($allow.Count) enabled allow rules" 'Check whether rules match required roles; do not bulk delete.'
    }
    Invoke-SafeProbe $Results 'Protection' 'Microsoft Defender' {
        if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { throw 'Defender cmdlets unavailable.' }
        $status = Get-MpComputerStatus -ErrorAction Stop
        $pref = Get-MpPreference -ErrorAction Stop
        $out = [pscustomobject]@{
            AntivirusEnabled=$status.AntivirusEnabled
            RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled
            BehaviorMonitorEnabled=$status.BehaviorMonitorEnabled
            AntivirusSignatureLastUpdated=$status.AntivirusSignatureLastUpdated
            DisableRealtimeMonitoring=$pref.DisableRealtimeMonitoring
            ExclusionPathCount=@($pref.ExclusionPath).Count
            ExclusionProcessCount=@($pref.ExclusionProcess).Count
            ExclusionExtensionCount=@($pref.ExclusionExtension).Count
        }
        Export-Inventory 'defender-status' @($out) $InventoryDir
        Add-Finding $Results 'Protection' 'Defender real-time protection' $(if ($status.RealTimeProtectionEnabled) {'PASS'} else {'REVIEW'}) "Enabled=$($status.RealTimeProtectionEnabled)" 'Inspect installed AV products, Defender policy, and legitimate exclusions.'
        Add-Finding $Results 'Protection' 'Defender exclusions' 'INFO' ("Paths=$($out.ExclusionPathCount), processes=$($out.ExclusionProcessCount), extensions=$($out.ExclusionExtensionCount)") 'Sensitive exclusion paths are intentionally omitted from reports; review locally.'
    }
    Invoke-SafeProbe $Results 'Protection' 'Windows event logs' {
        $events = @('Security','System','Application') | ForEach-Object {
            $log = Get-WinEvent -ListLog $_ -ErrorAction Stop
            [pscustomobject]@{Name=$log.LogName; Enabled=$log.IsEnabled; MaximumSizeInBytes=$log.MaximumSizeInBytes; Mode=$log.LogMode}
        }
        Export-Inventory 'windows-event-logs' @($events) $InventoryDir
        foreach ($log in $events) {
            if (-not $log.Enabled) {
                Add-Finding $Results 'Protection' "Log disabled: $($log.Name)" 'REVIEW' 'Disabled' 'Consider logging requirements and retention policy.'
            }
        }
    }
    Invoke-SafeProbe $Results 'Protection' 'Drive encryption status' {
        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $volumes = @(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,ProtectionStatus,VolumeStatus,EncryptionMethod)
            Export-Inventory 'bitlocker' $volumes $InventoryDir
        }
    }
}
