function Invoke-AuditSystem {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'System' 'OS inventory' {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        Add-Finding $Results 'System' 'Operating system' 'INFO' ("$($os.Caption); version $($os.Version); build $($os.BuildNumber); role $($cs.DomainRole); domain $($cs.Domain)") 'Confirm you are auditing the intended lab VM.'
        $isAdmin = Test-IsAdmin
        Add-Finding $Results 'System' 'Administrative permissions' $(if ($isAdmin) { 'PASS' } else { 'REVIEW' }) ("Elevated=$([bool]$isAdmin)") 'Some audit checks need an elevated shell.'
        Export-Inventory 'os' @($os | Select-Object Caption,Version,BuildNumber,ProductType,LastBootUpTime) $InventoryDir
    }
    Invoke-SafeProbe $Results 'System' 'Startup and service status' {
        $services = @(Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName)
        Export-Inventory 'services' $services $InventoryDir
        $required = @(Get-ConfigValues $Config 'RequiredServices')
        if ($required.Count -eq 0) { Add-Finding $Results 'System' 'Required service policy' 'INFO' 'No required services listed in config.' 'Document lab services before changes.' }
        foreach ($name in $required) {
            $service = $services | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
            if ($null -eq $service) {
                Add-Finding $Results 'System' "Required service: $name" 'WARN' 'Not found' 'Verify whether this service should be installed.'
            } else {
                Add-Finding $Results 'System' "Required service: $name" $(if ($service.State -eq 'Running') {'PASS'} else {'REVIEW'}) "$($service.State) / $($service.StartMode)" 'Review whether service should be running.'
            }
        }
    }
    Invoke-SafeProbe $Results 'System' 'Time service' {
        $time = Get-Service W32Time -ErrorAction SilentlyContinue
        if ($time) { Add-Finding $Results 'System' 'Windows Time service' 'INFO' "State=$($time.Status); startup=$($time.StartType)" 'Domain controllers and Kerberos depend on correct time.' }
    }
}
