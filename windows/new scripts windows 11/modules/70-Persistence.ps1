function Invoke-AuditPersistence {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'Persistence' 'Scheduled tasks' {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $task = $_
            [pscustomobject]@{
                Path=$task.TaskPath; Name=$task.TaskName; State=$task.State;
                Actions=(($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ')
            }
        })
        Export-Inventory 'scheduled-tasks' $tasks $InventoryDir
        foreach ($task in $tasks) {
            if ((Test-SuspiciousPath $task.Actions) -or $task.Actions -match '(?i)-encodedcommand\b|powershell\s+-enc\b') {
                Add-Finding $Results 'Persistence' 'Unusual scheduled task action' 'REVIEW' "$($task.Path)$($task.Name): $($task.Actions)" 'Inspect publisher and purpose; suspicious path/flags alone are not conclusive.'
            }
        }
    }
    Invoke-SafeProbe $Results 'Persistence' 'Auto-run registry keys' {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        $items = @()
        foreach ($key in $keys) {
            if (-not (Test-Path -LiteralPath $key)) { continue }
            $registry = Get-Item -LiteralPath $key -ErrorAction Stop
            foreach ($name in $registry.GetValueNames()) {
                $value = [string]$registry.GetValue($name)
                $items += [pscustomobject]@{RegistryPath=$key; Name=$name; Data=$value}
                if (Test-SuspiciousPath $value) {
                    Add-Finding $Results 'Persistence' 'Autostart in writable path' 'REVIEW' "$name : $value" 'Inspect publisher and command purpose; preserve forensic evidence.'
                }
            }
        }
        Export-Inventory 'registry-autoruns' $items $InventoryDir
    }
    Invoke-SafeProbe $Results 'Persistence' 'Startup directories' {
        $dirs = @(
            (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'),
            (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')
        )
        $files = @()
        foreach ($dir in $dirs) {
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            $files += @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue | Select-Object FullName,Name,Length,LastWriteTime)
        }
        Export-Inventory 'startup-folder-items' $files $InventoryDir
        foreach ($file in $files) {
            if ($file.Name -ne 'desktop.ini') {
                Add-Finding $Results 'Persistence' 'Startup folder item' 'REVIEW' $file.FullName 'Confirm this item belongs to an approved application.'
            }
        }
    }
    Invoke-SafeProbe $Results 'Persistence' 'Service executable paths' {
        $services = @(Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName,StartName)
        foreach ($s in $services) {
            if (Test-SuspiciousPath $s.PathName) {
                Add-Finding $Results 'Persistence' 'Service from writable location' 'REVIEW' "$($s.Name): $($s.PathName)" 'Validate executable signature and service owner.'
            }
        }
    }
    Invoke-SafeProbe $Results 'Persistence' 'Image File Execution Options' {
        $programs = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe')
        foreach ($program in $programs) {
            $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$program"
            if (-not (Test-Path -LiteralPath $key)) { continue }
            $val = (Get-ItemProperty -LiteralPath $key -Name Debugger -ErrorAction SilentlyContinue)
            if ($val -and $val.Debugger) {
                Add-Finding $Results 'Persistence' "IFEO debugger redirect: $program" 'REVIEW' 'Debugger override exists (command withheld).' 'Inspect locally; this can be legitimate debugging or accessibility backdoor persistence.'
            }
        }
    }
    Invoke-SafeProbe $Results 'Persistence' 'Permanent WMI subscriptions' {
        $ns = 'root\subscription'
        $filters = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query,EventNamespace)
        $consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name,__CLASS)
        $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter,Consumer)
        Export-Inventory 'wmi-event-filters' $filters $InventoryDir
        Export-Inventory 'wmi-event-consumers' $consumers $InventoryDir
        Export-Inventory 'wmi-event-bindings' $bindings $InventoryDir
        if ($bindings.Count -gt 0) { Add-Finding $Results 'Persistence' 'Permanent WMI bindings' 'REVIEW' "$($bindings.Count) bindings detected" 'Review associated event filters and consumers.' }
    }
    Invoke-SafeProbe $Results 'Persistence' 'BITS transfer jobs' {
        if (-not (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue)) { return }
        $jobs = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName,JobState,OwnerAccount,TransferType,CreationTime)
        Export-Inventory 'bits-jobs' $jobs $InventoryDir
        if ($jobs.Count) { Add-Finding $Results 'Persistence' 'BITS jobs' 'REVIEW' "$($jobs.Count) jobs enumerated" 'Confirm persistent jobs correspond to legitimate applications.' }
    }
}
