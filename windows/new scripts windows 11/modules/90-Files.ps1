function Invoke-AuditFiles {
    param($Results, $Config, [string]$InventoryDir)
    Invoke-SafeProbe $Results 'Files' 'File discovery' {
        $searchRoots = @(Get-ConfigValues $Config 'SearchFolders')
        if ($searchRoots.Count -eq 0) {
            Add-Finding $Results 'Files' 'File discovery' 'SKIP' 'No SearchFolders specified in configuration.' 'Choose small, approved directories in a personal lab. No default full-disk search is performed.'
            return
        }
        $extensions = @('.exe','.ps1','.bat','.cmd','.vbs','.js','.hta','.scr','.mp3','.mp4','.wav','.flac','.m4a','.avi','.mkv','.mov','.zip','.7z','.rar','.pcap','.pcapng','.torrent')
        $maxFilesPerFolder = 1500
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($root in $searchRoots) {
            if (-not (Test-Path -LiteralPath $root -PathType Container)) {
                Add-Finding $Results 'Files' 'Missing scan folder' 'REVIEW' "$root" 'Fix or remove the lab path in configuration.'
                continue
            }
            $files = @(Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $extensions -contains $_.Extension.ToLowerInvariant() } | Select-Object -First $maxFilesPerFolder)
            foreach ($f in $files) {
                [void]$items.Add([pscustomobject]@{Path=$f.FullName;Extension=$f.Extension;Bytes=$f.Length;Hidden=[bool]($f.Attributes -band [IO.FileAttributes]::Hidden);Modified=$f.LastWriteTime})
            }
            if ($files.Count -ge $maxFilesPerFolder) {
                Add-Finding $Results 'Files' "Search cap reached: $root" 'REVIEW' "$maxFilesPerFolder entries" 'Narrow the search folder to avoid collecting an excessive number of filenames.'
            }
        }
        Export-Inventory 'lab-files-by-extension' $items.ToArray() $InventoryDir
        Add-Finding $Results 'Files' 'Selected file extensions' 'INFO' "$($items.Count) filenames inventoried; nothing deleted or read internally" 'Extensions and hidden attributes do not establish that a file is malicious or unauthorized.'
    }
}
