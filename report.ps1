# date for filestamps and path to config folder
$now = Get-Date "2024-10-14"
$weekAgo = $now.AddDays(-7)
$path = ".\network_configs"

# function

function Find-SecurityIssues {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $files = Get-ChildItem -Path $Path -Recurse -Filter *.conf

    foreach ($file in $files) {
        $content = Get-Content $file.FullName
        $issues = @()

        $issues += ($content | Select-String -Pattern '\b(password|secret)\b' -SimpleMatch)
        $issues += ($content | Select-String -Pattern '\b(public|private)\b' -SimpleMatch)

        $issues += ($content | Select-String -Pattern 'enable password' -SimpleMatch)

        $issues += ($content | Select-String -Pattern 'username .* password' -SimpleMatch)
        
        $issues += ($content | Select-String -Pattern '\btelnet\b' -SimpleMatch)

        $issues += ($content | Select-String -Pattern 'ip http server' -SimpleMatch)

        $issues += ($conent | Select-String -Pattern 'logic local' -SimpleMatch)

        $issues += ($content | Select-String -Pattern '\bdefault\b' -SimpleMatch)

        foreach ($match in $issues | Where-Object { $_ }) {
            [PSCustomObject]@{
                File     = $file.Name
                Line     = $match.LineNumber
                Text     = $match.Line.Trim()
                Category = if ($match.Line -match 'enable password') {
                    'weak enable password'
                }
                elseif ($match.Line -match 'snmp-server community|public|private') {
                    'Weak SNMP community'
                }
                elseif ($match.Line -match 'username .* password') {
                    'user with cleartext password'
                }
                elseif ($match.Line -match 'telnet') {
                    'Insecure remote access (Telnet)'
                }
                elseif ($match.Line -match 'ip http server') {
                    'Insecure management access (HTTP)'
                }
                elseif ($match.Line -match 'login local') {
                    'Local login without AAA'
                }
                elseif ($match.Line -match 'default') {
                    'Default configuration'
                }
                else {
                    'Password/Secret in cleartext'
                }
            }
        }
    }

}
# write section header to the report
@"
================================================================================
|                     SECURITY AUDIT REPORT - TechCorp AB                      |
================================================================================
"@ | Out-File -FilePath "security_audit.txt" -Force

"Generated: $($now.ToString('yyyy-MM-dd'))" | Out-File -FilePath "security_audit.txt" -Append
"Audit Path: $path" | Out-File -FilePath "security_audit.txt" -Append
" " | Out-File -FilePath "security_audit.txt" -Append

# file inventory
@"


FILE INVENTORY
============== 
File                Count       Total Size (KB)
----                -----       ---------------
"@ | Out-File -FilePath "security_audit.txt" -Append
$allfiles = Get-ChildItem -Path $path -Recurse -File
$groups = $allFiles |
Group-Object Extension |
Select-Object @{Name = "Extension"; Expression = { if ($_.Name) { $_.Name } else { "<no extension>" } } },
@{Name = "Count"; Expression = { $_.Count } },
@{Name = "TotalSizeKB"; Expression = { [math]::Round( ($_.Group | Measure-Object Length -Sum).Sum / 1KB, 2) } } 
$order = @(".conf", ".log", ".rules", ".bak")
$sorted = $groups | Sort-Object @{Expression = {
        $idx = $order.IndexOf($_.Extension)
        if ($idx -ge 0) { $idx } else { [int]::MaxValue }
    }
}, Extension
$sorted | ForEach-Object {
    "{0,-19} {1,-11} {2,-6}" -f $_.Extension, $_.Count, $_.TotalSizeKB
}    | Out-String | Out-File -FilePath "security_audit.txt" -Append

# top 5 largest log files
@"


TOP 5 LARGEST LOG FILES
=======================
File name                      Size (KB) 
---------                      ---------
"@ | Out-File -FilePath "security_audit.txt" -Append

Get-ChildItem -Path $path -Recurse -File -Filter *.log |
Sort-Object Length -Descending |
Select-Object -First 5 |
ForEach-Object {
    "{0,-25} {1,10:N2}" -f $_.Name,
    ($_.Length / 1KB)
} | Out-File -FilePath "security_audit.txt" -Append


# files modified last 7 days
@"



FILES MODIFIED LAST 7 DAYS
========================== 
File name                       Size (KB)        Last write date 
---------                       ---------        --------------- 
"@ | Out-File -FilePath "security_audit.txt" -Append
Get-ChildItem -Path $path -Recurse -File |
Where-Object { $_.LastWriteTime -gt $weekAgo -and $_.LastWriteTime -le $now } |
Sort-Object LastWriteTime -Descending |
ForEach-Object {
    "{0,-31} {1,-16} {2,-14}" -f $_.Name,
    [math]::Round($_.Length / 1KB, 2),
    $_.LastWriteTime.ToString("yyyy-MM-dd")
} | Out-File -FilePath "security_audit.txt" -Append


# security issues in log files
@"


SECURITY ISSUES IN LOG FILES
============================
File name                       Error   Failed   Denied
---------                       -----   ------   ------
"@ | Out-File -FilePath "security_audit.txt" -Append

Get-ChildItem -Path $path -Recurse -Filter *.log | ForEach-Object {
    $file = $_.FullName
    $errorCount = (Select-String -Path $file -Pattern "ERROR" -SimpleMatch | Measure-Object).Count
    $failedCount = (Select-String -Path $file -Pattern "FAILED" -SimpleMatch | Measure-Object).Count
    $deniedCount = (Select-String -Path $file -Pattern "DENIED" -SimpleMatch | Measure-Object).Count

    "{0,-31} {1,-7} {2,-8} {3,-7}" -f $_.Name, $errorCount, $failedCount, $deniedCount
} | Out-File -FilePath "security_audit.txt" -Append

# failed login attempts
@"


FAILED LOGIN ATTEMPTS
=====================
"@ | Out-File -FilePath "security_audit.txt" -Append

$ipPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

$failedLines = Get-ChildItem -Path $path -Recurse -Filter *.log |
Select-String -Pattern "FAILED"

$failedIPs = foreach ($line in $failedLines) {
    if ($line.line -match $ipPattern) {
        $matches[0]
    }
    else {
        "unknown sources"
    }
}
$total = $failedIPs.Count
"Failed Login Attempts: $total" | Out-File -FilePath "security_audit.txt" -Append

$failedIPs | Group-Object | ForEach-Object {
    "- $($_.Count) attempts from $($_.Name)"
} | Out-File -FilePath "security_audit.txt" -Append

# weak configuration warnings
@"


WEAK CONFIGURATION WARNINGS
===========================
"@  | Out-File -FilePath "security_audit.txt" -Append

Find-SecurityIssues -Path $path | 
where-Object { $_ -ne $null } | ForEach-Object {
    "{0,-22} (line {1,2}): {2,-30} [{3,-10}]" -f $_.File, $_.Line, $_.Text, $_.Category
} | Out-File -FilePath "security_audit.txt" -Append

# files missing backup
@"


FILES MISSING BACKUP
--------------------
"@ | Out-File -FilePath "security_audit.txt" -Append

$confFiles = Get-ChildItem -Path $path -Recurse -Filter *.conf
$bakFiles = Get-ChildItem -Path $path -Recurse -Filter *.bak

$confBase = $confFiles.BaseName | ForEach-Object { $_.ToLower() }
$bakBase = $bakFiles.BaseName | ForEach-Object { $_.ToLower() }

$missing = $confBase | Where-Object { $_ -notin $bakBase }

if ($missing) {
    "Missing backup: $($missing.Count)" | Out-File -FilePath "security_audit.txt" -Append
    $missing | ForEach-Object { "- {0}.conf" -f $_ } |
    Out-File -FilePath "security_audit.txt" -Append
}
else {
    "No missing backups detected." | Out-File -FilePath "security_audit.txt" -Append
}

# ip_addresses.csv
$ipPattern = "\d{ 1, 3 }\.\d { 1, 3 }\.\d { 1, 3 }\.\d { 1, 3 }"

Get-ChildItem -Path $path -Recurse -Filter *.conf |
Select-String -Pattern $ipPattern -AllMatches |
ForEach-Object { $_.Matches.Value } |
Sort-Object -Unique |
ForEach-Object {
    [PSCustomObject]@{IPAdress = $_ }
} | Export-Csv -Path "ip_addresses.csv" -NoTypeInformation -Encoding UTF8

# config_inventory.csv
Get-ChildItem -Path $path -Recurse -Include *.conf, *.rules, *.log |
Sort-Object  LastWRiteTime -Descending |
Select-Object @{Name = "File name"; Expression = { $_.Name } }, 
@{Name = "Size (KB)"; Expression = { [math]::Round($_.Length / 1KB, 2) } },
@{Name = "Last write date"; Expression = { $_.LastWriteTime.ToString("yyyy-MM-dd") } } |
Export-Csv -Path "config_inventory.csv" -NoTypeInformation -Encoding UTF8

# compare to baseline
$baseline = Get-Content "$path\network_configs\baseline\baseline-router.conf"
$current = Get-ChildItem -Path $path -Recurse -Filter *.conf |
Where-Object { $_.Name -ne "baseline-router.conf" }

$results = foreach ($file in $current) {
    $diff = Compare-Object -ReferenceObject $baseline -DifferenceObject (Get-Content $file.FullName)
    foreach ($entry in $diff) {
        [PSCustomObject]@{
            File          = $file.Name
            Difference    = $entry.InputObject
            SideIndicator = $entry.SideIndicator
        }
    }
}

$results | Export-Csv -Path "config_differences.csv" -NoTypeInformation -Encoding UTF8

@"

================================================================================
|                          END OF REPORT - TechCorp AB                         |
================================================================================
"@ | Out-File -FilePath "security_audit.txt" -Append
