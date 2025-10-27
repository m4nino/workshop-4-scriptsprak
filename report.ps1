# date for filestamps and path to config folder
$now = Get-Date "2024-10-14"
$weekAgo = $now.AddDays(-7)
$path = ".\network_configs"


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
    $_.LastWriteTime.ToString("yyy-MM-dd")
} | Out-File -FilePath "Security_audit.txt" -Append

$patterns = "ERROR", "FAILED", "DENIED"

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



# ip_addresses.csv
$ipPattern = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

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


@"

================================================================================
|                           END OF REPORT - TechCorp AB                        |
================================================================================
"@ | Out-File -FilePath "security_audit.txt" -Append
