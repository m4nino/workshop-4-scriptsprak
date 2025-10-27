# date for filestamps and path to config folder
$now = Get-Date "2024-10-14"
$weekAgo = $now.AddDays(-7)
$path = ".\network_configs"


# write section header to the report
"=" * 80 | Out-File -FilePath "security_audit.txt"
"|                     SECURITY AUDIT REPORT - TechCorp AB                      |" | Out-File -FilePath "security_audit.txt" -Append
"=" * 80 | Out-File -FilePath "security_audit.txt" -Append
"Generated: $($now.ToString('yyyy-MM-dd'))" | Out-File -FilePath "security_audit.txt" -Append
"Audit Path: $path" | Out-File -FilePath "security_audit.txt" -Append
" " | Out-File -FilePath "security_audit.txt" -Append

# files modified last 7 days
"FILES MODIFIED LAST 7 DAYS" | Out-File -FilePath "security_audit.txt" -Append
"=" * 27 | Out-File -FilePath "security_audit.txt" -Append
Get-ChildItem -Path $path -Recurse -File |
Where-Object { $_.LastWriteTime -gt $weekAgo -and $_.LastWriteTime -le $now } |
Sort-Object LastWriteTime -Descending |
Select-Object Name,
@{Name = "SizeKB"; Expression = { [math]::Round($_.Length / 1KB, 2) } },
@{Name = "LastWriteDate"; Expression = { $_.LastWriteTime.ToString("yyyy-MM-dd") } } |
Format-Table -AutoSize | Out-String |
Out-File -FilePath "security_audit.txt" -Append

# config_inventory.csv
Get-ChildItem -Path $path -Recurse -Include *.conf, *.rules, *.log |
Sort-Object  LastWRiteTime -Descending |
Select-Object Name, 
@{Name = "SizeKB"; Expression = { [math]::Round($_.Length / 1KB, 2) } },
@{Name = "LastWriteDate"; Expression = { $_.LastWriteTime.ToString("yyyy-MM-dd") } } |
Export-Csv -Path "config_inventory.csv" -NoTypeInformation -Encoding UTF8