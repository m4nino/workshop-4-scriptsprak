# date for filestamps and path to config folder
$now = Get-Date "2024-10-14"
$path = ".\network_configs"


# write section header to the report
"=" * 80 | Out-File -FilePath "security_audit.txt"
"|                     SECURITY AUDIT REPORT - TechCorp AB                      |" | Out-File -FilePath "security_audit.txt" -Append
"=" * 80 | Out-File -FilePath "security_audit.txt" -Append
"Generated: $now" | Out-File -FilePath "security_audit.txt" -Append
"Audit Path: $path" | Out-File -FilePath "security_audit.txt" -Append
" " | Out-File -FilePath "security_audit.txt" -Append
