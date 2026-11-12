# Email Analyzer uninstaller
Add-Type -AssemblyName System.Windows.Forms
$AppName = 'Email Analyzer'
$Dest = Join-Path $env:LOCALAPPDATA "Programs\$AppName"

$answer = [System.Windows.Forms.MessageBox]::Show(
    "Remove $AppName from this PC?`n`nYour saved reports next to checked files are not touched.",
    "$AppName", 'YesNo', 'Question')
if ($answer -ne 'Yes') { exit 0 }

foreach ($folder in 'Desktop', 'Programs', 'SendTo') {
    $lnk = Join-Path ([Environment]::GetFolderPath($folder)) "$AppName.lnk"
    Remove-Item $lnk -Force -ErrorAction SilentlyContinue
}
Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\EmailAnalyzer' -Recurse -Force -ErrorAction SilentlyContinue
Get-Process pythonw -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Dest*" } | Stop-Process -Force

# The folder is deleted after this script exits, so it is not in use
Start-Process cmd.exe -ArgumentList "/c timeout /t 2 /nobreak >nul & rmdir /s /q `"$Dest`"" -WindowStyle Hidden
[System.Windows.Forms.MessageBox]::Show("$AppName has been removed.", "$AppName", 'OK', 'Information') | Out-Null
