
Write-Host "[SOC] Immediate Monitoring Active" -ForegroundColor Cyan

$watchPath = "$env:USERPROFILE\Downloads"
$suspiciousExtensions = @(".exe", ".dll", ".bat", ".ps1", ".vbs")
$logFile = "C:\sandbox_logs\incident_log.txt"

# Ensure log folder exists
$logFolder = Split-Path $logFile
if (!(Test-Path $logFolder)) { New-Item -ItemType Directory -Path $logFolder | Out-Null }
if (!(Test-Path $logFile)) { New-Item -ItemType File -Path $logFile | Out-Null }

# Load GUI support
Add-Type -AssemblyName System.Windows.Forms

Write-Host "[SOC] Watching Downloads Folder..." -ForegroundColor Green
Write-Host "Press CTRL + C to Stop" -ForegroundColor Yellow

$knownFiles = @()

while ($true) {
    $currentFiles = Get-ChildItem -Path $watchPath -File -ErrorAction SilentlyContinue

    foreach ($file in $currentFiles) {
        if ($knownFiles -notcontains $file.FullName) {

            $knownFiles += $file.FullName
            $ext = $file.Extension.ToLower()

            if ($suspiciousExtensions -contains $ext) {

                # Popup alert
                [System.Windows.Forms.MessageBox]::Show(
                    "🚨 Suspicious file detected and removed:`n$file",
                    "SOC Alert",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )

                # Log alert
                $log = "[$(Get-Date)] ALERT — Suspicious file detected & removed: $($file.FullName)"
                Add-Content $logFile $log

                # Remove suspicious file
                Start-Sleep -Milliseconds 300
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue

                Write-Host "🚨 ALERT Triggered & Removed: $($file.FullName)" -ForegroundColor Red
            }
            else {
                Write-Host "[SAFE] Downloaded: $($file.Name)" -ForegroundColor Green
            }
        }
    }

    Start-Sleep -Milliseconds 500
}

