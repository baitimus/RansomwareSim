<#
.SYNOPSIS
    Ransomware Awareness Simulation - Educational Tool
.DESCRIPTION
    A safe educational simulation to demonstrate the dangers of ransomware attacks.
    This tool encrypts files on the desktop for demonstration purposes only.
    All files are safely backed up and can be restored.
.NOTES
    Author: Security Education Team
    Version: 2.0
    Purpose: Educational demonstration only - completely safe
    Run in powershell: .\ransomware_sim.ps1 in folder of script
#>

param(
    [switch]$Debug,
    [string]$LogLevel = "Info"
)

# Set error action preference
$ErrorActionPreference = "Stop"

#region Configuration
$Script:Config = @{
    ModulePath = "$PSScriptRoot\AES.psm1"
    Desktop = [Environment]::GetFolderPath("Desktop")
    BackupFolder = "$PSScriptRoot\Backup_Originals"
    NotePath = "$([Environment]::GetFolderPath('Desktop'))\README_RESTORE.txt"
    Password = "RansomwareSimulation2024!"
    LogPath = "$PSScriptRoot\simulation.log"
    SupportedExtensions = @('.txt', '.pdf', '.docx', '.xlsx', '.png', '.jpg', '.jpeg', '.bmp', '.gif')
    MaxFileSize = 10MB
    Version = "2.0"
}
#endregion

#region Utility Functions
function Write-SimLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    try {
        Add-Content -Path $Script:Config.LogPath -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        # Ignore log file errors
    }
    
    # Write to console with colors
    $color = switch ($Level) {
        'Info' { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
        'Debug' { 'Magenta' }
    }
    
    if ($Level -ne 'Debug' -or $Debug) {
        Write-Host $logEntry -ForegroundColor $color
    }
}

function Test-Prerequisites {
    Write-SimLog "Checking prerequisites..." -Level Info
    
    # Check if AES module exists
    if (-not (Test-Path $Script:Config.ModulePath)) {
        Write-SimLog "AES.psm1 module not found at: $($Script:Config.ModulePath)" -Level Error
        return $false
    }
    
    # Try to import AES module
    try {
        Import-Module $Script:Config.ModulePath -Force -Global
        Write-SimLog "AES module loaded successfully" -Level Success
    } catch {
        Write-SimLog "Failed to load AES module: $_" -Level Error
        return $false
    }
      # Check if required AES functions are available
    $requiredFunctions = @('Encrypt-File', 'Decrypt-File', 'Get-AesKey')
    foreach ($func in $requiredFunctions) {
        # Try to find the function or its alias
        if (-not ((Get-Command $func -ErrorAction SilentlyContinue) -or 
                 (Get-Alias -Name $func -ErrorAction SilentlyContinue))) {
            Write-SimLog "Required function '$func' not found in AES module" -Level Error
            return $false
        }
    }
    
    # Check desktop path
    if (-not (Test-Path $Script:Config.Desktop)) {
        Write-SimLog "Desktop path not accessible: $($Script:Config.Desktop)" -Level Error
        return $false
    }
    
    Write-SimLog "All prerequisites met" -Level Success
    return $true
}

function Initialize-Environment {
    Write-SimLog "Initializing simulation environment..." -Level Info
    
    # Create backup folder
    if (-not (Test-Path $Script:Config.BackupFolder)) {
        try {
            New-Item -ItemType Directory -Path $Script:Config.BackupFolder -Force | Out-Null
            Write-SimLog "Created backup folder: $($Script:Config.BackupFolder)" -Level Success
        } catch {
            Write-SimLog "Failed to create backup folder: $_" -Level Error
            throw
        }
    }
    
    # Initialize log file
    if (-not (Test-Path $Script:Config.LogPath)) {
        try {
            New-Item -ItemType File -Path $Script:Config.LogPath -Force | Out-Null
            Write-SimLog "Initialized log file: $($Script:Config.LogPath)" -Level Success
        } catch {
            Write-SimLog "Warning: Could not create log file: $_" -Level Warning
        }
    }
    
    Write-SimLog "Environment initialization complete" -Level Success
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Magenta
    Write-Host "|                     RANSOMWARE AWARENESS SIMULATION v$($Script:Config.Version)                     |" -ForegroundColor Magenta
    Write-Host "+==============================================================================+" -ForegroundColor Magenta
    Write-Host "|  PURPOSE: Educational demonstration of ransomware attack patterns           |" -ForegroundColor Yellow
    Write-Host "|  STATUS:  100% SAFE - All files are backed up and can be restored          |" -ForegroundColor Green
    Write-Host "|  WARNING: This is for EDUCATIONAL PURPOSES ONLY                            |" -ForegroundColor Red
    Write-Host "+------------------------------------------------------------------------------+" -ForegroundColor Magenta
    Write-Host ""
}
#endregion

#region File Operations
function Get-TargetFiles {
    Write-SimLog "Scanning for target files on desktop..." -Level Info
    
    try {
        $allFiles = Get-ChildItem $Script:Config.Desktop -File -ErrorAction Stop
        Write-SimLog "Found $($allFiles.Count) total files on desktop" -Level Debug
        
        $targetFiles = $allFiles | Where-Object {
            $Script:Config.SupportedExtensions -contains $_.Extension.ToLower() -and
            $_.Length -le $Script:Config.MaxFileSize -and
            $_.Name -notlike "*.locked"
        }
        
        Write-SimLog "Identified $($targetFiles.Count) target files for encryption" -Level Info
        return $targetFiles
    } catch {
        Write-SimLog "Error scanning desktop files: $_" -Level Error
        return @()
    }
}

function Get-EncryptedFiles {
    Write-SimLog "Scanning for encrypted files..." -Level Info
    
    try {
        $encryptedFiles = Get-ChildItem $Script:Config.Desktop -Filter "*.locked" -File -ErrorAction Stop
        Write-SimLog "Found $($encryptedFiles.Count) encrypted files" -Level Info
        return $encryptedFiles
    } catch {
        Write-SimLog "Error scanning encrypted files: $_" -Level Error
        return @()
    }
}

function Backup-File {
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo]$File
    )
    
    $backupPath = Join-Path $Script:Config.BackupFolder $File.Name
    $counter = 1
    
    # Handle duplicate filenames
    while (Test-Path $backupPath) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($File.Name)
        $ext = $File.Extension
        $backupPath = Join-Path $Script:Config.BackupFolder "${name}_${counter}${ext}"
        $counter++
    }
    
    try {
        Copy-Item $File.FullName -Destination $backupPath -Force
        Write-SimLog "Backed up file: $($File.Name) -> $([System.IO.Path]::GetFileName($backupPath))" -Level Debug
        return $backupPath
    } catch {
        Write-SimLog "Failed to backup file $($File.Name): $_" -Level Error
        throw
    }
}

function Invoke-EncryptionSimulation {
    Write-SimLog "Starting encryption simulation..." -Level Info
    Show-Banner
      Write-Host "[ENCRYPTION] INITIATING ENCRYPTION SIMULATION..." -ForegroundColor Red
    Write-Host ""
    
    # Get target files
    $targetFiles = Get-TargetFiles
    
    if ($targetFiles.Count -eq 0) {
        Write-Host "[WARNING] No target files found on desktop!" -ForegroundColor Yellow
        Write-Host ""        Write-Host "Supported file types:" -ForegroundColor Gray
        $Script:Config.SupportedExtensions | ForEach-Object { Write-Host "   - $_" -ForegroundColor DarkGray }
        Write-Host ""
        Write-Host "[TIP] Create some test files to see the simulation in action:" -ForegroundColor Cyan
        Write-Host "   New-Item -Path '$($Script:Config.Desktop)\test.txt' -ItemType File -Value 'Sample content'" -ForegroundColor DarkCyan
        Write-Host "   New-Item -Path '$($Script:Config.Desktop)\document.docx' -ItemType File" -ForegroundColor DarkCyan
        Write-Host ""
        return
    }
      Write-Host "Target files identified:" -ForegroundColor Green
    $targetFiles | ForEach-Object { Write-Host "   - $($_.Name) ($([math]::Round($_.Length / 1KB, 2)) KB)" -ForegroundColor Gray }
    Write-Host ""
      # Confirm action
    Write-Host "[WARNING] This will encrypt $($targetFiles.Count) files on your desktop." -ForegroundColor Yellow
    Write-Host "   All files will be safely backed up first." -ForegroundColor Green
    $confirm = Read-Host "Continue? (y/N)"
    
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Simulation cancelled by user." -ForegroundColor Yellow
        return
    }
    
    # Initialize environment
    Initialize-Environment
    
    # Process files
    $successCount = 0
    $errorCount = 0
      Write-Host ""
    Write-Host "[PROCESSING] Processing files..." -ForegroundColor Cyan
    
    foreach ($file in $targetFiles) {
        try {
            Write-Host "   Encrypting: $($file.Name)..." -ForegroundColor Gray -NoNewline
              # Backup original file
            Backup-File -File $file
            
            # Encrypt file
            Encrypt-File -FilePath $file.FullName -Password $Script:Config.Password
            
            # Remove original
            Remove-Item $file.FullName -Force
            
            Write-Host " [SUCCESS]" -ForegroundColor Green
            Write-SimLog "Successfully encrypted: $($file.Name)" -Level Success
            $successCount++
            
        } catch {
            Write-Host " [FAILED]" -ForegroundColor Red
            Write-SimLog "Failed to encrypt $($file.Name): $_" -Level Error
            $errorCount++
        }
    }
    
    # Create ransom note
    New-RansomNote
    
    # Show results
    Write-Host ""
    Write-Host "[COMPLETE] ENCRYPTION SIMULATION COMPLETE" -ForegroundColor Red
    Write-Host "   [SUCCESS] Successfully encrypted: $successCount files" -ForegroundColor Green
    Write-Host "   [ERROR] Errors: $errorCount files" -ForegroundColor Red
    Write-Host "   [BACKUP] All originals backed up to: $($Script:Config.BackupFolder)" -ForegroundColor Yellow
    Write-Host ""
    
    Write-SimLog "Encryption simulation completed. Success: $successCount, Errors: $errorCount" -Level Info
}

function New-RansomNote {
    $noteContent = @"
[ENCRYPTED] YOUR FILES HAVE BEEN ENCRYPTED! [ENCRYPTED]

This is an EDUCATIONAL SIMULATION demonstrating how ransomware works.

[WARNING] DO NOT PANIC - This is completely safe! [WARNING]

What happened:
- Selected files on your desktop have been encrypted for demonstration
- All original files are safely backed up
- This is NOT real malware

What you've learned:
- How quickly ransomware can encrypt files
- The importance of regular backups
- Why you should never click suspicious links or download unknown files

To restore your files:
1. Run this simulation again and choose the restore option
2. Or manually copy files from: $($Script:Config.BackupFolder)

Remember: Real ransomware is dangerous!
- Keep your software updated
- Use reputable antivirus
- Regular backups are essential
- Be cautious with email attachments

This simulation was created for educational purposes only.
"@

    try {
        Set-Content -Path $Script:Config.NotePath -Value $noteContent -Encoding UTF8
        Write-SimLog "Created ransom note: $($Script:Config.NotePath)" -Level Success
    } catch {
        Write-SimLog "Failed to create ransom note: $_" -Level Error
    }
}

function Invoke-RestoreFiles {
    Write-SimLog "Starting file restoration..." -Level Info
    
    Write-Host "[RESTORE] RESTORING FILES FROM BACKUP..." -ForegroundColor Green
    Write-Host ""
    
    if (-not (Test-Path $Script:Config.BackupFolder)) {
        Write-Host "[ERROR] Backup folder not found!" -ForegroundColor Red
        return
    }
    
    $backupFiles = Get-ChildItem $Script:Config.BackupFolder -File
    $encryptedFiles = Get-EncryptedFiles
    
    if ($backupFiles.Count -eq 0) {
        Write-Host "[WARNING] No backup files found!" -ForegroundColor Yellow
        return
    }
    
    Write-Host "[INFO] Found $($backupFiles.Count) backup files" -ForegroundColor Cyan
    Write-Host "[INFO] Found $($encryptedFiles.Count) encrypted files" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Read-Host "Restore all files from backup? (y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Restoration cancelled." -ForegroundColor Yellow
        return
    }
    
    $successCount = 0
    $errorCount = 0
    
    # Remove encrypted files first
    foreach ($encFile in $encryptedFiles) {
        try {
            Remove-Item $encFile.FullName -Force
            Write-SimLog "Removed encrypted file: $($encFile.Name)" -Level Debug
        } catch {
            Write-SimLog "Failed to remove encrypted file $($encFile.Name): $_" -Level Warning
        }
    }
    
    # Restore from backup
    foreach ($backupFile in $backupFiles) {
        try {
            $destPath = Join-Path $Script:Config.Desktop $backupFile.Name
            Copy-Item $backupFile.FullName -Destination $destPath -Force
            Write-Host "   Restored: $($backupFile.Name)" -ForegroundColor Green
            $successCount++
        } catch {
            Write-Host "   Failed: $($backupFile.Name)" -ForegroundColor Red
            Write-SimLog "Failed to restore $($backupFile.Name): $_" -Level Error
            $errorCount++
        }
    }
    
    # Remove ransom note
    if (Test-Path $Script:Config.NotePath) {
        try {
            Remove-Item $Script:Config.NotePath -Force
            Write-SimLog "Removed ransom note" -Level Success
        } catch {
            Write-SimLog "Failed to remove ransom note: $_" -Level Warning
        }
    }
      Write-Host ""
    Write-Host "[COMPLETE] RESTORATION COMPLETE" -ForegroundColor Green
    Write-Host "   [SUCCESS] Successfully restored: $successCount files" -ForegroundColor Green
    Write-Host "   [ERROR] Errors: $errorCount files" -ForegroundColor Red
    Write-Host ""
    
    Write-SimLog "File restoration completed. Success: $successCount, Errors: $errorCount" -Level Info
}

function Show-SystemStatus {
    Write-SimLog "Displaying system status..." -Level Debug
      Show-Banner
    Write-Host "[STATUS] SYSTEM STATUS" -ForegroundColor Cyan
    Write-Host ""
    
    $normalFiles = Get-TargetFiles
    $encryptedFiles = Get-EncryptedFiles
    $backupFiles = @()
    
    if (Test-Path $Script:Config.BackupFolder) {
        $backupFiles = Get-ChildItem $Script:Config.BackupFolder -File -ErrorAction SilentlyContinue
    }
    
    $hasRansomNote = Test-Path $Script:Config.NotePath
    
    # Summary
    Write-Host "File Status:" -ForegroundColor White
    Write-Host "   Normal files:     $($normalFiles.Count)" -ForegroundColor Green
    Write-Host "   Encrypted files:  $($encryptedFiles.Count)" -ForegroundColor Red
    Write-Host "   Backup files:     $($backupFiles.Count)" -ForegroundColor Yellow
    Write-Host "   Ransom note:      $(if ($hasRansomNote) { 'Present' } else { 'Not found' })" -ForegroundColor $(if ($hasRansomNote) { 'Red' } else { 'Green' })
    Write-Host ""
      # Detailed file lists
    if ($normalFiles.Count -gt 0) {
        Write-Host "Normal Files:" -ForegroundColor Green
        $normalFiles | ForEach-Object { 
            Write-Host "   - $($_.Name) ($([math]::Round($_.Length / 1KB, 2)) KB)" -ForegroundColor Gray 
        }
        Write-Host ""
    }
    
    if ($encryptedFiles.Count -gt 0) {
        Write-Host "Encrypted Files:" -ForegroundColor Red
        $encryptedFiles | ForEach-Object { 
            Write-Host "   - $($_.Name) ($([math]::Round($_.Length / 1KB, 2)) KB)" -ForegroundColor Gray 
        }
        Write-Host ""
    }
    
    if ($backupFiles.Count -gt 0) {
        Write-Host "Backup Files:" -ForegroundColor Yellow
        $backupFiles | ForEach-Object { 
            Write-Host "   - $($_.Name) ($([math]::Round($_.Length / 1KB, 2)) KB)" -ForegroundColor Gray 
        }
        Write-Host ""
    }
      # System info
    Write-Host "Configuration:" -ForegroundColor White
    Write-Host "   Desktop path:     $($Script:Config.Desktop)" -ForegroundColor Gray
    Write-Host "   Backup folder:    $($Script:Config.BackupFolder)" -ForegroundColor Gray
    Write-Host "   Log file:         $($Script:Config.LogPath)" -ForegroundColor Gray
    Write-Host "   Max file size:    $([math]::Round($Script:Config.MaxFileSize / 1MB, 1)) MB" -ForegroundColor Gray
    Write-Host ""
}

function Test-SystemHealth {
    Write-SimLog "Running system health check..." -Level Info
    
    Show-Banner
    Write-Host "SYSTEM HEALTH CHECK" -ForegroundColor Magenta
    Write-Host ""
    
    $issues = @()
    
    # Test script functions
    Write-Host "Testing Core Functions:" -ForegroundColor White
    $coreFunctions = @(
        'Get-TargetFiles', 'Get-EncryptedFiles', 'Backup-File', 
        'Invoke-EncryptionSimulation', 'Invoke-RestoreFiles', 'New-RansomNote'
    )
    
    foreach ($func in $coreFunctions) {
        if (Get-Command $func -ErrorAction SilentlyContinue) {
            Write-Host "   [OK] $func" -ForegroundColor Green
        } else {
            Write-Host "   [MISSING] $func" -ForegroundColor Red
            $issues += "Missing function: $func"
        }
    }
    Write-Host ""
    
    # Test AES module functions
    Write-Host "Testing AES Module Functions:" -ForegroundColor White
    $aesFunctions = @('Encrypt-File', 'Decrypt-File', 'Get-AesKey')
    
    foreach ($func in $aesFunctions) {
        if (Get-Command $func -ErrorAction SilentlyContinue) {
            Write-Host "   [OK] $func" -ForegroundColor Green
        } else {
            Write-Host "   [MISSING] $func" -ForegroundColor Red
            $issues += "Missing AES function: $func"
        }
    }
    Write-Host ""
    
    # Test file paths
    Write-Host "Testing File Paths:" -ForegroundColor White
    $paths = @{
        'Desktop' = $Script:Config.Desktop
        'AES Module' = $Script:Config.ModulePath
        'Backup Folder' = $Script:Config.BackupFolder
    }
      foreach ($pathName in $paths.Keys) {
        $path = $paths[$pathName]
        if (Test-Path $path) {
            Write-Host "   [OK] $pathName ($path)" -ForegroundColor Green
        } else {
            Write-Host "   [NOT FOUND] $pathName ($path)" -ForegroundColor Red
            $issues += "Missing path: $pathName"
        }
    }
    Write-Host ""
    
    # Summary
    if ($issues.Count -eq 0) {
        Write-Host "All systems operational!" -ForegroundColor Green
    } else {
        Write-Host "Found $($issues.Count) issues:" -ForegroundColor Yellow
        $issues | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
    }
    Write-Host ""
    
    Write-SimLog "System health check completed. Issues found: $($issues.Count)" -Level Info
}

function Show-LogFile {
    Write-SimLog "Displaying log file..." -Level Debug
    
    Show-Banner
    Write-Host "[LOG] SIMULATION LOG (Last 25 entries)" -ForegroundColor Cyan
    Write-Host ""
    
    if (Test-Path $Script:Config.LogPath) {
        try {
            $logEntries = Get-Content $Script:Config.LogPath | Select-Object -Last 25
            if ($logEntries) {
                $logEntries | ForEach-Object { 
                    $color = if ($_ -match '\[Error\]') { 'Red' }
                            elseif ($_ -match '\[Warning\]') { 'Yellow' }
                            elseif ($_ -match '\[Success\]') { 'Green' }
                            elseif ($_ -match '\[Debug\]') { 'Magenta' }
                            else { 'Gray' }
                    Write-Host $_ -ForegroundColor $color
                }
            } else {
                Write-Host "Log file is empty." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Error reading log file: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Log file not found: $($Script:Config.LogPath)" -ForegroundColor Yellow
    }
    Write-Host ""
}
#endregion

#region Main Menu
function Show-MainMenu {
    do {
        Show-Banner
          Write-Host "MAIN MENU" -ForegroundColor White
        Write-Host ""
        Write-Host "   1   Start Encryption Simulation" -ForegroundColor Red
        Write-Host "   2   Restore Files from Backup" -ForegroundColor Green
        Write-Host "   3   Show System Status" -ForegroundColor Cyan
        Write-Host "   4   View Log File" -ForegroundColor Yellow
        Write-Host "   5   Open Backup Folder" -ForegroundColor Blue
        Write-Host "   6   System Health Check" -ForegroundColor Magenta
        Write-Host "   7   About / Help" -ForegroundColor DarkCyan
        Write-Host "   0   Exit" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Supported file types: $($Script:Config.SupportedExtensions -join ', ')" -ForegroundColor DarkGray
        Write-Host "Max file size: $([math]::Round($Script:Config.MaxFileSize / 1MB, 1)) MB" -ForegroundColor DarkGray
        Write-Host ""
        
        $choice = Read-Host "Select option (0-7)"
        
        switch ($choice) {
            '1' {
                Invoke-EncryptionSimulation
                Read-Host "`nPress Enter to continue"
            }
            '2' {
                Invoke-RestoreFiles
                Read-Host "`nPress Enter to continue"
            }
            '3' {
                Show-SystemStatus
                Read-Host "`nPress Enter to continue"
            }
            '4' {
                Show-LogFile
                Read-Host "`nPress Enter to continue"
            }
            '5' {
                if (Test-Path $Script:Config.BackupFolder) {
                    Start-Process explorer.exe -ArgumentList $Script:Config.BackupFolder
                    Write-Host "Opening backup folder..." -ForegroundColor Green
                } else {
                    Write-Host "Backup folder doesn't exist yet." -ForegroundColor Yellow
                }
                Start-Sleep -Seconds 2
            }
            '6' {
                Test-SystemHealth
                Read-Host "`nPress Enter to continue"
            }
            '7' {
                Show-AboutHelp
                Read-Host "`nPress Enter to continue"
            }
            '0' {
                Write-Host ""
                Write-Host "Thank you for using the Ransomware Awareness Simulation!" -ForegroundColor Green
                Write-Host "Remember: Stay safe, keep backups, and be cautious online!" -ForegroundColor Yellow
                Write-Host ""
                Write-SimLog "Simulation session ended by user" -Level Info
                return
            }
            default {
                Write-Host ""
                Write-Host "[ERROR] Invalid selection. Please choose 0-7." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

function Show-AboutHelp {
    Show-Banner
    
    Write-Host "[INFO] ABOUT RANSOMWARE AWARENESS SIMULATION" -ForegroundColor Cyan    Write-Host ""
    Write-Host "Purpose:" -ForegroundColor White
    Write-Host "   This tool demonstrates how ransomware attacks work in a completely safe environment."
    Write-Host "   It helps users understand the importance of cybersecurity best practices."
    Write-Host ""
    Write-Host "Safety:" -ForegroundColor White
    Write-Host "   - All files are safely backed up before encryption"
    Write-Host "   - Uses standard AES encryption (not malicious code)"
    Write-Host "   - Files can be restored at any time"
    Write-Host "   - No data is actually lost or damaged"
    Write-Host ""
    Write-Host "Educational Value:" -ForegroundColor White
    Write-Host "   - Shows how quickly files can be encrypted"
    Write-Host "   - Demonstrates the importance of backups"
    Write-Host "   - Raises awareness about ransomware threats"
    Write-Host "   - Teaches prevention strategies"
    Write-Host ""    Write-Host "Real Ransomware Prevention:" -ForegroundColor Yellow
    Write-Host "   - Keep software and OS updated"
    Write-Host "   - Use reputable antivirus software"
    Write-Host "   - Regular backups (3-2-1 rule)"
    Write-Host "   - Be cautious with email attachments"
    Write-Host "   - Don't click suspicious links"
    Write-Host "   - Use strong, unique passwords"
    Write-Host ""
    Write-Host "Technical Details:" -ForegroundColor White
    Write-Host "   Version: $($Script:Config.Version)"
    Write-Host "   PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Host "   Encryption: AES-256"
    Write-Host "   Backup Location: $($Script:Config.BackupFolder)"
    Write-Host ""
}
#endregion

#region Main Execution
try {
    # Initialize logging
    Write-SimLog "=== Ransomware Awareness Simulation v$($Script:Config.Version) Started ===" -Level Info
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Host ""
        Write-Host "[ERROR] Prerequisites not met. Cannot continue." -ForegroundColor Red
        Write-Host "Please ensure AES.psm1 is in the same directory as this script." -ForegroundColor Yellow
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Show main menu
    Show-MainMenu
    
} catch {
    Write-SimLog "Unhandled error: $_" -Level Error
    Write-Host ""
    Write-Host "[ERROR] An unexpected error occurred: $_" -ForegroundColor Red
    Write-Host "Check the log file for more details: $($Script:Config.LogPath)" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
} finally {
    Write-SimLog "=== Simulation Session Ended ===" -Level Info
}
#endregion