# ============================================
# PowerShell Script: Defender Exclusion Checker
# ============================================

<#
.SYNOPSIS
    Scans all local fixed drives and their directories up to a specified depth using Windows Defender.
    Identifies folders where scans are skipped, indicating possible exclusions.

.DESCRIPTION
    This script:
    - Retrieves all fixed local drives.
    - Allows specifying the depth of directory traversal via parameters.
    - Scans each folder up to the specified depth.
    - Continues scanning subdirectories even if a parent folder is excluded.
    - Provides neat and organized output of scan results.

.PARAMETER ScanDepth
    The depth to which directories are scanned.
    - 1: Only top-level folders.
    - 2: Top-level and their immediate subfolders.
    - 3: Top-level, immediate subfolders, and their subfolders.
    - And so on.
    Default is 3.

.EXAMPLE
    .\DefenderExclusionChecker.ps1 -ScanDepth 2

.NOTES
    - Ensure Windows Defender's MpCmdRun.exe path is correct.
    - Run the script with necessary permissions to access all folders.
    - Scanning large directories may take considerable time.
#>

# --------- Parameters ---------
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, HelpMessage = "Specify the depth to which directories should be scanned. Default is 3.")]
    [ValidateRange(1, 10)]
    [int]$ScanDepth = 3
)

# --------- Configuration Parameters ---------
# Path to Microsoft Defender's MpCmdRun.exe
$MpCmdRunPath = "C:\Program Files\Windows Defender\MpCmdRun.exe"

# Verify that MpCmdRun.exe exists
if (-Not (Test-Path -Path $MpCmdRunPath)) {
    Write-Error "MpCmdRun.exe not found at path: $MpCmdRunPath. Please verify the path."
    exit 1
}

# --------- Function Definitions ---------

function Scan-Folder {
    param (
        [string]$Path,
        [int]$CurrentDepth,
        [int]$MaxDepth
    )

    # Initialize an array to collect scan results
    $localResults = @()

    # Only proceed if current depth is within the max depth
    if ($CurrentDepth -gt $MaxDepth) {
        return $localResults
    }

    # Check if the path is accessible
    if (-not (Test-Path -Path $Path -PathType Container)) {
        $localResults += [PSCustomObject]@{
            Path    = $Path
            Status  = "Inaccessible"
            Message = "Cannot access the folder."
            Depth   = $CurrentDepth
        }
        return $localResults
    }

    Write-Host (" " * (($CurrentDepth - 1) * 2)) + "Scanning: $Path" -ForegroundColor Cyan

    try {
        # Perform a custom scan on the folder
        $scanOutput = & "$MpCmdRunPath" -Scan -ScanType 3 -File "$Path\*" 2>&1
    }
    catch {
        $localResults += [PSCustomObject]@{
            Path    = $Path
            Status  = "Error"
            Message = $_.Exception.Message
            Depth   = $CurrentDepth
        }
        Write-Host (" " * (($CurrentDepth - 1) * 2)) + "Error scanning: $Path" -ForegroundColor Red
        return $localResults
    }

    # Check if 'skipped' appears in the Defender output
    if ($scanOutput -match 'skipped') {
        $localResults += [PSCustomObject]@{
            Path    = $Path
            Status  = "Excluded"
            Message = "Scan was skipped."
            Depth   = $CurrentDepth
        }
        Write-Host (" " * (($CurrentDepth - 1) * 2)) + "[EXCLUSION DETECTED] Scan skipped." -ForegroundColor Yellow
    }
    else {
        $localResults += [PSCustomObject]@{
            Path    = $Path
            Status  = "Scanned"
            Message = "Scan completed."
            Depth   = $CurrentDepth
        }
        Write-Host (" " * (($CurrentDepth - 1) * 2)) + "Scan completed." -ForegroundColor Green
    }

    # Proceed to scan subdirectories if within depth
    if ($CurrentDepth -lt $MaxDepth) {
        try {
            $subFolders = Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue
        }
        catch {
            $localResults += [PSCustomObject]@{
                Path    = $Path
                Status  = "Error"
                Message = $_.Exception.Message
                Depth   = $CurrentDepth
            }
            Write-Host (" " * (($CurrentDepth - 1) * 2)) + "Error accessing subfolders of: $Path" -ForegroundColor Red
            return $localResults
        }

        foreach ($subFolder in $subFolders) {
            $subResults = Scan-Folder -Path $subFolder.FullName -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
            $localResults += $subResults
        }
    }

    return $localResults
}

# --------- Main Script Execution ---------

Write-Host "Starting Windows Defender Exclusion Checker..." -ForegroundColor Magenta
Write-Host "Scan Depth: $ScanDepth" -ForegroundColor Magenta

# Get all local fixed drives via WMI
$drives = Get-WmiObject Win32_LogicalDisk -Filter "DriveType = 3" | Select-Object -ExpandProperty DeviceID

# Initialize a list to store scan results
$scanResults = @()

foreach ($drive in $drives) {
    Write-Host "`n=== Processing Drive: $drive ===" -ForegroundColor Blue

    # Start scanning from the root of the drive
    $driveScanResults = Scan-Folder -Path "$drive\" -CurrentDepth 1 -MaxDepth $ScanDepth
    $scanResults += $driveScanResults
}

Write-Host "`n=== Scan Completed ===" -ForegroundColor Magenta

# --------- Output Summary ---------

# Filter results for excluded or errors
$excludedFolders      = $scanResults | Where-Object { $_.Status -eq "Excluded" }
$errorFolders         = $scanResults | Where-Object { $_.Status -eq "Error" }
$inaccessibleFolders  = $scanResults | Where-Object { $_.Status -eq "Inaccessible" }

# Display Summary
Write-Host "`nSummary of Exclusions and Issues:" -ForegroundColor Yellow
Write-Host "---------------------------------"

if ($excludedFolders.Count -gt 0) {
    Write-Host "`n[Excluded Folders]" -ForegroundColor Red
    $excludedFolders | Select-Object Path, Message | Format-Table -AutoSize
}
else {
    Write-Host "`nNo exclusions detected." -ForegroundColor Green
}

if ($errorFolders.Count -gt 0) {
    Write-Host "`n[Folders with Errors]" -ForegroundColor DarkRed
    $errorFolders | Select-Object Path, Message | Format-Table -AutoSize
}

if ($inaccessibleFolders.Count -gt 0) {
    Write-Host "`n[Inaccessible Folders]" -ForegroundColor DarkYellow
    $inaccessibleFolders | Select-Object Path, Message | Format-Table -AutoSize
}

Write-Host "`nDetailed Scan Results:" -ForegroundColor Cyan
$scanResults | Select-Object Path, Status, Message, Depth | Format-Table -AutoSize

# Optionally, export the results to a CSV file
# $scanResults | Export-Csv -Path "DefenderScanResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" -NoTypeInformation

Write-Host "`nScript execution finished." -ForegroundColor Magenta
