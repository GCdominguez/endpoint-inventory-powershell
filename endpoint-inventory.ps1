# Endpoint Inventory / Compliance Report v4
# Purpose:
# - Collect practical Windows endpoint state
# - Validate expected software, service, OS, and architecture state
# - Save a new report only when meaningful endpoint state changes
# - Ignore volatile fields like GeneratedAt
# - Exclude noisy package-manager raw output from drift comparison
# - Keep only the newest 5 historical report iterations

# Lab note:
# In production, scripts like this should be signed, version-controlled,
# deployed through an endpoint management platform, and written to centralized logging.

$Root = "C:\ProgramData\EndpointLab"
$ScriptDir = "$Root\Scripts"
$ReportDir = "$Root\Reports"
$HistoryDir = "$ReportDir\History"
$MaxReports = 5

New-Item -ItemType Directory -Path $ScriptDir -Force | Out-Null
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
New-Item -ItemType Directory -Path $HistoryDir -Force | Out-Null

function Get-StringSha256 {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputString
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $hashBytes = $sha256.ComputeHash($bytes)

    return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

$GeneratedAt = Get-Date
$Timestamp = $GeneratedAt.ToString("yyyyMMdd-HHmmssfff")

$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1

$isWindows11 = $os.Caption -like "*Windows 11*"
$isArm64 = $os.OSArchitecture -like "*ARM*"

# Service expectations
# Not every service must be actively running.
# Some services only need to be enabled or available.
$serviceExpectations = @(
    [PSCustomObject]@{
        Name = "Spooler"
        ExpectedStatus = "Running"
        ExpectedStartModePolicy = $null
        Reason = "Print Spooler should be running on this test endpoint"
    },
    [PSCustomObject]@{
        Name = "wuauserv"
        ExpectedStatus = $null
        ExpectedStartModePolicy = "NotDisabled"
        Reason = "Windows Update does not need to be running constantly, but should not be disabled"
    }
)

$services = foreach ($expected in $serviceExpectations) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$($expected.Name)'" -ErrorAction SilentlyContinue

    if ($svc) {
        $statusPass = if ($expected.ExpectedStatus) {
            $svc.State -eq $expected.ExpectedStatus
        }
        else {
            $true
        }

        $startModePass = switch ($expected.ExpectedStartModePolicy) {
            "NotDisabled" { $svc.StartMode -ne "Disabled" }
            $null { $true }
            default { $svc.StartMode -eq $expected.ExpectedStartModePolicy }
        }

        [PSCustomObject]@{
            Name                    = $svc.Name
            DisplayName             = $svc.DisplayName
            Status                  = $svc.State
            StartMode               = $svc.StartMode
            ExpectedStatus          = $expected.ExpectedStatus
            ExpectedStartModePolicy = $expected.ExpectedStartModePolicy
            Compliant               = ($statusPass -and $startModePass)
            Reason                  = $expected.Reason
        }
    }
    else {
        [PSCustomObject]@{
            Name                    = $expected.Name
            DisplayName             = $null
            Status                  = "NotFound"
            StartMode               = $null
            ExpectedStatus          = $expected.ExpectedStatus
            ExpectedStartModePolicy = $expected.ExpectedStartModePolicy
            Compliant               = $false
            Reason                  = "Service not found"
        }
    }
}

# Registry-based software detection
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$notepad = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Notepad++*" } |
    Select-Object -First 1 DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, PSPath

$expectedNotepadVersion = "8.9.6.4"
$notepadInstalled = $null -ne $notepad

if ($notepadInstalled) {
    $notepadReport = [ordered]@{
        Installed        = $true
        DisplayName      = $notepad.DisplayName
        Version          = $notepad.DisplayVersion
        ExpectedVersion  = $expectedNotepadVersion
        VersionCompliant = ($notepad.DisplayVersion -eq $expectedNotepadVersion)
        Publisher        = $notepad.Publisher
        InstallLocation  = $notepad.InstallLocation
        UninstallString  = $notepad.UninstallString
        DetectionSource  = "Registry uninstall key"
    }
}
else {
    $notepadReport = [ordered]@{
        Installed        = $false
        DisplayName      = $null
        Version          = $null
        ExpectedVersion  = $expectedNotepadVersion
        VersionCompliant = $false
        Publisher        = $null
        InstallLocation  = $null
        UninstallString  = $null
        DetectionSource  = "Registry uninstall key"
    }
}

# Optional WinGet visibility
# This is included in the final report for troubleshooting,
# but intentionally excluded from drift comparison because raw package-manager output can be noisy.
$wingetNotepad = $null

if (Get-Command winget -ErrorAction SilentlyContinue) {
    $wingetNotepad = winget list --name "Notepad++" 2>$null
}
else {
    $wingetNotepad = "winget not available"
}

$checks = @(
    [PSCustomObject]@{
        Check  = "OS detected"
        Result = if ($os.Caption) { "Pass" } else { "Fail" }
        Detail = $os.Caption
    },
    [PSCustomObject]@{
        Check  = "Windows 11 detected"
        Result = if ($isWindows11) { "Pass" } else { "Fail" }
        Detail = $os.Caption
    },
    [PSCustomObject]@{
        Check  = "Architecture detected"
        Result = if ($os.OSArchitecture) { "Pass" } else { "Fail" }
        Detail = $os.OSArchitecture
    },
    [PSCustomObject]@{
        Check  = "ARM64 architecture"
        Result = if ($isArm64) { "Pass" } else { "Info" }
        Detail = $os.OSArchitecture
    },
    [PSCustomObject]@{
        Check  = "Notepad++ installed"
        Result = if ($notepadInstalled) { "Pass" } else { "Fail" }
        Detail = if ($notepadInstalled) { $notepad.DisplayVersion } else { "Not detected" }
    },
    [PSCustomObject]@{
        Check  = "Notepad++ expected version"
        Result = if ($notepadInstalled -and $notepad.DisplayVersion -eq $expectedNotepadVersion) { "Pass" } else { "Fail" }
        Detail = if ($notepadInstalled) { "Installed=$($notepad.DisplayVersion); Expected=$expectedNotepadVersion" } else { "Not detected" }
    },
    [PSCustomObject]@{
        Check  = "Service compliance"
        Result = if (($services | Where-Object { $_.Compliant -eq $false }).Count -eq 0) { "Pass" } else { "Fail" }
        Detail = ($services | ForEach-Object { "$($_.Name): Status=$($_.Status), StartMode=$($_.StartMode), Compliant=$($_.Compliant)" }) -join "; "
    }
)

$failedChecks = ($checks | Where-Object { $_.Result -eq "Fail" }).Count
$passedChecks = ($checks | Where-Object { $_.Result -eq "Pass" }).Count
$infoChecks = ($checks | Where-Object { $_.Result -eq "Info" }).Count

$overallStatus = if ($failedChecks -eq 0) { "Compliant" } else { "NeedsAttention" }

# Stable endpoint state used for comparison.
# GeneratedAt, ContentHash, and raw WinGet output are intentionally excluded.
$stateForComparison = [ordered]@{
    SchemaVersion = "4.0"
    OverallStatus = $overallStatus

    Device = [ordered]@{
        ComputerName  = $env:COMPUTERNAME
        UserContext   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        OS            = $os.Caption
        Version       = $os.Version
        BuildNumber   = $os.BuildNumber
        Architecture  = $os.OSArchitecture
        IsWindows11   = $isWindows11
        IsArm64       = $isArm64
        ProcessorName = $cpu.Name
        AddressWidth  = $cpu.AddressWidth
    }

    Services = $services

    Software = [ordered]@{
        NotepadPlusPlus = $notepadReport
    }

    Checks = $checks

    Summary = [ordered]@{
        TotalChecks = $checks.Count
        Passed      = $passedChecks
        Failed      = $failedChecks
        Info        = $infoChecks
    }
}

$comparisonJson = $stateForComparison | ConvertTo-Json -Depth 8 -Compress
$currentHash = Get-StringSha256 -InputString $comparisonJson

# Find latest historical report, if one exists
$latestReport = Get-ChildItem -Path $HistoryDir -Filter "endpoint-report-*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$previousHash = $null

if ($latestReport) {
    try {
        $previousReport = Get-Content $latestReport.FullName -Raw | ConvertFrom-Json
        $previousHash = $previousReport.ContentHash
    }
    catch {
        $previousHash = $null
    }
}

if ($previousHash -eq $currentHash) {
    Write-Host "No meaningful endpoint state change detected."
    Write-Host "No new report created."
    Write-Host "Current content hash: $currentHash"
    return
}

# Add volatile/report metadata only after comparison
$finalReport = [ordered]@{
    SchemaVersion = "4.0"
    GeneratedAt   = $GeneratedAt.ToString("s")
    ContentHash   = $currentHash
    OverallStatus = $overallStatus

    Device = $stateForComparison.Device
    Services = $stateForComparison.Services
    Software = $stateForComparison.Software

    PackageManager = [ordered]@{
        WingetNotepadRaw = $wingetNotepad
    }

    Checks = $stateForComparison.Checks
    Summary = $stateForComparison.Summary
}

$currentJsonPath = "$ReportDir\endpoint-report.json"
$currentSummaryPath = "$ReportDir\endpoint-summary.txt"

$historyJsonPath = "$HistoryDir\endpoint-report-$Timestamp.json"
$historySummaryPath = "$HistoryDir\endpoint-summary-$Timestamp.txt"

$finalReport | ConvertTo-Json -Depth 8 | Out-File $currentJsonPath -Encoding UTF8
$finalReport | ConvertTo-Json -Depth 8 | Out-File $historyJsonPath -Encoding UTF8

$checkSummary = $checks | ForEach-Object {
    "- $($_.Check): $($_.Result) [$($_.Detail)]"
} | Out-String

$serviceSummary = $services | ForEach-Object {
    "- $($_.Name): Status=$($_.Status), StartMode=$($_.StartMode), Compliant=$($_.Compliant)"
} | Out-String

$summaryText = @"
Endpoint Inventory Summary
Generated: $($finalReport.GeneratedAt)
Content Hash: $($finalReport.ContentHash)
Overall Status: $($finalReport.OverallStatus)

Device:
Computer: $($finalReport.Device.ComputerName)
User Context: $($finalReport.Device.UserContext)
OS: $($finalReport.Device.OS)
Version: $($finalReport.Device.Version)
Build: $($finalReport.Device.BuildNumber)
Architecture: $($finalReport.Device.Architecture)
Processor: $($finalReport.Device.ProcessorName)

Software:
Notepad++ Installed: $($finalReport.Software.NotepadPlusPlus.Installed)
Notepad++ Version: $($finalReport.Software.NotepadPlusPlus.Version)
Expected Version: $($finalReport.Software.NotepadPlusPlus.ExpectedVersion)
Version Compliant: $($finalReport.Software.NotepadPlusPlus.VersionCompliant)

Services:
$serviceSummary

Checks:
$checkSummary

Current JSON Report:
$currentJsonPath

Historical JSON Report:
$historyJsonPath
"@

$summaryText | Out-File $currentSummaryPath -Encoding UTF8
$summaryText | Out-File $historySummaryPath -Encoding UTF8

# Retention: keep only newest 5 report iterations
$reportFiles = Get-ChildItem -Path $HistoryDir -Filter "endpoint-report-*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

if ($reportFiles.Count -gt $MaxReports) {
    $reportsToDelete = $reportFiles | Select-Object -Skip $MaxReports

    foreach ($reportFile in $reportsToDelete) {
        $summaryFileName = $reportFile.Name -replace "endpoint-report-", "endpoint-summary-" -replace "\.json$", ".txt"
        $summaryFilePath = Join-Path $HistoryDir $summaryFileName

        Remove-Item $reportFile.FullName -Force -ErrorAction SilentlyContinue
        Remove-Item $summaryFilePath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Meaningful endpoint state change detected."
Write-Host "New report created."
Write-Host "Overall Status: $overallStatus"
Write-Host "Content Hash: $currentHash"
Write-Host "Current JSON report written to: $currentJsonPath"
Write-Host "Current summary written to: $currentSummaryPath"
Write-Host "Historical JSON report written to: $historyJsonPath"
Write-Host "Historical summary written to: $historySummaryPath"$isWindows11 = $os.Caption -like "*Windows 11*"
$isArm64 = $os.OSArchitecture -like "*ARM*"

# Service expectations
# Not every service must be actively running. Some only need to be enabled/available.
$serviceExpectations = @(
    [PSCustomObject]@{
        Name = "Spooler"
        ExpectedStatus = "Running"
        ExpectedStartMode = $null
        Reason = "Print Spooler should be running on this test endpoint"
    },
    [PSCustomObject]@{
        Name = "wuauserv"
        ExpectedStatus = $null
        ExpectedStartMode = "Manual"
        Reason = "Windows Update does not need to be running constantly, but should not be disabled"
    }
)

$services = foreach ($expected in $serviceExpectations) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$($expected.Name)'" -ErrorAction SilentlyContinue

    if ($svc) {
        $statusPass = if ($expected.ExpectedStatus) {
            $svc.State -eq $expected.ExpectedStatus
        }
        else {
            $true
        }

        $startModePass = if ($expected.ExpectedStartMode) {
            $svc.StartMode -eq $expected.ExpectedStartMode -or $svc.StartMode -eq "Auto"
        }
        else {
            $true
        }

        [PSCustomObject]@{
            Name              = $svc.Name
            DisplayName       = $svc.DisplayName
            Status            = $svc.State
            StartMode         = $svc.StartMode
            ExpectedStatus    = $expected.ExpectedStatus
            ExpectedStartMode = $expected.ExpectedStartMode
            Compliant         = ($statusPass -and $startModePass)
            Reason            = $expected.Reason
        }
    }
    else {
        [PSCustomObject]@{
            Name              = $expected.Name
            DisplayName       = $null
            Status            = "NotFound"
            StartMode         = $null
            ExpectedStatus    = $expected.ExpectedStatus
            ExpectedStartMode = $expected.ExpectedStartMode
            Compliant         = $false
            Reason            = "Service not found"
        }
    }
}

# Registry-based software detection
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$notepad = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Notepad++*" } |
    Select-Object -First 1 DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, PSPath

$expectedNotepadVersion = "8.9.6.4"
$notepadInstalled = $null -ne $notepad

if ($notepadInstalled) {
    $notepadReport = [ordered]@{
        Installed        = $true
        DisplayName      = $notepad.DisplayName
        Version          = $notepad.DisplayVersion
        ExpectedVersion  = $expectedNotepadVersion
        VersionCompliant = ($notepad.DisplayVersion -eq $expectedNotepadVersion)
        Publisher        = $notepad.Publisher
        InstallLocation  = $notepad.InstallLocation
        UninstallString  = $notepad.UninstallString
        DetectionSource  = "Registry uninstall key"
    }
}
else {
    $notepadReport = [ordered]@{
        Installed        = $false
        DisplayName      = $null
        Version          = $null
        ExpectedVersion  = $expectedNotepadVersion
        VersionCompliant = $false
        Publisher        = $null
        InstallLocation  = $null
        UninstallString  = $null
        DetectionSource  = "Registry uninstall key"
    }
}

# Optional raw WinGet package visibility
$wingetNotepad = winget list --name "Notepad++" 2>$null

$checks = @(
    [PSCustomObject]@{
        Check  = "OS detected"
        Result = if ($os.Caption) { "Pass" } else { "Fail" }
        Detail = $os.Caption
    },
    [PSCustomObject]@{
        Check  = "Windows 11 detected"
        Result = if ($isWindows11) { "Pass" } else { "Fail" }
        Detail = $os.Caption
    },
    [PSCustomObject]@{
        Check  = "Architecture detected"
        Result = if ($os.OSArchitecture) { "Pass" } else { "Fail" }
        Detail = $os.OSArchitecture
    },
    [PSCustomObject]@{
        Check  = "ARM64 architecture"
        Result = if ($isArm64) { "Pass" } else { "Info" }
        Detail = $os.OSArchitecture
    },
    [PSCustomObject]@{
        Check  = "Notepad++ installed"
        Result = if ($notepadInstalled) { "Pass" } else { "Fail" }
        Detail = if ($notepadInstalled) { $notepad.DisplayVersion } else { "Not detected" }
    },
    [PSCustomObject]@{
        Check  = "Notepad++ expected version"
        Result = if ($notepadInstalled -and $notepad.DisplayVersion -eq $expectedNotepadVersion) { "Pass" } else { "Fail" }
        Detail = if ($notepadInstalled) { "Installed=$($notepad.DisplayVersion); Expected=$expectedNotepadVersion" } else { "Not detected" }
    },
    [PSCustomObject]@{
        Check  = "Service compliance"
        Result = if (($services | Where-Object { $_.Compliant -eq $false }).Count -eq 0) { "Pass" } else { "Fail" }
        Detail = ($services | ForEach-Object { "$($_.Name): Status=$($_.Status), StartMode=$($_.StartMode), Compliant=$($_.Compliant)" }) -join "; "
    }
)

$failedChecks = ($checks | Where-Object { $_.Result -eq "Fail" }).Count
$passedChecks = ($checks | Where-Object { $_.Result -eq "Pass" }).Count
$infoChecks = ($checks | Where-Object { $_.Result -eq "Info" }).Count

$overallStatus = if ($failedChecks -eq 0) { "Compliant" } else { "NeedsAttention" }

# This is the stable content used for comparison.
# GeneratedAt is intentionally excluded.
$stateForComparison = [ordered]@{
    SchemaVersion = "3.0"
    OverallStatus = $overallStatus

    Device = [ordered]@{
        ComputerName  = $env:COMPUTERNAME
        UserContext   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        OS            = $os.Caption
        Version       = $os.Version
        BuildNumber   = $os.BuildNumber
        Architecture  = $os.OSArchitecture
        IsWindows11   = $isWindows11
        IsArm64       = $isArm64
        ProcessorName = $cpu.Name
        AddressWidth  = $cpu.AddressWidth
    }

    Services = $services

    Software = [ordered]@{
        NotepadPlusPlus = $notepadReport
    }

    PackageManager = [ordered]@{
        WingetNotepadRaw = $wingetNotepad
    }

    Checks = $checks

    Summary = [ordered]@{
        TotalChecks = $checks.Count
        Passed      = $passedChecks
        Failed      = $failedChecks
        Info        = $infoChecks
    }
}

$comparisonJson = $stateForComparison | ConvertTo-Json -Depth 8 -Compress
$currentHash = Get-StringSha256 -InputString $comparisonJson

# Find latest historical report, if one exists
$latestReport = Get-ChildItem -Path $HistoryDir -Filter "endpoint-report-*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$previousHash = $null

if ($latestReport) {
    try {
        $previousReport = Get-Content $latestReport.FullName -Raw | ConvertFrom-Json
        $previousHash = $previousReport.ContentHash
    }
    catch {
        $previousHash = $null
    }
}

if ($previousHash -eq $currentHash) {
    Write-Host "No meaningful endpoint state change detected."
    Write-Host "No new report created."
    Write-Host "Current content hash: $currentHash"
    return
}

# Add volatile/report metadata only after comparison
$finalReport = [ordered]@{
    SchemaVersion = "3.0"
    GeneratedAt   = $GeneratedAt.ToString("s")
    ContentHash   = $currentHash
    OverallStatus = $overallStatus

    Device = $stateForComparison.Device
    Services = $stateForComparison.Services
    Software = $stateForComparison.Software
    PackageManager = $stateForComparison.PackageManager
    Checks = $stateForComparison.Checks
    Summary = $stateForComparison.Summary
}

$jsonPath = "$HistoryDir\endpoint-report-$Timestamp.json"
$summaryPath = "$HistoryDir\endpoint-summary-$Timestamp.txt"

$finalReport | ConvertTo-Json -Depth 8 | Out-File $jsonPath -Encoding UTF8

$checkSummary = $checks | ForEach-Object {
    "- $($_.Check): $($_.Result) [$($_.Detail)]"
} | Out-String

$serviceSummary = $services | ForEach-Object {
    "- $($_.Name): Status=$($_.Status), StartMode=$($_.StartMode), Compliant=$($_.Compliant)"
} | Out-String

@"
Endpoint Inventory Summary
Generated: $($finalReport.GeneratedAt)
Content Hash: $($finalReport.ContentHash)
Overall Status: $($finalReport.OverallStatus)

Device:
Computer: $($finalReport.Device.ComputerName)
User Context: $($finalReport.Device.UserContext)
OS: $($finalReport.Device.OS)
Version: $($finalReport.Device.Version)
Build: $($finalReport.Device.BuildNumber)
Architecture: $($finalReport.Device.Architecture)
Processor: $($finalReport.Device.ProcessorName)

Software:
Notepad++ Installed: $($finalReport.Software.NotepadPlusPlus.Installed)
Notepad++ Version: $($finalReport.Software.NotepadPlusPlus.Version)
Expected Version: $($finalReport.Software.NotepadPlusPlus.ExpectedVersion)
Version Compliant: $($finalReport.Software.NotepadPlusPlus.VersionCompliant)

Services:
$serviceSummary

Checks:
$checkSummary

JSON Report:
$jsonPath
"@ | Out-File $summaryPath -Encoding UTF8

# Retention: keep only newest 5 report iterations
$reportFiles = Get-ChildItem -Path $HistoryDir -Filter "endpoint-report-*.json" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

if ($reportFiles.Count -gt $MaxReports) {
    $reportsToDelete = $reportFiles | Select-Object -Skip $MaxReports

    foreach ($reportFile in $reportsToDelete) {
        $summaryFileName = $reportFile.Name -replace "endpoint-report-", "endpoint-summary-" -replace "\.json$", ".txt"
        $summaryFilePath = Join-Path $HistoryDir $summaryFileName

        Remove-Item $reportFile.FullName -Force -ErrorAction SilentlyContinue
        Remove-Item $summaryFilePath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Meaningful endpoint state change detected."
Write-Host "New report created."
Write-Host "Overall Status: $overallStatus"
Write-Host "Content Hash: $currentHash"
Write-Host "JSON report written to: $jsonPath"
Write-Host "Summary written to: $summaryPath"
