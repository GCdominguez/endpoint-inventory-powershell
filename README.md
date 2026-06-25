# Endpoint Inventory PowerShell Lab

PowerShell endpoint compliance and drift-detection lab for Windows inventory, service state, software detection, JSON reporting, and report retention.

## Overview

This project demonstrates a practical Windows endpoint inventory and compliance workflow using PowerShell.

The script collects endpoint state, validates expected configuration, detects meaningful changes, and writes reports only when the endpoint state changes. It is designed as a lab project for endpoint engineering, software deployment validation, drift detection, and automation practice.

## What the script checks

* Windows OS version and build
* Processor architecture, including ARM64 detection
* Execution/user context
* Service state and expected service configuration
* Notepad++ installation detection through registry uninstall keys
* Expected software version compliance
* WinGet package visibility
* Pass/fail compliance checks
* JSON and text summary report output

## Key behavior

The script avoids creating noisy duplicate reports.

Instead of writing a new report every time it runs, it builds a stable representation of endpoint state, excludes volatile metadata such as timestamp, hashes the meaningful content, and only saves a new historical report when endpoint state changes.

It also keeps only the newest five report iterations and deletes older reports.

## Lab paths

Script location on the test endpoint:

```text
C:\ProgramData\EndpointLab\Scripts\endpoint-inventory.ps1
```

Current report output:

```text
C:\ProgramData\EndpointLab\Reports
```

Historical report output:

```text
C:\ProgramData\EndpointLab\Reports\History
```

## Example workflow

Run the script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& "C:\ProgramData\EndpointLab\Scripts\endpoint-inventory.ps1"
```

If no endpoint state has changed, no new historical report is created.

To force a meaningful state change, stop the Print Spooler service:

```powershell
Stop-Service -Name Spooler
& "C:\ProgramData\EndpointLab\Scripts\endpoint-inventory.ps1"
```

The script should detect the service state change, create a new report, and mark the endpoint as needing attention.

Restore the service:

```powershell
Start-Service -Name Spooler
& "C:\ProgramData\EndpointLab\Scripts\endpoint-inventory.ps1"
```

The script should detect that the endpoint returned to the expected state and create a new report.

Run the script again without changing anything:

```powershell
& "C:\ProgramData\EndpointLab\Scripts\endpoint-inventory.ps1"
```

No new report should be created because there was no meaningful endpoint state change.

## Why this matters

This lab models several endpoint engineering concepts:

* Desired state validation
* Software detection
* Version compliance
* Service health checks
* Architecture-aware reporting
* JSON output
* Drift detection
* Report retention
* Signal-to-noise reduction

The goal is not just to collect data, but to determine whether the endpoint is in the expected state and whether that state has changed over time.

## Notes

This is a lab project. In a production environment, scripts like this should typically be version-controlled, signed, deployed through a management platform, and written to a centralized reporting or monitoring system.

Generated reports may include local machine names, user context, software state, and hashes. Reports are intentionally excluded from the repository through `.gitignore`.
