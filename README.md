<#
.SYNOPSIS
    This PowerShell script ensures that the system is configured to audit Account Management - User Account Management failures.

.NOTES
    Author          : Seth Suri
    LinkedIn        : (https://www.linkedin.com/in/seth-suri-98b461184/)
    GitHub          : (github.com/sethsuri)
    Date Created    : 2024-09-09
    Last Modified   : 2024-09-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
#>

# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator."
    exit
}

# Enable "Audit: Force audit policy subcategory settings"
Write-Host "Enabling 'Audit: Force audit policy subcategory settings'..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

# Refresh Group Policy to apply the setting
gpupdate /force

# Configure Audit Policy for "User Account Management - Failure"
Write-Host "Configuring audit policy for 'User Account Management - Failure'..."
auditpol /set /subcategory:"User Account Management" /failure:enable

# Verify the configuration
Write-Host "Verifying the audit policy configuration..."
auditpol /get /subcategory:"User Account Management"

Write-Host "Audit policy has been successfully configured!"

