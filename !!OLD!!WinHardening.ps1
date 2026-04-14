# Script for Hardening Windows 10 Device for CCDC Event 
# By: Jacob Lee

# Function to print status in color
function Print-Status {
    param (
        [string]$Message,
        [bool]$IsSuccess
    )

    if ($IsSuccess) {
        Write-Host "$Message" -ForegroundColor Green
    } else {
        Write-Host "$Message" -ForegroundColor Red
    }
}

# Enables Windows Defender Antivirus 
try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Print-Status "Windows Defender Antivirus enabled successfully." $true
} catch {
    Print-Status "Failed To Enable Windows Defender Antivirus - Manual Disable Required" $false
}

# Enables Windows Defender Firewall 
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Print-Status "Windows Defender Firewall enabled successfully." $true
} catch {
    Print-Status "Failed To Enable Windows Defender Firewall - Manual Disable Required" $false
}

# Disable Remote Desktop
try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1
    Print-Status "Remote Desktop disabled successfully." $true
} catch {
    Print-Status "Failed To Disable Remote Desktop - Manual Disable Required" $false
}

Write-Host "Hardening Complete" -ForegroundColor Yellow
Write-Host "Please Manually Verify All Changes Have Taken Effect" -ForegroundColor Yellow
