#Requires -RunAsAdministrator
<#
CCDC Windows Hardening Script
Use at your own risk. Test before deploying broadly.
Built to be aggressive, but with toggles for competition-safe use.

Recommended:
  powershell.exe -ExecutionPolicy Bypass -File .\CCDC-Windows-Hardening.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

# =========================
# TOGGLES
# =========================
$Config = [ordered]@{
    AllowRDP                    = $false   # Set true only if you need it
    RestrictRDPToSpecificIPs    = $false   # If true, edit $AllowedRdpIPs below
    AllowedRdpIPs               = @("10.0.0.0/8","192.168.0.0/16")

    AllowWinRM                  = $false   # Set true only if you actively use remoting
    AllowSMBFileSharing         = $false   # Set true if the system must serve shares
    RemoveSMBv1                 = $true

    EnableDefenderASR           = $true
    EnableControlledFolderAccess= $false   # Can break apps, leave off unless validated
    EnablePowerShellLogging     = $true
    EnableTranscription         = $true

    DisableSpooler              = $true    # Turn off if printing is required
    DisableRemoteRegistry       = $true
    DisableUPnP                 = $true
    DisableSSDPSRV              = $true
    DisableWebClient            = $true

    DisableGuestAccount         = $true
    RenameBuiltInAdmin          = $false   # Safer to leave false during CCDC unless coordinated
    NewAdminName                = "LocalOpsAdmin"

    SetStrongPasswordPolicy     = $true
    SetAccountLockoutPolicy     = $true

    EnableFirewallLogging       = $true
    EnableAuditing              = $true
    DisableAutoRun              = $true
    HardenUAC                   = $true
    DisableLLMNR                = $true
    DisableNetBIOS              = $false   # Risky if legacy systems exist
    RestrictAnonymous           = $true
    DisableCachedDomainLogons   = $false   # Risky in domain scenarios, leave off unless needed
}

# =========================
# LOGGING
# =========================
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "C:\CCDC-Hardening"
$TranscriptPath = Join-Path $LogDir "hardening_$TimeStamp.log"
$JsonReportPath = Join-Path $LogDir "report_$TimeStamp.json"

if (-not (Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}

Start-Transcript -Path $TranscriptPath -Force

$Report = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    StartTime    = (Get-Date).ToString("s")
    Actions      = @()
    Warnings     = @()
    Errors       = @()
}

function Add-ReportAction {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
    $Report.Actions += $Message
}

function Add-ReportWarning {
    param([string]$Message)
    Write-Warning $Message
    $Report.Warnings += $Message
}

function Add-ReportError {
    param([string]$Message)
    Write-Error $Message
    $Report.Errors += $Message
}

function Set-RegDword {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Set-RegString {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
}

function Disable-ServiceSafe {
    param([Parameter(Mandatory)][string]$Name)
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        }
        Set-Service -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue
        Add-ReportAction "Disabled service: $Name"
    } catch {
        Add-ReportWarning "Service not found or could not be modified: $Name"
    }
}

function Enable-ServiceSafe {
    param([Parameter(Mandatory)][string]$Name)
    try {
        Set-Service -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $Name -ErrorAction SilentlyContinue
        Add-ReportAction "Enabled service: $Name"
    } catch {
        Add-ReportWarning "Service not found or could not be modified: $Name"
    }
}

# =========================
# BASIC PRECHECKS
# =========================
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
    Add-ReportAction "Confirmed script is running elevated"
} catch {
    Add-ReportError $_.Exception.Message
    Stop-Transcript
    throw
}

# =========================
# ACCOUNTS AND LOCAL USERS
# =========================
try {
    if ($Config.DisableGuestAccount) {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest) {
            Disable-LocalUser -Name "Guest"
            Add-ReportAction "Disabled Guest account"
        }
    }

    # Inventory administrators
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass, PrincipalSource
    $Report["LocalAdministrators"] = $admins

    # Rename built-in Administrator if requested
    if ($Config.RenameBuiltInAdmin) {
        $adminSid = "S-1-5-21-*-500"
        $admin = Get-LocalUser | Where-Object { $_.SID -like $adminSid }
        if ($admin -and $admin.Name -ne $Config.NewAdminName) {
            Rename-LocalUser -Name $admin.Name -NewName $Config.NewAdminName
            Add-ReportAction "Renamed built-in Administrator to $($Config.NewAdminName)"
        }
    }
} catch {
    Add-ReportError "Account hardening failed: $($_.Exception.Message)"
}

# =========================
# PASSWORD AND LOCKOUT POLICY
# =========================
try {
    if ($Config.SetStrongPasswordPolicy) {
        & net accounts /minpwlen:14 | Out-Null
        & net accounts /maxpwage:30 | Out-Null
        & net accounts /minpwage:1 | Out-Null
        & net accounts /uniquepw:10 | Out-Null
        Add-ReportAction "Applied local password policy: min 14 chars, max age 30 days, unique 10"
    }

    if ($Config.SetAccountLockoutPolicy) {
        & net accounts /lockoutthreshold:5 | Out-Null
        & net accounts /lockoutduration:30 | Out-Null
        & net accounts /lockoutwindow:30 | Out-Null
        Add-ReportAction "Applied account lockout policy: 5 attempts, 30 minute lockout"
    }
} catch {
    Add-ReportError "Password or lockout policy failed: $($_.Exception.Message)"
}

# =========================
# UAC HARDENING
# =========================
try {
    if ($Config.HardenUAC) {
        $uac = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-RegDword -Path $uac -Name "EnableLUA" -Value 1
        Set-RegDword -Path $uac -Name "ConsentPromptBehaviorAdmin" -Value 2
        Set-RegDword -Path $uac -Name "PromptOnSecureDesktop" -Value 1
        Set-RegDword -Path $uac -Name "EnableInstallerDetection" -Value 1
        Set-RegDword -Path $uac -Name "FilterAdministratorToken" -Value 1
        Add-ReportAction "Hardened UAC settings"
    }
} catch {
    Add-ReportError "UAC hardening failed: $($_.Exception.Message)"
}

# =========================
# AUTORUN / AUTOPLAY
# =========================
try {
    if ($Config.DisableAutoRun) {
        $explorer = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Set-RegDword -Path $explorer -Name "NoDriveTypeAutoRun" -Value 255
        Set-RegDword -Path $explorer -Name "NoAutorun" -Value 1
        Add-ReportAction "Disabled AutoRun/AutoPlay"
    }
} catch {
    Add-ReportError "AutoRun hardening failed: $($_.Exception.Message)"
}

# =========================
# NETWORK NAME RESOLUTION / LEGACY
# =========================
try {
    if ($Config.DisableLLMNR) {
        $dnsClient = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Set-RegDword -Path $dnsClient -Name "EnableMulticast" -Value 0
        Add-ReportAction "Disabled LLMNR"
    }

    if ($Config.RestrictAnonymous) {
        $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-RegDword -Path $lsa -Name "RestrictAnonymous" -Value 1
        Set-RegDword -Path $lsa -Name "RestrictAnonymousSAM" -Value 1
        Set-RegDword -Path $lsa -Name "EveryoneIncludesAnonymous" -Value 0
        Set-RegDword -Path $lsa -Name "NoLMHash" -Value 1
        Add-ReportAction "Restricted anonymous access and disabled LM hash storage"
    }

    if ($Config.DisableCachedDomainLogons) {
        $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-RegString -Path $winlogon -Name "CachedLogonsCount" -Value "0"
        Add-ReportAction "Disabled cached domain logons"
    }

    if ($Config.DisableNetBIOS) {
        Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object {
            try {
                $_.SetTcpipNetbios(2) | Out-Null
            } catch {}
        }
        Add-ReportAction "Disabled NetBIOS over TCP/IP on active adapters"
    }
} catch {
    Add-ReportError "Legacy networking hardening failed: $($_.Exception.Message)"
}

# =========================
# SMB HARDENING
# =========================
try {
    if ($Config.RemoveSMBv1) {
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Add-ReportAction "Disabled SMBv1 optional feature"
        } catch {
            Add-ReportWarning "Could not disable SMBv1 via optional feature API"
        }

        try {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue | Out-Null
            Add-ReportAction "Disabled SMBv1 at SMB server configuration level"
        } catch {
            Add-ReportWarning "Could not set SMB server SMBv1 configuration"
        }
    }

    # Require signing where possible
    try {
        Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue | Out-Null
        Add-ReportAction "Enabled and required SMB signing on server"
    } catch {
        Add-ReportWarning "Could not enforce SMB signing on server"
    }

    if (-not $Config.AllowSMBFileSharing) {
        # Block inbound SMB
        Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
        Add-ReportAction "Disabled inbound File and Printer Sharing firewall rules"
    }
} catch {
    Add-ReportError "SMB hardening failed: $($_.Exception.Message)"
}

# =========================
# RDP HARDENING
# =========================
try {
    $ts = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdpTcp = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

    if (-not $Config.AllowRDP) {
        Set-RegDword -Path $ts -Name "fDenyTSConnections" -Value 1
        Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
        Add-ReportAction "Disabled RDP and disabled Remote Desktop firewall rules"
    } else {
        Set-RegDword -Path $ts -Name "fDenyTSConnections" -Value 0
        Set-RegDword -Path $rdpTcp -Name "UserAuthentication" -Value 1
        Set-RegDword -Path $rdpTcp -Name "SecurityLayer" -Value 2
        Set-RegDword -Path $rdpTcp -Name "MinEncryptionLevel" -Value 3
        Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue
        Add-ReportAction "Enabled RDP with NLA and stronger transport settings"

        if ($Config.RestrictRDPToSpecificIPs -and $Config.AllowedRdpIPs.Count -gt 0) {
            Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Set-NetFirewallRule -RemoteAddress $Config.AllowedRdpIPs -ErrorAction SilentlyContinue
            Add-ReportAction "Restricted RDP firewall scope to specific IP ranges"
        }
    }
} catch {
    Add-ReportError "RDP hardening failed: $($_.Exception.Message)"
}

# =========================
# WINRM / PS REMOTING
# =========================
try {
    if (-not $Config.AllowWinRM) {
        Disable-PSRemoting -Force -ErrorAction SilentlyContinue
        Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction SilentlyContinue
        Add-ReportAction "Disabled PowerShell remoting and WinRM"
    } else {
        Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name WinRM -ErrorAction SilentlyContinue
        Add-ReportAction "WinRM allowed by configuration"
    }
} catch {
    Add-ReportError "WinRM hardening failed: $($_.Exception.Message)"
}

# =========================
# FIREWALL
# =========================
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    Add-ReportAction "Enabled Windows Firewall on all profiles with inbound block and outbound allow"

    if ($Config.EnableFirewallLogging) {
        foreach ($profile in @("Domain","Private","Public")) {
            Set-NetFirewallProfile -Profile $profile `
                -LogAllowed True `
                -LogBlocked True `
                -LogFileName "$LogDir\pfirewall_$($profile.ToLower()).log" `
                -LogMaxSizeKilobytes 16384
        }
        Add-ReportAction "Enabled firewall allow/block logging for all profiles"
    }

    # Disable common remote admin exposure you probably do not want by default
    Get-NetFirewallRule -DisplayGroup "Network Discovery" -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
    Add-ReportAction "Disabled Network Discovery firewall rules"
} catch {
    Add-ReportError "Firewall hardening failed: $($_.Exception.Message)"
}

# =========================
# DEFENDER
# =========================
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
    Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
    Set-MpPreference -CloudBlockLevel High -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
    Set-MpPreference -CheckForSignaturesBeforeRunningScan $true -ErrorAction SilentlyContinue
    Set-MpPreference -ScanArchiveFiles $true -ErrorAction SilentlyContinue
    Set-MpPreference -ScanPackedExecutables $true -ErrorAction SilentlyContinue
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false -ErrorAction SilentlyContinue
    Add-ReportAction "Hardened Microsoft Defender Antivirus preferences"

    try {
        Update-MpSignature -ErrorAction SilentlyContinue | Out-Null
        Add-ReportAction "Triggered Defender signature update"
    } catch {
        Add-ReportWarning "Could not update Defender signatures"
    }

    if ($Config.EnableControlledFolderAccess) {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
        Add-ReportAction "Enabled Controlled Folder Access"
    }

    if ($Config.EnableDefenderASR) {
        $ids = @(
            "56A863A9-875E-4185-98A7-B882C64B5CE5", # Block abuse of exploited vulnerable signed drivers
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", # Block executable content from email/webmail
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", # Block all Office apps from creating child processes
            "3B576869-A4EC-4529-8536-B80A7769E899", # Block Office apps from creating executable content
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84", # Block Office apps from injecting code
            "D3E037E1-3EB8-44C8-A917-57927947596D", # Block JS/VBS from launching downloaded executable content
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", # Block execution of potentially obfuscated scripts
            "26190899-1602-49E8-8B27-EB1D0A1CE869", # Block Office communication app child processes
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", # Block credential stealing from LSASS
            "01443614-CD74-433A-B99E-2ECDC07BFC25", # Block executable files from running unless they meet prevalence/age/trust
            "C1DB55AB-C21A-4637-BB3F-A12568109D35"  # Use advanced protection against ransomware
        )
        $actions = @("Enabled") * $ids.Count
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction SilentlyContinue
        Add-ReportAction "Enabled a strong set of Defender ASR rules"
    }
} catch {
    Add-ReportError "Defender hardening failed: $($_.Exception.Message)"
}

# =========================
# POWERSHELL LOGGING
# =========================
try {
    if ($Config.EnablePowerShellLogging) {
        $psPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        $modulePath = Join-Path $psPolicy "ModuleLogging"
        $moduleNamesPath = Join-Path $modulePath "ModuleNames"
        $scriptBlockPath = Join-Path $psPolicy "ScriptBlockLogging"

        Set-RegDword -Path $modulePath -Name "EnableModuleLogging" -Value 1
        if (-not (Test-Path $moduleNamesPath)) {
            New-Item -Path $moduleNamesPath -Force | Out-Null
        }
        Set-RegString -Path $moduleNamesPath -Name "*" -Value "*"

        Set-RegDword -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1
        Add-ReportAction "Enabled PowerShell module logging and script block logging"
    }

    if ($Config.EnableTranscription) {
        $transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        Set-RegDword -Path $transcriptionPath -Name "EnableTranscripting" -Value 1
        Set-RegDword -Path $transcriptionPath -Name "EnableInvocationHeader" -Value 1
        Set-RegString -Path $transcriptionPath -Name "OutputDirectory" -Value "$LogDir\Transcripts"
        if (-not (Test-Path "$LogDir\Transcripts")) {
            New-Item -Path "$LogDir\Transcripts" -ItemType Directory -Force | Out-Null
        }
        Add-ReportAction "Enabled PowerShell transcription"
    }
} catch {
    Add-ReportError "PowerShell logging hardening failed: $($_.Exception.Message)"
}

# =========================
# AUDIT POLICY
# =========================
try {
    if ($Config.EnableAuditing) {
        & auditpol /set /category:* /success:enable /failure:enable | Out-Null

        # Explicitly set critical subcategories
        & auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable | Out-Null
        & auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable | Out-Null
        Add-ReportAction "Enabled broad auditing and critical subcategories"
    }
} catch {
    Add-ReportError "Audit policy hardening failed: $($_.Exception.Message)"
}

# =========================
# SERVICES
# =========================
try {
    if ($Config.DisableRemoteRegistry) { Disable-ServiceSafe -Name "RemoteRegistry" }
    if ($Config.DisableSpooler)        { Disable-ServiceSafe -Name "Spooler" }
    if ($Config.DisableUPnP)           { Disable-ServiceSafe -Name "upnphost" }
    if ($Config.DisableSSDPSRV)        { Disable-ServiceSafe -Name "SSDPSRV" }
    if ($Config.DisableWebClient)      { Disable-ServiceSafe -Name "WebClient" }
} catch {
    Add-ReportError "Service hardening failed: $($_.Exception.Message)"
}

# =========================
# SHARES AND OPEN PORTS INVENTORY
# =========================
try {
    $Report["Shares"] = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description, CurrentUsers
    $Report["ListeningPorts"] = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | 
        Select-Object LocalAddress, LocalPort, OwningProcess
    Add-ReportAction "Collected shares and listening ports inventory"
} catch {
    Add-ReportWarning "Could not inventory shares or listening ports"
}

# =========================
# QUICK VERIFICATION SNAPSHOT
# =========================
try {
    $verification = [ordered]@{
        FirewallProfiles      = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
        RDPRegistry           = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue | Select-Object fDenyTSConnections
        WinRMService          = Get-Service -Name WinRM -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
        DefenderStatus        = Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled, NISEnabled
        SMBServerConfig       = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RequireSecuritySignature, EnableSecuritySignature
        LocalAdmins           = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name, ObjectClass, PrincipalSource
        AuditSnapshot         = & auditpol /get /category:* 
    }
    $Report["Verification"] = $verification
    Add-ReportAction "Collected verification snapshot"
} catch {
    Add-ReportWarning "Could not collect full verification snapshot"
}

$Report["EndTime"] = (Get-Date).ToString("s")
$Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonReportPath -Encoding UTF8

Write-Host ""
Write-Host "Hardening complete." -ForegroundColor Cyan
Write-Host "Transcript: $TranscriptPath"
Write-Host "Report:     $JsonReportPath"
Write-Host ""

Stop-Transcript
