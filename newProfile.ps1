<# NEWPROFILE.PS1
Synopsis
Newprofile.ps1 runs after the user signs in with their target account.
DESCRIPTION
This script is used to capture the SID of the destination user account after sign in.  The SID is then written to the registry.
USE
This script is intended to be run as a scheduled task.  The task is created by the startMigrate.ps1 script and is disabled by this script.
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt
Jesse Weimer
#>

$ErrorActionPreference = "SilentlyContinue"
# CMDLET FUNCTIONS

# set log function
function log()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$message
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    Write-Output "$ts $message"
}

# CMDLET FUNCTIONS

# START SCRIPT FUNCTIONS

# get json settings
function getSettingsJSON()
{
    param(
        [string]$json = "settings.json"
    )
    $global:settings = Get-Content -Path "$($PSScriptRoot)\$($json)" | ConvertFrom-Json
    return $settings
}

# initialize script
function initializeScript()
{
    Param(
        [string]$logPath = $settings.logPath,
        [string]$logName = "newProfile.log",
        [string]$localPath = $settings.localPath
    )
    Start-Transcript -Path "$logPath\$logName" -Verbose
    log "Initializing script..."
    if(!(Test-Path $localPath))
    {
        mkdir $localPath
        log "Local path created: $localPath"
    }
    else
    {
        log "Local path already exists: $localPath"
    }
    $global:localPath = $localPath
    $context = whoami
    log "Running as $($context)"
    log "Script initialized"
    return $localPath
}

# get new user SID
function getNewUserSID()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$newUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName),
        [string]$newUserSID = (New-Object System.Security.Principal.NTAccount($newUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    )
    log "New user: $newUser"
    if(![string]::IsNullOrEmpty($newUserSID))
    {
        reg.exe add $regPath /v "NewUserSID" /t REG_SZ /d $newUserSID /f | Out-Host
        log "SID written to registry"
    
    }
    else
    {
        log "New user SID not found"
    }
}

# disable newProfile task
function disableNewProfileTask()
{
    Param(
        [string]$taskName = "newProfile"
    )
    Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop
    log "newProfile task disabled"    
}

# revoke logon provider
function revokeLogonProvider()
{
    Param(
        [string]$logonProviderPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}",
        [string]$logonProviderName = "Disabled",
        [int]$logonProviderValue = 1
    )
    reg.exe add $logonProviderPath /v $logonProviderName /t REG_DWORD /d $logonProviderValue /f | Out-Host
    log "Revoked logon provider."
}

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$legalNoticeCaption = "legalnoticecaption",
        [string]$legalNoticeCaptionValue = "Almost there...",
        [string]$legalNoticeText = "legalnoticetext",
        [string]$legalNoticeTextValue = "Your PC will restart one more time to join the $($targetTenantName) environment."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v $legalNoticeCaption /t REG_SZ /d $legalNoticeCaptionValue /f | Out-Host
    reg.exe add $legalNoticeRegPath /v $legalNoticeText /t REG_SZ /d $legalNoticeTextValue /f | Out-Host
    log "Set lock screen caption."
}

# enable auto logon
function enableAutoLogon()
{
    Param(
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoLogonName = "AutoAdminLogon",
        [string]$autoLogonValue = 1
    )
    log "Enabling auto logon..."
    reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $autoLogonValue /f | Out-Host
    log "Auto logon enabled."
}

# set finalBoot task
function setFinalBootTask()
{
    Param(
        [string]$taskName = "finalBoot",
        [string]$taskXML = "$($localPath)\$($taskName).xml"
    )
    log "Setting $($taskName) task..."
    if($taskXML)
    {
        schtasks.exe /Create /TN $taskName /XML $taskXML
        log "$($taskName) task set."
    }
    else
    {
        log "Failed to set $($taskName) task: $taskXML not found"
    }
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# get settings
try
{
    getSettingsJSON
    log "Settings retrieved"
}
catch
{
    $message = $_.Exception.Message
    log "Settings not loaded: $message"
    log "Exiting script"
    Exit 1
}

# initialize script
try
{
    initializeScript
    log "Script initialized"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to initialize script: $message"
    log "Exiting script"
    Exit 1
}

# get new user SID
try
{
    getNewUserSID
    log "New user SID retrieved"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to get new user SID: $message"
    log "Exiting script"
    Exit 1
}

# disable newProfile task
try
{
    disableNewProfileTask
    log "newProfile task disabled"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable newProfile task: $message"
    log "Exiting script"
    Exit 1
}

# revoke logon provider
try
{
    revokeLogonProvider
    log "Logon provider revoked"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to revoke logon provider: $message"
    log "WARNING: Logon provider not revoked"
}

# set lock screen caption
try
{
    setLockScreenCaption
    log "Lock screen caption set"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption: $message"
    log "WARNING: Lock screen caption not set"
}

# enable auto logon
try
{
    enableAutoLogon
    log "Auto logon enabled"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to enable auto logon: $message"
    log "WARNING: Auto logon not enabled"
}

# set finalBoot task
try
{
    setFinalBootTask
    log "finalBoot task set"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set finalBoot task: $message"
    log "Exiting script"
    Exit 1
}

Start-Sleep -Seconds 2
log "rebooting computer"

shutdown -r -t 00
Stop-Transcript
