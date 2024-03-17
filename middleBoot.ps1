<# MIDDLEBOOT.PS1
Synopsis
Middleboot.ps1 is the second script in the migration process.
DESCRIPTION
This script is used to automatically restart the computer immediately after the installation of the startMigrate.ps1 script and change the lock screen text.  The password logon credential provider is also enabled to allow the user to log in with their new credentials.
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
        [string]$logName = "middleBoot.log",
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

# restore logon credential provider
function restoreLogonProvider()
{
    Param(
        [string]$logonProviderPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}",
        [string]$logonProviderName = "Disabled",
        [int]$logonProviderValue = 0
    )
    reg.exe add $logonProviderPath /v $logonProviderName /t REG_DWORD /d $logonProviderValue /f | Out-Host
    log "Logon credential provider restored"
}

# set legal notice
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$legalCaptionName = "legalnoticecaption",
        [string]$legalCaptionValue = "Join $($targetTenantName)",
        [string]$legalTextName = "legalnoticetext",
        [string]$text = "Sign in with your new $($targetTenantName) email address and password to start migrating your data."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalPath /v $legalCaptionName /t REG_SZ /d $legalCaptionValue /f | Out-Host
    reg.exe add $legalPath /v $legalTextName /t REG_SZ /d $text /f | Out-Host
    log "Lock screen caption set"
}

# disable auto logon
function disableAutoLogon()
{
    Param(
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoLogonName = "AutoAdminLogon",
        [string]$autoLogonValue = 0
    )
    log "Disabling auto logon..."
    reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $autoLogonValue /f | Out-Host
    log "Auto logon disabled"
}

# disable middleBoot task
function disableTask()
{
    Param(
        [string]$taskName = "middleBoot"
    )
    log "Disabling middleBoot task..."
    Disable-ScheduledTask -TaskName $taskName
    log "middleBoot task disabled"    
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# run get settings function
try
{
    getSettingsJSON
    log "Retrieved settings JSON"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to get settings JSON: $message"
    log "Exiting script"
    Exit 1
}

# run initialize script function
try
{
    initializeScript
    log "Initialized script"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to initialize script: $message"
    log "Exiting script"
    Exit 1
}

# run restore logon credential provider function
try
{
    restoreLogonProvider
    log "Restored logon credential provider"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to restore logon credential provider: $message"
    log "Exiting script"
    Exit 1
}

# run set lock screen caption function
try
{
    setLockScreenCaption
    log "Set lock screen caption"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption: $message"
    log "WARNING: Lock screen caption not set"
}

# run disable auto logon function
try
{
    disableAutoLogon
    log "Disabled auto logon"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable auto logon: $message"
    log "Exiting script"
    Exit 1
}

# run disable task function
try
{
    disableTask
    log "Disabled middleBoot task"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to disable middleBoot task: $message"
    log "Exiting script"
    Exit 1
}

# END SCRIPT
log "Restarting computer..."
shutdown -r -t 5

Stop-Transcript