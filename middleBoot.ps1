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

# FUNCTION: exitScript
# PURPOSE: Exit script with error code
# DESCRIPTION: This function exits the script with an error code.  It takes an exit code, function name, and local path as input and outputs 
function exitScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int]$exitCode,
        [Parameter(Mandatory=$true)]
        [string]$functionName,
        [string]$localpath = $settings.localPath
    )
    if($exitCode -eq 1)
    {
        log "Function $($functionName) failed with critical error.  Exiting script with exit code $($exitCode)."
        log "Will remove $($localpath) and reboot device.  Please log in with local admin credentials on next boot to troubleshoot."
        Remove-Item -Path $localpath -Recurse -Force -Verbose
        log "Removed $($localpath)."
        # enable password logon provider
        reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}" /v "Disabled" /t REG_DWORD /d 0 /f | Out-Host
        log "Enabled logon provider."
        log "rebooting device..."
        shutdown -r -t 30
        Stop-Transcript
        Exit -1
    }
    elseif($exitCode -eq 4)
    {
        log "Function $($functionName) failed with non-critical error.  Exiting script with exit code $($exitCode)."
        Remove-Item -Path $localpath -Recurse -Force -Verbose
        log "Removed $($localpath)."
        Stop-Transcript
        Exit 1
    }
    else
    {
        log "Function $($functionName) failed with unknown error.  Exiting script with exit code $($exitCode)."
        Stop-Transcript
        Exit 1
    }
}

# get json settings
function getSettingsJSON()
{
    param(
        [string]$json = "settings.json"
    )
    $settings = Get-Content -Path "$($PSScriptRoot)\$($json)" | ConvertFrom-Json
    return $settings
}

# run getSettingsJSON
log "Getting settings JSON..."
try
{
    $settings = getSettingsJSON
    log "Settings JSON retrieved"
}
catch
{
    log "Failed to retrieve settings JSON"
    exitScript -exitCode 1 -functionName "getSettingsJSON"
}

# start transcript
log "Starting transcript..."
Start-Transcript -Path "$(settings.$logPath)\middleBoot.log" -Verbose

# initialize script
function initializeScript()
{
    Param(
        [Parameter(Mandatory=$false)]
        [bool]$installTag, 
        [string]$localPath = $settings.localPath
    )
    log "Initializing script..."
    if(!(Test-Path $localPath))
    {
        mkdir $localPath
        log "Created $($localPath)."
    }
    else
    {
        log "$($localPath) already exists."
    }
    if($installTag -eq $true)
    {
        New-Item -Path "$($localPath)\install.tag" -ItemType file -Force
        log "Created $($installTag)."
    }
    $context = whoami
    log "Running as $($context)."
}

# run initializeScript
log "Running initializeScript..."
try
{
    initializeScript
    log "initializeScript completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run initializeScript: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "initializeScript"
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

# run restoreLogonProvider
log "Running restoreLogonProvider..."
try
{
    restoreLogonProvider
    log "restoreLogonProvider completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run restoreLogonProvider: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "restoreLogonProvider"
}

# set legal notice
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$caption = "Join $($targetTenantName)",
        [string]$text = "Sign in with your new $($targetTenantName) email address and password to start migrating your data."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalPath /v "legalnoticecaption" /t REG_SZ /d $caption /f | Out-Host
    reg.exe add $legalPath /v "legalnoticetext" /t REG_SZ /d $text /f | Out-Host
    log "Lock screen caption set"
}

# run setLockScreenCaption
log "Running setLockScreenCaption..."
try
{
    setLockScreenCaption
    log "setLockScreenCaption completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run setLockScreenCaption: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
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

# run disableAutoLogon
log "Running disableAutoLogon..."
try
{
    disableAutoLogon
    log "disableAutoLogon completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run disableAutoLogon: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "disableAutoLogon"
}

# disable middleBoot task
log "Disabling middleBoot task..."
Disable-ScheduledTask -TaskName "middleBoot"
log "middleBoot task disabled"    

# END SCRIPT
log "Restarting computer..."
shutdown -r -t 5

Stop-Transcript