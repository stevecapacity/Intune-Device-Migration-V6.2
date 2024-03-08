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

# error action and import module
$ErrorActionPreference = "SilentlyContinue"
Import-Module "$($PSScriptRoot)\migrationFunctions.psm1"


# get settings json function
log "Running FUNCTION: getSettingsJSON..."
try 
{
    $settings = getSettingsJSON
    log "FUNCTION: getSettingsJSON completed successfully."
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: getSettingsJSON failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "getSettingsJSON"
}

# initialize script function
log "Running FUNCTION: initializeScript..."
try
{
    initializeScript -logName "middleBoot"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "initializeScript"
}

# disable Task function
log "Disable middleBoot task..."
Disable-ScheduledTask -TaskName "middleBoot" -ErrorAction SilentlyContinue
log "middleBoot task disabled."

# restore logon provider
log "Running FUNCTION: toggleLogonProvider..."
try 
{
    toggleLogonProvider -status "enabled"
    log "FUNCTION: toggleLogonProvider completed successfully."    
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: toggleLogonProvider failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "toggleLogonProvider"
}

# turn off auto logon
log "Running FUNCTION: toggleAutoLogon..."
try 
{
    toggleAutoLogon -status "disabled"
    log "FUNCTION: toggleAutoLogon completed successfully."    
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: toggleAutoLogon failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "toggleAutoLogon"
}

# set lock screen caption
log "Running FUNCTION: setLockScreenCaption..."
try 
{
    setLockScreenCaption -caption "Join $($settings.targetTenant.tenantName)" -text "Sign in with your $($settings.targetTenant.tenantName) email address and password to start migrating your data."
    log "FUNCTION: setLockScreenCaption completed successfully."
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: setLockScreenCaption failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}

log "Exiting script with success."

Stop-Transcript

shutdown -r -t 5



