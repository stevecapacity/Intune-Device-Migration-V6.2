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
    initializeScript -logName "newProfile"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "initializeScript"
}

# disable newProfile Task
log "Disable newProfile task..."
Disable-ScheduledTask -TaskName "newProfile" -ErrorAction SilentlyContinue
log "newProfile task disabled."

# construct new user object
log "Running FUNCTION: newUserObject..."
try
{
    $user = newUserObject -domainJoined "NO" -azureAdJoined "YES"
    log "FUNCTION: newUserObject completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: newUserObject failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "newUserObject"
}

# write new user properties to registry
log "Writing NEW User properties to registry..."
foreach($x in $user.Keys)
{
    try
    {
        reg.exe add $($settings.regPath) /v "NEW_$($x)" /t REG_SZ /d $($user[$x]) /f | Out-Host
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to write $x to registry: $message"
        log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
        exitScript -exitCode 1 -functionName "writeNewUserProperties"
    }
}

# enable auto logon
log "Enabling auto logon..."
try
{
    toggleAutoLogon -status "enabled"
    log "FUNCTION: toggleAutoLogon completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: toggleAutoLogon failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "toggleAutoLogon"
}

# revoke logon provider
log "Revoking logon provider..."
try
{
    toggleLogonProvider -status "disabled"
    log "FUNCTION: revokeLogonProvider completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: revokeLogonProvider failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "revokeLogonProvider"
}

# set lock screen caption
log "Setting lock screen caption..."
try
{
    setLockScreenCaption -caption "Almost there..." -text "Your PC will restart one more time to join the $($settings.targetTenant.tenantName) environment."
    log "Lock screen caption set."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption: $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}

# set final migration tasks
log "Setting post migration tasks..."
$tasks = @("finalBoot")
foreach($task in $tasks)
{
    $taskPath = "$($settings.localPath)\$($task).xml"
    if($taskPath)
    {
        schtasks.exe /Create /TN $task /XML $taskPath
        log "Post migration task created: $task"
    }
    else
    {
        log "Post migration task not found: $task"
    }
}

log "Post migration tasks set."
log "Exiting script"

Stop-Transcript

shutdown -r -t 00

