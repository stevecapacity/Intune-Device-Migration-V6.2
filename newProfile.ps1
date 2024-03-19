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
$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

# start transcript
log "Starting transcript..."
Start-Transcript -Path "$(settings.$logPath)\newProfile.log" -Verbose

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

# authenticate to target tenant
function msGraphAuthenticate()
{
    Param(
        [string]$tenant = $settings.targetTenant.tenantName,
        [string]$clientId = $settings.targetTenant.clientId,
        [string]$clientSecret = $settings.targetTenant.clientSecret
    )
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/x-www-form-urlencoded")

    $body = "grant_type=client_credentials&scope=https://graph.microsoft.com/.default"
    $body += -join ("&client_id=" , $clientId, "&client_secret=", $clientSecret)

    $response = Invoke-RestMethod "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Method 'POST' -Headers $headers -Body $body

    #Get Token form OAuth.
    $token = -join ("Bearer ", $response.access_token)

    #Reinstantiate headers.
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $token)
    $headers.Add("Content-Type", "application/json")
    log "MS Graph Authenticated"
    $global:headers = $headers
}

# run msGraphAuthenticate
log "Authenticating to source tenant..."
try 
{
    msGraphAuthenticate
    log "Authenticated to source tenant."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to authenticate to source tenant: $message."
    log "Exiting script."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# get new user attributes
function newUserObject()
{
    Param(
        [string]$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName).UserName,
        [string]$SID = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$profilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID)" -Name "ProfileImagePath"),
        [string]$SAMName = ($user).Split("\")[1],
        [string]$upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($SID)\IdentityCache\$($SID)" -Name "UserName"),
        [string]$entraId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers).id
    )
    $userObject = @{
        user = $user
        SID = $SID
        profilePath = $profilePath
        SAMName = $SAMName
        upn = $upn
        entraId = $entraId
    }
    return $userObject
}

# run newUserObject
log "Running newUserObject..."
try
{
    $user = newUserObject
    log "newUserObject completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run newUserObject: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "newUserObject"
}

# write user properties to registry
log "Writing user properties to registry..."
foreach($x in $user.Keys)
{
    $name = "NEW_$($x)"
    $value = $($user[$x])
    $regPath = $settings.regPath
    try
    {
        log "Writing $($name) to registry with value $($value)..."
        reg.exe add $regPath /v $name /t REG_SZ /d $value /f | Out-Host
        log "Wrote $($name) to registry."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to write $($name) to registry: $message"
        log "Exiting script..."
        exitScript -exitCode 4 -functionName "writeUserProperties"
    }
}

# disable newProfile task
log "Disabling newProfile task..."
Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop
log "newProfile task disabled"    


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

# run revokeLogonProvider
log "Running revokeLogonProvider..."
try
{
    revokeLogonProvider
    log "revokeLogonProvider completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run revokeLogonProvider: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "revokeLogonProvider"
}

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$caption = "Almost there...",
        [string]$text = "Your PC will restart one more time to join the $($targetTenantName) environment."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v "legalnoticecaption" /t REG_SZ /d $caption /f | Out-Host
    reg.exe add $legalNoticeRegPath /v "legalNoticeText" /t REG_SZ /d $text /f | Out-Host
    log "Set lock screen caption."
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
    exitScript -exitCode 4 -functionName "setLockScreenCaption"
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

# run enableAutoLogon
log "Running enableAutoLogon..."
try
{
    enableAutoLogon
    log "enableAutoLogon completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run enableAutoLogon: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "enableAutoLogon"
}

# set finalBoot tasks
log "Setting finalBoot tasks..."
$tasks = @("finalBoot","postMigrate","AutopilotRegistration")
foreach($task in $tasks)
{
    $taskPath = "$($settings.localPath)\$($task).xml"
    if($taskPath)
    {
        schtasks.exe /Create /TN $task /XML $taskPath
        log "$($taskName) task set."
    }
    else
    {
        log "Failed to set $($taskName) task."
    }
}

Start-Sleep -Seconds 2
log "rebooting computer"

shutdown -r -t 00
Stop-Transcript
