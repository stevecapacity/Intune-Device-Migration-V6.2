<# POSTMIGRATE.PS1
Synopsis
PostMigrate.ps1 is run after the migration reboots have completed and the user signs into the PC.
DESCRIPTION
This script is used to update the device group tag in Entra ID and set the primary user in Intune and migrate the bitlocker recovery key.
USE
.\postMigrate.ps1
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
Start-Transcript -Path "$(settings.$logPath)\postMigrate.log" -Verbose

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
    exitScript -exitCode 4 -functionName "initializeScript"
}

# disable post migrate task
log "Disabling postMigrate task..."
Disable-ScheduledTask -TaskName "postMigrate" -ErrorAction Stop
log "postMigrate task disabled"


# authenticate to MS Graph
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
log "Running msGraphAuthenticate..."
try
{
    msGraphAuthenticate
    log "msGraphAuthenticate completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run msGraphAuthenticate: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# newDeviceObject function
function newDeviceObject()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_Bios).serialNumber,
        [string]$hostname = $env:COMPUTERNAME,
        [string]$groupTag = $settings.groupTag
    )
    $intuneObject = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$serialNumber'" -Headers $headers)
    if(($intuneObject.'@odata.count') -eq 1)
    {
        $intuneId = $intuneObject.value.id
        $entraId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/devices?`$filter=deviceId eq '$($intuneObject.value.azureADDeviceId)'" -Headers $headers).value.id
    }
    else 
    {
        $intuneId = $null
    }
    if([string]::IsNullOrEmpty($groupTag))
    {
        try
        {
            $groupTag = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "OG_groupTag").OG_groupTag
        }
        catch
        {
            $groupTag = $null
        }
    }
    else
    {
        $groupTag = $groupTag
    }
    $pc = @{
        serialNumber = $serialNumber
        hostname = $hostname
        intuneId = $intuneId
        groupTag = $groupTag
        entraId = $entraId
    }
    return $pc
}

# run newDeviceObject
log "Running newDeviceObject..."
try
{
    $pc = newDeviceObject
    log "newDeviceObject completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run newDeviceObject: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "newDeviceObject"
}

# set primary user
function setPrimaryUser()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$intuneID = $pc.intuneId,
        [string]$userID = (Get-ItemProperty -Path $regKey -Name "NEW_EntraId").NEW_entraId,
        [string]$userUri = "https://graph.microsoft.com/beta/users/$userID",
        [string]$intuneDeviceRefUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneID/users/`$ref"
    )
    log "Setting primary user..."
    $id = "@odata.id"
    $JSON = @{ $id="$userUri" } | ConvertTo-Json

    Invoke-RestMethod -Uri $intuneDeviceRefUri -Headers $headers -Method Post -Body $JSON
    log "Primary user for $intuneID set to $userID"
}

# run setPrimaryUser
log "Running setPrimaryUser..."
try
{
    setPrimaryUser
    log "setPrimaryUser completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run setPrimaryUser: $message"
    log "Primary user was not set- set manually in Intune."
}

# update device group tag
function updateGroupTag()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$groupTag = $pc.groupTag,
        [string]$aadDeviceId = $pc.entraId,
        [string]$deviceUri = "https://graph.microsoft.com/beta/devices"
    )
    log "Updating device group tag..."
    if([string]::IsNullOrEmpty($groupTag))
    {
        log "Group tag not found- will not be used."
    }
    else
    {
        $aadObject = Invoke-RestMethod -Method Get -Uri "$($deviceUri)?`$filter=deviceId eq '$($aadDeviceId)'" -Headers $headers
        $physicalIds = $aadObject.value.physicalIds
        $deviceId = $aadObject.value.id
        $groupTag = "[OrderID]:$($groupTag)"
        $physicalIds += $groupTag

        $body = @{
            physicalIds = $physicalIds
        } | ConvertTo-Json
        Invoke-RestMethod -Uri "$deviceUri/$deviceId" -Method Patch -Headers $headers -Body $body
        log "Device group tag updated to $groupTag"      
    }
}

# run updateGroupTag
log "Running updateGroupTag..."
try
{
    updateGroupTag
    log "updateGroupTag completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run updateGroupTag: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "updateGroupTag"
}

# migrate bitlocker function
function migrateBitlockerKey()
{
    Param(
        [string]$mountPoint = "C:",
        [PSCustomObject]$bitLockerVolume = (Get-BitLockerVolume -MountPoint $mountPoint),
        [string]$keyProtectorId = ($bitLockerVolume.KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword"}).KeyProtectorId
    )
    log "Migrating Bitlocker key..."
    if($bitLockerVolume.KeyProtector.count -gt 0)
    {
        BackupToAAD-BitLockerKeyProtector -MountPoint $mountPoint -KeyProtectorId $keyProtectorId
        log "Bitlocker key migrated"
    }
    else
    {
        log "Bitlocker key not migrated"
    }
}

# decrypt drive
function decryptDrive()
{
    Param(
        [string]$mountPoint = "C:"
    )
    Disable-BitLocker -MountPoint $mountPoint
    log "Drive $mountPoint decrypted"
}

# manage bitlocker
# if bitlockerMethod is MIGRATE, run migrateBitlocker function
if($settings.bitlockerMethod -eq "migrate")
{
    log "Running FUNCTION: migrateBitlocker..."
    try
    {
        migrateBitlocker
        log "FUNCTION: migrateBitlocker completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: migrateBitlocker failed - $message."
        log "Exiting script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "migrateBitlocker"
    }
}
else 
{
    log "Bitlocker method is not MIGRATE. Skipping migrateBitlocker function."
}

# if bitlockerMethod is DECRYPT, run decryptDrive function
if($settings.bitlockerMethod -eq "decrypt")
{
    log "Running FUNCTION: decryptDrive..."
    try
    {
        decryptDrive
        log "FUNCTION: decryptDrive completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: decryptDrive failed - $message."
        log "Exiting script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "decryptDrive"
    }
}
else 
{
    log "Bitlocker method is not DECRYPT. Skipping decryptDrive function."
}

# reset legal notice policy
function resetLockScreenCaption()
{
    Param(
        [string]$lockScreenRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$lockScreenCaption = "legalnoticecaption",
        [string]$lockScreenText = "legalnoticetext"
    )
    log "Resetting lock screen caption..."
    Remove-ItemProperty -Path $lockScreenRegPath -Name $lockScreenCaption -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $lockScreenRegPath -Name $lockScreenText -ErrorAction SilentlyContinue
    log "Lock screen caption reset"
}

# run resetLockScreenCaption
log "Running resetLockScreenCaption..."
try
{
    resetLockScreenCaption
    log "resetLockScreenCaption completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run resetLockScreenCaption: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "resetLockScreenCaption"
}

# remove migration user
log "Removing migration user..."
Remove-LocalUser -Name "MigrationInProgress" -ErrorAction Stop
log "Migration user removed"


# END SCRIPT

Stop-Transcript