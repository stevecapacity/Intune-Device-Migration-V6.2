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
    exitScript -exitCode 4 -functionName "getSettingsJSON"
}

# initialize script function
log "Running FUNCTION: initializeScript..."
try
{
    initializeScript -logName "postMigrate"
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# disable postMigrate Task
log "Disable postMigrate task..."
Disable-ScheduledTask -TaskName "postMigrate" -ErrorAction SilentlyContinue
log "postMigrate task disabled."

# ms graph authentication
log "Running FUNCTION: msGraphAuthenticate..."
try
{
    msGraphAuthenticate
    log "FUNCTION: msGraphAuthenticate completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: msGraphAuthenticate failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# construct new device object
log "Running FUNCTION: newDeviceObject..."
try
{
    $device = newDeviceObject
    log "FUNCTION: newDeviceObject completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: newDeviceObject failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 4 -functionName "newDeviceObject"
}

# get user object from graph
log "Getting user object from target tenant..."
$currentUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName).UserName
$currentSID = (New-Object System.Security.Principal.NTAccount($currentUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$upn = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache\$($currentSID)\Name2SID\$($currentSID)" -Name "IdentityName"
$userID = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Method Get -Headers $headers).id
log "User Entra object ID is $($userID)"

# set primary user in Intune
log "Setting primary user in Intune..."
$userUri = "https://graph.microsoft.com/beta/users/$($userID)"
$deviceRefUri = "https://graph.microsoft.com/beta/devices/$($device.intuneId)/users/`$ref"

$id = "@odata.id"
$JSON = @{ $id="$userUri" } | ConvertTo-Json

Invoke-RestMethod -Uri $deviceRefUri -Method Post -Headers $headers -Body $JSON
log "Primary user set in Intune."

# update device group tag in Entra ID
$regPath = $settings.regPath
$regKey = "Registry::$regPath"
$groupTag = (Get-ItemProperty -Path $regKey -Name "OG_groupTag").OG_groupTag
$aadDeviceId = $device.azureAdDeviceId

if([string]::IsNullOrEmpty($groupTag))
{
    log "Group tag not found - will not be used."
}
else
{
    $aadObject = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/devices/$($aadDeviceId)" -Headers $headers
    $physicalIds = $aadObject.physicalIds
    $groupTag = "[OrderID]:$($groupTag)"
    $physicalIds += $groupTag
    $body = @{
        physicalIds = $physicalIds
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devices/$($aadDeviceId)" -Method Patch -Headers $headers -Body $body
    log "Group tag updated in Entra ID."
}

# migrate or decrypt bitlocker recovery key
log "managing bitlocker recovery key..."
if($settings.bitlockerMethod -eq "Migrate")
{
    log "Migrating bitlocker recovery key..."
    $bitLockerVolume = Get-BitLockerVolume -MountPoint "C:"
    $keyProtectorId = ($bitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }).KeyProtectorId
    if($bitLockerVolume.KeyProtector.count -gt 0)
    {
        BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $keyProtectorId
        log "Bitlocker key migrated"
    }
    else
    {
        log "Bitlocker key not migrated"
    }
}
elseif($settings.bitlockerMethod -eq "Decrypt")
{
    log "Decrypting bitlocker recovery key..."
    Disable-BitLocker -MountPoint "C:"
    log "Bitlocker drive decrypted"
}
else
{
    log "Bitlocker method not set - no action taken."
}

# reset lock screen caption
log "Resetting lock screen caption..."
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -ErrorAction SilentlyContinue
log "Lock screen caption reset."

# remove migration user
log "Removing migration user..."
Remove-LocalUser -Name "MigrationInProgress" -ErrorAction SilentlyContinue
log "Migration user removed."

log "End post migrate script"

Stop-Transcript














