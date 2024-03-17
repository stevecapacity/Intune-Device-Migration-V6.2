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
        [string]$logName = "postMigrate.log",
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

# disable post migrate task
function disablePostMigrateTask()
{
    Param(
        [string]$taskName = "postMigrate"
    )
    log "Disabling postMigrate task..."
    Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop
    log "postMigrate task disabled"
}

# get device info
function getDeviceInfo()
{
    Param(
        [string]$hostname = $env:COMPUTERNAME,
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS | Select-Object SerialNumber).SerialNumber
    )
    $global:deviceInfo = @{
        "hostname" = $hostname
        "serialNumber" = $serialNumber
    }
    foreach($key in $deviceInfo.Keys)
    {
        log "$($key): $($deviceInfo[$key])"
    }
}

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

# get user graph info
function getGraphInfo()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$serialNumber = $deviceInfo.serialNumber,
        [string]$intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
        [string]$newUserSID = (Get-ItemPropertyValue -Path $regKey -Name "NewUserSID"),
        [string]$userUri = "https://graph.microsoft.com/beta/users",
        [string]$upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($newUserSID)\IdentityCache\$($newUserSID)" -Name "UserName")
    )
    log "Getting graph info..."
    $intuneObject = Invoke-RestMethod -Uri "$($intuneUri)?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get
    if(($intuneObject.'@odata.count') -eq 1)
    {
        $global:intuneID = $intuneObject.value.id
        $global:aadDeviceID = $intuneObject.value.azureADDeviceId
        log "Intune Device ID: $intuneID, Azure AD Device ID: $aadDeviceID, User ID: $userID"
    }
    else
    {
        log "Intune object not found"
    }
    $userObject = Invoke-RestMethod -Uri "$userUri/$upn" -Headers $headers -Method Get
    if(![string]::IsNullOrEmpty($userObject.id))
    {
        $global:userID = $userObject.id
        log "User ID: $userID"
    }
    else
    {
        log "User object not found"
    }
}

# set primary user
function setPrimaryUser()
{
    Param(
        [string]$intuneID = $intuneID,
        [string]$userID = $userID,
        [string]$userUri = "https://graph.microsoft.com/beta/users/$userID",
        [string]$intuneDeviceRefUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneID/users/`$ref"
    )
    log "Setting primary user..."
    $id = "@odata.id"
    $JSON = @{ $id="$userUri" } | ConvertTo-Json

    Invoke-RestMethod -Uri $intuneDeviceRefUri -Headers $headers -Method Post -Body $JSON
    log "Primary user for $intuneID set to $userID"
}

# update device group tag
function updateGroupTag()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$groupTag = (Get-ItemPropertyValue -Path $regKey -Name "GroupTag" -ErrorAction Ignore),
        [string]$aadDeviceID = $aadDeviceID,
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
function manageBitlocker()
{
    Param(
        [string]$bitlockerMethod = $settings.bitlockerMethod
    )
    log "Getting bitlocker action..."
    if($bitlockerMethod -eq "Migrate")
    {
        migrateBitlockerKey
    }
    elseif($bitlockerMethod -eq "Decrypt")
    {
        decryptDrive
    }
    else
    {
        log "Bitlocker method not set. Skipping..."
    }
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

# remove migration user
function removeMigrationUser()
{
    Param(
        [string]$migrationUser = "MigrationInProgress"
    )
    Remove-LocalUser -Name $migrationUser -ErrorAction Stop
    log "Migration user removed"
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# get settings
try
{
    getSettingsJSON
    log "Retrieved settings"
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
    log "Script not initialized: $message"
    log "Exiting script"
    Exit 1
}

# disable post migrate task
try
{
    disablePostMigrateTask
    log "Post migrate task disabled"
}
catch
{
    $message = $_.Exception.Message
    log "Post migrate task not disabled: $message"
    log "Exiting script"
    Exit 1
}

# get device info
try
{
    getDeviceInfo
    log "Device info retrieved"
}
catch
{
    $message = $_.Exception.Message
    log "Device info not retrieved: $message"
    log "Exiting script"
    Exit 1
}

# authenticate to MS Graph
try
{
    msGraphAuthenticate
    log "MS Graph authenticated"
}
catch
{
    $message = $_.Exception.Message
    log "MS Graph not authenticated: $message"
    log "Exiting script"
    Exit 1
}

# get graph info
try
{
    getGraphInfo
    log "Graph info retrieved"
}
catch
{
    $message = $_.Exception.Message
    log "Graph info not retrieved: $message"
    log "Exiting script"
    Exit 1
}

# set primary user
try
{
    setPrimaryUser
    log "Primary user set"
}
catch
{
    $message = $_.Exception.Message
    log "Primary user not set: $message"
    log "WARNING: Primary user not set- try manually setting in Intune"
}

# update device group tag
try
{
    updateGroupTag
    log "Device group tag updated if applicable"
}
catch
{
    $message = $_.Exception.Message
    log "Device group tag not updated: $message"
    log "WARNING: Device group tag not updated- try manually updating in Intune"
}

# manage bitlocker
try
{
    manageBitlocker
    log "Bitlocker managed"
}
catch
{
    $message = $_.Exception.Message
    log "Bitlocker not managed: $message"
    log "WARNING: Bitlocker not managed- try setting policy manually in Intune"
}

# reset lock screen caption
try
{
    resetLockScreenCaption
    log "Lock screen caption reset"
}
catch
{
    $message = $_.Exception.Message
    log "Lock screen caption not reset: $message"
    log "WARNING: Lock screen caption not reset- try setting manually"
}

# remove migration user
try
{
    removeMigrationUser
    log "Migration user removed"
}
catch
{
    $message = $_.Exception.Message
    log "Migration user not removed: $message"
    log "WARNING: Migration user not removed- try removing manually"
}

# END SCRIPT


Stop-Transcript