<# FINALBOOT.PS1
Synopsis
Finalboot.ps1 is the last script that automatically reboots the PC.
DESCRIPTION
This script is used to change ownership of the original user profile to the destination user and then reboot the machine.  It is executed by the 'finalBoot' scheduled task.
USE
.\finalBoot.ps1
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

Start-Transcript -Path "$($settings.logPath)\finalBoot.log" -Verbose

# initialize script function
log "Running FUNCTION: initializeScript..."
try
{
    initializeScript
    log "FUNCTION: initializeScript completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "initializeScript"
}

# disable final boot task
log "Disable finalBoot task..."
Disable-ScheduledTask -TaskName "finalBoot" -ErrorAction SilentlyContinue
log "finalBoot task disabled."

# retrieve user objects from source and target
$regPath = $settings.regPath
$regKey = "Registry::$regPath"
$objects = @("OG_profilePath","OG_SAMName","OG_SID","OG_userName","OG_UPN","NEW_profilePath","NEW_SAMName","NEW_SID","NEW_userName","NEW_UPN","OG_domainJoined")
foreach($object in $objects)
{
    $value = Get-ItemPropertyValue -Path $regKey -Name $object
    if(![string]::IsNullOrEmpty($value))
    {
        New-Variable -Name $object -Value $value -Scope Global -Force
        log "Retrieved $($object): $value"
    }
    else
    {
        log "Failed to retrieve $($object)."
    }
}

# remove AAD.broker.plugin from the source user profile
log "Removing AAD.broker.plugin from source user profile..."
$aadBrokerPath = (Get-ChildItem -Path "$($OG_profilePath)\AppData\Local\Packages" -Recurse | Where-Object {$_.Name -match "Microsoft.AAD.BrokerPlugin_*"} | Select-Object FullName).FullName
if([string]::IsNullOrEmpty($aadBrokerPath))
{
    log "AAD.broker.plugin not found in source user profile."
}
else
{
    Remove-Item -Path $aadBrokerPath -Recurse -Force -ErrorAction SilentlyContinue
    log "AAD.broker.plugin removed from source user profile."
}

# delete new user profile
log "Deleting new user profile..."
$newProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $NEW_SID}
Remove-CimInstance -InputObject $newProfile -Verbose | Out-Null
log "New user profile deleted."

# change ownership of source user profile to new user
log "Changing ownership of source user profile to new user..."
$originalProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $OG_SID}
$changeArguments = @{
    NewOwnerSID = $NEW_SID
    Flags = 0
}
$originalProfile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changeArguments
Start-Sleep -Seconds 1
log "Ownership changed."

# cleanup identity store cache
function cleanupLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$oldUserName = $OG_UPN
    )
    log "Cleaning up identity store cache..."
    $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($GUID in $logonCacheGUID)
    {
        $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No subkeys found for $GUID"
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                if($subKey -eq "Name2Sid" -or $subKey -eq "SAM_Name" -or $subKey -eq "Sid2Name")
                {
                    $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                    if(!($subFolders))
                    {
                        log "Error - no sub folders found for $subKey"
                        continue
                    }
                    else
                    {
                        $subFolders = $subFolders.trim('{}')
                        foreach($subFolder in $subFolders)
                        {
                            $cacheUsername = Get-ItemPropertyValue -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "IdentityName" -ErrorAction SilentlyContinue
                            if($cacheUsername -eq $oldUserName)
                            {
                                Remove-Item -Path "$logonCache\$GUID\$subKey\$subFolder" -Recurse -Force
                                log "Registry key deleted: $logonCache\$GUID\$subKey\$subFolder"
                                continue                                       
                            }
                        }
                    }
                }
            }
        }
    }
}

log "Running FUNCTION: cleanupLogonCache..."
try
{
    cleanupLogonCache
    log "FUNCTION: cleanupLogonCache completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: cleanupLogonCache failed. $message"
    exitScript -exitCode 1 -functionName "cleanupLogonCache"
}

# cleanup identity store cache
function cleanupIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$oldUserName = $OG_UPN
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        $idCacheUsername = Get-ItemPropertyValue -Path "$idCache\$key\$subKey\$subFolder" -Name "UserName" -ErrorAction SilentlyContinue
                        if($idCacheUsername -eq $oldUserName)
                        {
                            Remove-Item -Path "$idCache\$key\$subKey\$subFolder" -Recurse -Force
                            log "Registry path deleted: $idCache\$key\$subKey\$subFolder"
                            continue
                        }
                    }
                }
            }
        }
    }
}

if($OG_domainJoined -eq "NO")
{
    log "Running FUNCTION: cleanupIdentityStore..."
    try
    {
        cleanupIdentityStore
        log "FUNCTION: cleanupIdentityStore completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: cleanupIdentityStore failed. $message"
        exitScript -exitCode 1 -functionName "cleanupIdentityStore"
    }
}
else
{
    log "Domain joined status is YES - skipping cleanupIdentityStore function."
}

# update samname in identityStore LogonCache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$targetSAMName = $OG_SAMName
    )

    if($NEW_SAMName -like "$($OG_SAMName)_*")
    {
        log "New user is $newUser, which is the same as $originalUser with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

        $logonCacheGUID = (Get-ChildItem -Path $logonCache | Select-Object Name | Split-Path -Leaf).trim('{}')
        foreach($GUID in $logonCacheGUID)
        {
            $subKeys = Get-ChildItem -Path "$logonCache\$GUID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
            if(!($subKeys))
            {
                log "No subkeys found for $GUID"
                continue
            }
            else
            {
                $subKeys = $subKeys.trim('{}')
                foreach($subKey in $subKeys)
                {
                    if($subKey -eq "Name2Sid")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $NEW_SID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    log "Attempted to update SAMName value (in Name2Sid registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Detected Sid '$detectedUserSID' is for different user - skipping Sid in Name2Sid registry folder..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "SAM_Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                $detectedUserSID = Get-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" | Select-Object -ExpandProperty "Sid" -ErrorAction SilentlyContinue
                                if($detectedUserSID -eq $NEW_SID)
                                {
                                    Rename-Item "$logonCache\$GUID\$subKey\$subFolder" -NewName $targetSAMName -Force
                                    log "Attempted to update SAM_Name key name (in SAM_Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user in SAM_Name registry folder (User: $subFolder, SID: $detectedUserSID)..."
                                }
                            }
                        }
                    }
                    elseif($subKey -eq "Sid2Name")
                    {
                        $subFolders = Get-ChildItem -Path "$logonCache\$GUID\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                        if(!($subFolders))
                        {
                            log "Error - no sub folders found for $subKey"
                            continue
                        }
                        else
                        {
                            $subFolders = $subFolders.trim('{}')
                            foreach($subFolder in $subFolders)
                            {
                                if($subFolder -eq $NEW_SID)
                                {
                                    Set-ItemProperty -Path "$logonCache\$GUID\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                                    log "Attempted to update SAM_Name value (in Sid2Name registry folder) to '$targetSAMName'."
                                    continue                                       
                                }
                                else
                                {
                                    log "Skipping different user SID ($subFolder) in Sid2Name registry folder..."
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        log "New username is $newUser, which does not match older username ($oldUser) with _##### appended to end. SamName LogonCache registry will not be updated."
    }
}

log "Running FUNCTION: updateSamNameLogonCache..."
try
{
    updateSamNameLogonCache
    log "FUNCTION: updateSamNameLogonCache completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: updateSamNameLogonCache failed. $message"
    exitScript -exitCode 1 -functionName "updateSamNameLogonCache"
}

# update samname in identityStore Cache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$targetSAMName = $OG_SAMName
    )
    log "Cleaning up identity store cache..."
    $idCacheKeys = (Get-ChildItem -Path $idCache | Select-Object Name | Split-Path -Leaf).trim('{}')
    foreach($key in $idCacheKeys)
    {
        $subKeys = Get-ChildItem -Path "$idCache\$key" -ErrorAction SilentlyContinue | Select-Object Name | Split-Path -Leaf
        if(!($subKeys))
        {
            log "No keys listed under '$idCache\$key' - skipping..."
            continue
        }
        else
        {
            $subKeys = $subKeys.trim('{}')
            foreach($subKey in $subKeys)
            {
                $subFolders = Get-ChildItem -Path "$idCache\$key\$subKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | Split-Path -Leaf
                if(!($subFolders))
                {
                    log "No subfolders detected for $subkey- skipping..."
                    continue
                }
                else
                {
                    $subFolders = $subFolders.trim('{}')
                    foreach($subFolder in $subFolders)
                    {
                        if($subFolder -eq $NEW_SID)
                        {
                            Set-ItemProperty -Path "$idCache\$key\$subKey\$subFolder" -Name "SAMName" -Value $targetSAMName -Force
                            log "Attempted to update SAMName value to $targetSAMName."
                        }
                    }
                }
            }
        }
    }
}

log "Running FUNCTION: updateSamNameIdentityStore if not domain joined..."
if($OG_domainJoined -eq "NO")
{
    try
    {
        updateSamNameIdentityStore
        log "FUNCTION: updateSamNameIdentityStore completed successfully."
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: updateSamNameIdentityStore failed. $message"
        exitScript -exitCode 1 -functionName "updateSamNameIdentityStore"
    }
}
else
{
    log "Domain joined status is YES - skipping updateSamNameIdentityStore function."
}

# reset display last username policy
Log "Resetting display last username policy..."
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d 0 /f | Out-Host
log "Display last username policy reset."


# set post migration tasks
log "Setting post migration tasks..."
$tasks = @("postMigrate","AutopilotRegistration")
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

# enable logon credential provider
log "Enabling logon credential provider..."
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

# disable auto logon
log "Disabling auto logon..."
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
log "Setting lock screen caption..."
try
{
    setLockScreenCaption -caption "Welcome to $($settings.targetTenant.tenantName)" -text "Your PC is now part of $($settings.targetTenant.tenantName).  Please sign in"
    log "Lock screen caption set."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption: $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}

log "End of finalBoot.ps1"

Stop-Transcript

shutdown -r -t 5