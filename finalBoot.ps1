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
Start-Transcript -Path "$($settings.logPath)\finalBoot.log" -Verbose

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

# disable finalBoot task
log "Disabling finalBoot task..."
Disable-ScheduledTask -TaskName "finalBoot"
log "finalBoot task disabled"

# enable auto logon
function disableAutoLogon()
{
    Param(
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoAdminLogon = "AutoAdminLogon",
        [int]$autoAdminLogonValue = 0
    )
    log "Disabling auto logon..."
    reg.exe add $autoLogonPath /v $autoAdminLogon /t REG_SZ /d $autoAdminLogonValue /f | Out-Host
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

# get new and old user data from registry
$regPath = $settings.regPath
$regKey = "Registry::$regPath"
$userArray = @(
    "user",
    "SID",
    "profilePath",
    "SAMName",
    "upn"
)
foreach($x in $userArray)
{
    $new = Get-ItemPropertyValue -Path $regKey -Name "NEW_$($x)"
    $old = Get-ItemPropertyValue -Path $regKey -Name "OG_$($x)"
    if([string]::IsNullOrEmpty($new))
    {
        log "Error - NEW_$($x) is null or empty"
    }
    else
    {
        New-Variable -Name "NEW_$($x)" -Value $new -Scope global -Force
        log "Created variable NEW_$($x) with value $($new)"
    }
    if([string]::IsNullOrEmpty($old))
    {
        log "Error - OG_$($x) is null or empty"
    }
    else
    {
        New-Variable -Name "OG_$($x)" -Value $old -Scope global -Force
        log "Created variable OG_$($x) with value $($old)"
    }
}

$domainJoin = Get-ItemPropertyValue -Path $regKey -Name "OG_domainJoined"

# remove aadBrokerPlugin from original profile
$aadBrokerPath = (Get-ChildItem -Path "$($OG_profilePath)\AppData\Local\Packages" -Recurse | Where-Object {$_.Name -match "Microsoft.AAD.BrokerPlugin_*"} | Select-Object FullName).FullName
if($aadBrokerPath)
{
    log "Removing aadBrokerPlugin from $($OG_profilePath)..."
    Remove-Item -Path $aadBrokerPath -Recurse -Force
    log "aadBrokerPlugin removed"
}
else
{
    log "No aadBrokerPlugin found in $($OG_profilePath)"
}

# delete new user profile
function deleteNewUserProfile()
{
    Param(
        [string]$newUserSID = $NEW_SID
    )
    log "Deleting new user profile..."
    $newProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $newUserSID}
    Remove-CimInstance -InputObject $newProfile -Verbose | Out-Null
    log "New user profile deleted"
}

# run deleteNewUserProfile
log "Running deleteNewUserProfile..."
try
{
    deleteNewUserProfile
    log "deleteNewUserProfile completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run deleteNewUserProfile: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "deleteNewUserProfile"
}

# change ownership of original profile
function changeOriginalProfileOwner()
{
    Param(
        [string]$originalUserSID = $OG_SID,
        [string]$newUserSID = $NEW_SID
    )
    log "Changing ownership of original profile..."
    $originalProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $originalUserSID}
    $changeArguments = @{
        NewOwnerSID = $newUserSID
        Flags = 0
    }
    $originalProfile | Invoke-CimMethod -MethodName ChangeOwner -Arguments $changeArguments
    Start-Sleep -Seconds 1
}

# run changeOriginalProfileOwner
log "Running changeOriginalProfileOwner..."
try
{
    changeOriginalProfileOwner
    log "changeOriginalProfileOwner completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run changeOriginalProfileOwner: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "changeOriginalProfileOwner"
}

# cleanup identity store cache
function cleanupLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$oldUserName = $OG_upn
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

# run cleanupLogonCache
log "Running cleanupLogonCache..."
try
{
    cleanupLogonCache
    log "cleanupLogonCache completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run cleanupLogonCache: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "cleanupLogonCache"
}

# cleanup identity store cache
function cleanupIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$oldUserName = $OG_upn
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

# run cleanup identity store cache if not domain joined
if($domainJoin -eq "NO")
{
    log "Running cleanupIdentityStore..."
    try
    {
        cleanupIdentityStore
        log "cleanupIdentityStore completed"
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to run cleanupIdentityStore: $message"
        log "Exiting script..."
        exitScript -exitCode 1 -functionName "cleanupIdentityStore"
    }
}
else
{
    log "Machine is domain joined - skipping cleanupIdentityStore."
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
        log "New user is $NEW_SAMName, which is the same as $OG_SAMName with _##### appended to the end. Removing appended characters on SamName in LogonCache registry..."

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
        log "New username is $NEW_SAMName, which does not match older username ($OG_SAMName) with _##### appended to end. SamName LogonCache registry will not be updated."
    }
}

# run updateSamNameLogonCache
log "Running updateSamNameLogonCache..."
try
{
    updateSamNameLogonCache
    log "updateSamNameLogonCache completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run updateSamNameLogonCache: $message"
    log "Exiting script..."
    exitScript -exitCode 1 -functionName "updateSamNameLogonCache"
}

# update samname in identityStore Cache (this is required when displaynames are the same in both tenants, and new samname gets random characters added at the end)
function updateSamNameIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$targetSAMName = $OG_SAMName
    )
    if($NEW_SAMName -like "$($OG_SAMName)_*")
    {
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
                            else
                            {
                                log "Skipping different user SID ($subFolder) in $subKey registry folder..."
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        log "New username is $NEW_SAMName, which does not match older username ($OG_SAMName) with _##### appended to end. SamName IdentityStore registry will not be updated."
    }
}

# run updateSamNameIdentityStore if not domain joined
if($domainJoin -eq "NO")
{
    log "Running updateSamNameIdentityStore..."
    try
    {
        updateSamNameIdentityStore
        log "updateSamNameIdentityStore completed"
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to run updateSamNameIdentityStore: $message"
        log "Exiting script..."
        exitScript -exitCode 1 -functionName "updateSamNameIdentityStore"
    }
}
else
{
    log "Machine is domain joined - skipping updateSamNameIdentityStore."
}

# set display last user name policy
function displayLastUsername()
{
    Param(
        [string]$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$regKey = "Registry::$regPath",
        [string]$regName = "DontDisplayLastUserName",
        [int]$regValue = 0
    )
    $currentRegValue = Get-ItemPropertyValue -Path $regKey -Name $regName
    if($currentRegValue -eq $regValue)
    {
        log "$($regName) is already set to $($regValue)."
    }
    else
    {
        reg.exe add $regPath /v $regName /t REG_DWORD /d $regValue /f | Out-Host
        log "Set $($regName) to $($regValue) at $regPath."
    }
}

# set display last user name policy
log "Setting display last user name policy..."
try
{
    displayLastUsername
    log "Display last user name policy set."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set display last user name policy: $message"
    log "WARNING: Sign in manually and fix this policy setting."
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

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$caption = "Welcome to $($targetTenantName)!",
        [string]$text = "Your PC is now part of $($targetTenantName).  Please sign in."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v "legalnoticecaption" /t REG_SZ /d $caption /f | Out-Host
    reg.exe add $legalNoticeRegPath /v "legalnoticetext" /t REG_SZ /d $text /f | Out-Host
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
    exitScript -exitCode 1 -functionName "setLockScreenCaption"
}


# END SCRIPT
log "Script completed"
log "Rebooting machine..."

shutdown -r -t 5

Stop-Transcript