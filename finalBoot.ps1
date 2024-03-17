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
        [string]$logName = "finalBoot.log",
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

# disable finalBoot task
function disableFinalBootTask()
{
    Param(
        [string]$taskName = "finalBoot"
    )
    Write-Host "Disabling finalBoot task..."
    try 
    {
        Disable-ScheduledTask -TaskName $taskName
        Write-Host "finalBoot task disabled"    
    }
    catch 
    {
        $message = $_.Exception.Message
        Write-Host "finalBoot task not disabled: $message"
    }
}

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

# get user info from registry
function getUserInfo()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [array]$userArray = @("OriginalUserSID", "OriginalUserName", "OriginalProfilePath", "NewUserSID")
    )
    log "Getting user info from registry..."
    foreach($user in $userArray)
    {
        $value = Get-ItemPropertyValue -Path $regKey -Name $user
        if(![string]::IsNullOrEmpty($value))
        {
            New-Variable -Name $user -Value $value -Scope Global -Force
            log "$($user): $value"
        }
    }
}

# remove AAD.Broker.Plugin from original profile
function removeAADBrokerPlugin()
{
    Param(
        [string]$originalProfilePath = $OriginalProfilePath,
        [string]$aadBrokerPlugin = "Microsoft.AAD.BrokerPlugin_*"
    )
    log "Removing AAD.Broker.Plugin from original profile..."
    $aadBrokerPath = (Get-ChildItem -Path "$($originalProfilePath)\AppData\Local\Packages" -Recurse | Where-Object {$_.Name -match $aadBrokerPlugin} | Select-Object FullName).FullName
    if([string]::IsNullOrEmpty($aadBrokerPath))
    {
        log "AAD.Broker.Plugin not found"
    }
    else
    {
        Remove-Item -Path $aadBrokerPath -Recurse -Force -ErrorAction SilentlyContinue
        log "AAD.Broker.Plugin removed" 
    }
}

# delete new user profile
function deleteNewUserProfile()
{
    Param(
        [string]$newUserSID = $NewUserSID
    )
    log "Deleting new user profile..."
    $newProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {$_.SID -eq $newUserSID}
    Remove-CimInstance -InputObject $newProfile -Verbose | Out-Null
    log "New user profile deleted"
}

# change ownership of original profile
function changeOriginalProfileOwner()
{
    Param(
        [string]$originalUserSID = $OriginalUserSID,
        [string]$newUserSID = $NewUserSID
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

# cleanup identity store cache
function cleanupLogonCache()
{
    Param(
        [string]$logonCache = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache",
        [string]$oldUserName = $OriginalUserName
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

# cleanup identity store cache
function cleanupIdentityStore()
{
    Param(
        [string]$idCache = "HKLM:\Software\Microsoft\IdentityStore\Cache",
        [string]$oldUserName = $OriginalUserName
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

# set post migrate tasks
function setPostMigrateTasks()
{
    Param(
        [array]$tasks = @("postMigrate","AutopilotRegistration"),
        [string]$localPath = $localPath
    )
    log "Setting post migrate tasks..."
    foreach($task in $tasks)
    {
        $taskPath = "$($localPath)\$($task).xml"
        if($taskPath)
        {
            schtasks.exe /Create /TN $task /XML $taskPath
            log "$($task) task set."
        }
        else
        {
            log "Failed to set $($task) task: $taskPath not found"
        }
    }
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

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$legalNoticeCaption = "legalnoticecaption",
        [string]$legalNoticeCaptionValue = "Welcome to $($targetTenantName)!",
        [string]$legalNoticeText = "legalnoticetext",
        [string]$legalNoticeTextValue = "Your PC is now part of $($targetTenantName).  Please sign in."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v $legalNoticeCaption /t REG_SZ /d $legalNoticeCaptionValue /f | Out-Host
    reg.exe add $legalNoticeRegPath /v $legalNoticeText /t REG_SZ /d $legalNoticeTextValue /f | Out-Host
    log "Set lock screen caption."
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# run get settings
try
{
    getSettingsJSON
    log "Settings retrieved"
}
catch
{
    $message = $_.Exception.Message
    log "Settings not loaded: $message"
    log "Exiting script"
    Exit 1
}

# run initialize script
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

# run disable finalBoot task
try
{
    disableFinalBootTask
    log "finalBoot task disabled"
}
catch
{
    $message = $_.Exception.Message
    log "finalBoot task not disabled: $message"
    log "Exiting script"
    Exit 1
}

# run disable auto logon
try
{
    disableAutoLogon
    log "Auto logon disabled"
}
catch
{
    $message = $_.Exception.Message
    log "Auto logon not disabled: $message"
    log "Exiting script"
    Exit 1
}

# run get user info
try
{
    getUserInfo
    log "User info retrieved"
}
catch
{
    $message = $_.Exception.Message
    log "User info not retrieved: $message"
    log "Exiting script"
    Exit 1
}

# run remove AAD.Broker.Plugin
try
{
    removeAADBrokerPlugin
    log "AAD.Broker.Plugin removed"
}
catch
{
    $message = $_.Exception.Message
    log "AAD.Broker.Plugin not removed: $message"
    log "WARNING: Remove AAD.Broker.Plugin manually"
}

# run delete new user profile
try
{
    deleteNewUserProfile
    log "New user profile deleted"
}
catch
{
    $message = $_.Exception.Message
    log "New user profile not deleted: $message"
    log "Exiting script"
    Exit 1
}

# run change original profile owner
try
{
    changeOriginalProfileOwner
    log "Original profile owner changed"
}
catch
{
    $message = $_.Exception.Message
    log "Original profile owner not changed: $message"
    log "Exiting script"
    Exit 1
}

# run cleanup logon cache
try
{
    cleanupLogonCache
    log "Logon cache cleaned"
}
catch
{
    $message = $_.Exception.Message
    log "Logon cache not cleaned: $message"
    log "Exiting script"
    Exit 1
}

# run cleanup identity store
try
{
    cleanupIdentityStore
    log "Identity store cleaned"
}
catch
{
    $message = $_.Exception.Message
    log "Identity store not cleaned: $message"
    log "Exiting script"
    Exit 1
}

# run display last username
try
{
    displayLastUsername
    log "Display last username set"
}
catch
{
    $message = $_.Exception.Message
    log "Display last username not set: $message"
    log "Exiting script"
    Exit 1
}

# run set post migrate tasks
try
{
    setPostMigrateTasks
    log "Post migrate tasks set"
}
catch
{
    $message = $_.Exception.Message
    log "Post migrate tasks not set: $message"
    log "Exiting script"
    Exit 1
}

# run restore logon provider
try
{
    restoreLogonProvider
    log "Logon provider restored"
}
catch
{
    $message = $_.Exception.Message
    log "Logon provider not restored: $message"
    log "Exiting script"
    Exit 1
}

# run set lock screen caption
try
{
    setLockScreenCaption
    log "Lock screen caption set"
}
catch
{
    $message = $_.Exception.Message
    log "Lock screen caption not set: $message"
    log "Exiting script"
    Exit 1
}

# END SCRIPT
log "Script completed"
log "Rebooting machine..."

shutdown -r -t 5

Stop-Transcript