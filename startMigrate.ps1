<# INTUNE TENANT-TO-TENANT DEVICE MIGRATION V6.0
Synopsis
This solution will automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.
DESCRIPTION
Intune Tenant-to-Tenant Migration Solution leverages the Microsoft Graph API to automate the migration of devices from one Intune tenant to another Intune tenant.  Devices can be hybrid AD Joined or Azure AD Joined.  The solution will also migrate the device's primary user profile data and files.  The solution leverages Windows Configuration Designer to create a provisioning package containing a Bulk Primary Refresh Token (BPRT).  Tasks are set to run after the user signs into the PC with destination tenant credentials to update Intune attributes including primary user, Entra ID device group tag, and device category.  In the last step, the device is registered to the destination tenant Autopilot service.  
USE
This script is packaged along with the other files into an intunewin file.  The intunewin file is then uploaded to Intune and assigned to a group of devices.  The script is then run on the device to start the migration process.

NOTES
When deploying with Microsoft Intune, the install command must be "%WinDir%\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File startMigrate.ps1" to ensure the script runs in 64-bit mode.
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
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$message
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss tt"
    Write-Output "$ts $message"
}

# get dsreg status
function joinStatus()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$joinType
    )
    $dsregStatus = dsregcmd.exe /status
    $status = ($dsregStatus | Select-String $joinType).ToString().Split(":")[1].Trim()
    return $status
}

# function get admin status
function getAdminStatus()
{
    Param(
        [string]$adminUser = "Administrator"
    )
    $adminStatus = (Get-LocalUser -Name $adminUser).Enabled
    log "Administrator account is $($adminStatus)."
    return $adminStatus
}

# generate random password
function generatePassword {
    Param(
        [int]$length = 12
    )
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',<.>/?"
    $securePassword = New-Object -TypeName System.Security.SecureString
    1..$length | ForEach-Object {
        $random = $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)]
        $securePassword.AppendChar($random)
    }
    return $securePassword
}

# END CMDLET FUNCTIONS

# SCRIPT FUNCTIONS START

#  get json settings
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
        [string]$localPath = $settings.localPath,
        [string]$logPath = $settings.logPath,
        [string]$installTag = "$($localPath)\install.tag",
        [string]$logName = "startMigrate.log"
    )
    Start-Transcript -Path "$logPath\$logName" -Verbose
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
    $global:localPath = $localPath
    $context = whoami
    log "Running as $($context)."
    New-Item -Path $installTag -ItemType file -Force
    log "Created $($installTag)."
    return $localPath
}

# copy package files
function copyPackageFiles()
{
    Param(
        [string]$destination = $localPath
    )
    Copy-Item -Path "$($PSScriptRoot)\*" -Destination $destination -Recurse -Force
    log "Copied files to $($destination)."
}

# authenticate to source tenant
function msGraphAuthenticate()
{
    Param(
        [string]$tenant = $settings.sourceTenant.tenantName,
        [string]$clientId = $settings.sourceTenant.clientId,
        [string]$clientSecret = $settings.sourceTenant.clientSecret
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

# get device info
function getDeviceInfo()
{
    Param(
        [string]$hostname = $env:COMPUTERNAME,
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS | Select-Object SerialNumber).SerialNumber,
        [string]$osBuild = (Get-WmiObject -Class Win32_OperatingSystem | Select-Object BuildNumber).BuildNumber
    )
    $global:deviceInfo = @{
        "hostname" = $hostname
        "serialNumber" = $serialNumber
        "osBuild" = $osBuild
    }
    foreach($key in $deviceInfo.Keys)
    {
        log "$($key): $($deviceInfo[$key])"
    }
}

# get original user info
function getOriginalUserInfo()
{
    Param(
        [string]$originalUser = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName).UserName,
        [string]$originalUserSID = (New-Object System.Security.Principal.NTAccount($originalUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$originalUserName = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($originalUserSID)\IdentityCache\$($originalUserSID)" -Name "UserName"),
        [string]$originalProfilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($originalUserSID)" -Name "ProfileImagePath"),
        [string]$regPath = $settings.regPath
    )
    $global:originalUserInfo = @{
        "originalUser" = $originalUser
        "originalUserSID" = $originalUserSID
        "originalUserName" = $originalUserName
        "originalProfilePath" = $originalProfilePath
    }
    foreach($key in $originalUserInfo.Keys)
    {
        New-Variable -Name $key -Value $originalUserInfo[$key] -Scope Global -Force
        if([string]::IsNullOrEmpty($originalUserInfo[$key]))
        {
            log "Failed to set $($key) to registry."
        }
        else 
        {
            reg.exe add $regPath /v "$($key)" /t REG_SZ /d "$($originalUserInfo[$key])" /f | Out-Host
            log "Set $($key) to $($originalUserInfo[$key]) at $regPath."
        }
    }
}

# get device info from source tenant
function getDeviceGraphInfo()
{
    Param(
        [string]$hostname = $deviceInfo.hostname,
        [string]$serialNumber = $deviceInfo.serialNumber,
        [string]$regPath = $settings.regPath,
        [string]$groupTag = $settings.groupTag,
        [string]$intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
        [string]$autopilotUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"
    )
    log "Getting Intune object for $($hostname)..."
    $intuneObject = Invoke-RestMethod -Uri "$($intuneUri)?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get
    if(($intuneObject.'@odata.count') -eq 1)
    {
        $intuneID = $intuneObject.value.id
        log "Intune ID: $($intuneID)"
    }
    else
    {
        log "Failed to get Intune object for $($hostname)."
    }
    log "Getting Autopilot object for $($hostname)..."
    $autopilotObject = Invoke-RestMethod -Uri "$($autopilotUri)?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers -Method Get
    if(($autopilotObject.'@odata.count') -eq 1)
    {
        $autopilotID = $autopilotObject.value.id
        log "Autopilot ID: $($autopilotID)"
    }
    else
    {
        log "Failed to get Autopilot object for $($hostname)."
    }
    if([string]::IsNullOrEmpty($groupTag))
    {
        log "Group tag is not set in JSON; getting from graph..."
        $groupTag = $autopilotObject.value.groupTag
    }
    else 
    {
        log "Group tag is set in JSON; using $($groupTag)."
    }
    $global:deviceGraphInfo = @{
        "intuneID" = $intuneID
        "autopilotID" = $autopilotID
        "groupTag" = $groupTag
    }
    foreach($key in $global:deviceGraphInfo.Keys)
    {
        if([string]::IsNullOrEmpty($global:deviceGraphInfo[$key]))
        {
            log "Failed to set $($key) to registry."
        }
        else 
        {
            reg.exe add $regPath /v "$($key)" /t REG_SZ /d "$($global:deviceGraphInfo[$key])" /f | Out-Host
            log "Set $($key) to $($global:deviceGraphInfo[$key]) at $regPath."
        }
    }
}

# set account creation policy
function setAccountConnection()
{
    Param(
        [string]$regPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts",
        [string]$regKey = "Registry::$regPath",
        [string]$regName = "AllowMicrosoftAccountConnection",
        [int]$regValue = 1
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

# set dont display last user name policy
function dontDisplayLastUsername()
{
    Param(
        [string]$regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$regKey = "Registry::$regPath",
        [string]$regName = "DontDisplayLastUserName",
        [int]$regValue = 1
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

# remove mdm certificate
function removeMDMCertificate()
{
    Param(
        [string]$certPath = 'Cert:\LocalMachine\My',
        [string]$issuer = "Microsoft Intune MDM Device CA"
    )
    Get-ChildItem -Path $certPath | Where-Object { $_.Issuer -match $issuer } | Remove-Item -Force
    log "Removed $($issuer) certificate."
}

# remove mdm enrollment
function removeMDMEnrollments()
{
    Param(
        [string]$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
    )
    $enrollments = Get-ChildItem -Path $enrollmentPath
    foreach($enrollment in $enrollments)
    {
        $object = Get-ItemProperty Registry::$enrollment
        $enrollPath = $enrollmentPath + $object.PSChildName
        $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
        if($key)
        {
            log "Removing $($enrollPath)..."
            Remove-Item -Path $enrollPath -Recurse
            log "Removed $($enrollPath)."
        }
        else
        {
            log "No MDM enrollments found."
        }
    }
    $global:enrollID = $enrollPath.Split("\")[-1]
    $additionaPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provinsioning\OMADM\Accounts\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$($enrollID)"
    )
    foreach($path in $additionaPaths)
    {
        if(Test-Path $path)
        {
            log "Removing $($path)..."
            Remove-Item -Path $path -Recurse
            log "Removed $($path)."
        }
        else
        {
            log "No additional paths found."
        }
    }
}

# remove mdm scheduled tasks
function removeMDMTasks()
{
    Param(
        [string]$taskPath = "\Microsoft\Windows\EnterpriseMgmt",
        [string]$enrollID = $enrollID
    )
    $mdmTasks = Get-ScheduledTask -TaskPath "$($taskPath)\$($enrollID)\" -ErrorAction Ignore
    if($mdmTasks -gt 0)
    {
        foreach($task in $mdmTasks)
        {
            log "Removing $($task.Name)..."
            try
            {
                Unregister-ScheduledTask -TaskName $task.Name -Confirm:$false
                log "Removed $($task.Name)."
            }
            catch
            {
                $message = $_.Exception.Message
                log "Failed to remove $($task.Name): $($message)."
            }
        }
    }
    else
    {
        log "No MDM tasks found."
    }
}

# set post migration tasks
function setPostMigrationTasks()
{
    Param(
        [string]$localPath = $localPath,
        [array]$tasks = @("middleboot","newProfile")
    )
    foreach($task in $tasks)
    {
        $taskPath = "$($localPath)\$($task).xml"
        if($taskPath)
        {
            schtasks.exe /Create /TN $task /XML $taskPath
            log "Created $($task) task."
        }
        else
        {
            log "Failed to create $($task) task: $taskPath not found."
        }     
    }
}

# check for AAD join and remove
function leaveAazureADJoin() {
    param (
        [string]$joinType = "AzureAdJoined",
        [string]$hostname = $deviceInfo.hostname,
        [string]$dsregCmd = "C:\Windows\System32\dsregcmd.exe"
    )
    log "Checking for Azure AD join..."
    $joinStatus = joinStatus -joinType $joinType
    if($joinStatus -eq "YES")
    {
        log "$hostname is Azure AD joined: leaving..."
        Start-Process -FilePath $dsregCmd -ArgumentList "/leave"
        log "Left Azure AD join."
    }
    else
    {
        log "$hostname is not Azure AD joined."
    }
}

# check for domain join and remove
function unjoinDomain()
{
    Param(
        [string]$joinType = "DomainJoined",
        [string]$hostname = $deviceInfo.hostname
    )
    log "Checking for domain join..."
    $joinStatus = joinStatus -joinType $joinType
    if($joinStatus -eq "YES")
    {
        $password = generatePassword -length 12
        log "Checking for local admin account..."
        $adminStatus = getAdminStatus
        if($adminStatus -eq $false)
        {
            log "Admin account is disabled; setting password and enabling..."
            Set-LocalUser -Name "Administrator" -Password $password -PasswordNeverExpires $true
            Get-LocalUser -Name "Administrator" | Enable-LocalUser
            log "Enabled Administrator account and set password."
        }
        else 
        {
            log "Admin account is enabled; setting password..."
            Set-LocalUser -Name "Administrator" -Password $password -PasswordNeverExpires $true
            log "Set Administrator password."
        }
        $cred = New-Object System.Management.Automation.PSCredential ("$hostname\Administrator", $password)
        log "Unjoining domain..."
        Remove-Computer -UnjoinDomainCredential $cred -Force -PassThru -Verbose
        log "$hostname unjoined domain."    
    }
    else
    {
        log "$hostname is not domain joined."
    }
}

# install provisioning package
function InstallPPKGPackage()
{
    Param(
        [string]$osBuild = $deviceInfo.osBuild,
        [string]$ppkg = (Get-ChildItem -Path $localPath -Filter "*.ppkg" -Recurse).FullName
    )
    if($ppkg)
    {
        Install-ProvisioningPackage -PackagePath $ppkg -QuietInstall -Force
        log "Installed provisioning package."
    }
    else 
    {
        log "Provisioning package not found."
    }
    
}

# delete graph objects in source tenant
function deleteGraphObjects()
{
    Param(
        [string]$intuneID = $deviceGraphInfo.intuneID,
        [string]$autopilotID = $deviceGraphInfo.autopilotID,
        [string]$intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
        [string]$autopilotUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"
    )
    if(![string]::IsNullOrEmpty($intuneID))
    {
        Invoke-RestMethod -Uri "$($intuneUri)/$($intuneID)" -Headers $headers -Method Delete
        Start-Sleep -Seconds 2
        log "Deleted Intune object."
    }
    else
    {
        log "Intune object not found."
    }
    if(![string]::IsNullOrEmpty($autopilotID))
    {
        Invoke-RestMethod -Uri "$($autopilotUri)/$($autopilotID)" -Headers $headers -Method Delete
        Start-Sleep -Seconds 2
        log "Deleted Autopilot object."   
    }
    else
    {
        log "Autopilot object not found."
    }
}

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

# set auto logon policy
function setAutoLogon()
{
    Param(
        [string]$migrationAdmin = "MigrationInProgress",
        [string]$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        [string]$autoLogonName = "AutoAdminLogon",
        [string]$autoLogonValue = 1,
        [string]$defaultUserName = "DefaultUserName",
        [string]$defaultPW = "DefaultPassword"
    )
    log "Create migration admin account..."
    $migrationPassword = generatePassword
    New-LocalUser -Name $migrationAdmin -Password $migrationPassword
    Add-LocalGroupMember -Group "Administrators" -Member $migrationAdmin
    log "Migration admin account created: $($migrationAdmin)."

    log "Setting auto logon..."
    reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $autoLogonValue /f | Out-Host
    reg.exe add $autoLogonPath /v $defaultUserName /t REG_SZ /d $migrationAdmin /f | Out-Host
    reg.exe add $autoLogonPath /v $defaultPW /t REG_SZ /d "@Password*123" /f | Out-Host
    log "Set auto logon to $($migrationAdmin)."
}

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$legalNoticeCaption = "legalnoticecaption",
        [string]$legalNoticeCaptionValue = "Migration in Progress...",
        [string]$legalNoticeText = "legalnoticetext",
        [string]$legalNoticeTextValue = "Your PC is being migrated to $targetTenantName and will reboot automatically within 30 seconds.  Please do not turn off your PC."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v $legalNoticeCaption /t REG_SZ /d $legalNoticeCaptionValue /f | Out-Host
    reg.exe add $legalNoticeRegPath /v $legalNoticeText /t REG_SZ /d $legalNoticeTextValue /f | Out-Host
    log "Set lock screen caption."
}


# SCRIPT FUNCTIONS END

# run getSettingsJSON
try 
{
    getSettingsJSON
    log "Retrieved settings JSON."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to get settings JSON: $message."  
    log "Exiting script."
    Exit 1  
}

# run initializeScript
try 
{
    initializeScript
    log "Initialized script."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to initialize script: $message."
    log "Exiting script."
    Exit 1
}

# run copyPackageFiles
try 
{
    copyPackageFiles
    log "Copied package files."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to copy package files: $message."
    log "Exiting script."
    Exit 1
}

# run msGraphAuthenticate
try 
{
    msGraphAuthenticate
    log "Authenticated to MS Graph."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to authenticate to MS Graph: $message."
    log "Exiting script."
    Exit 1
}

# run getDeviceInfo
try 
{
    getDeviceInfo
    log "Got device info."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to get device info: $message."
    log "Exiting script."
    Exit 1
}

# run getOriginalUserInfo
try 
{
    getOriginalUserInfo
    log "Got original user info."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to get original user info: $message."
    log "Exiting script."
    Exit 1
}

# run getDeviceGraphInfo
try 
{
    getDeviceGraphInfo
    log "Got device graph info."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to get device graph info: $message."
    log "WARNING: Validate device integrity post migration."
}

# run setAccountConnection
try 
{
    setAccountConnection
    log "Set account connection."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to set account connection: $message."
    log "WARNING: Validate device integrity post migration."
}

# run dontDisplayLastUsername
try 
{
    dontDisplayLastUsername
    log "Set dont display last username."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to set dont display last username: $message."
    log "WARNING: Validate device integrity post migration."
}

# run removeMDMCertificate
try 
{
    removeMDMCertificate
    log "Removed MDM certificate."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to remove MDM certificate: $message."
    log "WARNING: Validate device integrity post migration."
}

# run removeMDMEnrollments
try 
{
    removeMDMEnrollments
    log "Removed MDM enrollments."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to remove MDM enrollments: $message."
    log "Exiting script."
    Exit 1
}

# run removeMDMTasks
try 
{
    removeMDMTasks
    log "Removed MDM tasks."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to remove MDM tasks: $message."
    log "Warning: Validate device integrity post migration."
}

# run setPostMigrationTasks
try 
{
    setPostMigrationTasks
    log "Set post migration tasks."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to set post migration tasks: $message."
    log "Exiting script."
    Exit 1
}

# run leaveAazureADJoin
try 
{
    leaveAazureADJoin
    log "Left Azure AD join."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to leave Azure AD join: $message."
    log "Exiting script."
    Exit 1
}

# run unjoinDomain
try 
{
    unjoinDomain
    log "Unjoined domain."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to unjoin domain: $message."
    log "WARNING: Validate device integrity post migration."
}

# run InstallPPKGPackage
try 
{
    InstallPPKGPackage
    log "Installed provisioning package."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to install provisioning package: $message."
    log "Exiting script."
    Exit 1
}

# run deleteGraphObjects
try 
{
    deleteGraphObjects
    log "Deleted graph objects."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to delete graph objects: $message."
    log "WARNING: Validate device integrity post migration."
}

# run revokeLogonProvider
try 
{
    revokeLogonProvider
    log "Revoked logon provider."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to revoke logon provider: $message."
    log "WARNING: Validate device integrity post migration."
}

# run setAutoLogon
try 
{
    setAutoLogon
    log "Set auto logon."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to set auto logon: $message."
    log "WARNING: Validate device integrity post migration."
}

# run setLockScreenCaption
try 
{
    setLockScreenCaption
    log "Set lock screen caption."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption: $message."
    log "WARNING: Validate device integrity post migration."
}

# run reboot
log "Rebooting device..."
shutdown -r -t 30

# end transcript
Stop-Transcript
