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


# get json settings
$settings = Get-Content -Path "$($PSScriptRoot)\settings.json" | ConvertFrom-Json

# start transcript
log "Starting transcript..."
Start-Transcript -Path "$(settings.$logPath)\startMigrate.log" -Verbose

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
try 
{
    initializeScript -installTag $true
    log "Initialized script."
}
catch 
{
    $message = $_.Exception.Message
    log "Failed to initialize script: $message."
    log "Exiting script."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# copy package files
$destination = $settings.localPath
log "Copying files to $destination..."
Copy-Item -Path "$($PSScriptRoot)\*" -Destination $destination -Recurse -Force
log "Copied files to $($destination)."


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

# run account connection policy
log "Setting account connection policy..."
try
{
    setAccountConnection
    log "Set account connection policy."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set account connection policy: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "setAccountConnection"
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

# set dont display username at sign in policy
try
{
    dontDisplayLastUsername
    log "Set dont display last username policy."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set dont display last username policy: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "dontDisplayLastUsername"
}

# newDeviceObject function
function newDeviceObject()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_Bios).serialNumber,
        [string]$hostname = $env:COMPUTERNAME,
        [string]$azureAdJoined = (dsregcmd.exe /status | Select-String "AzureAdJoined").ToString().Split(":")[1].Trim(),
        [string]$domainJoined = (dsregcmd.exe /status | Select-String "DomainJoined").ToString().Split(":")[1].Trim(),
        [string]$certPath = 'Cert:\LocalMachine\My',
        [string]$issuer = "Microsoft Intune MDM Device CA",
        [string]$bitLocker = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus,
        [string]$groupTag = $settings.groupTag,
        [bool]$mdm = $false
    )
    $cert = Get-ChildItem -Path $certPath | Where-Object {$_.Issuer -match $issuer}
    if($cert)
    {
        $mdm = $true
        $intuneObject = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=serialNumber eq '$serialNumber'" -Headers $headers)
        if(($intuneObject.'@odata.count') -eq 1)
        {
            $intuneId = $intuneObject.value.id
            $entraId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/devices?`$filter=deviceId eq '$($intuneObject.value.entraId)'" -Headers $headers).value.id
            $autopilotObject = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($serialNumber)')" -Headers $headers)
            if(($autopilotObject.'@odata.count') -eq 1)
            {
                $autopilotId = $autopilotObject.value.id
                if([string]::IsNullOrEmpty($groupTag))
                {
                    $groupTag = $autopilotObject.value.groupTag
                }
                else
                {
                    $groupTag = $groupTag
                }
            }
            else
            {
                $autopilotId = $null
            }
        }
        else 
        {
            $intuneId = $null
            $entraId = $null
        }
    }
    else
    {
        $intuneId = $null
        $entraId = $null
        $autopilotId = $null
    }
    if([string]::IsNullOrEmpty($groupTag))
    {
        $groupTag = $null
    }
    else
    {
        $groupTag = $groupTag
    }
    $pc = @{
        serialNumber = $serialNumber
        hostname = $hostname
        azureAdJoined = $azureAdJoined
        domainJoined = $domainJoined
        bitLocker = $bitLocker
        mdm = $mdm
        intuneId = $intuneId
        entraId = $entraId
        autopilotId = $autopilotId
        groupTag = $groupTag
    }
    return $pc
}

# run newDeviceObject
log "Creating device object..."
try
{
    $pc = newDeviceObject
    log "Created device object."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to create device object: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "newDeviceObject"
}

# Write OG PC properties to the registry
log "Writing OG PC properties to the registry..."
foreach($x in $pc.Keys)
{
    $name = "OG_$($x)"
    $value = $($pc[$x])
    $regPath = $settings.regPath
    try
    {
        log "Writing $name to the registry with value $value..."
        reg.exe add $regPath /v $name /t REG_SZ /d $value /f | Out-Host
        log "$name written to registry with value $value."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to write $name to the registry - $message."
        log "Exiting script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "setRegObject"
    }
}

# newUserObject function
function newUserObject()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$domainJoin,
        [Parameter(Mandatory=$true)]
        [string]$aadJoin,
        [string]$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName).UserName,
        [string]$SID = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$profilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID)" -Name "ProfileImagePath"),
        [string]$SAMName = ($user).Split("\")[1]
    )
    if($domainJoin -eq "NO")
    {
        $upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$($SID)\IdentityCache\$($SID)" -Name "UserName")
        if($aadJoin -eq "YES")
        {
            $entraId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers).id
        }
        else
        {
            $entraId = $null
        }
    }
    else
    {
        $upn = $null
        $entraId = $null
    }
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
log "Creating user object..."
try
{
    $user = newUserObject -domainJoin $pc.domainJoined -aadJoin $pc.azureAdJoined
    log "Created user object."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to create user object: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "newUserObject"
}

# Write OG User properties to the registry
log "Writing OG User properties to the registry..."
foreach($x in $user.Keys)
{
    $name = "OG_$($x)"
    $value = $($user[$x])
    $regPath = $settings.regPath
    try
    {
        log "Writing $name to the registry with value $value..."
        reg.exe add $regPath /v $name /t REG_SZ /d $value /f | Out-Host
        log "$name written to registry with value $value."
    }
    catch
    {
        $message = $_.Exception.Message
        log "Failed to write $name to the registry - $message."
        log "Exiting script with non critial error.  Please review the log file and attempt to run the script again."
        exitScript -exitCode 4 -functionName "setRegObject"
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

log "Remove MDM certificate..."
try
{
    removeMDMCertificate
    log "Removed MDM certificate."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to remove MDM certificate: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "removeMDMCertificate"
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
    $enrollID = $enrollPath.Split("\")[-1]
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
log "Removing MDM scheduled tasks..."
try
{
    removeMDMTasks
    log "Removed MDM scheduled tasks."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to remove MDM scheduled tasks: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "removeMDMTasks"
}

# set post migration tasks
function setPostMigrationTasks()
{
    Param(
        [string]$localPath = $settings.localPath,
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

# run setPostMigrationTasks
log "Setting post migration tasks..."
try
{
    setPostMigrationTasks
    log "Set post migration tasks."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set post migration tasks: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "setPostMigrationTasks"
}

# check for Azure AD / Entra Join and leave
if($pc.azureAdJoined -eq "YES")
{
    log "PC is Azure AD joined; leaving..."
    try 
    {
        Start-Process -FilePath "dsregcmd.exe" -ArgumentList "/leave"
        log "Left Azure AD."
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Failed to leave Azure AD: $message."
        log "Exiting script."
        exitScript -exitCode 4 -functionName "leaveAAD"
    }
}
else
{
    log "PC is not Azure AD joined."
}

# FUNCTION: unjoinDomain
# PURPOSE: Unjoin from domain
# DESCRIPTION: This function unjoins from the domain.  It takes an unjoin account and hostname as input and outputs the status to the console.  If the account is disabled, it will enable the account and set the password.  If the account is enabled, it will set the password.
# INPUTS: $unjoinAccount (string), $hostname (string)
# OUTPUTS: example; Unjoined from domain
function unjoinDomain()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$unjoinAccount,
        [string]$hostname = $pc.hostname
    )
    log "Unjoining from domain..."
    $password = generatePassword
    log "Generated password for $unjoinAccount."
    log "Checking $($unjoinAccount) status..."
    [bool]$acctStatus = (Get-LocalUser -Name $unjoinAccount).Enabled
    if($acctStatus -eq $false)
    {
        log "$($unjoinAccount) is disabled; setting password and enabling..."
        Set-LocalUser -Name $unjoinAccount -Password $password -PasswordNeverExpires $true
        Get-LocalUser -Name $unjoinAccount | Enable-LocalUser
        log "Enabled $($unjoinAccount) account and set password."
    }
    else 
    {
        log "$($unjoinAccount) is enabled; setting password..."
        Set-LocalUser -Name $unjoinAccount -Password $password -PasswordNeverExpires $true
        log "Set password for $($unjoinAccount) account."
    }
    $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$hostname\$unjoinAccount", $password)
    log "Unjoining from domain..."
    Remove-Computer -UnjoinDomainCredential $cred -PassThru -Force -Verbose
    log "Unjoined from domain."
}

if($pc.domainJoined -eq "YES")
{
    log "PC is domain joined; unjoining..."
    try 
    {
        unjoinDomain -unjoinAccount "Administrator"
        log "Unjoined from domain."
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Failed to unjoin from domain: $message."
        log "Exiting script."
        exitScript -exitCode 4 -functionName "unjoinDomain"
    }
}
else
{
    log "PC is not domain joined."
}

# install provisioning package
$ppkg = (Get-ChildItem -Path $settings.localPath -Filter "*.ppkg" -Recurse).FullName
if($ppkg)
{
    log "provioning package found: $($ppkg)."
    try 
    {
        Install-ProvisioningPackage -PackagePath $ppkg -QuietInstall -Force
        log "Installed provisioning package."    
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Failed to install provisioning package: $message."
        log "Exiting script."
        exitScript -exitCode 4 -functionName "installProvisioningPackage"
    }
}
else 
{
    log "Provisioning package not found."
    exitScript -exitCode 4 -functionName "installProvisioningPackage"
}
    

# delete graph objects in source tenant
$intuneID = $pc.intuneId,
$autopilotID = $pc.entraId,
$intuneUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices"
$autopilotUri = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities"    
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
log "Revoking logon provider..."
try
{
    revokeLogonProvider
    log "Revoked logon provider."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to revoke logon provider: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "revokeLogonProvider"
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

# run setAutoLogon
log "Setting auto logon..."
try
{
    setAutoLogon
    log "Set auto logon."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set auto logon: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "setAutoLogon"
}

# set lock screen caption
function setLockScreenCaption()
{
    Param(
        [string]$targetTenantName = $settings.targetTenant.tenantName,
        [string]$legalNoticeRegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$caption = "Migration in Progress...",
        [string]$text = "Your PC is being migrated to $targetTenantName and will reboot automatically within 30 seconds.  Please do not turn off your PC."
    )
    log "Setting lock screen caption..."
    reg.exe add $legalNoticeRegPath /v "legalnoticecaption" /t REG_SZ /d $caption /f | Out-Host
    reg.exe add $legalNoticeRegPath /v "legalnoticetext" /t REG_SZ /d $text /f | Out-Host
    log "Set lock screen caption."
}

# run setLockScreenCaption
log "Setting lock screen caption..."
try
{
    setLockScreenCaption
    log "Set lock screen caption."
}
catch
{
    $message = $_.Exception.Message
    log "Failed to set lock screen caption: $message."
    log "Exiting script with exit code 4."
    exitScript -exitCode 4 -functionName "setLockScreenCaption"
}

# run reboot
log "Rebooting device..."
shutdown -r -t 30

# end transcript
Stop-Transcript
