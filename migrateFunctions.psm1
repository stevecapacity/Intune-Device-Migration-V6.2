# FUNCTION: Log
# PURPOSE: Log messages to console and log file
# DESCRIPTION: This function logs messages to the console and log file.  It takes a message as input and outputs the message with a timestamp to the console and log file.
# INPUTS: $message (string)
# OUTPUTS: example; 2021-01-01 12:00:00 PM message
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
# DESCRIPTION: This function exits the script with an error code.  It takes an exit code, function name, and local path as input and outputs the error message to the console and log file.  It also removes the local path and reboots the device if the exit code is 1.
# INPUTS: $exitCode (int), $functionName (string), $localpath (string)
# OUTPUTS: example; Function functionName failed with critical error.  Exiting script with exit code exitCode.
function exitScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int]$exitCode,
        [Parameter(Mandatory=$true)]
        [string]$functionName,
        [string]$localpath = $localPath
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

# FUNCTION: generatePassword
# PURPOSE: Generate a secure password for built in local admin account
# DESCRIPTION: This function generates a secure password for the built in local admin account when unjoining from domain.  It takes a length as input and outputs a secure password to the console.
# INPUTS: $length (int) | example; 12
# OUTPUTS: $securePassword (SecureString) | example; ************
function generatePassword {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [int]$length
    )
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',<.>/?"
    $securePassword = New-Object -TypeName System.Security.SecureString
    1..$length | ForEach-Object {
        $random = $charSet[(Get-Random -Minimum 0 -Maximum $charSet.Length)]
        $securePassword.AppendChar($random)
    }
    return $securePassword
}

# FUNCTION: getSettingsJSON
# PURPOSE: Get settings from JSON file
# DESCRIPTION: This function gets the settings from the JSON file and creates a global variable to be used throughout migration process.  It takes a JSON file as input and outputs the settings to the console.
# INPUTS: $json (string) | example; settings.json
# OUTPUTS: $settings (object) | example; @{setting1=value1; setting2=value2}
function getSettingsJSON
{
    Param(
        [string]$json = "settings.json"
    )
    $global:settings = Get-Content -Path "$($PSScriptRoot)\$($json)" | ConvertFrom-Json
    return $settings
}

# FUNCTION: initializeScript
# PURPOSE: Initialize the migration script
# DESCRIPTION: This function initializes the script.  It takes an install tag, log name, log path, and local path as input and outputs the local path to the console.
# INPUTS: $installTag (bool), $logName (string), $logPath (string), $localPath (string)
# OUTPUTS: $localPath (string) | example; C:\ProgramData\IntuneMigration
function initializeScript()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [bool]$installTag,
        [Parameter(Mandatory=$true)]
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
        log "Install tag is $installTag.  Creating at $($localPath)\installed.tag..."
        New-Item -Path "$($localPath)\installed.tag" -ItemType "file" -Force
        log "Created $($localPath)\installed.tag."
    }
    else
    {
        log "Install tag is $installTag."
    }
    $global:localPath = $localPath
    $context = whoami
    log "Running as $($context)."
    log "Script initialized."
    return $localPath
}

# FUNCTION: msGraphAuthenticate
# PURPOSE: Authenticate to Microsoft Graph
# DESCRIPTION: This function authenticates to Microsoft Graph.  It takes a tenant, client id, and client secret as input and outputs the headers to the console.
# INPUTS: $tenant (string), $clientId (string), $clientSecret (string)
# OUTPUTS: $headers (object) | example; @{Authorization=Bearer}
function msGraphAuthenticate()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$tenant,
        [Parameter(Mandatory=$true)]
        [string]$clientId,
        [Parameter(Mandatory=$true)]
        [string]$clientSecret
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

# FUNCTION: newDeviceObject
# PURPOSE: Create a new device object
# DESCRIPTION: This function creates a new device object.  It takes a serial number, hostname, disk size, free space, OS version, OS build, memory, azure ad joined, domain joined, bitlocker, group tag, and mdm as input and outputs the device object to the console.
# INPUTS: $serialNumber (string), $hostname (string), $diskSize (string), $freeSpace (string), $OSVersion (string), $OSBuild (string), $memory (string), $azureAdJoined (string), $domainJoined (string), $bitLocker (string), $groupTag (string), $mdm (bool)
# OUTPUTS: $pc (object) | example; @{serialNumber=serialNumber; hostname=hostname; diskSize=diskSize; freeSpace=freeSpace; OSVersion=OSVersion; OSBuild=OSBuild; memory=memory; azureAdJoined=azureAdJoined; domainJoined=domainJoined; bitLocker=bitLocker; groupTag=groupTag; mdm=mdm}
function newDeviceObject()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_Bios).serialNumber,
        [string]$hostname = $env:COMPUTERNAME,
        [string]$diskSize = ([Math]::Round(((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB), 2)).ToString() + " GB",
        [string]$freeSpace = ([Math]::Round(((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB), 2)).ToString() + " GB",
        [string]$OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version,
        [string]$OSBuild = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber,
        [string]$memory = ([Math]::Round(((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB), 2)).ToString() + " GB",
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
            $azureAdDeviceId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/devices?`$filter=deviceId eq '$($intuneObject.value.azureAdDeviceId)'" -Headers $headers).value.id
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
            $azureAdDeviceId = $null
        }
    }
    else
    {
        $intuneId = $null
        $azureAdDeviceId = $null
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
        diskSize = $diskSize
        freeSpace = $freeSpace
        OSVersion = $OSVersion
        OSBuild = $OSBuild
        memory = $memory
        azureAdJoined = $azureAdJoined
        domainJoined = $domainJoined
        bitLocker = $bitLocker
        mdm = $mdm
        intuneId = $intuneId
        azureAdDeviceId = $azureAdDeviceId
        autopilotId = $autopilotId
        groupTag = $groupTag
    }
    return $pc
}

# FUNCTION: newUserObject
# PURPOSE: Create new user object
# DESCRIPTION: This function constructs a new user object.  It takes a domain join, user, SID, profile path, and SAM name as input and outputs the user object to the console.
# INPUTS: $domainJoin (string), $user (string), $SID (string), $profilePath (string), $SAMName (string)
# OUTPUTS: $userObject (object) | example; @{user=user; SID=SID; profilePath=profilePath; SAMName=SAMName; upn=upn}
function newUserObject()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$domainJoined,
        [Parameter(Mandatory=$false)]
        [string]$azureAdJoined,
        [string]$user = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName).UserName,
        [string]$SID = (New-Object System.Security.Principal.NTAccount($user)).Translate([System.Security.Principal.SecurityIdentifier]).Value,
        [string]$upn = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache\$($SID)\Name2SID\$($SID)" -Name "IdentityName"),
        [string]$profilePath = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID)" -Name "ProfileImagePath"),
        [string]$SAMName = ($user).Split("\")[1]
    )
    if($azureAdJoined -eq "YES")
    {
        $aadId = (Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/users/$($upn)" -Headers $headers).id
    }
    else
    {
        $aadId = $null
    }
    $userObject = @{
        user = $user
        SID = $SID
        profilePath = $profilePath
        SAMName = $SAMName
        upn = $upn
        aadId = $aadId
    }
    return $userObject
}

# FUNCTION: removeMDMEnrollments
# PURPOSE: Remove MDM enrollments
# DESCRIPTION: This function removes MDM enrollments.  It takes an enrollment path as input and outputs the status to the console.
# INPUTS: $enrollmentPath (string) | example; HKLM:\SOFTWARE\Microsoft\Enrollments\
# OUTPUTS: example; Removed enrollmentPath

function removeMDMEnrollments()
{
    Param(
        [string]$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
    )
    $enrollments = Get-ChildItem -Path $enrollmentPath
    foreach ($enrollment in $enrollments) {
        $object = Get-ItemProperty Registry::$enrollment
        $enrollPath = $enrollmentPath + $object.PSChildName
        $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
        if($key)
        {
            log "Removing $($enrollPath)..."
            Remove-Item -Path $enrollPath -Recurse -Force
            $status = "Removed $($enrollPath)."
            log $status
        }
        else
        {
            $status = "No MDM enrollment found at $($enrollPath)."
            log $status
        }
    }
    $enrollID = $enrollPath.Split("\")[-1]
    $additionalPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provinsioning\OMADM\Accounts\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$($enrollID)",
        "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$($enrollID)"
    )
    foreach($path in $additionalPaths)
    {
        if(Test-Path $path)
        {
            log "Removing $($path)..."
            Remove-Item -Path $path -Recurse -Force
            $status = "Removed $($path)."
            log $status
        }
        else
        {
            $status = "No MDM enrollment found at $($path)."
            log $status
        }
    }
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
        [Parameter(Mandatory=$true)]
        [string]$hostname
    )
    log "Unjoining from domain..."
    $password = generatePassword -length 12
    log "Generated password for $unjoinAccount."
    log "Checking $($unjoinAccount) status..."
    [bool]$acctStatus = getAccountStatus -localAccount $unjoinAccount
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

# FUNCTION: toggleAutoLogon
# PURPOSE: Enable or disable AutoLogon
# DESCRIPTION: This function enables or disables AutoLogon.  It takes a status as input and outputs the status to the console.
# INPUTS: $status (string) | example; enabled
# OUTPUTS: example; Setting AutoLogon to enabled...
function toggleAutoLogon()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$status
    )
    log "Setting AutoLogon to $status..."
    $autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $autoLogonName = "AutoAdminLogon"
    $enabledValue = "1"
    $disabledValue = "0"
    if($status -eq "enabled")
    {
        log "Setting AutoLogon to enabled..."
        reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $enabledValue /f | Out-Host
        log "AutoLogon set to enabled."
    }
    elseif($status -eq "disabled")
    {
        log "Setting AutoLogon to disabled..."
        reg.exe add $autoLogonPath /v $autoLogonName /t REG_SZ /d $disabledValue /f | Out-Host
        log "AutoLogon set to disabled."
    }
}

# FUNCTION: toggleLogonProvider
# PURPOSE: Enable or disable logon provider
# DESCRIPTION: This function enables or disables the logon provider.  It takes a status as input and outputs the status to the console.
# INPUTS: $status (string) | example; enabled
# OUTPUTS: example; Enabling logon provider...
function toggleLogonProvider()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$status
    )
    $logonProviderPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}"
    $logonProviderName = "Disabled"
    $disabledValue = 1
    $enabledValue = 0
    if($status -eq "enabled")
    {
        log "Enabling logon provider..."
        reg.exe add $logonProviderPath /v $logonProviderName /t REG_DWORD /d $enabledValue /f | Out-Host
        log "Logon provider enabled."
    }
    elseif($status -eq "disabled")
    {
        log "Disabling logon provider..."
        reg.exe add $logonProviderPath /v $logonProviderName /t REG_DWORD /d $disabledValue /f | Out-Host
        log "Logon provider disabled."
    }
}

function setLockScreenCaption()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$caption,
        [Parameter(Mandatory=$true)]
        [string]$text,
        [string]$path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    )
    log "Setting lock screen caption..."
    reg.exe add $path /v "legalnoticecaption" /t REG_SZ /d $caption /f | Out-Host
    reg.exe add $path /v "legalnoticetext" /t REG_SZ /d $text /f | Out-Host
    log "Set lock screen caption."
}