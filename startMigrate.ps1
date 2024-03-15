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
Import-Module "$($PSScriptRoot)\migrateFunctions.psm1"

# Running FUNCTION: getSettingsJSON
log "Running FUNCTION: getSettingsJSON..."
try 
{
    $settings = getSettingsJSON
    log "FUNCTION: getSettingsJSON completed successfully"     
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: getSettingsJSON failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "getSettingsJSON"
}

Start-Transcript -Path "$($settings.logPath)\startMigrate.log" -Verbose

# Running FUNCTION: initializeScript
log "Running FUNCTION: initializeScript..."
try 
{
    initializeScript -installTag:$true
    log "FUNCTION: initializeScript completed successfully"     
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: initializeScript failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "initializeScript"
}

# Copy package files
$packageFiles = Get-ChildItem -Path "$($PSScriptRoot)\*" -Recurse
foreach($file in $packageFiles)
{
    $destination = $settings.localPath
    try 
    {
        Copy-Item -Path $file.FullName -Destination $destination -Recurse -Force
        Log "File copied: $($file.FullName) to $($destination)"
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Copy-Path failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "Copy-Path"
    }
}

# authenticate to source tenant
log "Running FUNCTION: msGraphAuthenticate..."
try 
{
    msGraphAuthenticate -tenant $settings.sourceTenant.tenantName -clientId $settings.sourceTenant.clientId -clientSecret $settings.sourceTenant.clientSecret
    log "FUNCTION: msGraphAuthenticate completed successfully"     
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: msGraphAuthenticate failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "msGraphAuthenticate"
}

# construct device object
log "Running FUNCTION: newDeviceObject..."
try 
{
    $pc = newDeviceObject
    log "FUNCTION: newDeviceObject completed successfully"     
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: newDeviceObject failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "newDeviceObject"
}

# Write OG PC properties to registry
log "Writing OG PC properties to registry..."
foreach($x in $pc.Keys)
{
    try 
    {
        reg.exe add $($settings.regPath) /v "OG_$($x)" /t REG_SZ /d $($pc[$x]) /f
        log "Registry key added: $($settings.regPath) /v OG_$($x) /t REG_SZ /d $($pc[$x]) /f"
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Registry key add failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "reg.exe add"
    }
}

# construct user object
log "Running FUNCTION: newUserObject..."
try
{
    $user = newUserObject -domainJoined $pc.domainJoined -azureAdJoined $pc.azureAdJoined
    log "FUNCTION: newUserObject completed successfully"     
}
catch 
{
    $message = $_.Exception.Message
    log "FUNCTION: newUserObject failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "newUserObject"
}

# Write OG User properties to registry
log "Writing OG User properties to registry..."
foreach($x in $user.Keys)
{
    try 
    {
        reg.exe add $($settings.regPath) /v "OG_$($x)" /t REG_SZ /d $($user[$x]) /f
        log "Registry key added: $($settings.regPath) /v OG_$($x) /t REG_SZ /d $($user[$x]) /f"
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Registry key add failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "reg.exe add"
    }
}

# set account connection policy
log "Running FUNCTION: setAccountConnectionPolicy..."
$currentAccountConnectionValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts" -Name "AllowMicrosoftAccountConnection"
if($currentAccountConnectionValue -eq 1)
{
    log "Account connection policy already set to 1"
}
else
{
    log "Setting account connection policy to 1"
    try 
    {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Accounts" -Name "AllowMicrosoftAccountConnection" -Value 1
        log "Account connection policy set to 1"
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Set-ItemProperty failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "Set-ItemProperty"
    }
}

# set don't display last signed in user
log "Running FUNCTION: setDontDisplayLastSignedInUser..."
$currentDontDisplayLastSignedInUserValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName"
if($currentDontDisplayLastSignedInUserValue -eq 1)
{
    log "DontDisplayLastUserName already set to 1"
}
else
{
    log "Setting DontDisplayLastUserName to 1"
    try 
    {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1
        log "DontDisplayLastUserName set to 1"
    }
    catch 
    {
        $message = $_.Exception.Message
        log "Set-ItemProperty failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "Set-ItemProperty"
    }
}

# remove previous MDM enrollments
log "Running FUNCTION: removeMDMEnrollments..."
$enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\"
$enrollments = Get-ChildItem -Path $enrollmentPath
foreach($enrollment in $enrollments)
{
    $object = Get-ItemProperty Registry::$enrollment
    $enrollPath = $enrollmentPath + $object.PSChildName
    $key = Get-ItemProperty -Path $enrollPath -Name "DiscoveryServiceFullURL"
    if($key)
    {
        log "Removing MDM enrollment: $($enrollPath)"
        Remove-Item -Path $enrollPath -Recurse
        log "MDM enrollment removed: $($enrollPath)"
        $enrollId = $enrollPath.Split("\")[-1]
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
            if(Test-Path -Path $path)
            {
                log "Removing MDM enrollment: $($path)"
                Remove-Item -Path $path -Recurse
                log "MDM enrollment removed: $($path)"
            }
            else
            {
                log "Skipping MDM enrollment: $($path)"
            }
        }
    }
    else
    {
        log "Skipping MDM enrollment: $($enrollPath)"
    }
}

# remove MDM certificate
log "Removing MDM certificate..."
Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { $_.Issuer -match "Microsoft Intune MDM Device CA" } | Remove-Item -Force
log "MDM certificate removed"

# set post migration tasks
log "Setting post migration tasks..."
$tasks = @("middleBoot","newProfile")
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

# remove device from Intune and Autopilot
if($pc.mdm -eq $true)
{
    log "$($pc.hostname) is enrolled in Intune."
    if([string]::IsNullOrEmpty($pc.intuneId))
    {
        log "IntuneId is null.  Skipping remove device from Intune"
    }
    else
    {
        log "IntuneId is not null.  Removing from Intune..."
        try 
        {
            Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($pc.intuneId)" -Method Delete -Headers $headers
        }
        catch 
        {
            $message = $_.Exception.Message
            log "FUNCTION: removeDeviceFromIntune failed with error: $message"
            log "Exiting script with non critical error.  Review log files for more information."
            exitScript -exitCode 4 -functionName "removeDeviceFromIntune"
        }
    }
    if([string]::IsNullOrEmpty($pc.autopilotId))
    {
        log "AutopilotId is null.  Skipping remove device from Autopilot"
    }
    else
    {
        log "AutopilotId is not null.  Removing from Autopilot..."
        try 
        {
            Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($pc.autopilotId)" -Method Delete -Headers $headers
        }
        catch 
        {
            $message = $_.Exception.Message
            log "FUNCTION: removeDeviceFromAutopilot failed with error: $message"
            log "Exiting script with non critical error.  Review log files for more information."
            exitScript -exitCode 4 -functionName "removeDeviceFromAutopilot"
        }
    }
}

# revoke login provider
log "Running FUNCTION: toggleLoginProvider..."
try
{
    toggleLogonProvider -status "disabled"
    log "FUNCTION: toggleLoginProvider completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: toggleLoginProvider failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "toggleLoginProvider"
}

# create auto logon migration admin
$migrateAdmin = "MigrationInProgress"
$migrateAdminPassword = "@Password*123"
$autoLogonPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

log "Creating auto logon migration admin..."
New-LocalUser -Name $migrateAdmin -Password (ConvertTo-SecureString -String $migrateAdminPassword -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member $migrateAdmin
reg.exe add $autoLogonPath /v "DefaultUserName" /t REG_SZ /d $migrateAdmin /f | Out-Host
reg.exe add $autoLogonPath /v "DefaultPassword" /t REG_SZ /d $migrateAdminPassword /f | Out-Host

# set auto logon
log "Running FUNCTION: setAutoLogon..."
try
{
    toggleAutoLogon -status "enabled"
    log "FUNCTION: setAutoLogon completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setAutoLogon failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "setAutoLogon"
}

# set lock screen caption
log "Running FUNCTION: setLockScreenCaption..."
try
{
    setLockScreenCaption -caption "Migration in progress" -text "This device is being migrated to $($settings.targetTenant.tenantName).  Please do not power off or restart the device."
    log "FUNCTION: setLockScreenCaption completed successfully"
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: setLockScreenCaption failed with error: $message"
    log "Exiting script with non critical error.  Review log files for more information."
    exitScript -exitCode 4 -functionName "setLockScreenCaption"
}

# leave AzureADJoin
log "Leaving AzureADJoin..."
if($pc.azureAdJoined -eq "YES")
{
   log "$($pc.hostname) is AzureADJoined.  Running FUNCTION: leaveAzureADJoin..."
   try 
   {
        Start-Process -FilePath "C:\Windows\System32\dsregcmd.exe" -ArgumentList "/leave"
        log "FUNCTION: leaveAzureADJoin completed successfully" 
   }
   catch 
   {
        $message = $_.Exception.Message
        log "FUNCTION: leaveAzureADJoin failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "leaveAzureADJoin"
   }
}
else
{
    log "$($pc.hostname) is not AzureADJoined.  Skipping leaveAzureADJoin"
}

# check for domain join and remove
log "Checking for domain join and removing..."
if($pc.domainJoined -eq "YES")
{
    log "$($pc.hostname) is domainJoined.  Running FUNCTION: removeDomainJoin..."
    $password = generatePassword -length 12
    $adminStatus = (Get-LocalUser -Name "Administrator").Enabled
    if($adminStatus -eq $false)
    {
        log "Administrator account is disabled.  Enabling account and setting password..."
        Set-LocalUser -Name "Administrator" -Password $password -PasswordNeverExpires $true
        Get-LocalUser -Name "Administrator" | Enable-LocalUser
    }
    else
    {
        log "Administrator account is enabled.  Setting password..."
        Set-LocalUser -Name "Administrator" -Password $password -PasswordNeverExpires $true
    }
    $cred = New-Object System.Management.Automation.PSCredential ("$($pc.hostname)\Administrator", $password)
    try
    {
        Remove-Computer -UnjoinDomainCredential $cred -PassThru -Force -Verbose
        log "FUNCTION: removeDomainJoin completed successfully"
    }
    catch
    {
        $message = $_.Exception.Message
        log "FUNCTION: removeDomainJoin failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "removeDomainJoin"
    }
}
else
{
    log "$($pc.hostname) is not domainJoined.  Skipping removeDomainJoin"
}

# install provisioning package
log "Installing provisioning package..."
$ppkg = (Get-ChildItem -Path $($settings.localPath) -Filter "*.ppkg" -Recurse).FullName
if($ppkg)
{
    log "Provisioning package found: $($ppkg)"
    try
    {
        Install-ProvisioningPackage -PackagePath $ppkg -QuietInstall -Force
        log "Provisioning package installed"
    }
    catch
    {
        $message = $_.Exception.Message
        log "Provisioning package install failed with error: $message"
        log "Exiting script with non critical error.  Review log files for more information."
        exitScript -exitCode 4 -functionName "installPpkg.ps1"
    }
}
else
{
    log "Provisioning package not found"
}

log "Exiting script with success"

Stop-Transcript