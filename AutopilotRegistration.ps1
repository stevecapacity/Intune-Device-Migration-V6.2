<# AUTOPILOTREGISTRATION.PS1
Synopsis
AutopilotRegistration.ps1 is the last script in the device migration process.
DESCRIPTION
This script is used to register the PC in the destination tenant Autopilot environment.  Will use a group tag if available.
USE
.\AutopilotRegistration.ps1
.OWNER
Steve Weiner
.CONTRIBUTORS
Logan Lautt

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
Start-Transcript -Path "$($settings.logPath)\autopilotRegistration.log" -Verbose

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

# disable scheduled task
log "Disabling AutopilotRegistration task..."
Disable-ScheduledTask -TaskName "AutopilotRegistration"
log "AutopilotRegistration task disabled"    


# install modules
function installModules()
{
    Param(
        [string]$nuget = "NuGet",
        [string[]]$modules = @(
            "Microsoft.Graph.Intune",
            "WindowsAutoPilotIntune"
        )
    )
    log "Checking for NuGet..."
    $installedNuGet = Get-PackageProvider -Name $nuget -ListAvailable -ErrorAction SilentlyContinue
    if(-not($installedNuGet))
    {      
        Install-PackageProvider -Name $nuget -Confirm:$false -Force
        log "NuGet successfully installed"    
    }
    else
    {
        log "NuGet already installed"
    }
    log "Checking for required modules..."
    foreach($module in $modules)
    {
        log "Checking for $module..."
        $installedModule = Get-Module -Name $module -ErrorAction SilentlyContinue
        if(-not($installedModule))
        {
            Install-Module -Name $module -Confirm:$false -Force
            Import-Module $module
            log "$module successfully installed"
        }
        else
        {
            Import-Module $module
            log "$module already installed"
        }
    }
}

# run installModules
log "Running installModules..."
try
{
    installModules
    log "installModules completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run installModules: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "installModules"
}

# authenticate ms graph
function msGraphAuthenticate()
{
    Param(
        [string]$tenant = $settings.targetTenant.tenantName,
        [string]$clientId = $settings.targetTenant.clientId,
        [string]$clientSecret = $settings.targetTenant.clientSecret,
        [string]$tenantId = $settings.targetTenant.tenantId
    )
    log "Authenticating to Microsoft Graph..."
    $clientSecureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
    $clientSecretCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $clientId,$clientSecureSecret
    Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientSecretCredential
    log "Authenticated to  $($tenant) Microsoft Graph"
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

# register autopilot device
function autopilotRegister()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber,
        [string]$hardwareIdentifier = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData),
        [string]$groupTag = $settings.groupTag
    )
    log "Registering Autopilot device..."
    if([string]::IsNullOrWhiteSpace($groupTag))
    {
        $regGroupTag = Get-ItemProperty -Path $regKey -Name "GroupTag" | Select-Object -ExpandProperty GroupTag -ErrorAction SilentlyContinue
        if([string]::IsNullOrWhiteSpace($regGroupTag))
        {
            log "No group tag found"
            Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier
            log "Autopilot device registered without group tag"
        }
        else 
        {
            $groupTag = $regGroupTag
            Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier -groupTag $groupTag
            log "Autopilot device registered with group tag $groupTag"
        }
    }
    else 
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier -groupTag $groupTag
        log "Autopilot device registered with group tag $groupTag"
    }
}

# run autopilotRegister
log "Running autopilotRegister..."
try
{
    autopilotRegister
    log "autopilotRegister completed"
}
catch
{
    $message = $_.Exception.Message
    log "Failed to run autopilotRegister: $message"
    log "Exiting script..."
    exitScript -exitCode 4 -functionName "autopilotRegister"
}

# stop transcript
log "Script completed"

Stop-Transcript
