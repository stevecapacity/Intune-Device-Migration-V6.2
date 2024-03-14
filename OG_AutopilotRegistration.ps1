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
    Param(
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
        [string]$logName = "autopilotRegistration.log",
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

# disable scheduled task
function disableAutopilotRegistrationTask()
{
    Param(
        [string]$taskName = "AutopilotRegistration"
    )
    Disable-ScheduledTask -TaskName $taskName
    log "AutopilotRegistration task disabled"    
}

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

# get autopilot info
function getAutopilotInfo()
{
    Param(
        [string]$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber,
        [string]$hardwareIdentifier = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
    )
    log "Collecting Autopilot device info..."
    if([string]::IsNullOrWhiteSpace($serialNumber)) 
    { 
        $serialNumber = $env:COMPUTERNAME 
    }
    $global:autopilotInfo = @{
        serialNumber = $serialNumber
        hardwareIdentifier = $hardwareIdentifier
    }
    log "Autopilot device info collected"
    return $autopilotInfo    
}

# register autopilot device
function autopilotRegister()
{
    Param(
        [string]$regPath = $settings.regPath,
        [string]$regKey = "Registry::$regPath",
        [string]$serialNumber = $autopilotInfo.serialNumber,
        [string]$hardwareIdentifier = $autopilotInfo.hardwareIdentifier,
        [string]$groupTag = (Get-ItemPropertyValue -Path $regKey -Name "GroupTag")
    )
    log "Registering Autopilot device..."
    if([string]::IsNullOrWhiteSpace($groupTag))
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier
        log "Autopilot device registered"
    }
    else 
    {
        Add-AutopilotImportedDevice -serialNumber $serialNumber -hardwareIdentifier $hardwareIdentifier -groupTag $groupTag
        log "Autopilot device registered with group tag $groupTag"
    }
}

# END SCRIPT FUNCTIONS

# START SCRIPT

# get settings
try 
{
    getSettingsJSON
    log "Settings retrieved"
}
catch 
{
    $message = $_.Exception.Message
    log "Error getting settings: $message"
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
    log "Error initializing script: $message"
    log "Exiting script"
    Exit 1    
}

# disable scheduled task
try 
{
    disableAutopilotRegistrationTask
    log "AutopilotRegistration task disabled"
}
catch 
{
    $message = $_.Exception.Message
    log "AutopilotRegistration task not disabled: $message"
    log "Exiting script"
    Exit 1
}

# install modules
try 
{
    installModules
    log "Modules installed"
}
catch 
{
    $message = $_.Exception.Message
    log "Error installing modules: $message"
    log "Exiting script"
    Exit 1
}

# authenticate ms graph
try 
{
    msGraphAuthenticate
    log "Authenticated to Microsoft Graph"
}
catch 
{
    $message = $_.Exception.Message
    log "Error authenticating to Microsoft Graph: $message"
    log "Exiting script"
    Exit 1
}

# get autopilot info
try 
{
    getAutopilotInfo
    log "Autopilot device info collected"
}
catch 
{
    $message = $_.Exception.Message
    log "Error collecting Autopilot device info: $message"
    log "Exiting script"
    Exit 1
}

# register autopilot device
try 
{
    autopilotRegister
    log "Autopilot device registered"
}
catch 
{
    $message = $_.Exception.Message
    log "Error registering Autopilot device: $message"
    log "WARNING: Try to manually register the device in Autopilot"
}

# END SCRIPT

# stop transcript
log "Script completed"

Stop-Transcript