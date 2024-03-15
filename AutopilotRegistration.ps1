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
    exitScript -exitCode 4 -functionName "getSettingsJSON"
}

Start-Transcript -Path "$($settings.logPath)\AutopilotRegistration.log" -Verbose


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
    exitScript -exitCode 4 -functionName "initializeScript"
}

# disable autopilotRegistration Task
log "Disable autopilotRegistration task..."
Disable-ScheduledTask -TaskName "autopilotRegistration" -ErrorAction SilentlyContinue
log "autopilotRegistration task disabled."

# install autopilot module
log "Running FUNCTION: installAutopilotModule..."
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

try
{
    installModules
    log "FUNCTION: installAutopilotModule completed successfully."
}
catch
{
    $message = $_.Exception.Message
    log "FUNCTION: installAutopilotModule failed. $message"
    log "Exiting script with critical error.  After reboot, login with admin credentials for more information."
    exitScript -exitCode 4 -functionName "installAutopilotModule"
}


# authenticate to msGraph for Autopilot
$clientSecureSecret = ConvertTo-SecureString $($settings.targetTenant.clientSecret) -AsPlainText -Force
$clientSecretCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $($settings.targetTenant.clientId),$clientSecureSecret
Connect-MgGraph -TenantId $($settings.targetTenant.tenantId) -ClientSecretCredential $clientSecretCredential
log "Authenticated to  $($settings.targetTenant.tenantName) Microsoft Graph"


# register to Autopilot
$serial = (Get-WmiObject -Class Win32_Bios).SerialNumber
$hwid = ((Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData)
$groupTag = (Get-ItemProperty -Path "HKLM:\SOFTWARE\IntuneMigration" -Name "OG_groupTag").OG_groupTag
if([string]::IsNullOrEmpty($groupTag))
{
    log "No group tag found.  Registering device without group tag."
    Add-AutopilotImportedDevice -serialNumber $serial -hardwareIdentifier $hwid
    log "Device registered to Autopilot."
}
else
{
    log "Group tag found.  Registering device with group tag: $groupTag"
    Add-AutopilotImportedDevice -serialNumber $serial -hardwareIdentifier $hwid -groupTag $groupTag
    log "Device registered to Autopilot."
}

log "AutopilotRegistration.ps1 completed successfully.
"
Stop-Transcript