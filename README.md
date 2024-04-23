# Intune Device Migration

## Overview
As business continue to move endpoint management to the cloud, the need for solutions beyond standard onboarding is growing.  Mergers, acquisitions, and divestitures between companies using Microsoft Intune require Windows PCs be moved from one tenant to another.

The **Intune Device Migration** solution allows devices to be offboarded from their existing tenant and automatically joined to their destination in a matter of minutes; all while retaining user data.

Using a custom solution that leverages PowerShell scripting, Microsoft Graph API, and Windows provisioning packages, organizations can migrate Windows PCs between tenants with minimal downtime and user disruption.
## Requirements
### Access
* Organization resources will require global administrator privileges to the M365 environment.
* Consultant or implementation resources will require the following access components:
    * User account
    * Intune and Entra ID P1 or P2 license
    * Intune Administrator role
### Graph API Permissions (Source and Destination tenant)
*Application permissions*
* Device.ReadWrite.All
* DeviceManagementConfiguration.ReadWrite.All
* DeviceManagementManagedDevices.PrivilegedOperations.All
* DeviceManagementManagedDevices.ReadWrite.All
* DeviceManagementServiceConfig.ReadWrite.All
* User.ReadWrite.All
### Tenant
* Entra ID connect must be configured to support Microsoft Account login:
    * Entra ID Premium subscription and a verified domain name.
    * Configured identity provider (IdP) to support the WS-Federation protocol and the SAML 2.0 token format.
    * Registered IdP as an enterprise application in Azure AD and assigned users or groups to it.
    * Enable Entra ID connect for their IdP in the Azure portal and provide the required metadata and settings.
* PCs must be in the following state:
    * Entra ID joined.
    * Intune managed.
### Technical
* PC requirements:
    * Windows 10 Build 22H2 (19045)
    * Windows 11 Build 22H2 (22621)
    * Minimum 8GB RAM
    * Minimum 256GB SSD storage
    * 64-bit CPU or System on a Chip (SoC) with two or more cores (4 is recommended)
    * Trusted Platform Module (TPM) version 2.0 or higher
    * Internet connection
* Network requirements:
    * The internet connection supports HTTPS over port 443.
    * The internet connection allows connections to the Microsoft online services endpoints.
    * The internet connection does not require authentication or use a proxy that requires authentication.
    * The Microsoft online services URLs needed are:
        * https://*.manage.microsoft.com
        * https://*.manage.microsoftazure.us
        * https://*.msazure.cn
        * https://*.microsoftonline.com
        * https://*.microsoftonline-p.com
        * https://*.microsoftonline.us
        * https://*.microsoftonline.de
        * https://*.microsoftonline.cn
### Licensing
* All users must be licensed for Microsoft Intune, either as a standalone service or as part of a bundle such as Microsoft 365 E3 or E5. 
* All users must be licensed for Entra ID Premium, either as a standalone service or as part of a bundle such as Microsoft 365 E3 or E5.
* Devices that are enrolled with Autopilot must also have a Windows 10 Enterprise E3 or E5 license, or an equivalent license that includes the Windows 10/11 Enterprise Subscription Activation (ESU) feature, otherwise the PC will remain with Windows Pro

## Assumptions
### Source tenant
* Users are assigned licensing to be entitled to Entra ID P1 and Intune P1
* Devices are Entra ID joined, domain joined, or hybrid domain joined
* Devices are enrolled to Intune and actively managed

### User migration
* User identities from source tenant have been migrated to destination tenant
* User data has been migrated from source to destination tenant including:
    * SharePoint
    * OneDrive
    * Exchange Online
    * Teams

### Destination tenant
* Users are assigned licensing to be entitled to Entra ID P1 and Intune P1
* Intune is configured to support the migrated Windows devices including:
    * **Policy configuration**
    * **Applications**
    * **Settings**
* Intune configurations have been validated with device enrollment

## Technical flow
The migration solution is comprised of several scripts and files that are compiled into an *.intunewin* file using the [Microsoft Win32 Content Prep Tool](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool).  When the application is installed, the **startMigrate.ps1** script is launched and begins to orchestrate the migration.  A provisioning package must be created using the [Windows Configuration Designer](https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-install-icd).

Once the migration starts, the solution goes through 8 phases:

### Phase 1 | Gather
* Package files are coppied locally to device
* Authenticate to **Source tenant** via Graph API
* Gather device and user info in current state
### Phase 2 | Prepare
* Set local security policy to allow migration
* Create scheduled tasks (initial)
* Add "MigrationInProgress" admin account
* Configure lock screen policy
### Phase 3 | Remove
* Delete MDM device certificate
* Remove MDM enrollment entries from registry
* 'Unjoin' from Entra ID
* If device is domain or hybrid joined, remove from domain
* Toggle auto logon *on*
* Delete Intune object from **Source tenant**
* Delete Autopilot object from **Source tenant**
* Install provisioning package to join **Destination tenant**

***1st Reboot***

### Phase 4 | Join
* Disable first set of scheduled tasks
* Toggle auto logon *off*
* Change lock screen message

***2nd Reboot***

### Phase 5 | New sign in
* User signs in with **Destination tenant** credentials
* Authenticate to **Destination tenant** via Graph API
* Collect 'new' user info
* Set final migration scheduled tasks
* Toggle auto logon *on*
* Change lock screen message

***3rd Reboot***

### Phase 6 | Change owner
* New user profile is deleted
* Original user profile owner is changed to new SID
* Clean up registry

***4th (and final) Reboot***

### Phase 7 | Post migrate
* Authenticate to **Destination tenant** via Graph API
* Disable final migration tasks
* Set primary user in **Destination tenant** Intune
* Set Group tag (Entra ID attribute)
* Migrate BitLocker key

### Phase 8 | Autopilot registration
* Authenticate to **Destination tenant** via Graph API
* Collect hardware info (hw hash)
* Register PC to Autopilot

## Migration Architecture
![image](./Device%20Migration%20V6.2.png)

