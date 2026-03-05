# HelloID-Conn-SA-Full-AD-ReportAccountsDisabledPast30Days

| :information_source: Information |
|:---|
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description

_HelloID-Conn-SA-Full-AD-ReportAccountsDisabledPast30Days_ is a delegated form designed for use with HelloID Service Automation (SA). It can be imported into HelloID and customized according to your requirements.

By using this delegated form, you can generate a report of Active Directory user accounts that were disabled within a specified time period. The following options are available:

1. Specify the number of days to look back for disabled accounts (default: 30 days).
2. View all AD user accounts that were disabled within the specified timeframe.
3. Option to export/download the report results to CSV.

The report displays key user information including DisplayName, SamAccountName, UserPrincipalName, Department, Title, LastLogonDate, and the date the account was disabled.

## Getting started

### Requirements

• **Active Directory Access**:
  The connector requires access to an Active Directory domain with sufficient permissions to query user accounts and replication metadata. A service account with appropriate AD permissions is necessary.

• **HelloID Agent**:
  A HelloID Agent must be installed and configured to communicate with the Active Directory domain.

• **PowerShell module 'ActiveDirectory'**:
  The HelloID Agent must have PowerShell available with Active Directory module support.

### Global Variables

The following global variables are used by the connector.

| Variable                | Description                                                                                                               | Mandatory |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------- | --------- |
| AdUsersDisabledSearchOu | The organizational units (OUs) to search for disabled AD users. Multiple OUs can be specified separated by semicolons (;) | Yes       |

## Remarks

### Report Search

- **PowerShell Data Source for User Search**: A PowerShell data source retrieves disabled AD users from the configured OUs. The search supports wildcards across DisplayName, Mail, UserPrincipalName, and SamAccountName.
- **Time Threshold:** The form accepts a threshold value (in days) to determine how far back to search for disabled accounts. Only accounts disabled within the specified timeframe are included in the report.
- **Disable Date Detection:** The connector uses `Get-ADReplicationAttributeMetadata` to accurately determine when an account was disabled, rather than relying on less reliable properties like LastLogonDate.
- **Filtering:** The connector first retrieves all disabled users from the specified OUs, then filters them based on when the userAccountControl attribute was last modified to match the disabled status.

## Development resources

### PowerShell Module
This connector uses the ActiveDirectory PowerShell module for querying Active Directory user accounts and replication metadata.

- [ActiveDirectory Module Documentation](https://learn.microsoft.com/en-us/powershell/module/activedirectory/)

### Cmdlets
The following PowerShell cmdlets are used by the connector:

| Cmdlet | Description |
| --- | --- |
| Get-ADForest | Retrieves the Active Directory forest information |
| Get-ADDomain | Retrieves Active Directory domain information |
| Get-ADUser | Retrieves Active Directory user accounts |
| Get-ADReplicationAttributeMetadata | Retrieves replication metadata for AD object attributes (used to determine disable date) |

### Cmdlet documentation
- [Get-ADForest](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adforest)
- [Get-ADDomain](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain)
- [Get-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser)
- [Get-ADReplicationAttributeMetadata](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationattributemetadata)

## Getting help

> 💡 **Tip:**
> For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages.

## HelloID docs
The official HelloID documentation can be found at: [https://docs.helloid.com/](https://docs.helloid.com/)
