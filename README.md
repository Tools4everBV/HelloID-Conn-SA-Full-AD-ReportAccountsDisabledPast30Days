<!-- Description -->
## Description
This HelloID Service Automation Delegated Form provides an Active Directory report containing the user accounts that are disabled in the past 30 days. The following options are available:
 1. Overview of AD user accounts that match this report


## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.1   | Added version number and updated all-in-one script | 2021/11/03  |
| 1.0.0   | Initial release | 2021/08/03  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
* [Description](#description)
* [All-in-one PowerShell setup script](#all-in-one-powershell-setup-script)
  * [Getting started](#getting-started)
* [Manual resources](#manual-resources)
* [Getting help](#getting-help)


## All-in-one PowerShell setup script
The PowerShell script "createform.ps1" contains a complete PowerShell script using the HelloID API to create the complete Form including user defined variables, tasks and data sources.

 _Please note that this script asumes none of the required resources do exists within HelloID. The script does not contain versioning or source control_


### Getting started
Please follow the documentation steps on [HelloID Docs](https://docs.helloid.com/hc/en-us/articles/360017556559-Service-automation-GitHub-resources) in order to setup and run the All-in one Powershell Script in your own environment.

## Manual resources
This Delegated Form uses the following resources in order to run

### Powershell data source 'ad-user-report-blocked-accounts-past-30-days-genertate-table-users'
This Powershell data source runs an Active Directory query to select the AD user accounts that match this report.

## Getting help
_If you need help, feel free to ask questions on our [forum](https://forum.helloid.com/forum/helloid-connectors/service-automation/500-helloid-sa-active-directory-report-ad-accounts-disabled-past-30-days)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
