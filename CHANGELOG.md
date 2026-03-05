# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.0.0] - 2026-03-05

### Changed

- Updated README.md to follow modern documentation standards and structure
- Improved README with detailed sections for Requirements, Global Variables, Remarks, and Development Resources
- Enhanced documentation with comprehensive cmdlet references and links to Microsoft documentation
- Reorganized documentation structure for better clarity and consistency with other HelloID connectors
- Updated terminology and descriptions throughout documentation
- Added detailed explanation of form input parameters and CSV export capabilities
- Improved consistency in naming conventions and formatting

### Added

- Comprehensive "Getting started" section in README with requirements and configuration details
- "Development resources" section with PowerShell module and cmdlet documentation
- Global Variables table documenting the `AdUsersDisabledSearchOu` variable
- Form input documentation for `thresholdDays` parameter
- Detailed remarks section explaining report search behavior and filtering logic
- Information about CSV export/download functionality in the description

## [1.0.1] - 2021-11-03

### Changed

- Added version number to documentation
- Updated all-in-one setup script

## [1.0.0] - 2021-08-03

This is the first official release of _HelloID-Conn-SA-Full-AD-ReportAccountsDisabledPast30Days_. This release includes functionality to report on Active Directory user accounts that were disabled within a specified time period (default: 30 days).

### Added

- PowerShell data source to retrieve disabled AD users within a configurable time threshold
- Uses `Get-ADReplicationAttributeMetadata` to accurately determine account disable dates
- Support for multiple organizational units (OUs) through the `AdUsersDisabledSearchOu` global variable
- Configurable threshold (in days) for how far back to search for disabled accounts
- Report displays user information including DisplayName, SamAccountName, UserPrincipalName, Department, Title, LastLogonDate, and disable date
- Delegated form with customizable search threshold and results display
- All-in-one setup script for HelloID form deployment
- Manual resource files for modular deployment

### Changed

### Deprecated

### Removed
