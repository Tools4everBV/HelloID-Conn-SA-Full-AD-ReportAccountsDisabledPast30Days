# Variables configured in form
$disabledThresholdDays = - ($datasource.thresholdDays)

# Build filter to retrieve all disabled users, then filter by disable date in code (as LastLogonDate is not reliable for this purpose)
$filter = "Enabled -eq `$False -and (Name -like '*')"

# Global variables
$searchOUs = $ADUsersDisabledSearchOU

# Fixed values
$propertiesToSelect = @(
	"ObjectGuid",
	"DisplayName",
	"SamAccountName",
	"UserPrincipalName",
	"Department",
	"Title",
	"LastLogonDate",
	"Enabled"
)

# Set debug logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

try {
	#region Get Primary Domain Controller
	$actionMessage = "querying Primary Domain Controller"
    
	$domainController = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator
	Write-Information "Queried Primary Domain Controller: $domainController"

	# Calculate date threshold
	$actionMessage = "calculating date threshold for disabled users"

	$currentDate = Get-Date
	$disabledThreshold = $currentDate.AddDays($disabledThresholdDays)
	Write-Information "Disabled threshold date: [$disabledThreshold]"

	# Query users
	$actionMessage = "querying AD account(s) matching the filter [$filter] in OU(s) [$($searchOUs)]"

	$ous = $searchOUs -split ';'
	$adUsers = [System.Collections.ArrayList]@()
	foreach ($ou in $ous) {
		$actionMessage = "querying AD account(s) matching the filter [$filter] in OU [$($ou)]"
		$getAdUsersSplatParams = @{
			Filter      = $filter
			Searchbase  = $ou
			Properties  = $propertiesToSelect
			Server      = $domainController
			Verbose     = $False
			ErrorAction = "Stop"
		}
		$getAdUsersResponse = Get-AdUser @getAdUsersSplatParams | Select-Object -Property $propertiesToSelect

		if ($getAdUsersResponse -is [array]) {
			[void]$adUsers.AddRange($getAdUsersResponse)
		}
		else {
			[void]$adUsers.Add($getAdUsersResponse)
		}
	}
	Write-Information "Queried AD account(s) matching the filter [$filter] in OU(s) [$($searchOUs)]. Result count: $(($adUsers | Measure-Object).Count)"
    
	# Filter users disabled within threshold
	$actionMessage = "filtering users disabled after threshold date [$disabledThreshold]"
    
	$disabledUsersBeforeX = [System.Collections.ArrayList]@()
	$adUsers | Foreach-Object {
		$actionMessage = "retrieving disable date for user [$($_.SamAccountName)]"
		$disabledAt = (Get-ADReplicationAttributeMetadata -Object $_.ObjectGuid -Properties userAccountControl -Server $domainController).LastOriginatingChangeTime
      
		# Check if disabledAt is within the threshold
		if (($disabledAt -lt $currentDate) -and ($disabledAt -gt $disabledThreshold)) {
			# Add disabledAt property and set with the retrieved disabled at date
			$_ | Add-Member -MemberType NoteProperty -Name "disabledAt" -Value $disabledAt -Force
			[void]$disabledUsersBeforeX.Add($_)
		}
	}
	Write-Information "Filtered users disabled after threshold date [$disabledThreshold]. Result count: $(($disabledUsersBeforeX | Measure-Object).Count)"

	# Send results to HelloID
	$disabledUsersBeforeX | ForEach-Object {
		Write-Output $_
	}
}
catch {
	$ex = $PSItem
	Write-Warning "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
	Write-Error "Error $($actionMessage). Error: $($ex.Exception.Message)"
	# exit # use when using multiple try/catch and the script must stop
}
