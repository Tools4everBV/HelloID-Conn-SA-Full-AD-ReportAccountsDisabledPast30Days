# Warning! When no disabledOU is specified. All users will be retrieved.
$disabledOU = ""
#Get Primary Domain Controller
$domainController = (Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain | Select-Object -Property PDCEmulator).PDCEmulator


$currentDate = Get-Date
$disabledThreshold = $currentDate.AddDays(-30)

try {
    $properties = @(
        "displayName",
        "samAccountName",
        "userPrincipalName",
        "department",
        "title",
        "lastLogonDate",
        "enabled",
        "distinguishedName"
    )

    if($disabledOU){
        $disabledUsers = Get-ADUser -filter * -SearchBase $disabledOU -Server $domainController -Properties $properties | Where-Object {$_.Enabled -eq $false} | Sort-Object samAccountNAme
    }else{
        $disabledUsers = Get-ADUser -filter * -Server $domainController -Properties $properties | Where-Object {$_.enabled -eq $false} | Sort-Object samAccountNAme
    }
    
    Write-Information "Processing [$($disabledUsers.sAMAccountName.count)] disabled users in OU '$disabledOU'"
    
    [System.Collections.ArrayList]$disabledUsersBeforeX =  @()
    foreach($disabledUser in $disabledUsers){
        $disabledAt = ($disabledUser | Get-ADReplicationAttributeMetadata -Properties userAccountControl -Server $domainController).LastOriginatingChangeTime
        if( ($disabledAt -lt $currentDate) -and ($disabledAt -gt $disabledThreshold) ){     
            $userObject = [Ordered]@{
                displayName         = $disabledUser.displayName
                samAccountName      = $disabledUser.samAccountName
                userPrincipalName   = $disabledUser.userPrincipalName
                department          = $disabledUser.department
                title               = $disabledUser.title
                lastLogonDate       = $disabledUser.lastLogonDate
                disabledAt          = $disabledAt
                distinguishedName   = $disabledUser.distinguishedName
            }
            $null = $disabledUsersBeforeX.Add($userObject)
        }
    }

    $resultCount = @($disabledUsersBeforeX).Count
    Write-information "Result count: $resultCount"
    
    if($resultCount -gt 0){
        foreach($user in $disabledUsersBeforeX){
            Write-output $user
        }
    }
} catch {
    Write-error "Error generating report. Error: $_"
    return
}
