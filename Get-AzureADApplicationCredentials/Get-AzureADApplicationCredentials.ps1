[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $FolderPath = "$env:USERPROFILE\Desktop",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $FileName = "$(Get-Date -f 'yyyy-MM-dd')-AzureADAppsCredentials.csv"
)    

function Output {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $App,
        
        [Parameter(Mandatory = $true)]
        $OwnerNames,
        
        [Parameter(Mandatory = $true)]
        $OwnerIds,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $Credential,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Certificate", "ClientSecret")]
        [string] $CredentialType
    )

    $now = Get-Date

    return [PSCustomObject] @{
        "ApplicationName"        = $App.DisplayName
        "ApplicationId"          = $App.AppId
        "Owner"                  = $OwnerNames
        "OwnerId"                = $OwnerIds
        "CredentialType"         = $CredentialType
        "StartDate"              = $Credential.StartDate
        "EndDate"                = $Credential.EndDate
        "Expired"                = ($Credential.EndDate -lt $now)
        "DaysToExpire"           = ($Credential.EndDate - $now).Days
    }
}

# Check if a Azure AD session is active
try
{
    Get-AzureADTenantDetail | Out-Null
}
catch
{
    Connect-AzureAD
}

# Get all Azure AD applications
$applications = Get-AzureADApplication -All $true

$output = foreach ($app in $applications)
{
    $secrets = $app.PasswordCredentials
    $certs = $app.KeyCredentials

    # Get the app owners and their object ID
    $owners = Get-AzureADApplicationOwner -ObjectId $app.ObjectId
    $ownerIds = $owners.ObjectId -Join ";"

    # Set ownerNames to null for applications with no assigned owner
    $ownerNames = $null

    # Determine if each owner is a user or application and join into one string
    $ownerNames = @(
        foreach ($owner in $owners) 
        {
            switch ($owner.ObjectType)
            {
                User
                {
                    $owner.UserPrincipalName
                }

                ServicePrincipal
                {
                    $owner.DisplayName
                }
            }
        }
    ) -Join ";"

    foreach ($cert in $certs)
    {
        Output -App $app -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $cert -CredentialType "Certificate"
    }

    foreach ($secret in $secrets)
    {
        Output -App $app -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $secret -CredentialType "ClientSecret"
    }
}

# Export the results as a CSV file
$filePath = Join-Path $FolderPath -ChildPath $FileName
$output | Export-CSV $filePath -NoTypeInformation