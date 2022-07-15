<#
    .SYNOPSIS
        This script gets information on expiring certificates and client secrets for all Azure AD applications.

    .DESCRIPTION
        This scripts uses the Microsoft.Graph module to get information for all Azure AD app registrations with expiring certificates and client secrets, to assist with application management.
        Results are exported as a CSV file to the location determined using the script parameters.

    .PARAMETER FolderPath
        Folder path to export the results to.

    .PARAMETER FileName
        File name to to export the results as.

    .EXAMPLE
        # Run script and save results to the default folder with the default filename
        .\Get-AzureADApplicationCredentials.ps1
        
        # Run script and save results to the folder C:\AzureADAppsCredentials with the default filename
        .\Get-AzureADApplicationCredentials.ps1 -FolderPath C:\AzureADAppsCredentials
        
        # Run script and save results to the default folder with the filename ScriptResults.csv
        .\Get-AzureADApplicationCredentials.ps1 -FileName ScriptResults.csv
        
        # Run script and save results to the folder C:\AzureADAppsCredentials with the filename ScriptResults.csv
        .\Get-AzureADApplicationCredentials.ps1 -FolderPath C:\AzureADAppsCredentials -FileName ScriptResults.csv
#>
    
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $FolderPath = "$env:USERPROFILE\Downloads",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    $FileName = "$(Get-Date -f 'yyyy-MM-dd')-AzureADAppsCredentials.csv"
)    

function Export-Credential {
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
        "Owners"                 = $OwnerNames
        "OwnerIds"               = $OwnerIds
        "CredentialType"         = $CredentialType
        "CredentialDescription"  = $Credential.DisplayName
        "CredentialId"           = $Credential.KeyId
        "Expired"                = ($Credential.EndDateTime -lt $now)
        "StartDate"              = $Credential.StartDateTime
        "EndDate"                = $Credential.EndDateTime
        "DaysToExpire"           = ($Credential.EndDateTime - $now).Days
        "CertificateUsage"       = $Credential.Usage
    }
}

# Check if an Azure AD session is active
try
{
    Get-MgOrganization -ErrorAction Stop | Out-Null
}
catch
{
    Connect-MgGraph
}

# Get all Azure AD applications
$applications = Get-MgApplication -All

$output = foreach ($app in $applications)
{

    # Get the app owners and their object ID
    $owners = Get-MgApplicationOwner -ApplicationId $app.Id
    $ownerIds = $owners.Id -Join ";"

    # Set ownerNames to null for applications with no assigned owner
    $ownerNames = $null

    # Determine if each owner is a user or application and join into one string
    $ownerNames = @(
        foreach ($owner in $owners) 
        {
            switch ($owner.AdditionalProperties."@odata.type")
            {
                "#microsoft.graph.user"
                {
                    $owner.AdditionalProperties.userPrincipalName
                }

                "#microsoft.graph.servicePrincipal"
                {
                    $owner.AdditionalProperties.appDisplayName
                }
            }
        }
    ) -Join ";"

    # Get certificate properties
    foreach ($cert in $app.KeyCredentials)
    {
        Export-Credential -App $app -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $cert -CredentialType "Certificate"
    }

    # Get client secret properties
    foreach ($secret in $app.PasswordCredentials)
    {
        Export-Credential -App $app -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $secret -CredentialType "ClientSecret"
    }
}

# Export the results as a CSV file
$filePath = Join-Path $FolderPath -ChildPath $FileName

try
{
    $output | Export-CSV $filePath -NoTypeInformation
    Write-Host "Export to $filePath succeeded" -ForegroundColor Cyan
}
catch
{
    Write-Error "Export to $filePath failed | $_ "
}
