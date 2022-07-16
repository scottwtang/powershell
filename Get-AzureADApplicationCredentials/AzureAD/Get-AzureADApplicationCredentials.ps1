<#
    .SYNOPSIS
        This script gets information on expiring certificates and client secrets for all Azure AD applications.

    .DESCRIPTION
        This scripts uses the AzureAD module to get information for all Azure AD app registrations with expiring certificates and client secrets, to assist with application management.
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
        [string] $OwnerNames,
        
        [Parameter(Mandatory = $true)]
        [string] $OwnerIds,
        
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
        "ObjectType"             = $App.ObjectType
        "Owners"                 = $OwnerNames
        "OwnerIds"               = $OwnerIds
        "CredentialType"         = $CredentialType
        "CredentialId"           = $Credential.KeyId
        "Expired"                = ($Credential.EndDate -lt $now)
        "StartDate"              = $Credential.StartDate
        "EndDate"                = $Credential.EndDate
        "DaysToExpire"           = ($Credential.EndDate - $now).Days
        "CertificateUsage"       = $Credential.Usage
    }
}

function Get-Owners {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $AppObjectId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $ObjectType
    )

    # Determine the object type which each use different cmdlets for retrieving the owner
    switch ($ObjectType)
    {
        Application
        {
            $owners = Get-AzureADApplicationOwner -ObjectId $AppObjectId
        }

        ServicePrincipal
        {
            $owners = Get-AzureADServicePrincipalOwner -ObjectId $AppObjectId
        }
    }

    # Join all owner IDs as one string
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

    return $ownerNames, $ownerIds
}

# Check if an Azure AD session is active
try
{
    Get-AzureADTenantDetail | Out-Null
}
catch
{
    Connect-AzureAD
}

# Get all Azure AD App Registrations
$applications = Get-AzureADApplication -All $true

# Get all Azure AD Enterprise Applications configured for SAML SSO
$servicePrincipals = Get-AzureADServicePrincipal -All $true | Where-Object { 
    ($_.Tags -contains "WindowsAzureActiveDirectoryCustomSingleSignOnApplication") -or 
    ($_.Tags -contains "WindowsAzureActiveDirectoryGalleryApplicationNonPrimaryV1") -or 
    ($_.Tags -contains "WindowsAzureActiveDirectoryGalleryApplicationPrimaryV1") -or 
    ($_.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp")
}

# Loop through each App Registration and retrieve the credentials properties
$output = foreach ($app in $applications)
{

    # Get the app owners and their object ID
    $ownerNames, $ownerIds = Get-Owners -AppObjectId $app.ObjectId -ObjectType $app.ObjectType
    
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

# Loop through each Enterprise Application and retrieve the credentials properties
$output += foreach ($app in $servicePrincipals)
{

    # Get the app owners and their object ID
    $ownerNames, $ownerIds = Get-Owners -AppObjectId $app.ObjectId -ObjectType $app.ObjectType

    # Get certificate properties filtering for certificates with Usage of Verify, to exclude the private key objects used for signing
    foreach ($cert in $app.KeyCredentials | Where-Object {$_.Usage -eq "Verify"} )
    {
        Export-Credential -App $app -OwnerNames $ownerNames -OwnerIds $ownerIds -Credential $cert -CredentialType "Certificate"
    }
}

# Export the results as a CSV file
$filePath = Join-Path $FolderPath -ChildPath $FileName

try
{
    $output | Sort-Object ApplicationName | Export-CSV $filePath -NoTypeInformation
    Write-Host "Export to $filePath succeeded" -ForegroundColor Cyan
}
catch
{
    Write-Error "Export to $filePath failed | $_ "
}
