using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

function Add-KeyVaultSecret
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $KeyVaultName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $SecretHint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $SecretValue,

        [Parameter(Mandatory = $false)]
        [ValidatePattern("\b(?!0+[dmy]\b)\d+[dmy]\b")]
        [ValidateNotNullOrEmpty()]
        [string] $SecretLifetime = "7d"
    )

    # Append the secret hint to construct the secret name
    $SecretName = "$(Get-Date -Format `"yyyy-MM-dd-HH-mm-ss`")-$SecretHint"

    # Convert secret value to secure string
    $secretValueSecure = ConvertTo-SecureString $SecretValue -AsPlainText -Force

    # Determine the secret expiration date from the lifetime parameter
    $lifetimeLength = $SecretLifetime -replace '[a-zA-Z]'
    $lifetimeUnit   = $SecretLifetime -replace '[0-9]'

    switch ($lifetimeUnit)
    {
        "d"
        {
            $lifetimeUnit = "AddDays"
        }

        "m"
        {
            $lifetimeUnit = "AddMonths"
        }

        "y"
        {
            $lifetimeUnit = "AddYears"
        }
    }

    # Set the expiration date offset from now
    $secretExpiration = (Get-Date).$lifetimeUnit($lifetimeLength)

    # Construct the secret parameters
    $params = @{
        Expires     = $secretExpiration
        Name        = $SecretName
        SecretValue = $secretValueSecure
        VaultName   = $KeyVaultName
    }

    try
    {
        # Add secret to Key Vault
        $secret = Set-AzKeyVaultSecret @params
      #  Write-PSFMessage -Level Verbose -Message "Successfully created Key Vault secret with URL `"$oneTimeSecretUrl`"" -Tag "Success"
      
        $tenantName = (Get-AzTenant).DefaultDomain # | Where-Object {$_.IsDefault -eq $true} | Select -ExpandProperty Name
        $secretUrl = "https://portal.azure.com/#@$($tenantName)/asset/Microsoft_Azure_KeyVault/Secret/$($secret.Id)"

        return $secretUrl
    }

    catch
    {
      #  Write-PSFMessage -Level Error -Message "Error creating One Time Secret" -Tag "Error" -ErrorRecord $_
    }    
}

# Connect to Azure as the managed identity
Connect-AzAccount -Identity

$params = @{
    KeyVaultName   = $Request.Body.KeyVaultName
    SecretHint     = $Request.Body.SecretHint
    SecretValue    = $Request.Body.SecretValue
    SecretLifetime = $Request.Body.SecretLifetime
}

$body = Add-KeyVaultSecret @params

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $body
})
