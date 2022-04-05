#$credential = Get-Credential
#$credential = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)

#Install-Module AzureADPreview -Force
#Import-Module AzureADPreview

#AzureADPreview\Connect-AzureAD
#AzureAD\Connect-AzureAD)


#region init variables to be refractored into function later
    $folderPath = "C:\Users\$env:UserName\Downloads\AzADAppRegistration"

    $inputFileName = "AppInput.json"
    $inputFilePath = Join-Path -Path $folderPath -ChildPath $inputFileName
    try
    {
        $inputFileObject = Get-Content -Path $inputFilePath -Raw | ConvertFrom-Json
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Ivalid JSON format from `"$inputFilePath`"" -Tag "Error" -Target $appDisplayName
        exit
    }

    $outputFileName = "AzADAppRegistrationInfo.json"
    $outputFilePath = Join-Path -Path $folderPath -ChildPath $outputFileName

    $outputFileObject = New-Object -TypeName PsObject

    # PsFramework logging
    if (-not(Get-Module -ListAvailable -Name PsFramework))
    {
        Install-Module -Name PsFramework -Scope CurrentUser
    }

    $logFileName = "AzADAppRegistration-$(Get-date -f 'yyyy-MM-dd').log"
    $logFilePath = Join-Path -Path $folderPath -ChildPath $logFileName
    Set-PSFLoggingProvider -Name LogFile -Enabled $true -FilePath $logFilePath -FileType "CSV" -UTC $true
#endregion

function Add-ApplicationOwner
{
    <#
    .DESCRIPTION
        Assigns owner(s) to an Azure AD application object, after testing if the passed owner exists as a user object or group object.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $App,

        [Parameter(Mandatory)]
        $Owners,

        [Parameter()]
        [object] $OutputObject
    )

    foreach ($owner in $Owners)
    {
        Write-PSFMessage -Level Host -Message "Starting attempt to find object `"$owner`"" -Target $App
        $ownerObjectId = (Get-AzureAdGroup -filter "DisplayName eq '$owner'").ObjectId

        if ($ownerObjectId -eq $null)
        {
            try
            {
                $ownerObjectId = (Get-AzureADUser -ObjectId $owner).ObjectId
                Write-PSFMessage -Level Host -Message "Retrieved user `"$owner`" with object ID `"$ownerObjectId`"" -Target $App
            }

            catch [Microsoft.Open.AzureAD16.Client.ApiException]
            {
                if ($_.Exception.Message.Contains("does not exist or one of its queried reference-property objects are not present."))
                {
                    Write-PSFMessage -Level Error -Message "Object not found `"$owner`"" -Target $App -Tag "Error" -ErrorRecord $_
                }
            }
        }
        
        else
        {
            Write-PSFMessage -Level Host -Message "Retrieved group `"$owner`" with object ID `"$ownerObjectId`"" -Target $App
        }

        try
        {
            Add-AzureAdApplicationOwner -ObjectId $App -RefObjectId $ownerObjectId
            Write-PSFMessage -Level Host -Message "Successfully added owner `"$owner`"" -Target $App -Tag "Success"
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error adding owner `"$owner`"" -Target $App -Tag "Error" -ErrorRecord $_
        }
    }

    # add to json output
    $owners = (Get-AzureAdApplicationOwner -ObjectId $App).UserPrincipalName    
    if ($OutputObject) {$OutputObject | Add-Member -MemberType NoteProperty -Name owners -Value $owners}
}

function Add-ClientSecret
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $App,

        [Parameter()]
        [object] $OutputObject
    )

    # set client secret properties with the timestamp as description, and a lifetime of 2 years
    $secretStartDate = Get-Date
    $secretEndDate = $secretStartDate.AddYears(2)
    $secretDescription = "Uploaded on $(Get-Date -Format `"yyyy-MM-dd HH:mm:ss`")"
    
    # create client secret
    try
    {
        $secret = New-AzureADApplicationPasswordCredential -ObjectId $App -CustomKeyIdentifier $secretDescription -StartDate $secretStartDate -EndDate $secretEndDate
        Write-PSFMessage -Level Host -Message "Successfully created client secret" -Target $App -Tag "Success"
        
        # add to json output        
        if ($OutputObject) {$OutputObject | Add-Member -MemberType NoteProperty -Name secret_description -Value $secretDescription}
        
        # get all secrets from app and compare the byte-to-string CustomKeyIdentifier against our $secretDescription above
        # this is done to obtain the secret's GUID/key ID which isn't returned when calling New-AzureADApplicationPasswordCredential
        try
        {
            $keys = Get-AzureAdApplicationPasswordCredential -ObjectId $App | Where-Object {$_.CustomKeyIdentifier -ne $null}

            foreach ($key in $keys)
            {
	            $enc = [system.Text.Encoding]::UTF8
	            $keyDescription = $enc.GetString($key.CustomKeyIdentifier)

	            if ($keyDescription -eq $secretDescription)
	            {
		            $secretId = $key.KeyId
                    Write-PSFMessage -Level Host -Message "Successfully retrieved client secret ID `"$secretId`"" -Target $App -Tag "Success"
	            }
            }
            
            # add to json output
            if ($OutputObject) {$OutputObject | Add-Member -MemberType NoteProperty -Name secret_id -Value $secretId}
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error retrieving client secret ID" -Target $App -Tag "Error" -ErrorRecord $_
        }

        # store the secret value using One Time Secret API
        New-OneTimeSecret -SecretValue $secret.Value -OutputObject $OutputObject
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error creating client secret" -Target $App -Tag "Error" -ErrorRecord $_
    }    
}

function New-OneTimeSecret
{
    <#
    .DESCRIPTION
        Create a temporary secret using the One Time Secret API (https://onetimesecret.com), translated from cURL to PowerShell
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $SecretValue,

        [Parameter()]
        [object] $OutputObject
    )

    try
    {
        # authentication username using encryption key file and secure string
        $configFolderPath = "C:\Users\$env:UserName\Downloads\AzADAppRegistration\config"
        $key = Get-Content (Join-Path -Path $configFolderPath -ChildPath "otsnu.key")
        $un = Get-Content (Join-Path -Path $configFolderPath -ChildPath "otsnu.txt")
        $secureString = $un | ConvertTo-SecureString -Key $key
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        $apiUsername = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    
        # authentication password using encryption key file and secure string
        $key = Get-Content (Join-Path -Path $configFolderPath -ChildPath "otswp.key")
        $pw = Get-Content (Join-Path -Path $configFolderPath -ChildPath "otswp.txt")
        $secureString = $pw | ConvertTo-SecureString -Key $key
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        $apiToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error constructing authentication info for One Time Secret" -Target $App -Tag "Error" -ErrorRecord $_
    }

    # convert credentials into base64 and embed in the header
    $base64AuthInfo = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($apiUsername):$($apiToken)"))
    $headers = @{
        Authorization = ("Basic $base64AuthInfo")
    }

    # construct the request body with optional parameters
    $body = @{
        secret = $SecretValue
        ttl = 604800
    }

    try
    {
        # send request to create secret and retrieve the URL that can be shared
        $oneTimeSecret = Invoke-RestMethod -Method POST -Headers $headers -Body $body -Uri "https://onetimesecret.com/api/v1/share" 
        $oneTimeSecretLink = "https://onetimesecret.com/secret/$($oneTimeSecret.secret_key)"
        Write-PSFMessage -Level Host -Message "Successfully created One Time Secret with link `"$oneTimeSecretLink`"" -Target $App -Tag "Success"

        # add to json output        
        if ($OutputObject) {$OutputObject | Add-Member -MemberType NoteProperty -Name secret_value -Value $oneTimeSecretLink}
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error creating One Time Secret" -Target $App -Tag "Error" -ErrorRecord $_
    }
}

function Remove-Application
{
}

foreach ($object in $inputFileObject.PSObject.Properties)
{
    switch ($object.Name)
    {
        New
        {
            $outputAppList = New-Object -TypeName PsObject

            foreach ($app in $inputFileObject.New.PsObject.Properties)
            {           

                # create app
                $appDisplayName = $app.Name
                $appPlatform = $app.Value.platform
                if ($appPlatform -eq "web")
                {
                }
                elseif ($appPlatform -eq "spa")
                {
                }
                elseif ($appPlatform -eq "native")
                {
                    $appPublicClient = $true
                }
                $appReplyUrls = $app.Value.reply_urls
                $appLogoutUrl = $app.Value.logout_url
                $appAccessToken = $app.Value.access_token
                $appIdToken = $app.Value.id_token
                $appClientSecret = $app.Value.client_secret
                $appOwners = $app.Value.owners

                try
                {
                    $appRegistration = New-AzureADApplication -DisplayName $appDisplayName # -ReplyUrls $appReplyUrls
                    Write-PSFMessage -Level Host -Message "Sucessfully created application `"$appDisplayName`" with object ID `"$($appRegistration.ObjectId)`"" -Tag "Success" -Target $appDisplayName
                }
                
                catch
                {
                    Write-PSFMessage -Level Error -Message "Error creating application with display name `"$appDisplayName`"" -Tag "Error" -Target $appDisplayName -ErrorRecord $_ 
                }

                $appRegistrationObjectId = $appRegistration.ObjectId 
                #$entApplication = New-AzureADServicePrincipal -DisplayName $AppDisplayName -AppId $appRegistration.AppId

#region add application info to json output
                $outputAppValues = [PsCustomObject]@{
	                app_id = $appRegistration.AppId
	                object_id = $appRegistration.ObjectId
	                tenant_id = (Get-AzureAdTenantDetail).ObjectId
                }
#endregion

#region add client secret
                if ($appClientSecret -eq $true)
                {
                    Add-ClientSecret -App $appRegistrationObjectId -OutputObject $outputAppValues
                }
#endregion

#region add application owners by object id
                if ($appOwners -ne $null -and $appOwners -ne "")
                {
                    Add-ApplicationOwner -App $appRegistrationObjectId -Owners $appOwners -OutputObject $outputAppValues
                }
#endregion

                $outputAppList | Add-Member -MemberType NoteProperty -Name $appRegistration.DisplayName -Value $outputAppValues             
            }

            # add all created apps into json output file
            $outputFileObject | Add-Member -MemberType NoteProperty -Name "New Applications" -Value $outputAppList
        }

        Remove
        {
            $outputAppList = New-Object -TypeName PsObject

            foreach ($appObjectId in $object.Value.object_id)
            {
                try
                {
                    $app = Get-AzureADApplication -ObjectId $appObjectId
                    Write-PSFMessage -Level Host -Message "Removing application `"$($app.DisplayName)`" with object ID `"$($app.ObjectId)`"" -Target $app

                    Remove-AzureADApplication -ObjectId $app.ObjectID
                }

                catch [Microsoft.Open.AzureAD16.Client.ApiException]
                {
                    if ($_.Exception.Message.Contains("Request_ResourceNotFound"))
                    {
                        Write-Warning "Object ID not found: `"$appObjectId`""
                    }

                    elseif ($_.Exception.Message.Contains("Invalid object identifier"))
                    {
                        Write-Warning "Invalid object ID string: `"$appObjectId`""
                    }

                    else
                    {
                        $Error[0].Exception.GetType().fullname
                    }
                }
            
                catch
                {
                    $Error[0].Exception.GetType().fullname
                }

                $outputAppValues = [PsCustomObject]@{
	                app_id = $app.AppId
	                object_id = $app.ObjectId
	                tenant_id = (Get-AzureAdTenantDetail).ObjectId
                }

                $outputAppList | Add-Member -MemberType NoteProperty -Name $app.DisplayName -Value $outputAppValues
            }

            $outputFileObject | Add-Member -MemberType NoteProperty -Name "Removed Applications" -Value $outputAppList
        }        
    }
}

$outputFileObject | ConvertTo-Json -Depth 5 | Out-File $outputFilePath -Append
