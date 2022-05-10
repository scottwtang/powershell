[CmdletBinding()]
param (
    [parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $AppName,

    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $AppRegistrationOwners,
    
    [parameter(Mandatory = $false)]
    [bool] $ClientSecret,
    
    [parameter(Mandatory = $false)]
    [bool] $AccessToken,
    
    [parameter(Mandatory = $false)]
    [bool] $IdToken,
    
    [parameter(Mandatory = $false)]
    $ApiPermissions,
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $OwnersDirectoryRole,
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $FolderPath = $PSScriptRoot,
       
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigFile = "config.json",
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputFile = "New-AADApplication-Output-$(Get-Date -f 'yyyy-MM-dd')-AppInfo.json",
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $LogFile = "New-AADApplication-Output-$(Get-Date -f 'yyyy-MM-dd')-Log.log",
    
    [parameter(Mandatory = $false)]
    [ValidateSet("Automation", "Manual")]
    [string] $ScriptMode = "Automation",
    
    [parameter(Mandatory = $false)]
    [ValidateSet("AzureLogAnalytics", "LogFile", "AzureLogAnalytics;LogFile", "LogFile;AzureLogAnalytics")]
    $PSFLogProvider = "AzureLogAnalytics"
)


function Add-AADRole
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $User,

        [Parameter(Mandatory = $true)]
        [string] $RoleName,

        [Parameter()]
        [string] $AppName
    )
    
    # validate the user exists
    try
    {
        $userObj = Get-MgUser -UserId $User -ErrorAction Stop
        Write-PSFMessage -Level Verbose -Message "Retrieved user `"$User`" with object ID `"$($userObj.Id)`"" -Target $AppName
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error retrieving object `"$User`"" -Target $AppName -Tag "Error" -ErrorRecord $_
    }

    try
    {
        
        # validate if the directory role has been activated
        $adminRole = Get-MgDirectoryRole -Filter "DisplayName eq '$RoleName'" -ErrorAction Stop

        # if the role has not been activated, we need to get the role template to activate the role
        if ($adminRole -eq $null)
        {
            $adminRoleTemplate = Get-MgDirectoryRoleTemplate -ErrorAction Stop | where {$_.DisplayName -eq $RoleName}
            $adminRole = New-MgDirectoryRole -RoleTemplateId $adminRoleTemplate.Id
            Write-PSFMessage -Level Verbose -Message "Activated directory role `"$RoleName`" with role Id `"$($adminRole.Id)`"" -Target $AppName
        }
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error finding directory role `"$RoleName`"" -Target $AppName -Tag "Error" -ErrorRecord $_
    }

    # assign the user to the activated role
    try
    {
        $body = @{
            "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/{$($userObj.Id)}"
        }

        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $adminRole.Id -BodyParameter $body -ErrorAction Stop
        Write-PSFMessage -Level Verbose -Message "Assigned directory role `"$RoleName`" to `"$User`"" -Target $AppName
    }
    
    catch
    {
        if ($_.Exception.Message -eq "One or more added object references already exist for the following modified properties: 'members'.")
        {
            Write-PSFMessage -Level Warning -Message "User `"$User`" is already assigned the directory role `"$RoleName`"" -Tag "Error" -Target $AppName
        }

        else
        {
            Write-PSFMessage -Level Error -Message "Error adding role `"$RoleName`" to user `"$User`"" -Target $AppName -Tag "Error" -ErrorRecord $_
        }
    }
}

function Add-ApplicationOwner
{
    <#
    .DESCRIPTION
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $AppObjectId,

        [Parameter()]
        [string] $AppName,

        [Parameter(Mandatory = $true)]
        $OwnerList
    )

    $OwnerList = $OwnerList.Split(";")
    foreach ($owner in $OwnerList)
    {

        # validate the given user exists
        try
        {
            $ownerObjectId = (Get-MgUser -UserId $owner -ErrorAction Stop).Id
            Write-PSFMessage -Level Verbose -Message "Retrieved user `"$owner`" with object ID `"$ownerObjectId`"" -Target $AppName
        }
        catch
        {
            Write-PSFMessage -Level Error -Message "Error retrieving object `"$owner`"" -Target $AppName -Tag "Error" -ErrorRecord $_
        }
            
        # assign the owner to the application
        try
        {
            $body = @{
                "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/{$ownerObjectId}"
            }

            New-MgApplicationOwnerByRef -ApplicationId $AppObjectId -BodyParameter $body -ErrorAction Stop
            Write-PSFMessage -Level Verbose -Message "Successfully added app registration owner `"$owner`"" -Target $AppName -Tag "Success"
        }

        catch
        {
            if ($_.Exception.Message -eq "One or more added object references already exist for the following modified properties: 'owners'.")
            {
                Write-PSFMessage -Level Error -Message "User `"$owner`" already assigned as app registration owner" -Target $AppName -Tag "Error" -ErrorRecord $_
            }

            else
            {
                Write-PSFMessage -Level Error -Message "Error adding owner `"$owner`"" -Target $AppName -Tag "Error" -ErrorRecord $_
            }
        }

        if ($OwnersDirectoryRole)
        {
            Add-AADRole -User $owner -RoleName $OwnersDirectoryRole
        }
    }

    # get the full list of owners and add to json output    
    if ($outputAppValues)
    {
        $owners = (Get-MgApplicationOwner -ApplicationId $AppObjectId) | ForEach-Object { 
            [PSCustomObject] @{
                Id = $_.Id
                DisplayName = $_.AdditionalProperties.displayName
                UserPrincipalName = $_.AdditionalProperties.userPrincipalName
            }
        }

        $outputAppValues | Add-Member -MemberType NoteProperty -Name owners -Value $owners
    }
}

function Add-ClientSecret
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $AppObjectId,

        [Parameter()]
        [string] $AppName
    )
       
    try
    {

        # set client secret properties with the timestamp as description, and a lifetime of 2 years
        $body = @{
            DisplayName = "Uploaded on $(Get-Date -Format `"yyyy-MM-dd HH:mm:ss`")"
            StartDateTime = Get-Date
            EndDateTime = (Get-Date).AddMonths(24)
        }
        
        # create client secret
        $secret = Add-MgApplicationPassword -Application $AppObjectId -PasswordCredential $body -ErrorAction Stop       
        Write-PSFMessage -Level Verbose -Message "Successfully created client secret" -Target $AppName -Tag "Success"        
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error creating client secret" -Target $AppName -Tag "Error" -ErrorRecord $_
    }

    # store the secret value using One Time Secret API
    $oneTimeSecret = New-OneTimeSecret -SecretMessage $secret.SecretText -AppName $AppName

    # add to json output        
    if ($outputAppValues)
    {
        $secret = [PSCustomObject] @{
            secret_id = $secret.KeyId
            secret_description = $secret.DisplayName
            secret_value = "https://onetimesecret.com/secret/$($oneTimeSecret.secret_key)"
        }

        $outputAppValues | Add-Member -MemberType NoteProperty -Name client_secret -Value $secret
    }
}

function Build-Signature 
{
    <#
    .SYNOPSIS
        Function to create authorization signature for posting to Azure Log Analytics

    .NOTES
        # Taken from https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
    #>

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string] $customerId,

        [parameter(Mandatory = $true)]
        [string] $sharedKey,

        [parameter(Mandatory = $true)]
        [string] $date,

        [parameter(Mandatory = $true)]
        [string] $contentLength,

        [parameter(Mandatory = $true)]
        [string] $method,

        [parameter(Mandatory = $true)]
        [string] $contentType,

        [parameter(Mandatory = $true)]
        [string] $resource
    )

    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash

    return $authorization
}

function Configure-PSF
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $PSFLogProvider
    )

    switch ($PSFLogProvider)
    {
        "AzureLogAnalytics"
        {
            $params = @{
                Enabled     = $true
                LogType     = "PSFLogging"
                Name        = "AzureLogAnalytics"
                SharedKey   = $log_shared_key
                WorkspaceId = $log_workspace_id
            }
        }

        "LogFile"
        {
            $params = @{
                Enabled  = $true
                FilePath = Join-Path -Path (Join-Path -Path $FolderPath -ChildPath "Logs") -ChildPath $LogFile
                FileType = "CSV"
                Name     = "LogFile"
                UTC      = $true
            }
        }
    }
    
    Set-PSFLoggingProvider @params
}

function New-AppRegistration
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $AppName
    )

    begin
    {
        $requiredResourceAccess = @{
            ResourceAppId = "00000003-0000-0000-c000-000000000000"
            ResourceAccess = @(

                # User.Read
                @{
                    Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
                    Type = "Scope"
                }
            )
        }

        $params = @{
            DisplayName = $AppName
            SignInAudience = "AzureADMyOrg"
            RequiredResourceAccess = $requiredResourceAccess
        }
    }

    process
    {
        try
        {
            $appRegistration = New-MgApplication @params
            $appObjectId = $appRegistration.Id
            Write-PSFMessage -Level Verbose -Message "Sucessfully created application `"$AppName`" with object ID `"$($appRegistration.Id)`"" -Tag "Success" -Target $AppName
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error creating application with display name `"$AppName`"" -Tag "Error" -Target $AppName -ErrorRecord $_ 
        }

        # add application info to json output
        $outputAppValues = [PsCustomObject] @{
            time_created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss +0")
	        tenant_name  = (Get-MgOrganization).DisplayName
	        tenant_id    = (Get-MgOrganization).Id
            app_name     = $appRegistration.DisplayName
	        app_id       = $appRegistration.AppId
	        object_id    = $appRegistration.Id
        }

        return $appRegistration, $appObjectId, $outputAppValues
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
        [string] $SecretMessage,

        [Parameter()]
        [string] $AppName
    )

    # convert credentials into base64 and embed in header
    $base64AuthInfo = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($ots_Username):$($ots_Token)"))
    $headers = @{
        Authorization = ("Basic $base64AuthInfo")
    }

    # construct the request body with optional parameters
    $body = @{
        secret = $SecretMessage
        ttl = 604800
    }

    try
    {
        # send request to create secret and retrieve the share URL
        $oneTimeSecret = Invoke-RestMethod -Method POST -Headers $headers -Body $body -Uri "https://onetimesecret.com/api/v1/share" 
        $oneTimeSecretUrl = "https://onetimesecret.com/secret/$($oneTimeSecret.secret_key)"
        Write-PSFMessage -Level Verbose -Message "Successfully created One Time Secret with URL `"$oneTimeSecretUrl`"" -Target $AppName -Tag "Success"

        return $oneTimeSecret
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error creating One Time Secret" -Target $AppName -Tag "Error" -ErrorRecord $_
    }
}

function Post-LogAnalyticsData
{
    <#
    .SYNOPSIS
        Function to create and post request to Azure Log Analytics

    .NOTES
        # Taken from https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
    #>

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string] $CustomerId,

        [parameter(Mandatory = $true)]
        [string] $SharedKey,

        [parameter(Mandatory = $true)]
        $Body,

        [parameter(Mandatory = $true)]
        [string] $LogType
    )

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $Body.Length

	$signatureArgs = @{
		customerId	    = $CustomerId
		sharedKey	    = $SharedKey
		date	        = $rfc1123date
		contentLength   = $contentLength
		method	        = $method
		contentType     = $contentType
		resource        = $resource
	}

    $signature = Build-Signature @signatureArgs

    $uri = "https://" + $CustomerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $LogType;
        "x-ms-date"            = $rfc1123date;
        #"time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $Body -UseBasicParsing
    return $response.StatusCode
}

function Update-AccessTokenIssuance
{
    [cmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string] $AppObjectId,
        
        [parameter(Mandatory = $true)]
        [bool] $Enabled,

        [parameter()]
        [string] $AppName
    )

    $params = @{
        Web = @{
            ImplicitGrantSettings = @{
                EnableAccessTokenIssuance = $Enabled
            }
        }
    }

    try
    {
        Update-MgApplication -ApplicationId $AppObjectId @params -ErrorAction Stop
        Write-PSFMessage -Level Verbose -Message "Setting access token issuance to: $Enabled" -Target $AppName -Tag "Success"
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error setting access token issuance" -Target $AppName -Tag "Error" -ErrorRecord $_
    }

    # add to json output        
    if ($outputAppValues)
    {
        $outputAppValues | Add-Member -MemberType NoteProperty -Name access_token -Value $Enabled
    }
}

function Update-IdTokenIssuance
{
    [cmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string] $AppObjectId,
        
        [parameter(Mandatory = $true)]
        [bool] $Enabled,

        [parameter()]
        [string] $AppName
    )

    $params = @{
        Web = @{
            ImplicitGrantSettings = @{
                EnableIdTokenIssuance = $Enabled
            }
        }
    }

    try
    {
        Update-MgApplication -ApplicationId $AppObjectId @params -ErrorAction Stop
        Write-PSFMessage -Level Verbose -Message "Setting ID token issuance to: $Enabled" -Target $AppName -Tag "Success"
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error setting ID token issuance" -Target $AppName -Tag "Error" -ErrorRecord $_
    }

    # add to json output        
    if ($outputAppValues)
    {
        $outputAppValues | Add-Member -MemberType NoteProperty -Name id_token -Value $Enabled
    }
}

function Update-MSGraphAccess
{
    [cmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [string] $AppObjectId,
        
        [parameter(Mandatory = $false)]
        [string]$resourceAppId = "00000003-0000-0000-c000-000000000000",

        [parameter(Mandatory = $true)]
        $resourceAccessList,
        
        [parameter(Mandatory = $false)]
        [string] $AppName
    )
    
    foreach ($permission in $resourceAccessList)
    {
        try
        {
            $permissionId = (Find-MgGraphPermission $permission.PermissionName -PermissionType $permission.PermissionType -ExactMatch -ErrorAction Stop).Id
            Write-PSFMessage -Level Verbose -Message "Retrieved permission ID `"$($permissionID)`" for permission `"$($permission.PermissionName)`" of type `"$($permission.PermissionType)`"" -Target $AppName -Tag "Success"
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error retrieving permission ID for permission `"$($permission.PermissionName)`" of type `"$($permission.PermissionType)`"" -Target $AppName -Tag "Error" -ErrorRecord $_
        }

        switch ($permission.PermissionType)
        {
            "Application"
            {
                $permissionType = "Role"
            }

            "Delegated"
            {
                $permissionType = "Scope"
            }
        }
        
        $params = @{
            ResourceAppId = $resourceAppId
            ResourceAccess = @(
                @{
                    Id   = $permissionId
                    Type = $permissionType
                }
            )
        }       

        $app = (Get-MgApplication -ApplicationId $AppObjectId)
        $params.ResourceAccess += $app.RequiredResourceAccess.ResourceAccess

        try
        {
            Update-MgApplication -ApplicationId $AppObjectId -RequiredResourceAccess $params
            Write-PSFMessage -Level Verbose -Message "Successfully added permission `"$($permission.PermissionName)`"" -Target $AppName -Tag "Success"
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error adding permission `"$($permission.PermissionName)`"" -Target $AppName -Tag "Error" -ErrorRecord $_
        }
    }

    # get the full list of permissions and add to json output    
    if ($outputAppValues)
    {
        $resourceAccessList = (Get-MgApplication -ApplicationId $AppObjectId).RequiredResourceAccess.ResourceAccess

        $outputAppValues | Add-Member -MemberType NoteProperty -Name resource_access -Value $resourceAccessList
    }
}

#region begin
    try
    {

        #region Set script variables from Azure Automation variables or configuration file
            switch ($ScriptMode)
            {
                "Automation"
                {
                    $tenant_id = (Get-AutomationVariable -Name 'tenant_id')
                    $client_id = (Get-AutomationVariable -Name 'client_id')
                    $client_secret = (Get-AutomationVariable -Name 'client_secret')
            
                    $log_workspace_id = (Get-AutomationVariable -Name 'log_workspace_id')
                    $log_shared_key = (Get-AutomationVariable -Name 'log_shared_key')

                    $ots_Username = (Get-AutomationVariable -Name 'ots_username')
                    $ots_Token = (Get-AutomationVariable -Name 'ots_token')
                }

                "Manual"
                {
                    $configFolderPath = Join-Path -Path $FolderPath -ChildPath "Config"
                    $configFilePath = Join-Path -Path $configFolderPath -ChildPath $ConfigFile
                    $configFileObject = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json

                    $tenant_id = $configFileObject.app_properties.tenant_id
                    $client_id = $configFileObject.app_properties.app_id
                    $client_secret = $configFileObject.app_properties.client_secret
            
                    $log_workspace_id = $configFileObject.log_analytics.workspace_id
                    $log_shared_key = $configFileObject.log_analytics.shared_key

                    $ots_Username = $configFileObject.one_time_secret.username
                    $ots_Token = $configFileObject.one_time_secret.token
                }
            }
        #endregion

        #region Configure PsFramework logging
            if (-not (Get-Module -ListAvailable -Name PsFramework) )
            {
                Install-Module -Name PsFramework -Scope CurrentUser -Force
            }

            $PSFLogProvider = $PSFLogProvider.Split(";")
            foreach ($logProvider in $PSFLogProvider)
            {
                Configure-PSF($logProvider)
            }
            
            # The 2nd loop is to ensure that all log providers are set before writing messages
            foreach ($logProvider in $PSFLogProvider)
            {
                Write-PSFMessage -Level Verbose -Message "Set PSFramework logging provider to `"$($logProvider)`"" -Target $AppName
            }
        #endregion

        #region Obtain access token to connect to MS Graph
            try
            {
                Disconnect-MgGraph
            }

            catch
            {
            }

            finally
            {
                $params = @{                
                    Uri    = "https://login.microsoftonline.com/$($tenant_id)/oauth2/v2.0/token"
                    Method = "POST"
                    Body   = @{
	                    client_id     = $client_id
	                    client_secret = $client_secret
                        grant_type    = "client_credentials"
                        scope         = "https://graph.microsoft.com/.default"
                    }
                }
 
                $connection = Invoke-RestMethod @params
                $token_expires = (Get-Date).AddSeconds($connection.expires_in)
                $graph = Connect-MgGraph -AccessToken $connection.access_token
                Write-PSFMessage -Level Verbose -Message "Obtained access token with validity until $token_expires" -Target $AppName
            }
        #endregion
    }

    catch
    {
        Write-Host "Error initializing script"
        Write-PSFMessage -Level Error -Message "Error initializing script" -Tag "Error"
        break
    }
#endregion

function Output-AppProperties
{
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $PSFLogProvider
    )

    switch ($PSFLogProvider)
    {
        "AzureLogAnalytics"
        {
        	$params = @{
		        CustomerId = $log_workspace_id
		        SharedKey  = $log_shared_key
		        Body       = $outputAppValues | ConvertTo-Json
		        LogType    = "AppProperties"
	        }

            $response = Post-LogAnalyticsData @params
        }

        "LogFile"
        {
            # construct file paths
            $outputFilePath = Join-Path -Path $FolderPath -ChildPath $OutputFile
            $outputFileObject = New-Object -TypeName PsObject
            $outputFileObject | Add-Member -MemberType NoteProperty -Name $appRegistration.DisplayName -Value $outputAppValues
            $outputFileObject | ConvertTo-Json -Depth 5 | Out-File $outputFilePath -Append
        }
    }
}

#region process
    # create app registration
    $appRegistration, $appObjectId, $outputAppValues = New-AppRegistration -AppName $AppName

    # create enterprise application/service principal
    $enterpriseApplication = New-MgServicePrincipal -AppId $appRegistration.AppId -Tags @("HideApp", "WindowsAzureActiveDirectoryIntegratedApp")   

    if ($AccessToken)
    {
        Update-AccessTokenIssuance -AppObjectId $appObjectId -AppName $AppName -Enabled $AccessToken
    }

    if ($IdToken)
    {
        Update-IdTokenIssuance -AppObjectId $appObjectId -AppName $AppName -Enabled $IdToken
    }

    if ($ApiPermissions)
    {
        Update-MSGraphAccess -AppObjectId $appObjectId -ResourceAccessList $ApiPermissions -AppName $AppName
    }

    # add application owners by object id
    if ($AppRegistrationOwners)
    {
        Add-ApplicationOwner -AppObjectId $appObjectId -AppName $AppName -OwnerList $AppRegistrationOwners
    }

    # add client secret
    if ($ClientSecret)
    {
        Add-ClientSecret -AppObjectId $appObjectId -AppName $AppName
    }

    foreach ($logProvider in $PSFLogProvider)
    {
        Output-AppProperties($logProvider)
    }
#endregion

#region end
    Disconnect-MgGraph
    
    # Wait until all logs are written and then disable each provider to avoid multiple logging instances
    Wait-PSFMessage 
    foreach ($logProvider in $PSFLogProvider)
    {
        Set-PSFLoggingProvider -Name $logProvider -Enabled $false
    }
#endregion
