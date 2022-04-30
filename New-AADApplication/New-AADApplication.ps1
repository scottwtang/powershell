[CmdletBinding()]
param (
    [parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $AppName,

    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $AppRegistrationOwners,
    
    [parameter(Mandatory = $false)]
    [bool] $ClientSecret = $true,
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $OwnersDirectoryRole,
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $FolderPath = $PSScriptRoot,
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigFolderPath = (Join-Path -Path $PSScriptRoot -ChildPath "Config"),
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $ConfigFile = "config.json",
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputFile = "New-AADApplication-Output-AppInfo.json",
    
    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $LogFile = "New-AADApplication-Log-$(Get-Date -f 'yyyy-MM-dd').log"
)

begin
{
    try
    {

        # construct file paths
        $configFilePath = Join-Path -Path $ConfigFolderPath -ChildPath $ConfigFile
        $outputFilePath = Join-Path -Path $FolderPath -ChildPath $OutputFile
        $logFilePath = Join-Path -Path (Join-Path -Path $FolderPath -ChildPath "Logs") -ChildPath $LogFile

        # PsFramework logging
        if (-not (Get-Module -ListAvailable -Name PsFramework))
        {
            Install-Module -Name PsFramework -Scope CurrentUser -Force
        }

        Set-PSFLoggingProvider -Name LogFile -Enabled $true -FilePath $logFilePath -FileType "CSV" -UTC $true

        # establish connection to AAD
        try
        {
            $var = Get-MgOrganization -ErrorAction Stop
        }
     
        catch [System.Security.Authentication.AuthenticationException]
        {
            # Disconnect-MgGraph -ErrorAction SilentlyContinue

            $configFileObject = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json 
            
            $uri = "https://login.microsoftonline.com/$($configFileObject.app_properties.tenant_id)/oauth2/v2.0/token"
            $body =  @{
                grant_type    = "client_credentials"
                scope         = "https://graph.microsoft.com/.default"
                client_id     = $configFileObject.app_properties.app_id
                client_secret = $configFileObject.app_properties.client_secret
            }
 
            $connection = Invoke-RestMethod -Uri $uri -Method POST -Body $body 
            $token = $connection.access_token
 
            Connect-MgGraph -AccessToken $token
        }
    }

    catch
    {
        Write-Host "Error initializing script"
        Write-PSFMessage -Level Error -Message "Error initializing script" -Tag "Error"
        break
    }

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
            Write-PSFMessage -Level Host -Message "Retrieved user `"$User`" with object ID `"$($userObj.Id)`"" -Target $AppName
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
                Write-PSFMessage -Level Host -Message "Activated directory role `"$RoleName`" with role Id `"$($adminRole.Id)`"" -Target $AppName
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
            Write-PSFMessage -Level Host -Message "Assigned directory role `"$RoleName`" to `"$User`"" -Target $AppName
        }
    
        catch
        {
            if ($_.Exception.Message -eq "One or more added object references already exist for the following modified properties: 'members'.")
            {
                Write-PSFMessage -Level Error -Message "User `"$User`" is already assigned the directory role `"$RoleName`"" -Tag "Error" -Target $AppName
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
                Write-PSFMessage -Level Host -Message "Retrieved user `"$owner`" with object ID `"$ownerObjectId`"" -Target $AppName
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
                Write-PSFMessage -Level Host -Message "Successfully added app registration owner `"$owner`"" -Target $AppName -Tag "Success"
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

            if ($Script:PSBoundParameters["OwnersDirectoryRole"])
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
            Write-PSFMessage -Level Host -Message "Successfully created client secret" -Target $AppName -Tag "Success"        
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error creating client secret" -Target $AppName -Tag "Error" -ErrorRecord $_
        }

        # add to json output        
        if ($outputAppValues)
        {
            $outputAppValues | Add-Member -MemberType NoteProperty -Name secret_id -Value $secret.KeyId
            $outputAppValues | Add-Member -MemberType NoteProperty -Name secret_description -Value $secret.DisplayName
        }

        # store the secret value using One Time Secret API
        New-OneTimeSecret -SecretMessage $secret.SecretText -AppName $AppName
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

            $signInAudience = "AzureADMyOrg"
        }

        process
        {
            try
            {
                $appRegistration = New-MgApplication -DisplayName $AppName -SignInAudience $signInAudience -RequiredResourceAccess $requiredResourceAccess
                $appObjectId = $appRegistration.Id
                Write-PSFMessage -Level Host -Message "Sucessfully created application `"$AppName`" with object ID `"$($appRegistration.Id)`"" -Tag "Success" -Target $AppName
            }

            catch
            {
                Write-PSFMessage -Level Error -Message "Error creating application with display name `"$AppName`"" -Tag "Error" -Target $AppName -ErrorRecord $_ 
            }

            # add application info to json output
            $outputAppValues = [PsCustomObject] @{
                timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss +0")
	            app_id = $appRegistration.AppId
	            object_id = $appRegistration.Id
	            tenant_id = (Get-MgOrganization).Id
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

        try
        {
            # authentication username using encryption key file and secure string
            $configFolderPath = Join-Path -Path $folderPath -ChildPath "config"
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
            Write-PSFMessage -Level Error -Message "Error constructing authentication info for One Time Secret" -Target $AppName -Tag "Error" -ErrorRecord $_
        }

        # convert credentials into base64 and embed in header
        $base64AuthInfo = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($apiUsername):$($apiToken)"))
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
            Write-PSFMessage -Level Host -Message "Successfully created One Time Secret with URL `"$oneTimeSecretUrl`"" -Target $AppName -Tag "Success"

            # add to json output        
            if ($outputAppValues) {$outputAppValues | Add-Member -MemberType NoteProperty -Name secret_value -Value $oneTimeSecretUrl}
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error creating One Time Secret" -Target $AppName -Tag "Error" -ErrorRecord $_
        }
    }
}

process
{
    # create app registration
    $appRegistration, $appObjectId, $outputAppValues = New-AppRegistration -AppName $AppName

    # create enterprise application/service principal
    $enterpriseApplication = New-MgServicePrincipal -AppId $appRegistration.AppId -Tags @("HideApp", "WindowsAzureActiveDirectoryIntegratedApp")   

    # add application owners by object id
    if ($Script:PSBoundParameters["AppRegistrationOwners"])
    {
        Add-ApplicationOwner -AppObjectId $appObjectId -AppName $AppName -OwnerList $AppRegistrationOwners
    }

    # add client secret
    if ($Script:PSBoundParameters["ClientSecret"])
    {
        Add-ClientSecret -AppObjectId $appObjectId -AppName $AppName
    }

    $outputFileObject = New-Object -TypeName PsObject
    $outputFileObject | Add-Member -MemberType NoteProperty -Name $appRegistration.DisplayName -Value $outputAppValues
    $outputFileObject | ConvertTo-Json -Depth 5 | Out-File $outputFilePath -Append
}
