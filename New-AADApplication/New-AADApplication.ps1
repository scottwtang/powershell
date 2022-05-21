[CmdletBinding()]
param (
    [parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $AppName,
    
    [parameter(Mandatory = $false)]
    [bool] $Visible = $false,
    
    [parameter(Mandatory = $false)]
    [string[]] $NativeUris,
    
    [parameter(Mandatory = $false)]
    [string[]] $SpaUris,
    
    [parameter(Mandatory = $false)]
    [string[]] $WebUris,
    
    [parameter(Mandatory = $false)]
    [bool] $AccessToken,
    
    [parameter(Mandatory = $false)]
    [bool] $IdToken,
    
    [parameter(Mandatory = $false)]
    [bool] $ClientSecret,
    
    [parameter(Mandatory = $false)]
    $ApiPermissions,
    
    [parameter(Mandatory = $false)]
    [bool] $ApiPermissionsGrantConsent = $true,
        
    [parameter(Mandatory = $false)]
    [object[]] $AppRoles,

    [parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $AppRegistrationOwners,
    
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
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]] $OwnerList
    )

    $OwnerList = $OwnerList.Split(";")
    foreach ($owner in $OwnerList)
    {

        # Validate the given user exists
        try
        {
            $ownerObjectId = (Get-MgUser -UserId $owner -ErrorAction Stop).Id
            Write-PSFMessage -Level Verbose -Message "Retrieved user `"$owner`" with object ID `"$ownerObjectId`"" -Target $AppObjectId
        }
        catch
        {
            Write-PSFMessage -Level Error -Message "Error retrieving object `"$owner`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
        }
            
        # Assign the owner to the application
        try
        {
            $body = @{
                "@odata.id"= "https://graph.microsoft.com/v1.0/directoryObjects/{$ownerObjectId}"
            }

            New-MgApplicationOwnerByRef -ApplicationId $AppObjectId -BodyParameter $body -ErrorAction Stop
            Write-PSFMessage -Level Verbose -Message "Successfully added app registration owner `"$owner`"" -Target $AppObjectId -Tag "Success"
        }

        catch
        {
            if ($_.Exception.Message -eq "One or more added object references already exist for the following modified properties: 'owners'.")
            {
                Write-PSFMessage -Level Error -Message "User `"$owner`" already assigned as app registration owner" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }

            else
            {
                Write-PSFMessage -Level Error -Message "Error adding owner `"$owner`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }
        }
    }

    # Get the full list of owners and add to json output    
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
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [int] $SecretLifetimeMonths = 24
    )
       
    try
    {

        # Set the client secret properties such as description and lifetime
        $params = @{
            DisplayName   = "Uploaded on $(Get-Date -Format `"yyyy-MM-dd HH:mm:ss`")"
            StartDateTime = Get-Date
            EndDateTime   = (Get-Date).AddMonths($SecretLifetimeMonths)
        }
        
        # Create client secret
        $secret = Add-MgApplicationPassword -Application $AppObjectId -PasswordCredential $params -ErrorAction Stop
        Write-PSFMessage -Level Verbose -Message "Successfully created client secret" -Target $AppObjectId -Tag "Success"
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error creating client secret" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
    }

    # Store the secret value using One Time Secret API
    $oneTimeSecret = New-OneTimeSecret -SecretMessage $secret.SecretText

    # add to json output        
    if ($outputAppValues)
    {
        $secret = [PSCustomObject] @{
            secret_id          = $secret.KeyId
            secret_description = $secret.DisplayName
            secret_value       = "https://onetimesecret.com/secret/$($oneTimeSecret.secret_key)"
        }

        $outputAppValues | Add-Member -MemberType NoteProperty -Name client_secret -Value $secret
    }
}

function Add-NativeUri
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]] $NativeUris
    )    

    $NativeUris = $NativeUris.Split(";")

    foreach ($uri in $NativeUris)
    {
        $params = @{
            PublicClient = @{
                RedirectUris = @("$uri")
            }
        }

        $existingUris = (Get-MgApplication -ApplicationId $AppObjectId).PublicClient.RedirectUris
        $params.PublicClient.RedirectUris += $existingUris

        try
        {
            if ( ($uri.StartsWith("https")) -or ($uri.StartsWith("http://localhost")) -or ($uri.StartsWith("http://127.0.0.1")) )
            {
                Update-MgApplication -ApplicationId $AppObjectId @params
                Write-PSFMessage -Level Verbose -Message "Successfully added native URI  `"$($uri)`"" -Target $AppObjectIds
            }

            else
            {
                throw "Invalid URI"
            }
        }

        catch
        {        
            if ($_.Exception.Message -eq "Invalid URI")
            {
                Write-PSFMessage -Level Error -Message "Error adding native URI `"$($uri)`" | URI must start with `"https`" or `"http://localhost`" or `"http://127.0.0.1`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }

            else
            {
                Write-PSFMessage -Level Error -Message "Error adding native URI `"$($uri)`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }
        }
    }
}

function Add-SpaUri
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]] $SpaUris
    )    

    $SpaUris = $SpaUris.Split(";")

    foreach ($uri in $SpaUris)
    {
        $params = @{
            Spa = @{
                RedirectUris = @("$uri")
            }
        }

        $existingUris = (Get-MgApplication -ApplicationId $AppObjectId).Spa.RedirectUris
        $params.Spa.RedirectUris += $existingUris

        try
        {
            if ( ($uri.StartsWith("https")) -or ($uri.StartsWith("http://localhost")) -or ($uri.StartsWith("http://127.0.0.1")) )
            {
                Update-MgApplication -ApplicationId $AppObjectId @params
                Write-PSFMessage -Level Verbose -Message "Successfully added SPA URI  `"$($uri)`"" -Target $AppObjectId
            }

            else
            {
                throw "Invalid URI"
            }
        }

        catch
        {        
            if ($_.Exception.Message -eq "Invalid URI")
            {
                Write-PSFMessage -Level Error -Message "Error adding SPA URI `"$($uri)`" | URI must start with `"https`" or `"http://localhost`" or `"http://127.0.0.1`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }

            else
            {
                Write-PSFMessage -Level Error -Message "Error adding SPA URI `"$($uri)`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }
        }
    }
}

function Add-WebUri
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]] $WebUris
    )    

    $WebUris = $WebUris.Split(";")

    foreach ($uri in $WebUris)
    {
        $params = @{
            Web = @{
                RedirectUris = @("$uri")
            }
        }

        $existingUris = (Get-MgApplication -ApplicationId $AppObjectId).Web.RedirectUris
        $params.Web.RedirectUris += $existingUris

        try
        {
            if ( ($uri.StartsWith("https")) -or ($uri.StartsWith("http://localhost")) -or ($uri.StartsWith("http://127.0.0.1")) )
            {
                Update-MgApplication -ApplicationId $AppObjectId @params
                Write-PSFMessage -Level Verbose -Message "Successfully added web URI  `"$($uri)`"" -Target $AppObjectId
            }

            else
            {
                throw "Invalid URI"
            }
        }

        catch
        {        
            if ($_.Exception.Message -eq "Invalid URI")
            {
                Write-PSFMessage -Level Error -Message "Error adding web URI `"$($uri)`" | URI must start with `"https`" or `"http://localhost`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }

            else
            {
                Write-PSFMessage -Level Error -Message "Error adding web URI `"$($uri)`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }
        }
    }
}

function Configure-PSF
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
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
        [ValidateNotNullOrEmpty()]
        [string] $AppName
    )

    # Set the default properties of the new app registration
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
            DisplayName            = $AppName
            RequiredResourceAccess = $requiredResourceAccess
            SignInAudience         = "AzureADMyOrg"
        }
    }

    process
    {

        # Create new app registration
        try
        {
            $appRegistration = New-MgApplication @params
            $appObjectId = $appRegistration.Id
            Write-PSFMessage -Level Verbose -Message "Sucessfully created application `"$AppName`" with object ID `"$($appRegistration.Id)`"" -Tag "Success" -Target $appObjectId
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error creating application with display name `"$AppName`"" -Tag "Error" -Target $appObjectId -ErrorRecord $_ 
        }

        # Add app properties to output object
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

function New-EnterpriseApplication
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [boolean] $Visible
    )

    # Set the default properties of the new enterprise application
    begin
    {
        $params = @{
            AppId = $AppId
            Tags  = [System.Collections.ArrayList]@(
                        "WindowsAzureActiveDirectoryIntegratedApp"
                    )
        }
        
        if ($Visible -eq $false)
        {
            $params.Tags.Add("HideApp") | Out-Null
        }
    }

    process
    {

        # Create new enterprise application
        try
        {            
            $enterpriseApplication = New-MgServicePrincipal @params
          #  Write-PSFMessage -Level Verbose -Message "Sucessfully created enterprise application `"$AppName`" with object ID `"$($appRegistration.Id)`"" -Tag "Success" -Target $appObjectId
        }

        catch
        {
         #   Write-PSFMessage -Level Error -Message "Error creating application with display name `"$AppName`"" -Tag "Error" -Target $appObjectId -ErrorRecord $_ 
        }
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
        [string] $SecretMessage
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
        Write-PSFMessage -Level Verbose -Message "Successfully created One Time Secret with URL `"$oneTimeSecretUrl`"" -Tag "Success"

        return $oneTimeSecret
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error creating One Time Secret" -Tag "Error" -ErrorRecord $_
    }
}

function Update-AccessTokenIssuance
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [bool] $Enabled
    )

    $params = @{
        ImplicitGrantSettings = @{
            EnableAccessTokenIssuance = $Enabled
        }
    }

    try
    {
        Update-MgApplication -ApplicationId $AppObjectId -Web $params -ErrorAction Stop
        Write-PSFMessage -Level Verbose -Message "Setting access token issuance to: $Enabled" -Target $AppObjectId -Tag "Success"
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error setting access token issuance" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
    }

    # add to json output        
    if ($outputAppValues)
    {
        $outputAppValues | Add-Member -MemberType NoteProperty -Name access_token -Value $Enabled
    }
}

function Update-AppRoles
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $AppRoles
    )

    foreach ($role in $AppRoles)
    {

        # Add default properties to each app role
        $role.Add("Id", (New-Guid).Guid)
        $role.Add("IsEnabled", $true)

        $newRoles = @($role)
    
        try
        {
        
            # Get the existing app roles and combine with new role
            $existingAppRoles = (Get-MgApplication -ApplicationId $AppObjectId).AppRoles
            $newRoles += ($existingAppRoles)
        
            # Update the application with new app roles
            Update-MgApplication -ApplicationId $AppObjectId -AppRoles $newRoles -ErrorAction Stop
            Write-PSFMessage -Level Verbose -Message "Successfully added new app role `"$($role.DisplayName)`"" -Target $AppObjectId
        }

        catch
        {
            if ($_.Exception.Message -eq "Request contains a property with duplicate values.")
            {                
                $duplicateRole = ((Get-MgApplication -ApplicationId $AppObjectId).AppRoles | Where-Object {$_.Value -eq $role.Value}).DisplayName
                Write-PSFMessage -Level Error -Message "Error adding new app role `"$($role.DisplayName)`" | App role value `"$($role.Value)`" already used in existing role `"$($duplicateRole)`"" -Target $AppObjectId -Tag "Error"
            }

            else
            {
                Write-PSFMessage -Level Error -Message "Error adding app role `"$($role.DisplayName)`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
            }
        }
    }

    # Add to json output    
    if ($outputAppValues)
    {
        $appRoles = (Get-MgApplication -ApplicationId $AppObjectId).AppRoles
        $outputAppValues | Add-Member -MemberType NoteProperty -Name app_roles -Value $appRoles
    }
}

function Update-IdTokenIssuance
{
    [cmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [bool] $Enabled
    )

    $params = @{
        ImplicitGrantSettings = @{
            EnableIdTokenIssuance = $Enabled
        }
    }

    try
    {
        Update-MgApplication -ApplicationId $AppObjectId -Web $params -ErrorAction Stop
        Write-PSFMessage -Level Verbose -Message "Setting ID token issuance to: $Enabled" -Target $AppObjectId -Tag "Success"
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error setting ID token issuance" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
    }

    # add to json output        
    if ($outputAppValues)
    {
        $outputAppValues | Add-Member -MemberType NoteProperty -Name id_token -Value $Enabled
    }
}

function Update-ResourceAccess
{
    [cmdletBinding()]
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,
        
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [guid] $ResourceAppId = "00000003-0000-0000-c000-000000000000",

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $ResourceAccessList
    )
    
    foreach ($permission in $ResourceAccessList)
    {

        # Find the permission ID by using the permission name and type
        try
        {
            $permissionId = (Find-MgGraphPermission $permission.PermissionName -PermissionType $permission.PermissionType -ExactMatch -ErrorAction Stop).Id
            Write-PSFMessage -Level Verbose -Message "Retrieved permission ID `"$($permissionID)`" for permission `"$($permission.PermissionName)`" of type `"$($permission.PermissionType)`"" -Target $AppObjectId -Tag "Success"
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error retrieving permission ID for permission `"$($permission.PermissionName)`" of type `"$($permission.PermissionType)`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
        }

        # Identify whether the permission type is an app role (application permission) or oauth2PermissionScope (delegated permission)
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
        
        # Reconstruct the permission syntax with the new permission ID and type
        $params = @{
            ResourceAppId = $ResourceAppId
            ResourceAccess = @(
                @{
                    Id   = $permissionId
                    Type = $permissionType
                }
            )
        }       

        # Combine the existing permissions of the target application with the new permissions
        $app = (Get-MgApplication -ApplicationId $AppObjectId)
        $params.ResourceAccess += $app.RequiredResourceAccess.ResourceAccess

        # Update the application permissions using the existing permissions and the new permissions
        try
        {
            Update-MgApplication -ApplicationId $AppObjectId -RequiredResourceAccess $params
            Write-PSFMessage -Level Verbose -Message "Successfully added permission `"$($permission.PermissionName)`"" -Target $AppObjectId -Tag "Success"
        }

        catch
        {
            Write-PSFMessage -Level Error -Message "Error adding permission `"$($permission.PermissionName)`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
        }
    }

    # Get the full list of permissions and add to json output    
    if ($outputAppValues)
    {
        $resourceAccessList = (Get-MgApplication -ApplicationId $AppObjectId).RequiredResourceAccess.ResourceAccess

        $outputAppValues | Add-Member -MemberType NoteProperty -Name resource_access -Value $resourceAccessList
    }
}

function Update-ResourceAccessAdminConsent
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [guid] $AppObjectId,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [guid] $ResourceAppId = "00000003-0000-0000-c000-000000000000",

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object[]] $ResourceAccessList
    )

    # Retrieve the App Registration client Id, and the Enterprise Application object Id
    $appClientId = (Get-MgApplication -Filter "Id eq '$($AppObjectId)'").AppId
    $appServicePrincipalObjectId = (Get-MgServicePrincipal -Filter "AppId eq '$($appClientId)'").Id

    # Retrieve the Enterprise Application object Id of the resource
    $resourceServicePrincipalObjectId = (Get-MgServicePrincipal -Filter "AppId eq '$($ResourceAppId)'").Id    

    # Construct the scope parameter as a space-delimited string of the delegated permissions
    [string]$scope = ($ResourceAccessList | Where-Object {$_.PermissionType -eq "Delegated"}).PermissionName

    $params = @{
	    ClientId    = $appServicePrincipalObjectId
	    ConsentType = "AllPrincipals"
	    ResourceId  = $resourceServicePrincipalObjectId
	    Scope       = $scope
    }
    
    # Grant admin consent for the permissions
    try
    {
        New-MgOauth2PermissionGrant @params | Out-Null
        Write-PSFMessage -Level Verbose -Message "Successfully granted admin consent for permissions `"$($scope)`"" -Target $AppObjectId -Tag "Success"
    }

    catch
    {
        Write-PSFMessage -Level Error -Message "Error granting admin consent for permissions `"$($scope)`"" -Target $AppObjectId -Tag "Error" -ErrorRecord $_
    }

    # Add to output    
    if ($outputAppValues)
    {
        $outputAppValues | Add-Member -MemberType NoteProperty -Name resource_access_admin_consent -Value $scope
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
                Write-PSFMessage -Level Verbose -Message "Set PSFramework logging provider to `"$($logProvider)`""
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
                Write-PSFMessage -Level Verbose -Message "Obtained access token with validity until $token_expires"
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
            [Parameter(Mandatory = $true)]
            [string] $CustomerId,

            [Parameter(Mandatory = $true)]
            [string] $SharedKey,

            [Parameter(Mandatory = $true)]
            [string] $Date,

            [Parameter(Mandatory = $true)]
            [string] $ContentLength,

            [Parameter(Mandatory = $true)]
            [string] $Method,

            [Parameter(Mandatory = $true)]
            [string] $ContentType,

            [Parameter(Mandatory = $true)]
            [string] $Resource
        )

        $xHeaders = "x-ms-date:" + $Date
        $stringToHash = $Method + "`n" + $ContentLength + "`n" + $ContentType + "`n" + $xHeaders + "`n" + $Resource

        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($SharedKey)

        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $encodedHash = [Convert]::ToBase64String($calculatedHash)
        $authorization = 'SharedKey {0}:{1}' -f $CustomerId, $encodedHash

        return $authorization
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
            [Parameter(Mandatory = $true)]
            [string] $CustomerId,

            [Parameter(Mandatory = $true)]
            [string] $SharedKey,

            [Parameter(Mandatory = $true)]
            $Body,

            [Parameter(Mandatory = $true)]
            [string] $LogType
        )

        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $contentLength = $Body.Length

	    $signatureArgs = @{
		    CustomerId	    = $CustomerId
		    SharedKey	    = $SharedKey
		    Date	        = $rfc1123date
		    ContentLength   = $contentLength
		    Method	        = $method
		    ContentType     = $contentType
		    Resource        = $resource
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
            $outputFileObject | ConvertTo-Json -Depth 8 | Out-File $outputFilePath -Append
        }
    }
}

#region process
    # Create app registration
    $appRegistration, $appObjectId, $outputAppValues = New-AppRegistration -AppName $AppName

    # Create enterprise application/service principal
    New-EnterpriseApplication -AppId $appRegistration.AppId -Visible $Visible

    if ($NativeUris)
    {
        New-NativeUris -AppObjectId $appObjectId -NativeUris $NativeUris
    }

    if ($SpaUris)
    {
        New-SpaUris -AppObjectId $appObjectId -SpaUris $SpaUris
    }

    if ($WebUris)
    {
        New-WebUris -AppObjectId $appObjectId -WebUris $WebUris
    }

    if ($AccessToken)
    {
        Update-AccessTokenIssuance -AppObjectId $appObjectId -Enabled $AccessToken
    }

    if ($IdToken)
    {
        Update-IdTokenIssuance -AppObjectId $appObjectId -Enabled $IdToken
    }

    if ($ApiPermissions)
    {
        Update-ResourceAccess -AppObjectId $appObjectId -ResourceAccessList $ApiPermissions
    }
    
    if ($ApiPermissionsGrantConsent)
    {
        Update-ResourceAccessAdminConsent -AppObjectId $appObjectId -ResourceAccessList $ApiPermissions
    }

    if ($AppRoles)
    {
        Update-AppRoles -AppObjectId $appObjectId -AppRoles $AppRoles
    }

    # add application owners by object id
    if ($AppRegistrationOwners)
    {
        Add-ApplicationOwner -AppObjectId $appObjectId -OwnerList $AppRegistrationOwners

        if ($OwnersDirectoryRole)
        {
            $OwnerList = $OwnerList.Split(";")
            foreach ($owner in $OwnerList)
            {
                Add-AADRole -User $owner -RoleName $OwnersDirectoryRole
            }
        }
    }

    # add client secret
    if ($ClientSecret)
    {
        Add-ClientSecret -AppObjectId $appObjectId
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