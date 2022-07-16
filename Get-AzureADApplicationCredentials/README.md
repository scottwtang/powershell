## Description

These scripts are designed to get information for all **Azure AD** **App Registrations** and **Enterprise Applications** with expiring certificates and client secrets, to assist with application management.

There is one script for the legacy **AzureAD** module, and one script for the **Microsoft.Graph** module. The results are nearly identical other than the **Microsoft.Graph** output including the `DisplayName` property for the `KeyCredentials` and `PasswordCredentials` objects.

Results are exported as a CSV file to the location determined in the script parameters.
