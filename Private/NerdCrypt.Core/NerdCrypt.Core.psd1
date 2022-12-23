@{
    ModuleVersion     = '1.1.0'
    RootModule        = 'NerdCrypt.Core.psm1'
    FunctionsToExport = @(
        'Encrypt-Object'
        'Decrypt-Object'
        'Protect-Data'
        'UnProtect-Data'
        'New-Password'
        'New-Converter'
        'Save-Credential'
        'Remove-Credential'
        'Get-SavedCredential'
        'Get-SavedCredentials'
        'Show-SavedCredentials'
    )
}