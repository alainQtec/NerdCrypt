@{
    RootModule             = 'NerdCrypt.psm1'
    ModuleVersion          = '<ModuleVersion>'
    GUID                   = '4d357a12-48a7-4d1d-8d2c-86321faf95d0'
    Author                 = 'Alain Herve'
    CompanyName            = 'alainQtec'
    Copyright              = '(c) 2022. All rights reserved.'
    Description            = 'AIO PowerShell module to do all things encryption-decryption.'
    PowerShellVersion      = '3.0'
    PowerShellHostName     = ''
    PowerShellHostVersion  = ''
    DotNetFrameworkVersion = '2.0'
    CLRVersion             = '2.0.50727'
    ProcessorArchitecture  = 'None'
    RequiredModules        = @("SecretManagement.Hashicorp.Vault.KV")
    RequiredAssemblies     = @()
    ScriptsToProcess       = @(
        '<ScriptsToProcess>'
    )
    TypesToProcess         = @()
    FormatsToProcess       = @()
    NestedModules          = @()
    FunctionsToExport      = @(
        '<FunctionsToExport>'
    ) #For performance, list functions explicitly
    CmdletsToExport        = '*'
    VariablesToExport      = '*'
    AliasesToExport        = '*' #For performance, list alias explicitly
    #DSCResourcesToExport = ''
    # List of all modules packaged with this module
    ModuleList             = @()
    # List of all files packaged with this module
    FileList               = @()
    # Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData            = @{
        #Support for PowerShellGet galleries.
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('Cryptography', 'Encrypt', 'Decrypt', 'AES-256')
            LicenseUri   = 'https://github.com/alainQtec/NerdCrypt/blob/main/LICENSE' # https://mit-license.org
            ProjectUri   = 'https://github.com/alainQtec/NerdCrypt'
            IconUri      = 'https://user-images.githubusercontent.com/79479952/188859195-36b440a9-c3f8-4294-b897-a3898eeb62a3.png'
            ReleaseNotes = "<ReleaseNotes>"
        }
    }
}