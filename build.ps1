# Self-Elevating To prevent UnauthorisedAccess Exceptions, we make sure the commands run as admin:
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $Process = [System.Diagnostics.ProcessStartInfo]::new("PowerShell")
    if ($null -ne $args) {
        $Process.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath' `"$args`";`""
    } else {
        $Process.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    }
    $Process.Verb = "runas";
    [System.Diagnostics.Process]::Start($Process);
    exit
}
$Version = (Get-Content $PSScriptRoot\version.txt)

# Cleanup last BUILD
$module = "$PSScriptRoot\module"
Remove-Item $module -Recurse -Force -ErrorAction SilentlyContinue; $null = New-Item $module -ItemType Directory

# Fix DePendencies
$DePendencies = @(
    "Pester"
    "PSScriptAnalyzer"
    "SecretManagement.Hashicorp.Vault.KV"
)
foreach ($ModName in $DePendencies) {
    $installed = Import-Module $ModName -PassThru -ErrorAction SilentlyContinue
    if (-not $installed) { Install-Module $ModName -Force -Scope CurrentUser }
}

# Copy Necessay Module files:
$moduleItems = @(
    "en-US"
    "Private"
    "Public"
    "LICENSE"
    "NerdCrypt.psm1"
)
foreach ($Item in $moduleItems) {
    Copy-Item -Recurse -Path $Item -Destination $module
}
#Dot source all functions in all ps1 files located in the Public folder
'Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -Exclude *.tests.ps1, *profile.ps1 | ForEach-Object { . $_.FullName }' | Add-Content -Path (Join-Path $module "NerdCrypt.psm1")

$ManifestInfo = @{
    RootModule             = 'NerdCrypt.psm1'
    ModuleVersion          = $Version
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
    ScriptsToProcess       = @("Private\NerdCrypt.Class.ps1")
    TypesToProcess         = @()
    FormatsToProcess       = @()
    NestedModules          = @()
    FunctionsToExport      = @(
        'Encrypt-Object',
        'Decrypt-Object',
        'New-PNKey',
        'Protect-Data',
        'UnProtect-Data'
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
            ReleaseNotes = "$ReleaseNotes"
        }
    }
}
Update-ModuleManifest -Path (Join-Path $module "NerdCrypt.psd1") @ManifestInfo
Test-Module.ps1