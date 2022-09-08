﻿# Self-Elevating To prevent UnauthorisedAccess Exceptions, we make sure the commands run as admin:
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
$script:ErrorActionPreference = 'Stop'
$script:VerbosePreference = 'SilentlyContinue'

Write-Verbose "[+] Cleanup files from last BUILD ..."
$module = "$PSScriptRoot\module"
Remove-Item $module -Recurse -Force -ErrorAction SilentlyContinue; $null = New-Item $module -ItemType Directory

Write-Verbose "[+] Resolve dependencies ..."
$DePendencies = @(
    "Pester"
    "PSScriptAnalyzer"
    "Microsoft.PowerShell.SecretStore"
    "SecretManagement.Hashicorp.Vault.KV"
    "Microsoft.PowerShell.SecretManagement"
)
foreach ($ModName in $DePendencies) {
    $installed = Import-Module $ModName -PassThru -ErrorAction SilentlyContinue
    if (-not $installed) { Install-Module $ModName -Force -Scope CurrentUser }
}

Write-Verbose "[+] Create Necessay Module files.."
$moduleItems = @(
    "en-US"
    "Private"
    "Public"
    "LICENSE"
)
foreach ($Item in $moduleItems) {
    Copy-Item -Recurse -Path $Item -Destination $module
}

$funcStrings = $null
$buildVersion = Get-Content $PSScriptRoot\version.txt
$manifestPath = "$PSScriptRoot\NerdCrypt.psd1"
$publicFuncFolderPath = "$PSScriptRoot\Public"
$publicFunctions = Get-ChildItem -Path $publicFuncFolderPath -Filter "*.ps1"
$publicFunctionNames = $publicFunctions | Select-Object -ExpandProperty BaseName

if (!(Get-PackageProvider | Where-Object { $_.Name -eq 'NuGet' })) {
    Install-PackageProvider -Name NuGet -Force | Out-Null
}
Import-PackageProvider -Name NuGet -Force | Out-Null

if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
}

$manifestContent = (Get-Content -Path $manifestPath -Raw) -replace '<ModuleVersion>', $buildVersion
$funcStrings = if ((Test-Path -Path $publicFuncFolderPath) -and $publicFunctionNames.count -gt 0) { "'$($publicFunctionNames -join "',`n        '")'" }
$scripts2process = "'$PSScriptRoot\Private\NerdCrypt.Class.ps1'"
$module_Manifest = Join-Path $module "NerdCrypt.psd1"
$manifestContent = $manifestContent -replace "'<FunctionsToExport>'", $funcStrings
$manifestContent = $manifestContent -replace "'<ScriptsToProcess>'", $scripts2process
$manifestContent | Set-Content -Path $module_Manifest

#Dot source all functions in all ps1 files located in the Public folder
$publicFunctions | ForEach-Object { ". $($_.FullName)" } | Add-Content -Path (Join-Path $module "NerdCrypt.psm1")
# Update-ModuleManifest -Path $module_Manifest @ManifestInfo
& "$PSScriptRoot\Test-Module.ps1"