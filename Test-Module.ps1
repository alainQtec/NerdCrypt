<#
.SYNOPSIS
    Run Tests
.DESCRIPTION
	The Test-Module.ps1 script lets you test the functions and other features of
	your module. It's part of the project, but it is not included in the module.
.NOTES
	===========================================================================
	Created on:   	9/6/2022 5:36 PM
	Created by:   	alain
	Organization: 	alainQtec
	Filename:     	Test-Module.ps1
	===========================================================================
#>
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Module')][string]$ModulePath,
    # Path Containing Tests
    [Parameter(Mandatory = $true, Position = 1)]
    [Alias('Tests')][string]$TestsPath
)
$manifestPath = Join-Path $ModulePath "NerdCrypt.psd1"
if ([IO.File]::Exists($manifestPath)) {
    Import-Module $manifestPath
} else {
    throw 'Module manifest file Was not Found!'
}
Write-Verbose "[+] Running tests ..."
Test-ModuleManifest -Path $manifestPath -ErrorAction Stop -Verbose
Invoke-Pester -Path $TestsPath -OutputFormat NUnitXml -OutputFile "$TestsPath\results.xml"