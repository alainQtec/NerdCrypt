<#
.SYNOPSIS
    Run Tests
.DESCRIPTION
	The Test-Module.ps1 script lets you test the functions and other features of
	your module in your PowerShell Studio module project. It's part of the project,
	but it is not included in the module.
.NOTES
	===========================================================================
	Created on:   	9/6/2022 5:36 PM
	Created by:   	alain
	Organization: 	alainQtec
	Filename:     	Test-Module.ps1
	===========================================================================
#>

#Explicitly import the module for testing
$manifestPath = (Join-Path $module "NerdCrypt.psd1")
Import-Module $manifestPath
Write-Verbose "[+] Running tests ..."
Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
Invoke-Pester -Path "$PSScriptRoot\tests" -OutputFormat NUnitXml -OutputFile Tests\results.xml