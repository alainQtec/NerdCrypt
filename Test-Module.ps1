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
Import-Module 'NerdCrypt'
Write-Verbose "[+] Running tests ..."
Invoke-Pester -Path "$PSScriptRoot\tests"