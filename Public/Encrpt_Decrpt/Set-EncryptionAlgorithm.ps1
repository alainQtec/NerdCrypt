function Set-EncryptionAlgorithm {
    <#
    .SYNOPSIS
        Used to set the encryption algorithm that will be used by other functions in the NerdCrypt module to encrypt and decrypt data.
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Public/Encrpt_Decrpt/Set-EncryptionAlgorithm.ps1
    .EXAMPLE
        Set-EncryptionAlgorithm -Algorithm "AES"
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = '')]
    [CmdletBinding(DefaultParameterSetName = 'default')]
    param (
        # The name of the encryption algorithm
        [Parameter(Mandatory = $true, ParameterSetName = 'default')]
        [string]$Name,

        # The name of the encryption algorithm
        [Parameter(Mandatory = $true, ParameterSetName = 'enum')]
        [Algorithm]$Algorithm
    )

    begin {
        $algorthm = [Algorithm]::AES
    }

    process {
    }

    end {
        # Store the algorithm name in a global variable for later use
        Set-Variable -Name EncryptionAlgorithm -Scope global -Value $algorthm
    }
}