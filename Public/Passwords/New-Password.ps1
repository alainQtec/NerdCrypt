function New-Password {
    <#
    .SYNOPSIS
        Creates a password string
    .DESCRIPTION
        Creates a password containing minimum of 8 characters, 1 lowercase, 1 uppercase, 1 numeric, and 1 special character.
        Created password can not exceed 999 characters
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Private/NerdCrypt.Core/NerdCrypt.Core.psm1
    .EXAMPLE
        New-Password
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No system state is being changed')]
    [CmdletBinding(DefaultParameterSetName = 'ByLength')]
    param (
        # Exact password Length
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'ByLength')]
        [Alias('l')][ValidateRange(9, 999)]
        [int]$Length,
        # Minimum Length
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'ByMinMax')]
        [Alias('min')]
        [int]$minLength,
        # Minimum Length
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'ByMinMax')]
        [Alias('max')]
        [int]$maxLength,
        # Retries / Iterations to randomise results
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'ByLength')]
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'ByMinMax')]
        [Alias('r')][ValidateRange(1, 100)][ValidateNotNullOrEmpty()]
        [int]$Iterations
    )

    begin {
        $Pass = [string]::Empty
        $params = $PSCmdlet.MyInvocation.BoundParameters
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByLength') {
            if ($params.ContainsKey('Length') -and $params.ContainsKey('Iterations')) {
                $Pass = [xgen]::Password($Iterations, $Length);
            } elseif ($params.ContainsKey('Length') -and !$params.ContainsKey('Iterations')) {
                $Pass = [xgen]::Password(1, $Length);
            } else {
                $Pass = [xgen]::Password();
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'ByMinMax') {
            if ($params.ContainsKey('Iterations')) {
                $pass = [xgen]::Password($Iterations, $minLength, $maxLength);
            } else {
                $Pass = [xgen]::Password(1, $minLength, $maxLength);
            }
        } else {
            throw [System.Management.Automation.ParameterBindingException]::new("Could Not Resolve ParameterSetname.");
        }
    }
    end {
        return $Pass
    }
}