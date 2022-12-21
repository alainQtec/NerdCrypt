﻿function New-K3Y {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'Params')]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'FromK3Y')]
        [ValidateNotNullOrEmpty()][K3Y]$K3YoBJ,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'FromK3Y')]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Params')]
        [ValidateNotNullOrEmpty()][string]$UserName = $Env:USERNAME,

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'FromK3Y')]
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'Params')]
        [Alias('Password', 'Securestring')]
        [ValidateNotNullOrEmpty()][securestring]$PrivateKey,

        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'FromK3Y')]
        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'Params')]
        [ValidateNotNullOrEmpty()][datetime]$Expirity = ([Datetime]::Now + [TimeSpan]::new(30, 0, 0, 0)), # One month

        [Parameter(Mandatory = $false, ParameterSetName = 'Params')]
        [switch]$Protect = $false
    )

    process {
        $k = $null
        if ($PSCmdlet.ParameterSetName -eq 'Params') {
            $k = [K3Y]::new($UserName, $PrivateKey, $Expirity); if ($Protect) { $k.User.Protect() };
            $k = [string][xconvert]::Tostring($k);
        } elseif ($PSCmdlet.ParameterSetName -eq 'FromK3Y') {
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('UserName')) {
                $K3YoBJ.User.UserName = $UserName;
            }
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('PrivateKey')) {
                [void]$K3YoBJ.ResolvePassword($PrivateKey);
            }
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Expirity')) {
                $K3YoBJ.Expirity = [Expirity]::new($Expirity);
            }
            $k = [xconvert]::Tostring($K3YoBJ);
        } else {
            throw [System.Management.Automation.ParameterBindingException]::new("Could Not Resolve ParameterSetname.");
        }
    }

    end {
        return $k
    }
}