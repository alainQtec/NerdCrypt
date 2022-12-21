function New-NCobject {
    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'default')]
    [outputType([NerdCrypt])]
    [Alias('NewNC')]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Object]$Object,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$User,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [securestring]$PrivateKey,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

        [switch]$Passthru
    )

    process {
        $Object = $null
        if ($PSCmdlet.ShouldProcess("Performing Operation Create NCobject", '', '')) {
            $Object = if (
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Object') -and
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('User') -and
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('PrivateKey') -and
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('PublicKey')
            ) {
                [NerdCrypt]::New($Object, $User, $PrivateKey, $PublicKey)
            } elseif (
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Object') -and
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('User') -and
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('PublicKey')
            ) {
                [NerdCrypt]::New($Object, $User, $PublicKey)
            } elseif (
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Object') -and
                $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('PublicKey')
            ) {
                [NerdCrypt]::New($Object, $PublicKey)
            } elseif ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Object')) {
                [NerdCrypt]::New($Object)
            } else {
                [NerdCrypt]::New()
            }
        }
    }
    End {
        return $Object
    }
}