function Decrypt-Object {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [SecureString]$PrivateKey = [K3Y]::GetPassword(),

        [Parameter(Mandatory = $true, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

        # Source or the Encryption Key. Full/Path of the keyfile you already have. It will be used to lock your keys. (ConvertTo-SecureString -String "Message" -Key [Byte[]])
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$Key,

        # Path OF the KeyFile (Containing You saved key base64String Key)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKeyFile')]
        [ValidateNotNullOrEmpty()]
        [string]$KeyFile,

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [int]$Iterations = 2
    )

    begin {
        $eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
        $fxn = ('[' + $MyInvocation.MyCommand.Name + ']');
        # Write-Invocation $MyInvocation
    }

    process {
        Write-Verbose "[+] $fxn $($PsCmdlet.ParameterSetName) ..."
        $PsW = switch ($PsCmdlet.ParameterSetName) {
            'WithKey' {  }
            'WithVault' {  }
            'WithSecureKey' { $PrivateKey }
            Default {
                throw 'Error!'
            }
        }
        $nc = [nerdcrypt]::new($InputBytes, $PublicKey);
        $bytes = $nc.Object.Bytes
        [void]$nc.Decrypt($PsW, $Iterations)
        if ($PsCmdlet.ParameterSetName -ne 'WithKey' -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('KeyOutFile')) {
            if (![string]::IsNullOrEmpty($KeyOutFile)) {
                Write-Verbose "[i] Export PublicKey (PNK) to $KeyOutFile ..."
                $nc.key.Export($KeyOutFile, $true)
            }
        }
        $bytes = $(if ($bytes.Equals($nc.Object.Bytes)) { $null }else { $nc.Object.Bytes })
    }

    end {
        $ErrorActionPreference = $eap
        return $bytes
    }
}