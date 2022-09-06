function Protect-Data {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'String', SupportsShouldProcess = $true)]
    [OutputType([Object[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'String')]
        [ValidateNotNullOrEmpty()]
        [string]$MSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecureString')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureMSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Xml')]
        [ValidateNotNullOrEmpty()]
        [Alias('XmlDoc')]
        [xml]$InputXml,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__AllParameterSets')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [ValidateNotNullOrEmpty()]
        [Alias('ProtectionScope')]
        [string]$Scope = 'CurrentUser',

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Entropy
    )

    begin {
        #Load The Assemblies
        if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
        [bool]$UseCustomEntropy = $null -ne $Entropy -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Entropy')
    }

    process {
        $ProtectedD = switch ($PsCmdlet.ParameterSetName) {
            'Xml' {
                if ($PSCmdlet.ShouldProcess("Xml", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), [ProtectionScope]$Scope)
                    }
                }
            }
            'string' {
                if ($PSCmdlet.ShouldProcess("String", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($Msg, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($Msg, [ProtectionScope]$Scope)
                    }
                }
            }
            'Bytes' {
                if ($PSCmdlet.ShouldProcess("Bytes", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($Bytes, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($Bytes, [ProtectionScope]$Scope)
                    }
                }
            }
            'SecureString' { throw 'Yeet!' }
            Default {
                throw 'Error!'
            }
        }
    }

    end {
        return $ProtectedD
    }
}