function UnProtect-Data {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'string', SupportsShouldProcess = $true)]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'String')]
        [ValidateNotNullOrEmpty()]
        [string]$MSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecureString')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureMSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Xml')]
        [ValidateNotNullOrEmpty()]
        [Alias('XmlDoc')]
        [xml]$InputXml,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__A llParameterSets')]
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
        $UnProtected = switch ($PsCmdlet.ParameterSetName) {
            'Xml' {
                if ($PSCmdlet.ShouldProcess("Xml", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), [ProtectionScope]$Scope)
                    }
                }
            }
            'string' {
                if ($PSCmdlet.ShouldProcess("String", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($Msg, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($Msg, [ProtectionScope]$Scope)
                    }
                }
            }
            'Bytes' {
                if ($PSCmdlet.ShouldProcess("Bytes", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($Bytes, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($Bytes, [ProtectionScope]$Scope)
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
        return $UnProtected
    }
}