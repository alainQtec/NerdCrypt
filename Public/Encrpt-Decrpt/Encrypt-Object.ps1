function Encrypt-Object {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [OutputType([byte[]])]
    param (
        # The Object you want to encrypt
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllParameterSets')]
        [Alias('InputObj')]
        $Object,

        # Use a strong password. It will be used Lock Your local Key (ConvertTo-SecureString -String "Message" -SecureKey [System.Security.SecureString]) before storing in vault.
        # Add this if you want 3rd layer of security. Useful when someone(Ex: Hacker) has somehow gained admin priviledges of your PC;
        # With a locked local Password vault it will require much more than just guessing The password, or any BruteForce tool.
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithSecureKey')]
        [Alias('Password', 'Securestring')]
        [SecureString]$PrivateKey = [K3Y]::GetPassword(),

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
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

        # FilePath to store your keys. Saves keys as base64 in an enrypted file. Ex: some_random_Name.key (Not recomended)
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('ExportFile')]
        [string]$KeyOutFile,

        # How long you want the encryption to last. Default to one month (!Caution Your data will be LOST Forever if you do not decrypt before the expirity date!)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithVault')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithPlainKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('KeyExpirity')]
        [datetime]$Expirity = ([Datetime]::Now + [TimeSpan]::new(30, 0, 0, 0)),

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithSecureKey')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithPlainKey')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithVault')]
        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [int]$Iterations = 2
    )

    DynamicParam {
        $DynamicParams = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        [bool]$IsPossiblefileType = $false
        [bool]$IsArrayObject = $false
        [int]$P = 6 #(Position)
        try {
            if ($Object.count -gt 1) {
                $InputType = @()
                $IsArrayObject = $true
                foreach ($Obj in $Object) {
                    $InputType += $Obj.GetType()
                }
                $InputType = $InputType | Sort-Object -Unique
            } else {
                $InputType = $Object.GetType()
            }
        } catch { $InputType = [string]::Empty }
        $IsPossiblefileTypes = @('string', 'string[]', 'System.IO.FileInfo', 'System.IO.FileInfo[]', 'System.Object', 'System.Object[]')
        if ($IsArrayObject) {
            foreach ($type in $InputType) {
                $IsPossiblefileType = [bool]($type -in $IsPossiblefileTypes) -or $IsPossiblefileType
            }
        } else {
            $IsPossiblefileType = [bool]($InputType -in $IsPossiblefileTypes)
        }
        #region OutFile
        if ($IsPossiblefileType) {
            $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
                Position                        = $P
                ParameterSetName                = '__AllParameterSets'
                Mandatory                       = $False
                ValueFromPipeline               = $false
                ValueFromPipelineByPropertyName = $false
                ValueFromRemainingArguments     = $false
                HelpMessage                     = 'Use to specify Output File, if inputObject is a file.'
                DontShow                        = $False
            }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
            $attributeCollection.Add($attributes);
            $attributeCollection.Add([System.Management.Automation.ValidateNotNullOrEmptyAttribute]::new())
            $attributeCollection.Add([System.Management.Automation.AliasAttribute]::new([System.String[]]('OutPutFile', 'DestinationFile')))
            $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("OutFile", [Object], $attributeCollection)
            $DynamicParams.Add("OutFile", $RuntimeParam)
            $P++
        }
        #endregion OutFile

        #region IgnoredArguments
        $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
        $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
            Position                        = $P
            ParameterSetName                = '__AllParameterSets'
            Mandatory                       = $False
            ValueFromPipeline               = $true
            ValueFromPipelineByPropertyName = $true
            ValueFromRemainingArguments     = $true
            HelpMessage                     = 'Allows splatting with arguments that do not apply. Do not use directly.'
            DontShow                        = $False
        }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
        $attributeCollection.Add($attributes)
        $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("IgnoredArguments", [Object[]], $attributeCollection)
        $DynamicParams.Add("IgnoredArguments", $RuntimeParam)
        #endregion IgnoredArguments
        return $DynamicParams
    }

    begin {
        $eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
        $PsCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue' }
        $PsW = [securestring]::new(); $nc = $null;
        $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
        $ExportsPNK = $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('KeyOutFile') -and ![string]::IsNullOrEmpty($KeyOutFile)
        if ($PsCmdlet.ParameterSetName -ne 'WithKey' -and !$ExportsPNK) {
            throw 'Plese specify PublicKey "ExportFile/Outfile" Parameter.'
        }
        # Write-Invocation $MyInvocation
    }

    process {
        Write-Verbose "[+] $fxn $($PsCmdlet.ParameterSetName) ..."
        Set-Variable -Name PsW -Scope Local -Visibility Private -Option Private -Value $(switch ($PsCmdlet.ParameterSetName) {
                'WithKey' {  }
                'WithVault' {  }
                'WithSecureKey' { $PrivateKey }
                Default {
                    throw 'Error!'
                }
            }
        );
        Set-Variable -Name nc -Scope Local -Visibility Private -Option Private -Value $([nerdcrypt]::new($Object));
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Expirity')) { $nc.key.Expirity = [Expirity]::new($Expirity) }
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('PublicKey')) {
            $nc.SetPNKey($PublicKey);
        } else {
            Write-Verbose "[+] Create PublicKey (K3Y) ...";
            $PNK = New-K3Y -UserName $nc.key.User.UserName -Password $PsW -Expirity $nc.key.Expirity.date -AsString -Protect
            $nc.SetPNKey($PNK);
        }
        $bytes = $nc.Object.Bytes
        [void]$nc.Encrypt($PsW, $Iterations)
        if ($ExportsPNK) {
            Write-Verbose "[i] Export PublicKey (PNK) to $KeyOutFile ..."
            $nc.key.Export($KeyOutFile, $true);
        }
        $bytes = $(if ($bytes.Equals($nc.Object.Bytes)) { $null }else { $nc.Object.Bytes })
    }

    end {
        $ErrorActionPreference = $eap
        return $bytes
    }
}