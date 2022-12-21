function ConvertFrom-Metadata {
    <#
    .Synopsis
        Deserializes objects from PowerShell Data language (PSD1)
    .Description
        Converts psd1 notation to actual objects, and supports passing in additional converters
        in addition to using the built-in registered converters (see Add-MetadataConverter).

        NOTE: Any Converters that are passed in are temporarily added as though passed Add-MetadataConverter
    .Example
        ConvertFrom-Metadata 'PSObject @{ Name = PSObject @{ First = "Joel"; Last = "Bennett" }; Id = 1; }'

        Id Name
        -- ----
        1 @{Last=Bennett; First=Joel}

        Convert the example string into a real PSObject using the built-in object serializer.
    .Example
        $data = ConvertFrom-Metadata .\Configuration.psd1 -Ordered

        Convert a module manifest into a hashtable of properties for introspection, preserving the order in the file
    .Example
        ConvertFrom-Metadata ("DateTimeOffset 635968680686066846 -05:00:00") -Converters @{
        "DateTimeOffset" = {
            param($ticks,$offset)
            [DateTimeOffset]::new( $ticks, $offset )
        }
        }

        Shows how to temporarily add a "ValidCommand" called "DateTimeOffset" to support extra data types in the metadata.

        See also the third example on ConvertTo-Metadata and Add-MetadataConverter
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName = "True", Position = 0)]
        [Alias("PSPath")]
        $InputObject,

        [Hashtable]$Converters = @{},

        $ScriptRoot = '$PSScriptRoot',

        # If set (and PowerShell version 4 or later) preserve the file order of configuration
        # This results in the output being an OrderedDictionary instead of Hashtable
        [Switch]$Ordered
    )
    begin {
        $Script:OriginalMetadataSerializers = $Script:MetadataSerializers.Clone()
        $Script:OriginalMetadataDeserializers = $Script:MetadataDeserializers.Clone()
        Add-MetadataConverter $Converters
        [string[]]$ValidCommands = @(
            "ConvertFrom-StringData", "Join-Path", "Split-Path", "ConvertTo-SecureString"
        ) + @($MetadataDeserializers.Keys)
        [string[]]$ValidVariables = "PSScriptRoot", "ScriptRoot", "PoshCodeModuleRoot", "PSCulture", "PSUICulture", "True", "False", "Null"
    }
    end {
        $Script:MetadataSerializers = $Script:OriginalMetadataSerializers.Clone()
        $Script:MetadataDeserializers = $Script:OriginalMetadataDeserializers.Clone()
    }
    process {
        $ErrorActionPreference = "Stop"
        $Tokens = $Null; $ParseErrors = $Null

        if (Test-PSVersion -lt "3.0") {
            # Write-Debug "$InputObject"
            if (!(Test-Path $InputObject -ErrorAction SilentlyContinue)) {
                $Path = [IO.path]::ChangeExtension([IO.Path]::GetTempFileName(), $ModuleManifestExtension)
                Set-Content -Encoding UTF8 -Path $Path $InputObject
                $InputObject = $Path
            } elseif (!"$InputObject".EndsWith($ModuleManifestExtension)) {
                $Path = [IO.path]::ChangeExtension([IO.Path]::GetTempFileName(), $ModuleManifestExtension)
                Copy-Item "$InputObject" "$Path"
                $InputObject = $Path
            }
            $Result = $null
            Import-LocalizedData -BindingVariable Result -BaseDirectory (Split-Path $InputObject) -FileName (Split-Path $InputObject -Leaf) -SupportedCommand $ValidCommands
            return $Result
        }

        if (Test-Path $InputObject -ErrorAction SilentlyContinue) {
            $AST = [System.Management.Automation.Language.Parser]::ParseFile( (Convert-Path $InputObject), [ref]$Tokens, [ref]$ParseErrors)
            $ScriptRoot = Split-Path $InputObject
        } else {
            $ScriptRoot = $PoshCodeModuleRoot
            $OFS = "`n"
            # Remove SIGnature blocks, PowerShell doesn't parse them in .psd1 and chokes on them here.
            $InputObject = "$InputObject" -replace "# SIG # Begin signature block(?s:.*)"
            $AST = [System.Management.Automation.Language.Parser]::ParseInput($InputObject, [ref]$Tokens, [ref]$ParseErrors)
        }

        if ($null -ne $ParseErrors -and $ParseErrors.Count -gt 0) {
            ThrowError -Exception (New-Object System.Management.Automation.ParseException (, [System.Management.Automation.Language.ParseError[]]$ParseErrors)) -ErrorId "Metadata Error" -Category "ParserError" -TargetObject $InputObject
        }

        # Get the variables or subexpressions from strings which have them ("StringExpandable" vs "String") ...
        $Tokens += $Tokens | Where-Object { "StringExpandable" -eq $_.Kind } | Select-Object -ExpandProperty NestedTokens

        # Work around PowerShell rules about magic variables
        # Replace "PSScriptRoot" magic variables with the non-reserved "ScriptRoot"
        if ($scriptroots = @($Tokens | Where-Object { ("Variable" -eq $_.Kind) -and ($_.Name -eq "PSScriptRoot") } | ForEach-Object { $_.Extent } )) {
            $ScriptContent = $Ast.ToString()
            for ($r = $scriptroots.count - 1; $r -ge 0; $r--) {
                $ScriptContent = $ScriptContent.Remove($scriptroots[$r].StartOffset, ($scriptroots[$r].EndOffset - $scriptroots[$r].StartOffset)).Insert($scriptroots[$r].StartOffset, '$ScriptRoot')
            }
            $AST = [System.Management.Automation.Language.Parser]::ParseInput($ScriptContent, [ref]$Tokens, [ref]$ParseErrors)
        }

        $Script = $AST.GetScriptBlock()
        try {
            $Script.CheckRestrictedLanguage( $ValidCommands, $ValidVariables, $true )
        } catch {
            ThrowError -Exception $_.Exception.InnerException -ErrorId "Metadata Error" -Category "InvalidData" -TargetObject $Script
        }

        if ($Ordered -and (Test-PSVersion -gt "3.0")) {
            # Make all the hashtables ordered, so that the output objects make more sense to humans...
            if ($Tokens | Where-Object { "AtCurly" -eq $_.Kind }) {
                $ScriptContent = $AST.ToString()
                $Hashtables = $AST.FindAll({ $args[0] -is [System.Management.Automation.Language.HashtableAst] -and ("ordered" -ne $args[0].Parent.Type.TypeName) }, $Recurse)
                $Hashtables = $Hashtables | ForEach-Object {
                    New-Object PSObject -Property @{Type = "([ordered]"; Position = $_.Extent.StartOffset }
                    New-Object PSObject -Property @{Type = ")"; Position = $_.Extent.EndOffset }
                } | Sort-Object Position -Descending
                foreach ($point in $Hashtables) {
                    $ScriptContent = $ScriptContent.Insert($point.Position, $point.Type)
                }
                $AST = [System.Management.Automation.Language.Parser]::ParseInput($ScriptContent, [ref]$Tokens, [ref]$ParseErrors)
                $Script = $AST.GetScriptBlock()
            }
        }

        $Mode, $ExecutionContext.SessionState.LanguageMode = $ExecutionContext.SessionState.LanguageMode, "RestrictedLanguage"

        try {
            $Script.InvokeReturnAsIs(@())
        } finally {
            $ExecutionContext.SessionState.LanguageMode = $Mode
        }
    }
}
