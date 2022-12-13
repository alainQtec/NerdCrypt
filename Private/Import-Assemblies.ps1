function Import-Assemblies {
    Param()
    Begin {
        $dllPath = if ($PSVersionTable.PSVersion.Major -ge 6) {
            [System.IO.Path]::Combine($PSScriptRoot, 'bin', 'netstandard')
        } else {
            [System.IO.Path]::Combine($PSScriptRoot, 'bin', 'netfx')
        }
        Write-Verbose "Import-Assemblies from $dllPath"
    }
    Process {
        $dlls = Get-ChildItem $dllPath -Filter "*.dll" -ErrorAction SilentlyContinue
        $bDll = $dlls | Where-Object { $_.BaseName -eq "BouncyCastle.Crypto" }
        if ($null -ne $bDll) {
            Set-Variable bouncyCastleDll -Value $bDll.Fullname
        }
        foreach ($dll in $dlls) {
            if ($dll.BaseName -eq "alainQtec.NerdCrypt.dll") {
                try {
                    Add-Type -Path $dll -ReferencedAssemblies $bouncyCastleDll -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    $Global:Error.Remove($Global:Error[0])
                }
            } else {
                try {
                    Add-Type -Path $dll -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    $Global:Error.Remove($Global:Error[0])
                }
            }
        }
    }
}
