```PowerShell
$dllPath = if ($PSVersionTable.PSVersion.Major -ge 6) {
        [System.IO.Path]::Combine('bin', 'netstandard')
    } else {
        [System.IO.Path]::Combine('bin', 'netfx')
    }
```
