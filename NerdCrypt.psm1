$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue

# Load dependencies
$PrivateModules = [string[]](Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty FullName)

# Import Private modules
if ($PrivateModules.Count -gt 0) {
    foreach ($Module in $PrivateModules) {
        Try {
            Import-Module $Module -ErrorAction Stop
        } Catch {
            Write-Error "Failed to import module $Module : $_"
        }
    }
}
# Dot source the files
foreach ($Import in @($Public + $Private)) {
    Try {
        . $Import.fullname
    } Catch {
        Write-Warning "Failed to import function $($Import.fullname): $_"
    }
    Export-ModuleMember $import.BaseName
}
Export-ModuleMember -Alias @('<Aliases>')