$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Classes = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Classes')) -Filter "*.Class.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
# Load dependencies
foreach ($class in $Classes) {
    Try {
        . $class.FullName
    } Catch {
        Write-Error "Failed to Load $($class.fullname): $_"
    }
}
$PrivateModules = [string[]](Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty FullName)
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
foreach ($import in @($Public + $Private)) {
    Try {
        . $import.fullname
    } Catch {
        Write-Error "Failed to import function $($import.fullname): $_"
    }
    Export-ModuleMember $import.BaseName
}
Export-ModuleMember -Alias @('<Aliases>')