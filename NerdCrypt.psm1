# Self-Elevating To prevent UnauthorisedAccess Exceptions, we make sure the commands run as admin:
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $Process = [System.Diagnostics.ProcessStartInfo]::new("PowerShell")
    if ($null -ne $args) {
        $Process.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath' `"$args`";`""
    } else {
        $Process.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    }
    $Process.Verb = "runas";
    [System.Diagnostics.Process]::Start($Process);
    exit
}
#Dot source all functions in all ps1 files located in the Public folder
Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -Exclude *.tests.ps1, *profile.ps1 |
ForEach-Object {
	. $_.FullName
}