Rename-Item "$PSScriptRoot\Module" -NewName "Nerdcrypt"
Publish-Module -Path "$PSScriptRoot\Module" -NuGetApiKey $Env:NUGETAPIKEY