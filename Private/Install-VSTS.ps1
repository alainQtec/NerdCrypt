# https://docs.microsoft.com/en-us/cli/vsts/install?view=vsts-cli-latest
# https://aka.ms/vsts-cli-windows-installer
function Install-VSTS {
    <#
    .SYNOPSIS
        Visual Studio Team Services and Team Foundation Server.
    .DESCRIPTION
        Visual Studio Application Lifecycle Management.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        Test-MyTestFunction -Verbose
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [CmdletBinding()]
    param (
    )

    begin {
    }

    process {
        $url = "https://aka.ms/vsts-cli-windows-installer"

        # Download the installer
        Invoke-WebRequest -Uri $url -OutFile "vsts-cli-installer.msi"

        # Install the VSTS CLI
        Start-Process "msiexec.exe" -ArgumentList "/i vsts-cli-installer.msi /qn" -Wait

        # Clean up the installer file
        Remove-Item "vsts-cli-installer.msi"

    }

    end {
    }
}