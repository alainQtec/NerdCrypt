<#
.SYNOPSIS
    A CUstom BuildScript For The Module NerdCrypt
.DESCRIPTION
    A longer description of the function, its purpose, common use cases, etc.
.LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
    .\build.ps1 -Task deploy
#>
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
[cmdletbinding(DefaultParameterSetName = 'task')]
param(
    [parameter(ParameterSetName = 'task', Position = 0)]
    [ValidateSet('Init', 'Clean', 'Compile', 'Import', 'Test', 'Deploy')]
    [string[]]$Task = @('Init', 'Clean', 'Compile', 'Import'),

    [parameter(ParameterSetName = 'help')]
    [switch]$Help,

    [switch]$UpdateModules
)

Begin {
    #Requires -RunAsAdministrator
    if ($null -ne ${env:=::}) { Throw 'Please Run this as Administrator' }
    #region    Variables
    Set-Variable -Name BuildId -Option AllScope -Value $([string]::Join('', (0..9 + (97..122 | ForEach-Object { [string][char]$_ }) | Get-Random -Count 19)) + '_')
    #region    ScriptBlocks
    $script:PSake_ScriptBlock = [scriptblock]::Create({
            # PSake makes variables declared here available in other scriptblocks
            Properties {
                # Find the build folder based on build system
                $ProjectRoot = [Environment]::GetEnvironmentVariable($BuildId + 'ProjectPath')
                if (-not $ProjectRoot) {
                    if ($pwd.Path -like "*ci*") {
                        Set-Location ..
                    }
                    $ProjectRoot = $pwd.Path
                }
                $outputDir = [Environment]::GetEnvironmentVariable($BuildId + 'BuildOutput')
                $Timestamp = Get-Date -UFormat "%Y%m%d-%H%M%S"
                $PSVersion = $PSVersionTable.PSVersion.ToString()
                $outputModDir = [IO.path]::Combine([Environment]::GetEnvironmentVariable($BuildId + 'BuildOutput'), [Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))
                $tests = "$projectRoot\Tests"
                $lines = ('-' * 70)
                $Verbose = @{}
                $TestFile = "TestResults_PS$PSVersion`_$TimeStamp.xml"
                $outputModVerDir = [IO.path]::Combine([Environment]::GetEnvironmentVariable($BuildId + 'BuildOutput'), [Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'), [Environment]::GetEnvironmentVariable($BuildId + 'BuildNumber'))
                $PathSeperator = [IO.Path]::PathSeparator
                $DirSeperator = [IO.Path]::DirectorySeparatorChar
                if ([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage') -match "!verbose") {
                    $Verbose = @{Verbose = $True }
                }
                $null = @($tests, $Verbose, $TestFile, $outputDir, $outputModDir, $outputModVerDir, $lines, $DirSeperator, $PathSeperator)
                $null = Invoke-Command -NoNewScope -ScriptBlock {
                    $l = [IO.File]::ReadAllLines([IO.Path]::Combine($([Environment]::GetEnvironmentVariable($BuildId + 'BuildScriptPath')), 'build.ps1'))
                    $t = New-Item $([IO.Path]::GetTempFileName().Replace('.tmp', '.ps1'))
                    Set-Content -Path "$($t.FullName)" -Value $l[$l.IndexOf('    #region    BuildHelper_Functions')..$l.IndexOf('    #endregion BuildHelper_Functions')] -Encoding UTF8 | Out-Null; . $t;
                    Remove-Item -Path $t.FullName
                }
            }
            FormatTaskName ({
                    param($String)
                    "$((Write-Heading "Executing task: {0}" -PassThru) -join "`n")" -f $String
                }
            )

            #Task Default -Depends Init,Test,Build,Deploy
            Task default -depends Test

            Task Init {
                Set-Location $ProjectRoot
                Write-Verbose "Build System Details:"
                Write-Verbose "$((Get-ChildItem Env: | Where-Object {$_.Name -match "^(BUILD_|SYSTEM_|BH)"} | Sort-Object Name | Format-Table Name,Value -AutoSize | Out-String).Trim())"

                Write-Verbose "Module Build version: $([Environment]::GetEnvironmentVariable($BuildId + 'BuildNumber'))"
                'Pester' | ForEach-Object {
                    $m = Get-Module $_ -ListAvailable -ErrorAction SilentlyContinue
                    if ($null -ne $m) {
                        Import-Module $(($m | Sort-Object Version -Descending)[0].Path) -Verbose:$false -ErrorAction Stop -Force
                    } else {
                        Install-Module $_ -Repository PSGallery -Scope CurrentUser -AllowClobber -SkipPublisherCheck -Confirm:$false -ErrorAction Stop -Force
                        Import-Module $_ -Verbose:$false -ErrorAction Stop -Force
                    }
                }
            } -description 'Initialize build environment'

            Task clean -depends Init {
                Remove-Module $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')) -Force -ErrorAction SilentlyContinue
                if (Test-Path -Path $outputDir -PathType Container -ErrorAction SilentlyContinue) {
                    Write-Verbose "Cleaning Previous build Output ..."
                    Get-ChildItem -Path $outputDir -Recurse -Force | Remove-Item -Force -Recurse
                }
                "    Cleaned previous Output directory [$outputDir]"
            } -description 'Cleans module output directory'

            Task Compile -depends Clean {
                Write-Verbose "Create module Output directory"
                New-Item -Path $outputModVerDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose "Add Module files ..."
                try {
                    foreach ($Item in @(
                            "bin"
                            "en-US"
                            "NerdCrypt.Core"
                            "Private"
                            "Public"
                            "LICENSE"
                            "$([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')).psd1"
                        )
                    ) {
                        Copy-Item -Recurse -Path $([IO.Path]::Combine($([Environment]::GetEnvironmentVariable($BuildId + 'BuildScriptPath')), $Item)) -Destination $([Environment]::GetEnvironmentVariable($BuildId + 'PSModulePath'))
                    }
                    if (![IO.File]::Exists($([Environment]::GetEnvironmentVariable($BuildId + 'PSModuleManifest')))) {
                        Throw "Could Not Create Module Manifest!"
                    }
                } catch {
                    throw $_
                }
                # Create Class
                $_NC_File = [IO.Path]::Combine($([Environment]::GetEnvironmentVariable($BuildId + 'PSModulePath')), "NerdCrypt.Core", "NerdCrypt.Core.psm1")
                $NC_Class = Get-Item $_NC_File
                if ($PSVersionTable.PSEdition -ne "Core" -and $PSVersionTable.PSVersion.Major -le 5.1) {
                    if ([IO.File]::Exists($NC_Class)) {
                        (Get-Content $NC_Class.FullName).Replace("    ZLib", '') -match '\S' | Out-File $NC_Class
                    } else {
                        Throw [System.IO.FileNotFoundException]::new('Unable to find the specified file.', "$_NC_File")
                    }
                }
                Write-Verbose -Message 'Creating psm1 ...'
                $psm1 = New-Item -Path ([IO.Path]::Combine($outputModVerDir, "$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))).psm1")) -ItemType File -Force
                $functionsToExport = @()
                $publicFunctionsPath = [IO.Path]::Combine($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectPath')), "Public")
                if (Test-Path $publicFunctionsPath -PathType Container -ErrorAction SilentlyContinue) {
                    Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" -Recurse -File | ForEach-Object {
                        $functionsToExport += $_.BaseName
                    }
                }
                $manifestContent = Get-Content -Path $([Environment]::GetEnvironmentVariable($BuildId + 'PSModuleManifest')) -Raw
                $PsModuleContent = Get-Content -Path ([IO.Path]::Combine($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectPath')), "$([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')).psm1" )) -Raw
                $PsModuleContent = $PsModuleContent.Replace("'<Aliases>'", "'Encrypt','Decrypt'")
                $PsModuleContent | Add-Content -Path $psm1 -Encoding UTF8
                $publicFunctionNames = Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" | Select-Object -ExpandProperty BaseName

                Write-Verbose -Message 'Creating psd1 ...'
                # Using .Replace() is Better than Update-ModuleManifest as this does not destroy the Indentation in the Psd1 file.
                $manifestContent = $manifestContent.Replace(
                    "'<FunctionsToExport>'", $(if ((Test-Path -Path $publicFunctionsPath) -and $publicFunctionNames.count -gt 0) { "'$($publicFunctionNames -join "',`n        '")'" }else { $null })
                ).Replace(
                    "<ModuleVersion>", $([Environment]::GetEnvironmentVariable($BuildId + 'BuildNumber'))
                ).Replace(
                    "<ReleaseNotes>", $([Environment]::GetEnvironmentVariable($BuildId + 'ReleaseNotes'))
                ).Replace(
                    "<Year>", ([Datetime]::Now.Year)
                )
                $manifestContent | Set-Content -Path $([Environment]::GetEnvironmentVariable($BuildId + 'PSModuleManifest'))
                if ((Get-ChildItem $outputModVerDir | Where-Object { $_.Name -eq "$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))).psd1" }).BaseName -cne $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))) {
                    "    Renaming manifest to correct casing"
                    Rename-Item (Join-Path $outputModVerDir "$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))).psd1") -NewName "$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))).psd1" -Force
                }
                "    Created compiled module at [$outputModDir]"
                "    Output version directory contents"
                Get-ChildItem $outputModVerDir | Format-Table -AutoSize
            } -description 'Compiles module from source'

            Task Import -depends Compile {
                '    Testing import of the Compiled module.'
                Test-ModuleManifest -Path $([Environment]::GetEnvironmentVariable($BuildId + 'PSModuleManifest'))
                Import-Module $([Environment]::GetEnvironmentVariable($BuildId + 'PSModuleManifest'))
            } -description 'Imports the newly compiled module'

            Task Test -depends Init {
                '    Importing Pester'
                Import-Module Pester -Verbose:$false -Force -ErrorAction Stop
                Push-Location
                Set-Location -PassThru $outputModDir
                if (-not $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectPath'))) {
                    Set-BuildEnvironment -Path $([Environment]::GetEnvironmentVariable($BuildId + 'BuildScriptPath'))\..
                }

                $origModulePath = $Env:PSModulePath
                if ( $Env:PSModulePath.split($pathSeperator) -notcontains $outputDir ) {
                    $Env:PSModulePath = ($outputDir + $pathSeperator + $origModulePath)
                }

                Remove-Module $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')) -ErrorAction SilentlyContinue -Verbose:$false
                Import-Module $outputModDir -Force -Verbose:$false
                $testResultsXml = Join-Path -Path $outputDir -ChildPath $TestFile
                $pesterParams = @{
                    OutputFormat = 'NUnitXml'
                    OutputFile   = $testResultsXml
                    PassThru     = $true
                    Path         = $tests
                }
                if ($script:ExcludeTag) {
                    $pesterParams['ExcludeTag'] = $script:ExcludeTag
                    "    Invoking Pester and excluding tag(s) [$($script:ExcludeTag -join ', ')] ..."
                } else {
                    '    Invoking Pester ...'
                }
                $testResults = Invoke-Pester @pesterParams
                '    Pester invocation complete!'
                if ($testResults.FailedCount -gt 0) {
                    $testResults | Format-List
                    Write-Error -Message 'One or more Pester tests failed. Build cannot continue!'
                }
                Pop-Location
                $Env:PSModulePath = $origModulePath
            } -description 'Run Pester tests against compiled module'

            Task Deploy -depends Init -description 'Deploy module to PSGallery' -preaction {
                if (($([Environment]::GetEnvironmentVariable($BuildId + 'BuildSystem')) -eq 'VSTS' -and $([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage')) -match '!deploy' -and $([Environment]::GetEnvironmentVariable($BuildId + 'BranchName')) -eq "main") -or $script:ForceDeploy -eq $true) {
                    if ($null -eq (Get-Module PoshTwit -ListAvailable)) {
                        "    Installing PoshTwit module..."
                        Install-Module PoshTwit -Scope CurrentUser
                    }
                    Import-Module PoshTwit -Verbose:$false
                    # Load the module, read the exported functions, update the psd1 FunctionsToExport
                    $commParsed = [Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage') | Select-String -Pattern '\sv\d+\.\d+\.\d+\s'
                    if ($commParsed) {
                        $commitVer = $commParsed.Matches.Value.Trim().Replace('v', '')
                    }
                    $CurrentVersion = (Get-Module $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))).Version
                    if ($moduleInGallery = Find-Module "$([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))*" -Repository PSGallery) {
                        $galVer = $moduleInGallery.Version.ToString()
                        "    Current version on the PSGallery is: $galVer"
                    } else {
                        $galVer = '0.0.1'
                    }
                    $galVerSplit = $galVer.Split('.')
                    $nextGalVer = [System.Version](($galVerSplit[0..($galVerSplit.Count - 2)] -join '.') + '.' + ([int]$galVerSplit[-1] + 1))

                    $versionToDeploy = if ($commitVer -and ([System.Version]$commitVer -lt $nextGalVer)) {
                        Write-Host -ForegroundColor Yellow "Version in commit message is $commitVer, which is less than the next Gallery version and would result in an error. Possible duplicate deployment build, skipping module bump and negating deployment"
                        Set-EnvironmentVariable -name ($BuildId + 'CommitMessage') -Value $([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage')).Replace('!deploy', '')
                        $null
                    } elseif ($commitVer -and ([System.Version]$commitVer -gt $nextGalVer)) {
                        Write-Host -ForegroundColor Green "Module version to deploy: $commitVer [from commit message]"
                        [System.Version]$commitVer
                    } elseif ($CurrentVersion -ge $nextGalVer) {
                        Write-Host -ForegroundColor Green "Module version to deploy: $CurrentVersion [from manifest]"
                        $CurrentVersion
                    } elseif ($([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage')) -match '!hotfix') {
                        Write-Host -ForegroundColor Green "Module version to deploy: $nextGalVer [commit message match '!hotfix']"
                        $nextGalVer
                    } elseif ($([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage')) -match '!minor') {
                        $minorVers = [System.Version]("{0}.{1}.{2}" -f $nextGalVer.Major, ([int]$nextGalVer.Minor + 1), 0)
                        Write-Host -ForegroundColor Green "Module version to deploy: $minorVers [commit message match '!minor']"
                        $minorVers
                    } elseif ($([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage')) -match '!major') {
                        $majorVers = [System.Version]("{0}.{1}.{2}" -f ([int]$nextGalVer.Major + 1), 0, 0)
                        Write-Host -ForegroundColor Green "Module version to deploy: $majorVers [commit message match '!major']"
                        $majorVers
                    } else {
                        Write-Host -ForegroundColor Green "Module version to deploy: $nextGalVer [PSGallery next version]"
                        $nextGalVer
                    }
                    # Bump the module version
                    if ($versionToDeploy) {
                        try {
                            $manifest = Import-PowerShellDataFile -Path $([Environment]::GetEnvironmentVariable($BuildId + 'PSModuleManifest'))
                            if ($([Environment]::GetEnvironmentVariable($BuildId + 'BuildSystem')) -eq 'VSTS' -and -not [String]::IsNullOrEmpty($Env:NugetApiKey)) {
                                $manifestPath = Join-Path $outputModVerDir "$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))).psd1"
                                if (-not $manifest) {
                                    $manifest = Import-PowerShellDataFile -Path $manifestPath
                                }
                                if ($manifest.ModuleVersion.ToString() -eq $versionToDeploy.ToString()) {
                                    "    Manifest is already the expected version. Skipping manifest version update"
                                } else {
                                    "    Updating module version on manifest to [$($versionToDeploy)]"
                                    Update-Metadata -Path $manifestPath -PropertyName ModuleVersion -Value $versionToDeploy -Verbose
                                }
                                try {
                                    "    Publishing version [$($versionToDeploy)] to PSGallery..."
                                    Publish-Module -Path $outputModVerDir -NuGetApiKey $Env:NugetApiKey -Repository PSGallery -Verbose
                                    "    Deployment successful!"
                                } catch {
                                    $err = $_
                                    Write-BuildError $err.Exception.Message
                                    throw $err
                                }
                            } else {
                                "    [SKIPPED] Deployment of version [$($versionToDeploy)] to PSGallery"
                            }
                            $commitId = git rev-parse --verify HEAD
                            if (-not [String]::IsNullOrEmpty($Env:GitHubPAT) -and $IsAC) {
                                $Project_Name = [Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')
                                "    Creating Release ZIP..."
                                $zipPath = [System.IO.Path]::Combine($PSScriptRoot, "$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))).zip")
                                if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
                                Add-Type -Assembly System.IO.Compression.FileSystem
                                [System.IO.Compression.ZipFile]::CreateFromDirectory($outputModDir, $zipPath)
                                "    Publishing Release v$($versionToDeploy) @ commit Id [$($commitId)] to GitHub..."
                                $ReleaseNotes = [Environment]::GetEnvironmentVariable($BuildId + 'ReleaseNotes')
                                $ReleaseNotes += (git log -1 --pretty=%B | Select-Object -Skip 2) -join "`n"
                                $ReleaseNotes += "`n`n***`n`n# Instructions`n`n"
                                $ReleaseNotes += @"
1. [Click here](https://github.com/alainQtec/$Project_Name/releases/download/v$($versionToDeploy.ToString())/$Project_Name.zip) to download the *$Project_Name.zip* file attached to the release.
2. **If on Windows**: Right-click the downloaded zip, select Properties, then unblock the file.
    > _This is to prevent having to unblock each file individually after unzipping._
3. Unzip the archive.
4. (Optional) Place the module folder somewhere in your ``PSModulePath``.
    > _You can view the paths listed by running the environment variable ```$Env:PSModulePath``_
5. Import the module, using the full path to the PSD1 file in place of ``$Project_Name`` if the unzipped module folder is not in your ``PSModulePath``:
    ``````powershell
    # In `$Env:PSModulePath
    Import-Module $Project_Name

    # Otherwise, provide the path to the manifest:
    Import-Module -Path C:\MyPSModules\$Project_Name\$($versionToDeploy.ToString())\$Project_Name.psd1
    ``````
"@
                                Set-EnvironmentVariable -name ('{0}{1}' -f $BuildId, 'ReleaseNotes') -Value $ReleaseNotes
                                $gitHubParams = @{
                                    VersionNumber    = $versionToDeploy.ToString()
                                    CommitId         = $commitId
                                    ReleaseNotes     = [Environment]::GetEnvironmentVariable($BuildId + 'ReleaseNotes')
                                    ArtifactPath     = $zipPath
                                    GitHubUsername   = 'alainQtec'
                                    GitHubRepository = [Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')
                                    GitHubApiKey     = $Env:GitHubPAT
                                    Draft            = $false
                                }
                                Publish-GithubRelease @gitHubParams
                                "    Release creation successful!"
                            } else {
                                "    [SKIPPED] Publishing Release v$($versionToDeploy) @ commit Id [$($commitId)] to GitHub"
                            }
                            if ($([Environment]::GetEnvironmentVariable($BuildId + 'BuildSystem')) -eq 'VSTS' -and -not [String]::IsNullOrEmpty($Env:TwitterAccessSecret) -and -not [String]::IsNullOrEmpty($Env:TwitterAccessToken) -and -not [String]::IsNullOrEmpty($Env:TwitterConsumerKey) -and -not [String]::IsNullOrEmpty($Env:TwitterConsumerSecret)) {
                                "    Publishing tweet about new release..."
                                $text = "#$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))) v$($versionToDeploy) is now available on the #PSGallery! https://www.powershellgallery.com/packages/$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')))/$($versionToDeploy.ToString()) #PowerShell"
                                $manifest.PrivateData.PSData.Tags | ForEach-Object {
                                    $text += " #$($_)"
                                }
                                if ($text.Length -gt 280) {
                                    "    Trimming [$($text.Length - 280)] extra characters from tweet text to get to 280 character limit..."
                                    $text = $text.Substring(0, 280)
                                }
                                "    Tweet text: $text"
                                Publish-Tweet -Tweet $text -ConsumerKey $Env:TwitterConsumerKey -ConsumerSecret $Env:TwitterConsumerSecret -AccessToken $Env:TwitterAccessToken -AccessSecret $Env:TwitterAccessSecret
                                "    Tweet successful!"
                            } else {
                                "    [SKIPPED] Twitter update of new release"
                            }
                        } catch {
                            Write-BuildError $_
                        }
                    } else {
                        Write-Host -ForegroundColor Yellow "No module version matched! Negating deployment to prevent errors"
                        Set-EnvironmentVariable -name ($BuildId + 'CommitMessage') -Value $([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage')).Replace('!deploy', '')
                    }
                } else {
                    Write-Host -ForegroundColor Magenta "Build system is not VSTS!"
                }
            }
        }
    )
    $script:PSake_Build = [ScriptBlock]::Create({
            Write-BuildLog "Resolving dependencies ..."
            $DePendencies = @(
                "Psake"
                "Pester"
                "PSScriptAnalyzer"
                "Microsoft.PowerShell.SecretStore"
                "SecretManagement.Hashicorp.Vault.KV"
                "Microsoft.PowerShell.SecretManagement"
            )
            foreach ($ModuleName in $DePendencies) {
                $ModuleName | Resolve-Module @update -Verbose
            }
            Write-BuildLog "Module Requirements Successfully resolved."
            $null = Set-Content -Path $Psake_BuildFile -Value $PSake_ScriptBlock

            Write-Heading "Invoking psake with task list: [ $($Task -join ', ') ]"
            $psakeParams = @{
                nologo    = $true
                buildFile = $Psake_BuildFile.FullName
                taskList  = $Task
            }
            if ($Task -eq 'TestOnly') {
                Set-Variable -Name ExcludeTag -Scope global -Value @('Module')
            } else {
                Set-Variable -Name ExcludeTag -Scope global -Value $null
            }
            Invoke-psake @psakeParams @verbose
            Remove-Item $Psake_BuildFile -Verbose | Out-Null
        }
    )
    $script:Clean_EnvBuildvariables = [scriptblock]::Create({
            Param (
                [Parameter(Position = 0)]
                [ValidatePattern('\w*')]
                [ValidateNotNullOrEmpty()]
                [string]$build_Id
            )
            if (![string]::IsNullOrWhiteSpace($build_Id)) {
                Write-Verbose "CleanUp ..."
                $OldEnvNames = [Environment]::GetEnvironmentVariables().Keys | Where-Object { $_ -like "$build_Id*" }
                if ($OldEnvNames.Count -gt 0) {
                    foreach ($Name in $OldEnvNames) { [Environment]::SetEnvironmentVariable($Name, $null) }
                }
            } else {
                Write-Warning "Invalid BuildId! Skipping ..."
            }
        }
    )
    #endregion ScriptBlockss
    $Psake_BuildFile = New-Item $([IO.Path]::GetTempFileName().Replace('.tmp', '.ps1'))
    #endregion Variables

    #region    BuildHelper_Functions
    function Set-BuildVariables {
        [cmdletbinding(SupportsShouldProcess = $true)]
        param(
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [Alias('RootPath')]
            [string]$Path = $PWD.Path,

            [Parameter(Position = 1)]
            [ValidatePattern('\w*')]
            [ValidateNotNullOrEmpty()][Alias('BuildId')]
            [String]$VariableNamePrefix = [string]::Join('', (0..9 + (97..122 | ForEach-Object { [string][char]$_ }) | Get-Random -Count 18)) + '_'
        )

        Process {
            $ScriptRoot = $(if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PWD.Path }else { $PSScriptRoot })
            $LastIdFile = [IO.Path]::Combine($HOME, 'Last_Build_Id.txt')
            Set-Variable -Name Last_Build_Id -Value $(if ([IO.File]::Exists($LastIdFile)) { (Get-Content $LastIdFile -Raw).Trim() }else { '' }) -Force -Option AllScope -Scope Global
            $VersionFile = [IO.Path]::Combine($ScriptRoot, 'Version.txt')
            Set-Variable -Name BuildId -Value $VariableNamePrefix -Force -Option AllScope -Scope Global
            [Environment]::SetEnvironmentVariable('BuildId', $BuildId)
            New-Variable -Name IsAC -Value $($IsAC -or (![string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('GITHUB_ACTION_PATH')))) -Scope Global -Force -Option AllScope
            New-Variable -Name IsCI -Value $($IsCI -or (![string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('TF_BUILD')))) -Scope Global -Force -Option AllScope
            if ([IO.File]::Exists($LastIdFile)) { Remove-Item $LastIdFile -Force }
            $BuildId | Out-File $LastIdFile -Force;
            Get-Item $LastIdFile -Force | ForEach-Object { $_.Attributes = $_.Attributes -bor "Hidden" }
            New-Variable -Name BuildScriptPath -Value ([Environment]::GetEnvironmentVariable($VariableNamePrefix + 'BuildScriptPath')) -Scope Local -Force
            if ([IO.File]::Exists($VersionFile)) {
                New-Variable -Name BuildVersion -Value $(Get-Content $VersionFile) -Scope Global -Force -Option AllScope
            } else {
                Write-Warning 'Could not Find Version File'
            }
            if (![string]::IsNullOrEmpty($Last_Build_Id)) {
                if ($PSCmdlet.ShouldProcess("$Env:ComputerName", "Clean Last Builds's Env~ variables")) {
                    Invoke-Command $Clean_EnvBuildvariables -ArgumentList $Last_Build_Id
                }
            }
            if ($PSCmdlet.ShouldProcess("$Env:ComputerName", "Set BuildEnvironmentVariables")) {
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'BuildStart') -Value $(Get-Date -Format o)
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'BuildScriptPath') -Value $(if ([string]::IsNullOrWhiteSpace($BuildScriptPath)) { $ScriptRoot }else { $BuildScriptPath })
                Set-Variable -Name BuildScriptPath -Value ([Environment]::GetEnvironmentVariable($BuildId + 'BuildScriptPath')) -Scope Local -Force
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'BuildSystem') -Value $(if ($IsCI) { "VSTS" }else { [System.Environment]::MachineName })
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'ProjectPath') -Value $(if ($IsCI) { $Env:SYSTEM_DEFAULTWORKINGDIRECTORY }else { $BuildScriptPath })
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'BranchName') -Value $(if ($IsCI) { $Env:BUILD_SOURCEBRANCHNAME }else { $(Push-Location $BuildScriptPath; (git rev-parse --abbrev-ref HEAD).Trim(); Pop-Location) })
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'CommitMessage') -Value $(if ($IsCI) { $Env:BUILD_SOURCEVERSIONMESSAGE }else { $(Push-Location $BuildScriptPath; (git log --format=%B -n 1).Trim(); Pop-Location) })
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'BuildNumber') -Value $(if ($IsCI) { $Env:BUILD_BUILDNUMBER } else { $(if ($buildVersion) { $buildVersion }else { "0.0.0" }) })
                Set-Variable -Name BuildNumber -Value ([Environment]::GetEnvironmentVariable($BuildId + 'BuildNumber')) -Scope Local -Force
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'BuildOutput') -Value $([IO.path]::Combine($BuildScriptPath, "BuildOutput"))
                Set-Variable -Name BuildOutput -Value ([Environment]::GetEnvironmentVariable($BuildId + 'BuildOutput')) -Scope Local -Force
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'ProjectName') -Value $("NerdCrypt")
                Set-Variable -Name ProjectName -Value ([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')) -Scope Local -Force
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'PSModulePath') -Value $([IO.path]::Combine($BuildOutput, $ProjectName, $BuildNumber))
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'PSModuleManifest') -Value $([IO.path]::Combine($BuildOutput, $ProjectName, $BuildNumber, "$ProjectName.psd1"))
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'ModulePath') -Value $(if (![string]::IsNullOrWhiteSpace($Env:PSModuleManifest)) { [IO.Path]::GetDirectoryName($Env:PSModuleManifest) }else { [IO.Path]::GetDirectoryName($BuildOutput) })
                Set-EnvironmentVariable -Name ('{0}{1}' -f $BuildId, 'ReleaseNotes') -Value $("# Changelog`n`n")
            }
        }
    }
    function Get-Elapsed {
        $buildstart = [Environment]::GetEnvironmentVariable($script:BuildId + 'BuildStart')
        $build_date = if ([string]::IsNullOrWhiteSpace($buildstart)) { Get-Date }else { Get-Date $buildstart }
        if ($IsCI) {
            "[ + $(((Get-Date) - $build_date).ToString())]"
        } else {
            "[$((Get-Date).ToString("HH:mm:ss")) + $(((Get-Date) - $build_date).ToString())]"
        }
    }
    function Get-LatestModuleVersion($Name) {
        # access the main module page, and add a random number to trick proxies
        $url = "https://www.powershellgallery.com/packages/$Name/?dummy=$(Get-Random)"
        $request = [System.Net.WebRequest]::Create($url)
        # do not allow to redirect. The result is a "MovedPermanently"
        $request.AllowAutoRedirect = $false
        try {
            # send the request
            $response = $request.GetResponse()
            # get back the URL of the true destination page, and split off the version
            $response.GetResponseHeader("Location").Split("/")[-1] -as [Version]
            # make sure to clean up
            $response.Close()
            $response.Dispose()
        } catch [System.Net.WebException] {
            throw 'Operation is not valid, Please check your Internet.'
        } catch {
            Write-Warning $_.Exception.Message
        }
    }
    function Resolve-Module {
        [Cmdletbinding()]
        param (
            [Parameter(Mandatory, ValueFromPipeline)]
            [Alias('Name')]
            [string[]]$Names,

            [switch]$UpdateModules
        )
        Begin {
            $PSDefaultParameterValues = @{
                '*-Module:Verbose'            = $false
                'Import-Module:ErrorAction'   = 'Stop'
                'Import-Module:Force'         = $true
                'Import-Module:Verbose'       = $false
                'Install-Module:AllowClobber' = $true
                'Install-Module:ErrorAction'  = 'Stop'
                'Install-Module:Force'        = $true
                'Install-Module:Scope'        = 'CurrentUser'
                'Install-Module:Verbose'      = $false
            }
        }
        process {
            foreach ($moduleName in $Names) {
                $versionToImport = [string]::Empty
                Write-Host "##[command] Resolving Module [$moduleName]" -ForegroundColor Magenta
                $Module = Get-Module -Name $moduleName -ListAvailable -Verbose:$false -ErrorAction SilentlyContinue
                if ($null -ne $Module) {
                    # Determine latest version on PSGallery and warn us if we're out of date
                    $latestLocalVersion = ($Module | Measure-Object -Property Version -Maximum).Maximum
                    $versionToImport = $latestLocalVersion
                    try {
                        $latestGalleryVersion = Get-LatestModuleVersion $moduleName # [todo] should be a retriable command.
                        if ($null -eq $latestGalleryVersion) {
                            Write-Warning "Unable to Find Module $moduleName. Check your Internet."
                        }
                        if ($null -eq (Get-Module -Name Psake -ListAvailable -ErrorAction SilentlyContinue)) {
                            Install-Module -Name Psake -Force -Verbose -Scope CurrentUser;
                        }
                        # Are we out of date?
                        if ($latestLocalVersion -lt $latestGalleryVersion) {
                            if ($UpdateModules) {
                                Write-Verbose -Message "$($moduleName) installed version [$($latestLocalVersion.ToString())] is outdated. Installing gallery version [$($latestGalleryVersion.ToString())]"
                                if ($UpdateModules) {
                                    Install-Module -Name $moduleName -RequiredVersion $latestGalleryVersion
                                    $versionToImport = $latestGalleryVersion
                                }
                            } else {
                                Write-Warning "$($moduleName) is out of date. Latest version on PSGallery is [$latestGalleryVersion]. To update, use the -UpdateModules switch."
                            }
                        }
                    } catch {
                        $null
                    }
                } else {
                    Write-Verbose -Message "[$($moduleName)] missing. Installing..."
                    Install-Module -Name $moduleName -Repository PSGallery
                    $versionToImport = (Get-Module -Name $moduleName -ListAvailable | Measure-Object -Property Version -Maximum).Maximum
                }

                Write-Verbose -Message "$($moduleName) installed. Importing..."
                if (![string]::IsNullOrEmpty($versionToImport)) {
                    Import-Module $moduleName -RequiredVersion $versionToImport
                } else {
                    Import-Module $moduleName
                }
            }
        }
    }
    function Write-BuildLog {
        [CmdletBinding()]
        param(
            [parameter(Mandatory, Position = 0, ValueFromRemainingArguments, ValueFromPipeline)]
            [System.Object]$Message,

            [parameter()]
            [Alias('c', 'Command')]
            [Switch]$Cmd,

            [parameter()]
            [Alias('w')]
            [Switch]$Warning,

            [parameter()]
            [Alias('s', 'e')]
            [Switch]$Severe,

            [parameter()]
            [Alias('x', 'nd', 'n')]
            [Switch]$Clean
        )
        Begin {
            if ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters['Debug'] -eq $true) {
                $fg = 'Yellow'
                $lvl = '##[debug]   '
            } elseif ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'] -eq $true) {
                $fg = if ($Host.UI.RawUI.ForegroundColor -eq 'Gray') {
                    'White'
                } else {
                    'Gray'
                }
                $lvl = '##[verbose] '
            } elseif ($Severe) {
                $fg = 'Red'
                $lvl = '##[error]   '
            } elseif ($Warning) {
                $fg = 'Yellow'
                $lvl = '##[warning] '
            } elseif ($Cmd) {
                $fg = 'Magenta'
                $lvl = '##[command] '
            } else {
                $fg = if ($Host.UI.RawUI.ForegroundColor -eq 'Gray') {
                    'White'
                } else {
                    'Gray'
                }
                $lvl = '##[info]    '
            }
        }
        Process {
            $fmtMsg = if ($Clean) {
                $Message -split "[\r\n]" | Where-Object { $_ } | ForEach-Object {
                    $lvl + $_
                }
            } else {
                $date = "$(Get-Elapsed) "
                if ($Cmd) {
                    $i = 0
                    $Message -split "[\r\n]" | Where-Object { $_ } | ForEach-Object {
                        $tag = if ($i -eq 0) {
                            'PS > '
                        } else {
                            '  >> '
                        }
                        $lvl + $date + $tag + $_
                        $i++
                    }
                } else {
                    $Message -split "[\r\n]" | Where-Object { $_ } | ForEach-Object {
                        $lvl + $date + $_
                    }
                }
            }
            Write-Host -ForegroundColor $fg $($fmtMsg -join "`n")
        }
    }
    function Write-BuildWarning {
        param(
            [parameter(Mandatory, Position = 0, ValueFromRemainingArguments, ValueFromPipeline)]
            [System.String]
            $Message
        )
        Process {
            Write-Warning $Message
            if ($IsCI) {
                Write-Host "##vso[task.logissue type=warning; ]$Message"
            } else {
            }
        }
    }
    function Write-BuildError {
        param(
            [parameter(Mandatory, Position = 0, ValueFromRemainingArguments, ValueFromPipeline)]
            [System.String]
            $Message
        )
        Process {
            if ($IsCI) {
                Write-Host "##vso[task.logissue type=error; ]$Message"
            }
            Write-Error $Message
        }
    }
    function Set-EnvironmentVariable {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [parameter(Position = 0)]
            [String]$Name,

            [parameter(Position = 1, ValueFromRemainingArguments)]
            [String[]]$Value
        )
        $FullVal = $Value -join " "
        Write-BuildLog "Setting env variable '$Name' to '$fullVal'"
        Set-Item -Path Env:\$Name -Value $FullVal -Force
        if ($IsCI) {
            "##vso[Task.Setvariable variable=$Name]$FullVal" | Write-Host
        }
    }
    function Invoke-CommandWithLog {
        [CmdletBinding()]
        Param (
            [parameter(Mandatory, Position = 0)]
            [ScriptBlock]
            $ScriptBlock
        )
        Write-BuildLog -Command ($ScriptBlock.ToString() -join "`n")
        $ScriptBlock.Invoke()
    }
    function Write-Heading {
        param(
            [parameter(Position = 0)]
            [String]$Title,

            [parameter(Position = 1)]
            [Switch]$Passthru
        )
        $msgList = @(
            ''
            "##[section] $(Get-Elapsed) $Title"
        ) -join "`n"
        if ($Passthru) {
            $msgList
        } else {
            $msgList | Write-Host -ForegroundColor Cyan
        }
    }
    function Write-EnvironmentSummary {
        param(
            [parameter(Position = 0, ValueFromRemainingArguments)]
            [String]$State
        )
        Write-Heading -Title "Build Environment Summary:"
        @(
            $(if ($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))) { "Project : $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))" })
            $(if ($State) { "State   : $State" })
            "Engine  : PowerShell $($PSVersionTable.PSVersion.ToString())"
            "Host OS : $(if($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows){"Windows"}elseif($IsLinux){"Linux"}elseif($IsMacOS){"macOS"}else{"[UNKNOWN]"})"
            "PWD     : $PWD"
            ''
        ) | Write-Host
    }
    function FindHashKeyValue {
        [CmdletBinding()]
        param(
            $SearchPath,
            $Ast,
            [string[]]
            $CurrentPath = @()
        )
        # Write-Debug "FindHashKeyValue: $SearchPath -eq $($CurrentPath -Join '.')"
        if ($SearchPath -eq ($CurrentPath -Join '.') -or $SearchPath -eq $CurrentPath[-1]) {
            return $Ast |
                Add-Member NoteProperty HashKeyPath ($CurrentPath -join '.') -PassThru -Force |
                Add-Member NoteProperty HashKeyName ($CurrentPath[-1]) -PassThru -Force
        }

        if ($Ast.PipelineElements.Expression -is [System.Management.Automation.Language.HashtableAst] ) {
            $KeyValue = $Ast.PipelineElements.Expression
            foreach ($KV in $KeyValue.KeyValuePairs) {
                $result = FindHashKeyValue $SearchPath -Ast $KV.Item2 -CurrentPath ($CurrentPath + $KV.Item1.Value)
                if ($null -ne $result) {
                    $result
                }
            }
        }
    }
    function Get-ModuleManifest {
        <#
        .SYNOPSIS
            Reads a specific value from a PowerShell metdata file (e.g. a module manifest)
        .DESCRIPTION
            By default Get-ModuleManifest gets the ModuleVersion, but it can read any key in the metadata file
        .EXAMPLE
            Get-ModuleManifest .\Configuration.psd1
            Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
        .Example
            Get-ModuleManifest .\Configuration.psd1 ReleaseNotes
            Returns the release notes!
        #>
        [CmdletBinding()]
        param(
            # The path to the module manifest file
            [Parameter(ValueFromPipelineByPropertyName = "True", Position = 0)]
            [Alias("PSPath")]
            [ValidateScript({ if ([IO.Path]::GetExtension($_) -ne ".psd1") { throw "Path must point to a .psd1 file" } $true })]
            [string]$Path,

            # The property (or dotted property path) to be read from the manifest.
            # Get-ModuleManifest searches the Manifest root properties, and also the nested hashtable properties.
            [Parameter(ParameterSetName = "Overwrite", Position = 1)]
            [string]$PropertyName = 'ModuleVersion',

            [switch]$Passthru
        )
        Begin {
            $eap = $ErrorActionPreference
            $ErrorActionPreference = "Stop"
            $Tokens = $Null; $ParseErrors = $Null
        }
        Process {
            if (!(Test-Path $Path)) {
                WriteError -ExceptionType System.Management.Automation.ItemNotFoundException `
                    -Message "Can't find file $Path" `
                    -ErrorId "PathNotFound,Metadata\Import-Metadata" `
                    -Category "ObjectNotFound"
                return
            }
            $Path = Convert-Path $Path
            $AST = [System.Management.Automation.Language.Parser]::ParseFile( $Path, [ref]$Tokens, [ref]$ParseErrors )

            $KeyValue = $Ast.EndBlock.Statements
            $KeyValue = @(FindHashKeyValue $PropertyName $KeyValue)
            if ($KeyValue.Count -eq 0) {
                WriteError -ExceptionType System.Management.Automation.ItemNotFoundException `
                    -Message "Can't find '$PropertyName' in $Path" `
                    -ErrorId "PropertyNotFound,Metadata\Get-Metadata" `
                    -Category "ObjectNotFound"
                return
            }
            if ($KeyValue.Count -gt 1) {
                $SingleKey = @($KeyValue | Where-Object { $_.HashKeyPath -eq $PropertyName })

                if ($SingleKey.Count -gt 1) {
                    WriteError -ExceptionType System.Reflection.AmbiguousMatchException `
                        -Message ("Found more than one '$PropertyName' in $Path. Please specify a dotted path instead. Matching paths include: '{0}'" -f ($KeyValue.HashKeyPath -join "', '")) `
                        -ErrorId "AmbiguousMatch,Metadata\Get-Metadata" `
                        -Category "InvalidArgument"
                    return
                } else {
                    $KeyValue = $SingleKey
                }
            }
            $KeyValue = $KeyValue[0]

            if ($Passthru) { $KeyValue } else {
                # # Write-Debug "Start $($KeyValue.Extent.StartLineNumber) : $($KeyValue.Extent.StartColumnNumber) (char $($KeyValue.Extent.StartOffset))"
                # # Write-Debug "End   $($KeyValue.Extent.EndLineNumber) : $($KeyValue.Extent.EndColumnNumber) (char $($KeyValue.Extent.EndOffset))"
                $KeyValue.SafeGetValue()
            }
        }
        End {
            $ErrorActionPreference = $eap
        }
    }
    function Publish-GitHubRelease {
        <#
        .SYNOPSIS
            Publishes a release to GitHub Releases. Borrowed from https://www.herebedragons.io/powershell-create-github-release-with-artifact
        #>
        [CmdletBinding()]
        Param (
            [parameter(Mandatory = $true)]
            [String]$VersionNumber,

            [parameter(Mandatory = $false)]
            [String]$CommitId = 'main',

            [parameter(Mandatory = $true)]
            [String]$ReleaseNotes,

            [parameter(Mandatory = $true)]
            [ValidateScript( { Test-Path $_ })]
            [String]$ArtifactPath,

            [parameter(Mandatory = $true)]
            [String]$GitHubUsername,

            [parameter(Mandatory = $true)]
            [String]$GitHubRepository,

            [parameter(Mandatory = $true)]
            [String]$GitHubApiKey,

            [parameter(Mandatory = $false)]
            [Switch]$PreRelease,

            [parameter(Mandatory = $false)]
            [Switch]$Draft
        )
        $releaseData = @{
            tag_name         = [string]::Format("v{0}", $VersionNumber)
            target_commitish = $CommitId
            name             = [string]::Format("$($([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName'))) v{0}", $VersionNumber)
            body             = $ReleaseNotes
            draft            = [bool]$Draft
            prerelease       = [bool]$PreRelease
        }

        $auth = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($gitHubApiKey + ":x-oauth-basic"))

        $releaseParams = @{
            Uri         = "https://api.github.com/repos/$GitHubUsername/$GitHubRepository/releases"
            Method      = 'POST'
            Headers     = @{
                Authorization = $auth
            }
            ContentType = 'application/json'
            Body        = (ConvertTo-Json $releaseData -Compress)
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $result = Invoke-RestMethod @releaseParams
        $uploadUri = $result | Select-Object -ExpandProperty upload_url
        $uploadUri = $uploadUri -creplace '\{\?name,label\}'
        $artifact = Get-Item $ArtifactPath
        $uploadUri = $uploadUri + "?name=$($artifact.Name)"
        $uploadFile = $artifact.FullName

        $uploadParams = @{
            Uri         = $uploadUri
            Method      = 'POST'
            Headers     = @{
                Authorization = $auth
            }
            ContentType = 'application/zip'
            InFile      = $uploadFile
        }
        $result = Invoke-RestMethod @uploadParams
    }
    #endregion BuildHelper_Functions
}
Process {
    Set-BuildVariables -VariableNamePrefix $BuildId
    Write-EnvironmentSummary "Build started"
    Write-Heading "Setting package feeds"
    $PKGRepoHash = @{
        PackageManagement = '1.3.1'
        PowerShellGet     = '2.1.2'
    }
    foreach ($PkgRepoName in $PKGRepoHash.Keys | Sort-Object) {
        Write-BuildLog "Updating $PkgRepoName"
        if ($null -eq (Get-Module $PkgRepoName -ListAvailable | Where-Object { [System.Version]$_.Version -ge [System.Version]($PKGRepoHash[$PkgRepoName]) })) {
            Write-BuildLog "$PkgRepoName is below the minimum required version! Updating ..."
            Install-Module "$PkgRepoName" -MinimumVersion $PKGRepoHash[$PkgRepoName] -Force -AllowClobber -SkipPublisherCheck -Scope CurrentUser -Verbose:$false -ErrorAction SilentlyContinue
        }
    }

    Invoke-CommandWithLog { Get-PackageProvider -Name Nuget -ForceBootstrap -Verbose:$false }
    if (!(Get-PackageProvider -Name Nuget)) {
        Invoke-CommandWithLog { Install-PackageProvider -Name NuGet -Force | Out-Null }
    }
    $null = Import-PackageProvider -Name NuGet -Force
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Invoke-CommandWithLog { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -Verbose:$false }
    }
    Invoke-CommandWithLog { $PSDefaultParameterValues = @{
            '*-Module:Verbose'            = $false
            'Import-Module:ErrorAction'   = 'Stop'
            'Import-Module:Force'         = $true
            'Import-Module:Verbose'       = $false
            'Install-Module:AllowClobber' = $true
            'Install-Module:ErrorAction'  = 'Stop'
            'Install-Module:Force'        = $true
            'Install-Module:Scope'        = 'CurrentUser'
            'Install-Module:Verbose'      = $false
        }
    }
    $update = @{}
    $verbose = @{}
    if ($PSBoundParameters.ContainsKey('UpdateModules')) {
        $update['UpdateModules'] = $PSBoundParameters['UpdateModules']
    }
    if ($PSBoundParameters.ContainsKey('Verbose')) {
        $verbose['Verbose'] = $PSBoundParameters['Verbose']
    }

    if ($Help) {
        Write-Heading "Getting help"
        Write-BuildLog -c '"psake" | Resolve-Module @update -Verbose'
        'psake' | Resolve-Module @update -Verbose
        Get-PSakeScriptTasks -buildFile $Psake_BuildFile.FullName | Sort-Object -Property Name | Format-Table -Property Name, Description, Alias, DependsOn
    } else {
        Write-Heading "Finalizing build Prerequisites"
        if ($([Environment]::GetEnvironmentVariable($BuildId + 'BuildSystem')) -eq 'VSTS') {
            if ($Task -eq 'Deploy') {
                $MSG = "Task is 'Deploy' and conditions for deployment are:`n" +
                "    + Current build system is VSTS     : $($Env:BUILD_BUILDURI -like 'vstfs:*') [$Env:BUILD_BUILDURI]`n" +
                "    + Current branch is main         : $($Env:BUILD_SOURCEBRANCHNAME -eq 'main') [$Env:BUILD_SOURCEBRANCHNAME]`n" +
                "    + Source is not a pull request     : $($Env:BUILD_SOURCEBRANCH -notlike '*pull*') [$Env:BUILD_SOURCEBRANCH]`n" +
                "    + Commit message matches '!deploy' : $($Env:BUILD_SOURCEVERSIONMESSAGE -match '!deploy') [$Env:BUILD_SOURCEVERSIONMESSAGE]`n" +
                "    + Current PS major version is 5    : $($PSVersionTable.PSVersion.Major -eq 5) [$($PSVersionTable.PSVersion.ToString())]`n" +
                "    + NuGet API key is not null        : $($null -ne $Env:NugetApiKey)`n"
                if (
                    $Env:BUILD_BUILDURI -notlike 'vstfs:*' -or
                    $Env:BUILD_SOURCEBRANCH -like '*pull*' -or
                    $Env:BUILD_SOURCEVERSIONMESSAGE -notmatch '!deploy' -or
                    $Env:BUILD_SOURCEBRANCHNAME -ne 'main' -or
                    $PSVersionTable.PSVersion.Major -ne 5 -or
                    $null -eq $Env:NugetApiKey
                ) {
                    $MSG = $MSG.Replace('and conditions for deployment are:', 'but conditions are not correct for deployment.')
                    $MSG | Write-Host -ForegroundColor Yellow
                    if (($([Environment]::GetEnvironmentVariable($BuildId + 'CommitMessage')) -match '!deploy' -and $([Environment]::GetEnvironmentVariable($BuildId + 'BranchName')) -eq "main") -or $script:ForceDeploy -eq $true) {
                        Write-Warning "Force Deploy"
                    } else {
                        "Skipping psake for this job!" | Write-Host -ForegroundColor Yellow
                        exit 0
                    }
                } else {
                    $MSG | Write-Host -ForegroundColor Green
                }
            }
            Invoke-Command -ScriptBlock $PSake_Build
            if ($Task -contains 'Import' -and $psake.build_success) {
                $Project_Name = [Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')
                $Project_Path = [Environment]::GetEnvironmentVariable($BuildId + 'BuildOutput')
                Write-Heading "Importing $Project_Name to local scope"
                $Module_Path = [IO.Path]::Combine($Project_Path, $Project_Name)
                Invoke-CommandWithLog { Import-Module $Module_Path -Verbose:$false }
            }
        } else {
            Invoke-Command -ScriptBlock $PSake_Build
            Write-BuildLog "Create a 'local' repository"
            $RepoPath = New-Item -Path "$([IO.Path]::Combine($Env:USERPROFILE, 'LocalPSRepo'))" -ItemType Directory -Force
            Register-PSRepository LocalPSRepo -SourceLocation "$RepoPath" -PublishLocation "$RepoPath" -InstallationPolicy Trusted -ErrorAction SilentlyContinue -Verbose:$false
            Write-Verbose "Verify that the new repository was created successfully"
            $PsRepo = Get-PSRepository LocalPSRepo -Verbose:$false
            if (-not (Test-Path -Path ($PsRepo.SourceLocation) -PathType Container -ErrorAction SilentlyContinue -Verbose:$false)) {
                New-Item -Path $PsRepo.SourceLocation -ItemType Directory -Force | Out-Null
            }
            $ModuleName = [Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')
            $ModulePath = [IO.Path]::Combine($([Environment]::GetEnvironmentVariable($BuildId + 'BuildOutput')), $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')), $([Environment]::GetEnvironmentVariable($BuildId + 'BuildNumber')))
            # Publish To LocalRepo
            $ModulePackage = [IO.Path]::Combine($RepoPath.FullName, "${ModuleName}.$([Environment]::GetEnvironmentVariable($BuildId + 'BuildNumber')).nupkg")
            if ([IO.File]::Exists($ModulePackage)) {
                Remove-Item -Path $ModulePackage -ErrorAction 'SilentlyContinue'
            }
            Write-Heading "Publish to Local PsRepository"
            $RequiredModules = Get-ModuleManifest ([IO.Path]::Combine($ModulePath, "$([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')).psd1")) RequiredModules -Verbose:$false
            foreach ($Module in $RequiredModules) {
                $md = Get-Module $Module -Verbose:$false; $mdPath = $md.Path | Split-Path
                Write-Verbose "Publish RequiredModule $Module ..."
                Publish-Module -Path $mdPath -Repository LocalPSRepo -Verbose:$false
            }
            Invoke-CommandWithLog { Publish-Module -Path $ModulePath -Repository LocalPSRepo } -Verbose:$false
            # Install Module
            Install-Module $ModuleName -Repository LocalPSRepo
            # Import Module
            if ($Task -contains 'Import' -and $psake.build_success) {
                Write-Heading "Importing $([Environment]::GetEnvironmentVariable($BuildId + 'ProjectName')) to local scope"
                Invoke-CommandWithLog { Import-Module $ModuleName }
            }
            # CleanUp
            Write-Verbose "CleanUp: Uninstall the test module, and delete the LocalPSRepo"
            Unregister-PSRepository 'LocalPSRepo'
            Remove-Item "$([IO.Path]::Combine($Env:USERPROFILE, 'LocalPSRepo'))" -Force -Recurse -ErrorAction 'SilentlyContinue'
            Uninstall-Module $ModuleName
        }
        Write-EnvironmentSummary "Build finished"
    }
}
End {
    if (!$IsAC) {
        Invoke-Command $Clean_EnvBuildvariables -ArgumentList $BuildId
    }
    exit ( [int](!$psake.build_success) )
}