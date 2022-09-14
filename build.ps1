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
    if ($null -ne ${env:=::}) {
        Throw 'Please Run this as Administrator'
    }
    #region    Variables
    $Env:_BuildStart = Get-Date -Format 'o'
    $Env:BuildScriptPath = $PSScriptRoot
    New-Variable -Name buildVersion -Value $(Get-Content ([IO.Path]::Combine($PSScriptRoot, 'version.txt'))) -Scope Global -Force -Option AllScope
    New-Variable -Name IsCI -Value $($IsCI -or (Test-Path Env:\TF_BUILD)) -Scope Global -Force -Option AllScope
    #region    ScriptBlocks
    $script:SetBuildVariables = [scriptblock]::Create({
            $gitVars = if ($IsCI) {
                @{
                    BHBranchName    = $Env:BUILD_SOURCEBRANCHNAME
                    BHProjectName   = $(if ($Env:BHProjectName) { $Env:BHProjectName }else { 'NerdCrypt' })
                    BHBuildNumber   = $Env:BUILD_BUILDNUMBER
                    BHBuildOutput   = "$Env:BuildScriptPath\BuildOutput"
                    BHBuildSystem   = 'VSTS'
                    BHProjectPath   = $Env:SYSTEM_DEFAULTWORKINGDIRECTORY
                    BHCommitMessage = $Env:BUILD_SOURCEVERSIONMESSAGE
                    BHReleaseNotes  = "# Changelog`n`n"
                }
            } else {
                @{
                    BHBranchName    = $(Push-Location $Env:BuildScriptPath; (git rev-parse --abbrev-ref HEAD).Trim(); Pop-Location)
                    BHProjectName   = $(if ($Env:BHProjectName) { $Env:BHProjectName }else { 'NerdCrypt' })
                    BHBuildNumber   = $(if ($buildVersion) { $buildVersion }else { 'Unknown' })
                    BHBuildOutput   = "$Env:BuildScriptPath\BuildOutput"
                    BHBuildSystem   = [System.Environment]::MachineName
                    BHProjectPath   = $Env:BuildScriptPath
                    BHCommitMessage = $(Push-Location $Env:BuildScriptPath; (git log --format=%B -n 1).Trim(); Pop-Location)
                    BHReleaseNotes  = "# Changelog`n`n"
                }
            }
            Write-Heading 'Setting environment variables if needed'
            foreach ($var in $gitVars.Keys) {
                if (-not (Test-Path Env:\$var)) {
                    Set-EnvironmentVariable $var $gitVars[$var]
                }
            }
            Set-EnvironmentVariable BHPSModulePath ([IO.path]::Combine($Env:BHBuildOutput, $Env:BHProjectName, $Env:BHBuildNumber))
            Set-EnvironmentVariable BHPSModuleManifest ([IO.path]::Combine($Env:BHBuildOutput, $Env:BHProjectName, $Env:BHBuildNumber, "$Env:BHProjectName.psd1"))
        }
    )
    $deployScriptBlock = [scriptblock]::Create({
            if (($Env:BHBuildSystem -eq 'VSTS' -and $Env:BHCommitMessage -match '!deploy' -and $Env:BHBranchName -eq "master") -or $script:ForceDeploy -eq $true) {
                if ($null -eq (Get-Module PoshTwit -ListAvailable)) {
                    "    Installing PoshTwit module..."
                    Install-Module PoshTwit -Scope CurrentUser
                }
                Import-Module PoshTwit -Verbose:$false
                # Load the module, read the exported functions, update the psd1 FunctionsToExport
                $commParsed = $Env:BHCommitMessage | Select-String -Pattern '\sv\d+\.\d+\.\d+\s'
                if ($commParsed) {
                    $commitVer = $commParsed.Matches.Value.Trim().Replace('v', '')
                }
                $curVer = (Get-Module $Env:BHProjectName).Version
                if ($moduleInGallery = Find-Module "$Env:BHProjectName*" -Repository PSGallery) {
                    $galVer = $moduleInGallery.Version.ToString()
                    "    Current version on the PSGallery is: $galVer"
                } else {
                    $galVer = '0.0.1'
                }
                $galVerSplit = $galVer.Split('.')
                $nextGalVer = [System.Version](($galVerSplit[0..($galVerSplit.Count - 2)] -join '.') + '.' + ([int]$galVerSplit[-1] + 1))

                $versionToDeploy = if ($commitVer -and ([System.Version]$commitVer -lt $nextGalVer)) {
                    Write-Host -ForegroundColor Yellow "Version in commit message is $commitVer, which is less than the next Gallery version and would result in an error. Possible duplicate deployment build, skipping module bump and negating deployment"
                    $Env:BHCommitMessage = $Env:BHCommitMessage.Replace('!deploy', '')
                    $null
                } elseif ($commitVer -and ([System.Version]$commitVer -gt $nextGalVer)) {
                    Write-Host -ForegroundColor Green "Module version to deploy: $commitVer [from commit message]"
                    [System.Version]$commitVer
                } elseif ($curVer -ge $nextGalVer) {
                    Write-Host -ForegroundColor Green "Module version to deploy: $curVer [from manifest]"
                    $curVer
                } elseif ($Env:BHCommitMessage -match '!hotfix') {
                    Write-Host -ForegroundColor Green "Module version to deploy: $nextGalVer [commit message match '!hotfix']"
                    $nextGalVer
                } elseif ($Env:BHCommitMessage -match '!minor') {
                    $minorVers = [System.Version]("{0}.{1}.{2}" -f $nextGalVer.Major, ([int]$nextGalVer.Minor + 1), 0)
                    Write-Host -ForegroundColor Green "Module version to deploy: $minorVers [commit message match '!minor']"
                    $minorVers
                } elseif ($Env:BHCommitMessage -match '!major') {
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
                        $manifest = Import-PowerShellDataFile -Path $Env:BHPSModuleManifest
                        if ($Env:BHBuildSystem -eq 'VSTS' -and -not [String]::IsNullOrEmpty($Env:NugetApiKey)) {
                            $manifestPath = Join-Path $outputModVerDir "$($Env:BHProjectName).psd1"
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
                        if (-not [String]::IsNullOrEmpty($Env:GitHubPAT)) {
                            "    Creating Release ZIP..."
                            $zipPath = [System.IO.Path]::Combine($PSScriptRoot, "$($Env:BHProjectName).zip")
                            if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
                            Add-Type -Assembly System.IO.Compression.FileSystem
                            [System.IO.Compression.ZipFile]::CreateFromDirectory($outputModDir, $zipPath)
                            "    Publishing Release v$($versionToDeploy) @ commit Id [$($commitId)] to GitHub..."
                            $ReleaseNotes = $Env:BHReleaseNotes
                            $ReleaseNotes += (git log -1 --pretty=%B | Select-Object -Skip 2) -join "`n"
                            $ReleaseNotes += "`n`n***`n`n# Instructions`n`n"
                            $ReleaseNotes += @"
1. [Click here](https://github.com/alainQtec/$($Env:BHProjectName)/releases/download/v$($versionToDeploy.ToString())/$($Env:BHProjectName).zip) to download the *$($Env:BHProjectName).zip* file attached to the release.
2. **If on Windows**: Right-click the downloaded zip, select Properties, then unblock the file.
    > _This is to prevent having to unblock each file individually after unzipping._
3. Unzip the archive.
4. (Optional) Place the module folder somewhere in your ``PSModulePath``.
    > _You can view the paths listed by running the environment variable ```$Env:PSModulePath``_
5. Import the module, using the full path to the PSD1 file in place of ``$($Env:BHProjectName)`` if the unzipped module folder is not in your ``PSModulePath``:
    ``````powershell
    # In `$Env:PSModulePath
    Import-Module $($Env:BHProjectName)

    # Otherwise, provide the path to the manifest:
    Import-Module -Path C:\MyPSModules\$($Env:BHProjectName)\$($versionToDeploy.ToString())\$($Env:BHProjectName).psd1
    ``````
"@
                            Set-Item -Path Env:\BHReleaseNotes -Value $ReleaseNotes
                            $gitHubParams = @{
                                VersionNumber    = $versionToDeploy.ToString()
                                CommitId         = $commitId
                                ReleaseNotes     = $Env:BHReleaseNotes
                                ArtifactPath     = $zipPath
                                GitHubUsername   = 'alainQtec'
                                GitHubRepository = $Env:BHProjectName
                                GitHubApiKey     = $Env:GitHubPAT
                                Draft            = $false
                            }
                            Publish-GithubRelease @gitHubParams
                            "    Release creation successful!"
                        } else {
                            "    [SKIPPED] Publishing Release v$($versionToDeploy) @ commit Id [$($commitId)] to GitHub"
                        }
                        if ($Env:BHBuildSystem -eq 'VSTS' -and -not [String]::IsNullOrEmpty($Env:TwitterAccessSecret) -and -not [String]::IsNullOrEmpty($Env:TwitterAccessToken) -and -not [String]::IsNullOrEmpty($Env:TwitterConsumerKey) -and -not [String]::IsNullOrEmpty($Env:TwitterConsumerSecret)) {
                            "    Publishing tweet about new release..."
                            $text = "#$($Env:BHProjectName) v$($versionToDeploy) is now available on the #PSGallery! https://www.powershellgallery.com/packages/$($Env:BHProjectName)/$($versionToDeploy.ToString()) #PowerShell"
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
                    $Env:BHCommitMessage = $Env:BHCommitMessage.Replace('!deploy', '')
                }
            } else {
                Write-Host -ForegroundColor Magenta "Build system is not VSTS, commit message does not contain '!deploy' and/or branch is not 'master' -- skipping module update!"
            }
        }
    )
    $PSake_ScriptBlock = [scriptblock]::Create({
            # PSake makes variables declared here available in other scriptblocks
            Properties {
                # Find the build folder based on build system
                $ProjectRoot = $Env:BHProjectPath
                if (-not $ProjectRoot) {
                    if ($pwd.Path -like "*ci*") {
                        Set-Location ..
                    }
                    $ProjectRoot = $pwd.Path
                }
                $outputDir = $Env:BHBuildOutput
                $Timestamp = Get-Date -UFormat "%Y%m%d-%H%M%S"
                $PSVersion = $PSVersionTable.PSVersion.ToString()
                $outputModDir = [IO.path]::Combine($Env:BHBuildOutput, $Env:BHProjectName)
                $tests = "$projectRoot\Tests"
                $lines = ('-' * 70)
                $Verbose = @{}
                $TestFile = "TestResults_PS$PSVersion`_$TimeStamp.xml"
                $outputModVerDir = [IO.path]::Combine($Env:BHBuildOutput, $Env:BHProjectName, $env:BHBuildNumber)
                $PathSeperator = [IO.Path]::PathSeparator
                $DirSeperator = [IO.Path]::DirectorySeparatorChar
                if ($Env:BHCommitMessage -match "!verbose") {
                    $Verbose = @{Verbose = $True }
                }
                $null = @($tests, $Verbose, $TestFile, $outputDir, $outputModDir, $outputModVerDir, $lines, $DirSeperator, $PathSeperator)
                $null = Invoke-Command -NoNewScope -ScriptBlock {
                    $l = [IO.File]::ReadAllLines([IO.Path]::Combine($Env:BuildScriptPath, 'build.ps1'))
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

                Write-Verbose "Module Build version: $env:BHBuildNumber"
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
                Remove-Module $Env:BHProjectName -Force -ErrorAction SilentlyContinue
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
                            "Classes"
                            "Private"
                            "Public"
                            "LICENSE"
                            "$Env:BHProjectName.psd1"
                        )
                    ) {
                        Copy-Item -Recurse -Path $([IO.Path]::Combine($env:BuildScriptPath, $Item)) -Destination $Env:BHPSModulePath
                    }
                    if (![IO.File]::Exists($Env:BHPSModuleManifest)) {
                        Throw "Could Not Create Module Manifest!"
                    }
                } catch {
                    throw $_
                }
                # Create Class
                $_NC_File = [IO.Path]::Combine($Env:BHPSModulePath, "Classes", "NerdCrypt.Class.ps1")
                $NC_Class = Get-Item $_NC_File
                if ($PSVersionTable.PSEdition -ne "Core" -and $PSVersionTable.PSVersion.Major -le 5.1) {
                    if ([IO.File]::Exists($NC_Class)) {
                        (Get-Content $NC_Class.FullName).Replace("    ZLib", '') -match '\S' | Out-File $NC_Class
                    } else {
                        Throw [System.IO.FileNotFoundException]::new('Unable to find the specified file.', "$_NC_File")
                    }
                }
                Write-Verbose -Message 'Creating psm1 ...'
                $psm1 = New-Item -Path ([IO.Path]::Combine($outputModVerDir, "$($Env:BHProjectName).psm1")) -ItemType File -Force
                $functionsToExport = @()
                $publicFunctionsPath = [IO.Path]::Combine($Env:BHProjectPath, "Public")
                if (Test-Path $publicFunctionsPath -PathType Container -ErrorAction SilentlyContinue) {
                    Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" -Recurse -File | ForEach-Object {
                        $functionsToExport += $_.BaseName
                    }
                }
                $manifestContent = Get-Content -Path $Env:BHPSModuleManifest -Raw
                $PsModuleContent = Get-Content -Path ([IO.Path]::Combine($Env:BHProjectPath, "$Env:BHProjectName.psm1" )) -Raw
                $PsModuleContent = $PsModuleContent.Replace("'<Aliases>'", "'Encrypt','Decrypt'")
                $PsModuleContent | Add-Content -Path $psm1 -Encoding UTF8
                $publicFunctionNames = Get-ChildItem -Path $publicFunctionsPath -Filter "*.ps1" | Select-Object -ExpandProperty BaseName

                Write-Verbose -Message 'Creating psd1 ...'
                # Using .Replace() is Better than Update-ModuleManifest as this does not destroy the Indentation in the Psd1 file.
                $manifestContent = $manifestContent.Replace(
                    "'<FunctionsToExport>'", $(if ((Test-Path -Path $publicFunctionsPath) -and $publicFunctionNames.count -gt 0) { "'$($publicFunctionNames -join "',`n        '")'" }else { $null })
                ).Replace(
                    "<ScriptsToProcess>", $((Get-ChildItem ([IO.Path]::Combine($Env:BHPSModulePath, "Classes")) -File -Filter "*.Class.ps1" | ForEach-Object { "$([IO.Path]::Combine('Classes', $_.Name))" }) -join ",`n        ").Trim()
                ).Replace(
                    "<ModuleVersion>", $Env:BHBuildNumber
                ).Replace(
                    "<ReleaseNotes>", $Env:BHReleaseNotes
                ).Replace(
                    "<Year>", ([Datetime]::Now.Year)
                )
                $manifestContent | Set-Content -Path $Env:BHPSModuleManifest
                if ((Get-ChildItem $outputModVerDir | Where-Object { $_.Name -eq "$($Env:BHProjectName).psd1" }).BaseName -cne $Env:BHProjectName) {
                    "    Renaming manifest to correct casing"
                    Rename-Item (Join-Path $outputModVerDir "$($Env:BHProjectName).psd1") -NewName "$($Env:BHProjectName).psd1" -Force
                }
                "    Created compiled module at [$outputModDir]"
                "    Output version directory contents"
                Get-ChildItem $outputModVerDir | Format-Table -AutoSize
            } -description 'Compiles module from source'

            Task Import -depends Compile {
                '    Testing import of the Compiled module.'
                Test-ModuleManifest -Path $Env:BHPSModuleManifest
                Import-Module $Env:BHPSModuleManifest
            } -description 'Imports the newly compiled module'

            Task Test -depends Init {
                '    Importing Pester'
                Import-Module Pester -Verbose:$false -Force -ErrorAction Stop
                Push-Location
                Set-Location -PassThru $outputModDir
                if (-not $Env:BHProjectPath) {
                    Set-BuildEnvironment -Path $env:BuildScriptPath\..
                }

                $origModulePath = $Env:PSModulePath
                if ( $Env:PSModulePath.split($pathSeperator) -notcontains $outputDir ) {
                    $Env:PSModulePath = ($outputDir + $pathSeperator + $origModulePath)
                }

                Remove-Module $Env:BHProjectName -ErrorAction SilentlyContinue -Verbose:$false
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

            Task Deploy -depends Init $deployScriptBlock -description 'Deploy module to PSGallery' -preaction {
                Import-Module $outputModDir -Force -Verbose:$false
            }
        }
    )
    #endregion ScriptBlockss
    $Psake_BuildFile = New-Item $([IO.Path]::GetTempFileName().Replace('.tmp', '.ps1'))
    #endregion Variables

    #region    BuildHelper_Functions
    function Get-Elapsed {
        if ($IsCI) {
            "[+$(((Get-Date) - (Get-Date $Env:_BuildStart)).ToString())]"
        } else {
            "[$((Get-Date).ToString("HH:mm:ss")) +$(((Get-Date) - (Get-Date $Env:_BuildStart)).ToString())]"
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
                $versionToImport = ''
                Write-Verbose -Message "Resolving Module [$($moduleName)]"
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
                Write-Host "##vso[task.logissue type=warning;]$Message"
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
                Write-Host "##vso[task.logissue type=error;]$Message"
            }
            Write-Error $Message
        }
    }
    function Set-EnvironmentVariable {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [parameter(Position = 0)]
            [String]
            $Name,
            [parameter(Position = 1, ValueFromRemainingArguments)]
            [String[]]
            $Value
        )
        $fullVal = $Value -join " "
        Write-BuildLog "Setting env variable '$Name' to '$fullVal'"
        Set-Item -Path Env:\$Name -Value $fullVal -Force
        if ($IsCI) {
            "##vso[task.setvariable variable=$Name]$fullVal" | Write-Host
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
            $(if ($Env:BHProjectName) { "Project : $Env:BHProjectName" })
            $(if ($State) { "State   : $State" })
            "Engine  : PowerShell $($PSVersionTable.PSVersion.ToString())"
            "Host OS : $(if($PSVersionTable.PSVersion.Major -le 5 -or $IsWindows){"Windows"}elseif($IsLinux){"Linux"}elseif($IsMacOS){"macOS"}else{"[UNKNOWN]"})"
            "PWD     : $PWD"
            ''
        ) | Write-Host
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
            [String]$CommitId = 'master',

            [parameter(Mandatory = $true)]
            [String]$Env:BHReleaseNotes,

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
            name             = [string]::Format("$($Env:BHProjectName) v{0}", $VersionNumber)
            body             = $Env:BHReleaseNotes
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
    Write-EnvironmentSummary "Build started"
    Invoke-Command -ScriptBlock $SetBuildVariables
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

    Invoke-CommandWithLog {
        Get-PackageProvider -Name Nuget -ForceBootstrap -Verbose:$false
        if (!(Get-PackageProvider -Name Nuget)) { Install-PackageProvider -Name NuGet -Force | Out-Null }
        Import-PackageProvider -Name NuGet -Force | Out-Null
    }
    Invoke-CommandWithLog {
        if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -Verbose:$false
        }
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
        Get-PSakeScriptTasks -buildFile $Psake_BuildFile.FullName |
            Sort-Object -Property Name |
            Format-Table -Property Name, Description, Alias, DependsOn
    } else {
        Write-Heading "Finalizing build Prerequisites"
        if (
            $Task -eq 'Deploy' -and (
                $Env:BUILD_BUILDURI -notlike 'vstfs:*' -or
                $Env:BUILD_SOURCEBRANCH -like '*pull*' -or
                $Env:BUILD_SOURCEVERSIONMESSAGE -notmatch '!deploy' -or
                $Env:BUILD_SOURCEBRANCHNAME -ne 'master' -or
                $PSVersionTable.PSVersion.Major -ne 5 -or
                $null -eq $Env:NugetApiKey
            )
        ) {
            "Task is 'Deploy', but conditions are not correct for deployment:`n" +
            "    + Current build system is VSTS     : $($Env:BUILD_BUILDURI -like 'vstfs:*') [$Env:BUILD_BUILDURI]`n" +
            "    + Current branch is master         : $($Env:BUILD_SOURCEBRANCHNAME -eq 'master') [$Env:BUILD_SOURCEBRANCHNAME]`n" +
            "    + Source is not a pull request	    : $($Env:BUILD_SOURCEBRANCH -notlike '*pull*') [$Env:BUILD_SOURCEBRANCH]`n" +
            "    + Commit message matches '!deploy' : $($Env:BUILD_SOURCEVERSIONMESSAGE -match '!deploy') [$Env:BUILD_SOURCEVERSIONMESSAGE]`n" +
            "    + Current PS major version is 5    : $($PSVersionTable.PSVersion.Major -eq 5) [$($PSVersionTable.PSVersion.ToString())]`n" +
            "    + NuGet API key is not null        : $($null -ne $Env:NugetApiKey)`n" +
            "Skipping psake for this job!" | Write-Host -ForegroundColor Yellow
            exit 0
        } else {
            if ($Task -eq 'Deploy') {
                "Task is 'Deploy' and conditions for deployment are:`n" +
                "    + Current build system is VSTS     : $($Env:BUILD_BUILDURI -like 'vstfs:*') [$Env:BUILD_BUILDURI]`n" +
                "    + Current branch is master         : $($Env:BUILD_SOURCEBRANCHNAME -eq 'master') [$Env:BUILD_SOURCEBRANCHNAME]`n" +
                "    + Source is not a pull request     : $($Env:BUILD_SOURCEBRANCH -notlike '*pull*') [$Env:BUILD_SOURCEBRANCH]`n" +
                "    + Commit message matches '!deploy' : $($Env:BUILD_SOURCEVERSIONMESSAGE -match '!deploy') [$Env:BUILD_SOURCEVERSIONMESSAGE]`n" +
                "    + Current PS major version is 5    : $($PSVersionTable.PSVersion.Major -eq 5) [$($PSVersionTable.PSVersion.ToString())]`n" +
                "    + NuGet API key is not null        : $($null -ne $Env:NugetApiKey)`n" | Write-Host -ForegroundColor Green
            }
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
            if ($Task -contains 'Import' -and $psake.build_success) {
                Write-Heading "Importing $Env:BHProjectName to local scope"
                Import-Module ([IO.Path]::Combine($Env:BHBuildOutput, $Env:BHProjectName)) -Verbose:$false
            }
            Write-EnvironmentSummary "Build finished"
        }
    }
}
End {
    exit ( [int](!$psake.build_success) )
}