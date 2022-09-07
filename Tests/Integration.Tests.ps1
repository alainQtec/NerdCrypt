Import-Module "$PSScriptRoot\..\module\NerdCrypt.psd1" -Force

Describe "Protect-Data" {
    It "should have command" {
        Get-Command Protect-Data | Should -Not -BeNullOrEmpty
    }
}

Describe "UnProtect-Data" {
    It "should have command" {
        Get-Command UnProtect-Data | Should -Not -BeNullOrEmpty
    }
}

Describe "Decrypt-Object" {
    It "should have command" {
        Get-Command Decrypt-Object | Should -Not -BeNullOrEmpty
    }
}

Describe "Encrypt-Object" {
    It "should have command" {
        Get-Command Encrypt-Object | Should -Not -BeNullOrEmpty
    }
}

Describe "New-PNKey" {
    It "should have command" {
        Get-Command New-PNKey | Should -Not -BeNullOrEmpty
    }
    It "should work" {
        (New-PNKey -UserName $nc.key.User.UserName -Password [xconvert]::ToSecurestring('P4ssw0rd') -Expirity $nc.key.Expirity.date -Protect) | Should -Not -BeNullOrEmpty
    }
}
