## ![logo_text](https://user-images.githubusercontent.com/79479952/188858942-da5021ad-35a2-4793-836b-3305e153e1df.png)
<img align="right" alt="logo" src="https://user-images.githubusercontent.com/79479952/188859195-36b440a9-c3f8-4294-b897-a3898eeb62a3.png">

NerdCrypt, is an all in one Encryption Decryption Powershell module. It contains tools to ease the work with nerdy cryptography.

<br />
<div align="Left">
  </br>
  <!-- Upload Artifacts -->
  <a href="https://github.com/alainQtec/NerdCrypt/actions/workflows/Upload_Artifact.yaml">
    <img src="https://github.com/alainQtec/NerdCrypt/actions/workflows/Upload_Artifact.yaml/badge.svg"
      alt="Upload artifact from Ubuntu" title="Upload artifacts" />
  </a>
  <!-- Publish Module -->
    <a href="https://github.com/alainQtec/NerdCrypt/actions/workflows/Publish.yaml">
        <img src="https://github.com/alainQtec/NerdCrypt/actions/workflows/Publish.yaml/badge.svg"
      alt="Publish Module" title="Publish Module" />
    </a>
  <!-- PS Gallery -->
  <a href="https://www.PowerShellGallery.com/packages/NerdCrypt">
    <img src="https://img.shields.io/powershellgallery/dt/NerdCrypt.svg?style=flat&logo=powershell&color=blue"
      alt="PowerShell Gallery" title="PowerShell Gallery" />
  </a>
  <!-- Continuous Intergration -->
  <a href="https://github.com/alainQtec/NerdCrypt/actions/workflows/CI.yaml">
    <img src="https://github.com/alainQtec/NerdCrypt/actions/workflows/CI.yaml/badge.svg?branch=main"
      alt="CI/CD" title="Continuous Intergration" />
  </a>
  <!-- GitHub Releases -->
  <a href="https://github.com/alainQtec/NerdCrypt/releases/latest">
    <img src="https://img.shields.io/github/downloads/alainQtec/NerdCrypt/total.svg?logo=github&color=blue"
      alt="Downloads" title="GitHub Release downloads" />
  </a>
  <!-- GitHub Releases -->
  <a href="https://github.com/alainQtec/NerdCrypt/releases/latest">
    <img src="https://img.shields.io/github/release/alainQtec/NerdCrypt.svg?label=version&logo=github"
      alt="Version" title="GitHub Release versions" />
  </a>
</div>
<br />

***

## 📖 **Description**

    AIO PowerShell module to do all things encryption-decryption.

NerdCrypt is a cross-platform PowerShell module handling string encryption and decryption using RSA keys only. It enables strings to be encrypted when the client only has the public key available, in the event the encrypted string is being sent to a secure endpoint housing the private key where it will be decrypted for further use. The same module can be implemented on the receiving endpoint to decrypt the strings as well, if desired.

## How to install:

```powershell
Find-module NerdCrypt | install-Module
```

Or
```powershell
Install-Module NerdCrypt -Scope CurrentUser -Repository PSGallery
```

To build the module, run `build.ps1`.

Want to run the Pester tests locally? Pass `Test` as the value to the `Task` script parameter like so:

```powershell
.\build.ps1 -Task Test
```

To Run all Tests:

```PowerShell
.\Test-Module.ps1 -Module $Module_Path -Tests ".\tests"
```

## 📚 **Wikis**

Everything is explained in the [wiki pages](https://github.com/alainQtec/NerdCrypt/wiki)... read it it's important ! you'll find tips and many other things... there is nothing here in the readme.

### GitHub Releases

Please see the [Releases section of this repository](https://github.com/alainQtec/NerdCrypt/releases) for instructions.

## 🤝 **Contributions**

 The repository is open to suggestions, contributions and all other forms of help.

Interested in helping out with the Module development? Please check out our [Contribution Guidelines](https://github.com/alainQtec/NerdCrypt/blob/master/CONTRIBUTING.md)!

Building the module locally to test changes is as easy as running the `build.ps1` file in the root of the repo. This will compile the module with your changes and import the newly compiled module at the end by default.

## Code of Conduct

Please adhere to our [Code of Conduct](https://github.com/alainQtec/NerdCrypt/blob/master/CODE_OF_CONDUCT.md) when interacting with this repo.
