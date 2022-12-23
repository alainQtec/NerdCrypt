## ![logo_text](https://user-images.githubusercontent.com/79479952/188858942-da5021ad-35a2-4793-836b-3305e153e1df.png)

<img align="right" alt="logo" src="https://user-images.githubusercontent.com/79479952/190868846-075673ee-44f8-4a3d-9640-2a254b27cbb6.png">

NerdCrypt, is an all in one Cryptography Powershell module.

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
  <!-- Latest gitHub Release version -->
  <a href="https://github.com/alainQtec/NerdCrypt/releases/latest">
    <img src="https://img.shields.io/github/release/alainQtec/NerdCrypt.svg?label=version&logo=github"
      alt="Version" title="GitHub Release versions" />
  </a>
</div>
<br />

---

## 📖 **Description**

    AIO PowerShell module to do all things encryption-decryption.

Cryptography is the study of techniques for secure communication in the presence of adversaries. It is a field of mathematics and computer science that requires a strong foundation in mathematical and computational concepts. Some people who are interested in cryptography may be considered "nerdy" due to their deep knowledge and interest in the subject.

<div style="float: right;">
  ![logo](https://github.com/alainQtec/NerdCrypt/blob/main/docs/images/CryptographyNerd.png)
</div>

However, cryptography is an important and fascinating field that has a wide range of practical applications, and anyone with an interest in mathematics, computer science, or security can find something interesting and worthwhile in the study of cryptography.

This Module's features focus mainly on **Data encryption**, **Data protection**, **Secure communication** and **User authentication**

## Usage

Here is a basic usage guide for NerdCrypt

For Extended usage read the [Wiki](https://github.com/alainQtec/NerdCrypt/wiki)

## 🧑‍💻 **How to install**

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

### 🚀 **GitHub Releases**

Please see the [Releases section of this repository](https://github.com/alainQtec/NerdCrypt/releases) for instructions.

## 🤝 **Contributions**

![Alt](https://repobeats.axiom.co/api/embed/d201fa56239511a45aa4aacb0e06e24f756cc531.svg "Repobeats analytics image")

This repository is open to suggestions, contributions and all other forms of help.

Interested in helping out with the Module development? Please check out our [Contribution Guidelines](https://github.com/alainQtec/NerdCrypt/blob/main/CONTRIBUTING.md)!

Building the module locally to test changes is as easy as running the `build.ps1` file in the root of the repo. This will compile the module with your changes and import the newly compiled module at the end by default.

## Code of Conduct

Please adhere to our [Code of Conduct](https://github.com/alainQtec/NerdCrypt/blob/main/CODE_OF_CONDUCT.md) when interacting with this repo.
