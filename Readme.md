# Synopsis

## NerdCrypt

NerdCrypt, is an all in one Encryption Decryption Powershell module. It contains tools to ease the work with nerdy cryptography.

    
# 📖 Description

    AIO PowerShell module to do all things encryption-decryption.
    
## How to install:

```powershell
Find-module NerdCrypt | install-Module
```
    
### Encryption 

    Applies several paranoid encryptions to an Object or a file.
    Encryption can be applied to any item that can be converted to a byte array.
    This function may currently encrypt Objects (i.e. "System.Object") and files.
    The function employs Rijndael AES-256, Rivest-Shamir-Adleman encryption (RSA), MD5 Triple D.E.S, and other algorithms.
    Yeah, It gets Pretty paranoid!

    There is an option to store your encryption key(s) in Windows Password vault so that the
    Decryptor Function (Decrypt-Object) can use them without need of your input again.
        
# 📋 NOTES

    + Most of the methods work. (Most).
    + This file is over a 1000 lines (All in One), so use regions code folding if your editor supports it.
    
## Examples
    
```Powershell
PS C:\> # Try this:
PS C:\> iex $((Invoke-RestMethod -Method Get https://api.github.com/gists/217860de99e8ddb89a8820add6f6980f).files.'Nerdcrypt.ps1'.content)
PS C:\> $n = [NerdCrypt]::new("H3llo W0rld!");
PS C:\> $e = $n.Encrypt(3);
PS C:\> $d = $n.Decrypt(3);
PS C:\> [xconvert]::BytesToObject($d);
H3llo W0rld!
```

# 📚 Wikis

I'm working hard to explain everything in the [wiki pages](https://github.com/alainQtec/NerdCrypt/wiki)... read it it's important ! you'll find tips, tweaks and many other things... there is nothing here in the readme.

# 🤝 Contributions

    The repository is open to suggestions, contributions and all other forms of help.
    
To contribute it's easy, just :

- Explain what it does exactly

- Sources of information if possible

- Pull request

For any contribution, it will be signed and thanked with the nickname of the person
