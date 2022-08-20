.SYNOPSIS
    AIO PowerShell class to do all things encryption-decryption.
.DESCRIPTION
    All in one Encryption Decryption ps Class.
    Great way of Learning Encryption/decryption methods using PowerShell classes
.NOTES
    [+] Most of the methods work. (Most).
    [+] This file is over a 1000 lines (All in One), so use regions code folding if your editor supports it.
.LINK
    https://gist.github.com/alainQtec/217860de99e8ddb89a8820add6f6980f
.EXAMPLE
    PS C:\> # Try this:
    PS C:\> iex $((Invoke-RestMethod -Method Get https://api.github.com/gists/217860de99e8ddb89a8820add6f6980f).files.'Nerdcrypt.ps1'.content)
    PS C:\> $n = [NerdCrypt]::new("H3llo W0rld!");
    PS C:\> $e = $n.Encrypt(3);
    PS C:\> $d = $n.Decrypt(3);
    PS C:\> [xconvert]::BytesToObject($d);
    H3llo W0rld!
