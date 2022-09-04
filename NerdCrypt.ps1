<#
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
#>

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
#region    Helpers

#region    enums
enum ProtectionScope {
    CurrentUser # The protected data is associated with the current user. Only threads running under the current user context can unprotect the data.
    LocalMachine # The protected data is associated with the machine context. Any process running on the computer can unprotect data. This enumeration value is usually used in server-specific applications that run on a server where untrusted users are not allowed access.
}
enum CipherType {
    Caesar
    Polybius
}
enum keyStoreMode {
    Vault
    KeyFile
    SecureString
}
enum SdCategory {
    Token
    Password
}
enum ExpType {
    Milliseconds
    Years
    Months
    Days
    Hours
    Minutes
    Seconds
}
enum CertStoreName {
    MY
    ROOT
    TRUST
    CA
}
if ($PSVersionTable.PSEdition -eq "Core" -or $PSVersionTable.PSVersion.Major -gt 5.1) {
    [void][xgen]::Enumerator('Compression', ('Deflate', 'Gzip', 'ZLib'))
} else {
    [void][xgen]::Enumerator('Compression', ('Deflate', 'Gzip'))
}
# [xgen]::Enumerator('ExpType', ('Milliseconds', 'Years', 'Months', 'Days', 'Hours', 'Minutes', 'Seconds'))
#endregion enums

#region    Custom_Stuff_generators
#!ALL methods shouldbe/are Static!
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class xgen {
    xgen() {}
    [string]static RandomName() {
        return [xgen]::RandomName(16)
    }
    [string]static RandomName([int]$Length) {
        return [string][xgen]::RandomName($Length, $Length);
    }
    [string]static RandomName([int]$minLength, [int]$maxLength) {
        [int]$iterations = 2
        $MinrL = 3; $MaxrL = 999 # Gotta have some restrictions, or one typo could endup creating insanely long Passwords, ex 30000 intead of 30.
        if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'String Length'. Try $MinrL or greater." ; Break }
        if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'String Length'. Try $MaxrL or lower." ; Break }
        [string]$samplekeys = [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }) + (0..9))
        return [string][xgen]::RandomSTR($samplekeys, $iterations, $minLength, $maxLength);
    }
    [string]static Password() {
        return [string][xgen]::Password(1);
    }
    [string]static Password([int]$iterations) {
        return [string][xgen]::Password($iterations, 30, 256);
    }
    [string]static Password([int]$iterations, [int]$Length) {
        return [string][xgen]::Password($iterations, $Length, $Length);
    }
    [string]static Password([int]$iterations, [int]$minLength, [int]$maxLength) {
        # https://stackoverflow.com/questions/55556/characters-to-avoid-in-automatically-generated-passwords
        $Passw0rd = [string]::Empty; [string]$samplekeys = [xconvert]::ToString([System.Convert]::FromBase64String("ISIjJCUmJygpKissLS4vMjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hKS0xNTk9QUlNUVVZXWFlaW1xdXl9hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eiB7fH1+"), '')
        $MinrL = 8; $MaxrL = 999 # Gotta have some restrictions, or one typo could endup creating insanely long or small Passwords, ex 30000 intead of 30.
        if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'Password Length'. Try $MinrL or greater." ; Break }
        if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'Password Length'. Try $MaxrL or lower." ; Break }
        if ($minLength -lt 130) {
            $Passw0rd = [string][xgen]::RandomSTR($samplekeys, $iterations, $minLength, $maxLength)
        } else {
            #This person Wants a really good password, so We create it:
            do {
                $Passw0rd = [string][xgen]::RandomSTR($samplekeys, $iterations, $minLength, $maxLength)
            } until ([int][xgen]::PasswordStrength($Passw0rd) -gt 125)
        }
        return $Passw0rd;
    }
    [int]static PasswordStrength([string]$passw0rd) {
        # Inspired by: https://www.security.org/how-secure-is-my-password/
        $passwordDigits = [System.Text.RegularExpressions.Regex]::new("\d", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordNonWord = [System.Text.RegularExpressions.Regex]::new("\W", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordUppercase = [System.Text.RegularExpressions.Regex]::new("[A-Z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordLowercase = [System.Text.RegularExpressions.Regex]::new("[a-z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        [int]$strength = 0; $digits = $passwordDigits.Matches($passw0rd); $NonWords = $passwordNonWord.Matches($passw0rd); $Uppercases = $passwordUppercase.Matches($passw0rd); $Lowercases = $passwordLowercase.Matches($passw0rd)
        if ($passw0rd.Length -gt 7) { $strength += 5 };
        if ($passw0rd.Length -gt 15) { $strength += 15 };
        if ($digits.Count -ge 2) { $strength += 5 };
        if ($digits.Count -ge 5) { $strength += 15 };
        if ($NonWords.Count -ge 2) { $strength += 5 };
        if ($NonWords.Count -ge 5) { $strength += 15 };
        if ($Uppercases.Count -ge 2) { $strength += 5 };
        if ($Uppercases.Count -ge 5) { $strength += 15 };
        if ($Lowercases.Count -ge 2) { $strength += 5 };
        if ($Lowercases.Count -ge 5) { $strength += 15 };
        if ($digits.Count -gt 15 -and $passw0rd.Length -ge 64) { $strength += 10 }; # Lenght is the real strength.
        if ($NonWords.Count -gt 10 -and $passw0rd.Length -ge 30) { $strength += 5 };
        if ($NonWords.Count -gt 15 -and $passw0rd.Length -ge 128) { $strength += 10 }; #The longer the more strong this password gets.
        if ($NonWords.Count -gt 10 -and $passw0rd.Length -ge 64 -and $Uppercases.Count -gt 5 -and $Lowercases.Count -gt 5) { $strength += 10 };
        if ($NonWords.Count -gt 15 -and $passw0rd.Length -ge 226 -and $Uppercases.Count -gt 15 -and $Lowercases.Count -gt 15) { $strength += 15 };
        return $strength;
    }
    [byte[]]static Salt() {
        return [byte[]][xconvert]::BytesFromObject([xgen]::RandomName(16))
    }
    [byte[]]static Salt([int]$iterations) {
        return [byte[]]$(1..$iterations | ForEach-Object { [xgen]::Salt() });
    }
    [byte[]]static Key() {
        return [xgen]::Key(2);
    }
    [byte[]]static Key([int]$iterations) {
        $password = $null; $salt = $null;
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToSecurestring([xgen]::Password($Iterations)));
        Set-Variable -Name salt -Scope Local -Visibility Private -Option Private -Value $([xgen]::Salt($Iterations));
        return [xgen]::Key($password, $salt)
    }
    [byte[]]static Key([securestring]$password) {
        return [xgen]::Key($password, $([System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15]))
    }
    [byte[]]static Key([securestring]$password, [byte[]]$salt) {
        $rfc2898 = $null; $key = $null;
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $password;
        Set-Variable -Name salt -Scope Local -Visibility Private -Option Private -Value $salt;
        Set-Variable -Name rfc2898 -Scope Local -Visibility Private -Option Private -Value $([System.Security.Cryptography.Rfc2898DeriveBytes]::new($password, $salt));
        Set-Variable -Name key -Scope Local -Visibility Private -Option Private -Value $($rfc2898.GetBytes(16));
        return $key
    }
    [byte[]]static RandomEntropy() {
        [byte[]]$entropy = [byte[]]::new(16);
        [void][System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($entropy)
        return $entropy
    }
    [string]static UniqueMachineId() {
        $Id = [string](Get-Variable -Name MachineId -Scope global -ErrorAction SilentlyContinue).Value
        if ([string]::IsNullOrWhiteSpace($Id)) {
            Set-Variable -Name MachineId -Visibility Public -Scope Global -Value $([string]::Join(':', $([string]::Join(':', $([wmisearcher]::new("SELECT * FROM Win32_BIOS").Get() | ForEach-Object { ([string]$_.Manufacturer, [string]$_.SerialNumber) })), $([System.Management.ManagementObjectCollection][wmiclass]::new("win32_processor").GetInstances() | Select-Object -ExpandProperty ProcessorId), $([wmisearcher]::new("SELECT * FROM Win32_LogicalDisk").Get() | Where-Object { $_.DeviceID -eq "C:" } | Select-Object -ExpandProperty VolumeSerialNumber))));
            $Id = [string](Get-Variable -Name MachineId -Scope global -ErrorAction SilentlyContinue).Value
        }
        return $Id
    }
    [string]static hidden RandomSTR([string]$InputSample, [int]$iterations, [int]$minLength, [int]$maxLength) {
        if ($maxLength -lt $minLength) { throw [System.ArgumentOutOfRangeException]::new('MinLength', "'MaxLength' cannot be less than 'MinLength'") }
        if ($iterations -le 0) { Write-Warning 'Negative and Zero Iterations are NOT Possible!'; return [string]::Empty }
        [char[]]$chars = [char[]]::new($InputSample.Length);
        $chars = $InputSample.ToCharArray();
        $Keys = [System.Collections.Generic.List[string]]::new();
        $rand = [Random]::new();
        [int]$size = $rand.Next([int]$minLength, [int]$maxLength);
        for ($i = 0; $i -lt $iterations; $i++) {
            [byte[]] $data = [Byte[]]::new(1);
            $crypto = [System.Security.Cryptography.RNGCryptoServiceProvider]::new();
            $data = [Byte[]]::new($size);
            $crypto.GetNonZeroBytes($data);
            $result = [System.Text.StringBuilder]::new($size);
            foreach ($b In $data) { $result.Append($chars[$b % ($chars.Length - 1)]) };
            [void]$Keys.Add($result.ToString());
        }
        $STR = [string]::Join('', $keys)
        if ($STR.Length -gt $maxLength) {
            $STR = $STR.Substring(0, $maxLength);
        }
        return $STR;
    }
    [string]static ResolvedPath([string]$Path) {
        return [xgen]::ResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    [string]static ResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
        if ($paths.Count -gt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
        } elseif ($paths.Count -lt 1) {
            throw [System.IO.IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
        }
        return $paths[0].Path
    }
    [string]static UnResolvedPath([string]$Path) {
        return [xgen]::UnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
    }
    [string]static UnResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
        return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
    }
    [void]static Enumerator([string]$Name, [string[]]$Members) {
        # Ex:
        # [xgen]::Enumerator("my.colors", ('blue', 'red', 'yellow'));
        # [Enum]::GetNames([my.colors]);
        try {
            $appdomain = [System.Threading.Thread]::GetDomain()
            $assembly = [System.Reflection.AssemblyName]::new()
            $assembly.Name = "EmittedEnum"
            $assemblyBuilder = $appdomain.DefineDynamicAssembly($assembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Save -bor [System.Reflection.Emit.AssemblyBuilderAccess]::Run);
            $moduleBuilder = $assemblyBuilder.DefineDynamicModule("DynamicModule", "DynamicModule.mod");
            $enumBuilder = $moduleBuilder.DefineEnum($name, [System.Reflection.TypeAttributes]::Public, [System.Int32]);
            for ($i = 0; $i -lt $Members.count; $i++) { [void]$enumBuilder.DefineLiteral($Members[$i], $i) }
            [void]$enumBuilder.CreateType()
        } catch {
            throw $_
        }
    }
    [System.Security.Cryptography.Aes]static Aes() { return [xgen]::Aes(1) }
    [System.Security.Cryptography.Aes]static Aes([int]$Iterations) {
        $salt = $null; $password = $null;
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToSecurestring([xgen]::Password($Iterations)));
        Set-Variable -Name salt -Scope Local -Visibility Private -Option Private -Value $([xgen]::Salt($Iterations));
        return [xgen]::Aes($password, $salt, $Iterations)
    }
    [System.Security.Cryptography.Aes]static Aes([securestring]$password, [byte[]]$salt, [int]$iterations) {
        $aes = $null; $M = $null; $P = $null; $k = $null;
        Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([System.Security.Cryptography.AesManaged]::new());
        #Note: 'Zeros' Padding was avoided, see: https://crypto.stackexchange.com/questions/1486/how-to-choose-a-padding-mode-with-aes # Personally I prefer PKCS7 as the best padding.
        for ($i = 1; $i -le $iterations; $i++) { ($M, $P, $k) = ((Get-Random ('ECB', 'CBC')), (Get-Random ('PKCS7', 'ISO10126', 'ANSIX923')), (Get-Random (128, 192, 256))) }
        $aes.Mode = Invoke-Expression "[System.Security.Cryptography.CipherMode]::$M";
        $aes.Padding = Invoke-Expression "[System.Security.Cryptography.PaddingMode]::$P";
        $aes.keysize = $k;
        $aes.Key = [xgen]::Key($password, $salt);
        $aes.IV = [xgen]::RandomEntropy();
        return $aes
    }
}
#endregion Custom_Stuff_generators

#region    Custom_Converters
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class XConvert {
    XConvert() {}
    [string]static Tostring([k3Y]$K3Y) {
        if ($null -eq $K3Y) { return [string]::Empty };
        $NotNullProps = ('User', 'UID', 'Expirity');
        $K3Y | Get-Member -MemberType Properties | ForEach-Object { $Prop = $_.Name; if ($null -eq $K3Y.$Prop -and $Prop -in $NotNullProps) { throw [System.ArgumentNullException]::new($Prop) } };
        $CustomObject = [xconvert]::ToPSObject($K3Y);
        return [string][xconvert]::ToCompressed([System.Convert]::ToBase64String([XConvert]::BytesFromObject($CustomObject)));
    }
    [string[]]static ToString([int[]]$CharCodes) {
        $String = @(); foreach ($n in $CharCodes) { $String += [string][char]$n }
        return $String
    }
    [string]static Tostring([Object]$Object) {
        $Bytes = [byte[]]::new(0);
        if ($Object.GetType() -eq [String]) {
            return $Object
        } elseif ($Object.GetType() -eq [byte[]]) {
            $Bytes = [byte[]]$Object
        } else {
            $Bytes = [XConvert]::BytesFromObject($Object);
        }
        return [string][System.Convert]::ToBase64String($Bytes);
    }
    [string]static ToString([System.Security.SecureString]$SecureString) {
        [string]$Pstr = [string]::Empty;
        [IntPtr]$zero = [IntPtr]::Zero;
        if ($null -eq $SecureString -or $SecureString.Length -eq 0) {
            return [string]::Empty;
        }
        try {
            Set-Variable -Name zero -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::SecurestringToBSTR($SecureString));
            Set-Variable -Name Pstr -Scope Local -Visibility Private -Option Private -Value ([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($zero));
        } finally {
            if ($zero -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($zero);
            }
        }
        return $Pstr;
    }
    [string]static ToString([int[]]$CharCodes, [string]$separator) {
        return [string]::Join($separator, [XConvert]::ToString($CharCodes));
    }
    [string]static ToString([int]$value, [int]$toBase) {
        [char[]]$baseChars = switch ($toBase) {
            # Binary
            2 { @('0', '1') }
            # Hexadecimal
            16 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f') }
            # Hexavigesimal
            26 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p') }
            # Sexagesimal
            60 { @('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x') }
            Default {
                throw [System.ArgumentException]::new("Invalid Base.")
            }
        }
        return [xconvert]::IntToString($value, $baseChars);
    }
    [SecureString]static ToSecurestring([string]$String) {
        $SecureString = $null; Set-Variable -Name SecureString -Scope Local -Visibility Private -Option Private -Value ([System.Security.SecureString]::new());
        if (![string]::IsNullOrEmpty($String)) {
            $Chars = $String.toCharArray()
            ForEach ($Char in $Chars) {
                $SecureString.AppendChar($Char)
            }
        }
        $SecureString.MakeReadOnly();
        return $SecureString
    }
    [int[]]static StringToCharCode([string[]]$string) {
        [bool]$encoderShouldEmitUTF8Identifier = $false; $Codes = @()
        $Encodr = [System.Text.UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
        for ($i = 0; $i -lt $string.Count; $i++) {
            $Codes += [int[]]$($Encodr.GetBytes($string[$i]))
        }
        return $Codes;
    }
    [bool]static StringToBoolean([string]$Text) {
        $Text = switch -Wildcard ($Text) {
            "1*" { "true"; break }
            "0*" { "false"; break }
            "yes*" { "true"; break }
            "no*" { "false"; break }
            "true*" { "true"; break }
            "false*" { "false"; break }
            "*true*" { "true"; break }
            "*false*" { "false"; break }
            "yeah*" { "true"; break }
            "y*" { "true"; break }
            "n*" { "false"; break }
            Default { "false" }
        }
        return [convert]::ToBoolean($Text)
    }
    [PsObject]static StringToCaesarCipher([string]$Text) {
        return [PsObject][XConvert]::StringToCaesarCipher($Text, $(Get-Random (1..25)))
    }
    [PsObject]static StringToCaesarCipher([string]$Text, [int]$Key) {
        $Text = $Text.ToLower();
        $Cipher = [string]::Empty;
        $alphabet = [string]"abcdefghijklmnopqrstuvwxyz";
        New-Variable -Name alphabet -Value $alphabet -Option Constant -Force;
        for ($i = 0; $i -lt $Text.Length; $i++) {
            if ($Text[$i] -eq " ") {
                $Cipher += " ";
            } else {
                [int]$index = $alphabet.IndexOf($text[$i]) + $Key
                if ($index -gt 26) {
                    $index = $index - 26
                }
                $Cipher += $alphabet[$index];
            }
        }
        $Output = [PsObject]::new()
        $Output | Add-Member -Name 'Cipher' -Value $Cipher -Type NoteProperty
        $Output | Add-Member -Name 'key' -Value $Key -Type NoteProperty
        return $Output
    }
    [string]static StringFromCaesarCipher([string]$Cipher, [int]$Key) {
        $Cipher = $Cipher.ToLower();
        $Key = $Key.ToLower();
        $Output = [string]::Empty;
        $alphabet = [string]"abcdefghijklmnopqrstuvwxyz";
        New-Variable -Name alphabet -Value $alphabet -Option Constant -Force;
        for ($i = 0; $i -lt $Cipher.Length; $i++) {
            if ($Cipher[$i] -eq " ") {
                $Output += " ";
            } else {
                $Output += $alphabet[($alphabet.IndexOf($Cipher[$i]) - $Key)];
            }
        };
        return $Output;
    }
    [PsObject]static StringToPolybiusCipher([String]$Text) {
        $Ciphrkey = Get-Random "abcdefghijklmnopqrstuvwxyz" -Count 25
        return [PsObject][XConvert]::StringToPolybiusCipher($Text, $Ciphrkey)
    }
    [PsObject]static StringToPolybiusCipher([string]$Text, [string]$Key) {
        $Text = $Text.ToLower();
        $Key = $Key.ToLower();
        [String]$Cipher = [string]::Empty
        [XConvert]::ValidatePolybiusCipher($Text, $Key, "Encrypt")
        [Array]$polybiusTable = New-Object 'string[,]' 5, 5;
        $letter = 0;
        for ($i = 0; $i -lt 5; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                $polybiusTable[$i, $j] = $Key[$letter];
                $letter++;
            }
        };
        $Text = $Text.Replace(" ", "");
        for ($i = 0; $i -lt $Text.Length; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                for ($k = 0; $k -lt 5; $k++) {
                    if ($polybiusTable[$j, $k] -eq $Text[$i]) {
                        $Cipher += [string]$j + [string]$k + " ";
                    }
                }
            }
        }
        $Output = [PsObject]::new()
        $Output | Add-Member -Name 'Cipher' -Value $Cipher -Type NoteProperty
        $Output | Add-Member -Name 'key' -Value $Key -Type NoteProperty
        return $Output
    }
    [string]static StringFromPolybiusCipher([string]$Cipher, [string]$Key) {
        $Cipher = $Cipher.ToLower();
        $Key = $Key.ToLower();
        [String]$Output = [string]::Empty
        [XConvert]::ValidatePolybiusCipher($Cipher, $Key, "Decrypt")
        [Array]$polybiusTable = New-Object 'string[,]' 5, 5;
        $letter = 0;
        for ($i = 0; $i -lt 5; $i++) {
            for ($j = 0; $j -lt 5; $j++) {
                $polybiusTable[$i, $j] = $Key[$letter];
                $letter++;
            }
        };
        $SplitInput = $Cipher.Split(" ");
        foreach ($pair in $SplitInput) {
            $Output += $polybiusTable[[convert]::ToInt32($pair[0], 10), [convert]::ToInt32($pair[1], 10)];
        };
        return $Output;
    }
    [void]static hidden ValidatePolybiusCipher([string]$Text, [string]$Key, [string]$Action) {
        if ($Text -notmatch "^[a-z ]*$" -and ($Action -ne 'Decrypt')) {
            throw('Text must only have alphabetical characters');
        }
        if ($Key.Length -ne 25) {
            throw('Key must be 25 characters in length');
        }
        if ($Key -notmatch "^[a-z]*$") {
            throw('Key must only have alphabetical characters');
        }
        for ($i = 0; $i -lt 25; $i++) {
            for ($j = 0; $j -lt 25; $j++) {
                if (($Key[$i] -eq $Key[$j]) -and ($i -ne $j)) {
                    throw('Key must have no repeating letters');
                }
            }
        }
    }
    [string]static StringToBinStR ([string]$string) {
        return [xconvert]::BinaryToBinStR([xconvert]::BinaryFromString("$string"), $false)
    }
    [string]static StringToBinStR ([string]$string, [bool]$Tidy) {
        return [xconvert]::BinaryToBinStR([xconvert]::BinaryFromString("$string"), $Tidy)
    }
    [string]static StringFromBinStR ([string]$BinStR) {
        return [xconvert]::BinaryToString([xconvert]::BinaryFromBinStR($BinStR))
    }
    [string]static BytesToRnStr([byte[]]$Inpbytes) {
        $rn = [System.Random]::new(); # Hides Byte Array in a random String
        $St = [System.string]::Join('', $($Inpbytes | ForEach-Object { [string][char]$rn.Next(97, 122) + $_ }))
        return $St
    }
    [byte[]]static BytesFromRnStr ([string]$rnString) {
        $az = [int[]](97..122) | ForEach-Object { [string][char]$_ }
        $by = [byte[]][string]::Concat($(($rnString.ToCharArray() | ForEach-Object { if ($_ -in $az) { [string][char]32 } else { [string]$_ } }) | ForEach-Object { $_ })).Trim().split([string][char]32);
        return $by
    }
    [string]static StringToCustomCipher([string]$Text) {
        ($e, $p, $q) = [System.Collections.Generic.List[BiGint]]@(17, 53, 61)
        $_res = @(); $Int32Arr = $text.ToCharArray() | ForEach-Object { if ([string]::IsNullOrEmpty([string]$_)) { [int]32 }else { [int]$_ } } # ie: Since [char]32 -eq " " # So we'r just filling spaces.
        $M = [System.Numerics.BigInteger]::Multiply($p, $q)
        foreach ($Item in $Int32Arr) {
            $_res += [System.Numerics.BigInteger]::ModPow($Item, $e, $M);
        }
        [string]$cipher = [xconvert]::ToCompressed([string]::Join(' ', $_res));
        return $cipher
    }
    [string]static StringFromCustomCipher([string]$cipher) {
        $Text = [string]::Empty; ($e, $p, $q) = [System.Collections.Generic.List[BiGint]]@(17, 53, 61)
        $09strr = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9');
        $_crr = [xconvert]::ToDecompressed($cipher).Split(' ')
        $_Arr = foreach ($code in $_crr) { [string]::Join('', ($code.ToCharArray() | Where-Object { [string]$_ -in $09strr })) };
        $_Mod = [System.Numerics.BigInteger]::Multiply($p, $q)
        $2753 = [BigInt]2753; # The Magic Number $2753 Came from:# {$Code_Phi = [System.Numerics.BigInteger]::Multiply([System.Numerics.BigInteger]::Subtract($p, 1), [System.Numerics.BigInteger]::Subtract($q, 1)); $t = $nt = $r = $nr = New-Object System.Numerics.BigInteger; $t = [System.Numerics.BigInteger]0; $nt = [System.Numerics.BigInteger]1; $r = [System.Numerics.BigInteger]$Code_Phi; $nr = [System.Numerics.BigInteger]$e; while ($nr -ne [System.Numerics.BigInteger]0) { $q = [System.Numerics.BigInteger]::Divide($r, $nr); $tmp = $nt; $nt = [System.Numerics.BigInteger]::Subtract($t, [System.Numerics.BigInteger]::Multiply($q, $nt)); $t = $tmp; $tmp = $nr; $nr = [System.Numerics.BigInteger]::Subtract($r, [System.Numerics.BigInteger]::Multiply($q, $nr)); $r = $tmp }; if ($r -gt 1) { return -1 }; if ($t -lt 0) { $t = [System.Numerics.BigInteger]::Add($t, $Code_Phi) }}
        $Text = [string]::Join('', $($(foreach ($Item in $_Arr) { [System.Numerics.BigInteger]::ModPow($Item, $2753, $_Mod) }) | ForEach-Object { [char][int]$_ }))
        return $Text
    }
    [PSCustomObject[]]Static ToPSObject([xml]$XML) {
        $Out = @(); foreach ($Object in @($XML.Objects.Object)) {
            $PSObject = [PSCustomObject]::new()
            foreach ($Property in @($Object.Property)) {
                $PSObject | Add-Member NoteProperty $Property.Name $Property.InnerText
            }
            $Out += $PSObject
        }
        return $Out
    }
    [PSCustomObject]Static ToPSObject([System.Object]$Obj) {
        $PSObj = [PSCustomObject]::new();
        $Obj | Get-Member -MemberType Properties | ForEach-Object {
            $Name = $_.Name; $PSObj | Add-Member -Name $Name -MemberType NoteProperty -Value $(if ($null -ne $Obj.$Name) { if ("Deserialized" -in (($Obj.$Name | Get-Member).TypeName.Split('.') | Sort-Object -Unique)) { $([xconvert]::ToPSObject($Obj.$Name)) } else { $Obj.$Name } } else { $null })
        }
        return $PSObj
    }
    [string]static ToProtected([string]$string) {
        $Scope = [ProtectionScope]::CurrentUser
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15];
        return [xconvert]::Tostring([xconvert]::ToProtected([xconvert]::BytesFromObject($string), $Entropy, $Scope))
    }
    [string]static ToProtected([string]$string, [ProtectionScope]$Scope) {
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15];
        return [xconvert]::Tostring([xconvert]::ToProtected([xconvert]::BytesFromObject($string), $Entropy, $Scope))
    }
    [string]static ToProtected([string]$string, [byte[]]$Entropy, [ProtectionScope]$Scope) {
        return [xconvert]::Tostring([xconvert]::ToProtected([xconvert]::BytesFromObject($string), $Entropy, $Scope))
    }
    [byte[]]static ToProtected([byte[]]$bytes, [byte[]]$Entropy, [ProtectionScope]$Scope) {
        $encryptedData = $null; # https://docs.microsoft.com/en-us/dotnet/api/System.Security.Cryptography.ProtectedData.Protect?
        try {
            if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
            $bytes64str = $null; Set-Variable -Name bytes64str -Scope Local -Visibility Private -Option Private -Value ([convert]::ToBase64String($bytes))
            $Entropy64str = $null; Set-Variable -Name Entropy64str -Scope Local -Visibility Private -Option Private -Value ([convert]::ToBase64String($Entropy))
            Set-Variable -Name encryptedData -Scope Local -Visibility Private -Option Private -Value $(Invoke-Expression "[System.Security.Cryptography.ProtectedData]::Protect([convert]::FromBase64String('$bytes64str'), [convert]::FromBase64String('$Entropy64str'), [System.Security.Cryptography.DataProtectionScope]::$($Scope.ToString()))");
        } catch [System.Security.Cryptography.CryptographicException] {
            throw [System.Security.Cryptography.CryptographicException]::new("Data was not encrypted. An error occurred!`n $($_.Exception.Message)");
        } catch {
            throw $_
        }
        return $encryptedData
    }
    [string]static ToUnProtected([string]$string, [ProtectionScope]$Scope) {
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15];
        return [xconvert]::BytesToObject([XConvert]::ToUnProtected([xconvert]::BytesFromObject($string), $Entropy, $Scope))
    }
    [string]static ToUnProtected([string]$string) {
        $Scope = [ProtectionScope]::CurrentUser
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15];
        return [xconvert]::BytesToObject([XConvert]::ToUnProtected([xconvert]::BytesFromObject($string), $Entropy, $Scope))
    }
    [string]static ToUnProtected([string]$string, [byte[]]$Entropy, [ProtectionScope]$Scope) {
        return [xconvert]::BytesToObject([XConvert]::ToUnProtected([xconvert]::BytesFromObject($string), $Entropy, $Scope))
    }
    [byte[]]static ToUnProtected([byte[]]$bytes, [byte[]]$Entropy, [ProtectionScope]$Scope) {
        $decryptedData = $null;
        try {
            if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
            $bytes64str = $null; Set-Variable -Name bytes64str -Scope Local -Visibility Private -Option Private -Value ([convert]::ToBase64String($bytes))
            $Entropy64str = $null; Set-Variable -Name Entropy64str -Scope Local -Visibility Private -Option Private -Value ([convert]::ToBase64String($Entropy))
            Set-Variable -Name decryptedData -Scope Local -Visibility Private -Option Private -Value $(Invoke-Expression "[System.Security.Cryptography.ProtectedData]::Unprotect([convert]::FromBase64String('$bytes64str'), [convert]::FromBase64String('$Entropy64str'), [System.Security.Cryptography.DataProtectionScope]::$($Scope.ToString()))");
        } catch [System.Security.Cryptography.CryptographicException] {
            throw [System.Security.Cryptography.CryptographicException]::new("Data was not decrypted. An error occurred!`n $($_.Exception.Message)");
        } catch {
            throw $_
        }
        return $decryptedData
    }
    [byte[]]static ToCompressed([byte[]]$Bytes) {
        return [xconvert]::ToCompressed($Bytes, 'Gzip');
    }
    [string]static ToCompressed([string]$Plaintext) {
        return [convert]::ToBase64String([XConvert]::ToCompressed([System.Text.Encoding]::UTF8.GetBytes($Plaintext)));
    }
    [byte[]]static ToCompressed([byte[]]$Bytes, [string]$Compression) {
        if (![bool]("$Compression" -as 'Compression')) {
            Throw [System.InvalidCastException]::new('Specified Compression is not valid.')
        }
        $outstream = [System.IO.MemoryStream]::new()
        $Comstream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($outstream, [System.IO.Compression.CompressionLevel]::Optimal) }
            Default { throw "Failed to Compress Bytes. Could Not resolve Compression!" }
        }
        [void]$Comstream.Write($Bytes, 0, $Bytes.Length); $Comstream.Close(); $Comstream.Dispose();
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    [byte[]]static ToDeCompressed([byte[]]$Bytes) {
        return [XConvert]::ToDeCompressed($Bytes, 'Gzip');
    }
    [string]static ToDecompressed([string]$Base64Text) {
        return [System.Text.Encoding]::UTF8.GetString([XConvert]::ToDecompressed([convert]::FromBase64String($Base64Text)));
    }
    [byte[]]static ToDeCompressed([byte[]]$Bytes, [string]$Compression) {
        if (![bool]("$Compression" -as 'Compression')) {
            Throw [System.InvalidCastException]::new('Specified Compression is not valid.')
        }
        $inpStream = [System.IO.MemoryStream]::new($Bytes)
        $ComStream = switch ($Compression) {
            "Gzip" { New-Object System.IO.Compression.GzipStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "Deflate" { New-Object System.IO.Compression.DeflateStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            "ZLib" { New-Object System.IO.Compression.ZLibStream($inpStream, [System.IO.Compression.CompressionMode]::Decompress); }
            Default { throw "Failed to DeCompress Bytes. Could Not resolve Compression!" }
        }
        $outStream = [System.IO.MemoryStream]::new();
        [void]$Comstream.CopyTo($outStream); $Comstream.Close(); $Comstream.Dispose(); $inpStream.Close()
        [byte[]]$OutPut = $outstream.ToArray(); $outStream.Close()
        return $OutPut;
    }
    [string]static ToRegexEscapedString([string]$LiteralText) {
        if ([string]::IsNullOrEmpty($LiteralText)) { $LiteralText = [string]::Empty }
        return [regex]::Escape($LiteralText);
    }
    [System.Collections.Hashtable]static FromRegexCapture([System.Text.RegularExpressions.Match]$Match, [regex]$Regex) {
        if (!$Match.Groups[0].Success) {
            throw New-Object System.ArgumentException('Match does not contain any captures.', 'Match')
        }
        $h = @{}
        foreach ($name in $Regex.GetGroupNames()) {
            if ($name -eq 0) {
                continue
            }
            $h.$name = $Match.Groups[$name].Value
        }
        return $h
    }
    [string]static hidden IntToString([Int]$value, [char[]]$baseChars) {
        [int]$i = 32;
        [char[]]$buffer = [Char[]]::new($i);
        [int]$targetBase = $baseChars.Length;
        do {
            $buffer[--$i] = $baseChars[$value % $targetBase];
            $value = $value / $targetBase;
        } while ($value -gt 0);
        [char[]]$result = [Char[]]::new(32 - $i);
        [Array]::Copy($buffer, $i, $result, 0, 32 - $i);
        return [string]::new($result)
    }
    [string]static BytesToHex([byte[]]$bytes) {
        #OneLiner: [string][System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary]::new($bytes).ToString().ToLowerInvariant();
        #TODO: fInd the dll Containg W3cXsd2001
        return [string][System.BitConverter]::ToString($bytes).replace('-', [string]::Empty).Tolower();
    }
    [byte[]]static BytesFromHex([string]$HexString) {
        #OneLiner: [byte[]][System.Runtime.Remoting.Metadata.W3cXsd2001.SoapHexBinary]::Parse($HexString).Value
        $outputLength = $HexString.Length / 2;
        $output = [byte[]]::new($outputLength);
        $numeral = [char[]]::new(2);
        for ($i = 0; $i -lt $outputLength; $i++) {
            $HexString.CopyTo($i * 2, $numeral, 0, 2);
            $output[$i] = [Convert]::ToByte([string]::new($numeral), 16);
        }
        return $output;
    }
    [byte[]]static BytesFromObject([object]$obj) {
        return [xconvert]::BytesFromObject($obj, $false);
    }
    [byte[]]static BytesFromObject([object]$obj, [bool]$protect) {
        if ($null -eq $obj) { return $null }; $bytes = $null;
        if ($obj.GetType() -eq [string] -and $([regex]::IsMatch([string]$obj, '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$') -and ![string]::IsNullOrWhiteSpace([string]$obj) -and !$obj.Length % 4 -eq 0 -and !$obj.Contains(" ") -and !$obj.Contains(" ") -and !$obj.Contains("`t") -and !$obj.Contains("`n"))) {
            $bytes = [convert]::FromBase64String($obj);
        } elseif ($obj.GetType() -eq [byte[]]) {
            $bytes = [byte[]]$obj
        } else {
            # Serialize the Object:
            try {
                #Use BinaryFormatter: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter?
                $bf = [System.Runtime.Serialization.Formatters.Binary.BinaryFormatter]::new();
                $ss = [System.IO.MemoryStream]::new(); # SerializationStream
                [void]$bf.Serialize($ss, $obj); # Serialise the graph
                $bytes = $ss.ToArray();
                [void]$ss.Dispose(); [void]$ss.Close();
            } catch [System.Management.Automation.MethodInvocationException], [System.Runtime.Serialization.SerializationException] {
                #Use Marshalling: https://docs.microsoft.com/en-us/dotnet/api/System.Runtime.InteropServices.Marshal?
                Write-Verbose "Object can't be serialized, Lets try Marshalling ..."; $TypeName = $obj.GetType().Name; $obj = $obj -as $TypeName
                if ($TypeName -in ("securestring", "Pscredential", "SecureCred")) { throw [System.Management.Automation.MethodInvocationException]::new("Cannot marshal an unmanaged structure") }
                [int]$size = [System.Runtime.InteropServices.Marshal]::SizeOf($obj); $bytes = [byte[]]::new($size);
                [IntPtr]$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size);
                [void][System.Runtime.InteropServices.Marshal]::StructureToPtr($obj, $ptr, $false);
                [void][System.Runtime.InteropServices.Marshal]::Copy($ptr, $bytes, 0, $size);
                [void][System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr);
            } catch {
                throw $_.Exception
            }
        }
        if ($protect) {
            # Protecteddata: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata.unprotect?
            $bytes = [byte[]][xconvert]::ToProtected($bytes);
        }
        return $bytes
    }
    [object[]]static BytesToObject([byte[]]$Bytes) {
        if ($null -eq $Bytes) { return $null }
        $bf = [System.Runtime.Serialization.Formatters.Binary.BinaryFormatter]::new()
        $ms = [System.IO.MemoryStream]::new(); $Obj = $null
        $ms.Write($Bytes, 0, $Bytes.Length);
        [void]$ms.Seek(0, [System.IO.SeekOrigin]::Begin);
        try {
            $Obj = [object]$bf.Deserialize($ms)
        } catch [System.Management.Automation.MethodInvocationException], [System.Runtime.Serialization.SerializationException] {
            $Obj = $ms.ToArray()
        } catch {
            throw $_.Exception
        }
        $ms.Dispose(); $ms.Close()
        return $Obj
    }
    [object[]]static BytesToObject([byte[]]$Bytes, [bool]$Unprotect) {
        if ($Unprotect) {
            $Bytes = [byte[]][xconvert]::ToUnProtected($Bytes)
        }
        return [XConvert]::BytesToObject($Bytes);
    }
    [System.Collections.BitArray]static BinaryFromString([string]$string) {
        [string]$BinStR = [string]::Empty;
        foreach ($ch In $string.ToCharArray()) {
            $BinStR += [Convert]::ToString([int]$ch, 2).PadLeft(8, '0');
        }
        return [xconvert]::BinaryFromBinStR($BinStR)
    }
    [string]static BinaryToString([System.Collections.BitArray]$BitArray) {
        [string]$finalString = [string]::Empty;
        # Manually read the first 8 bits and
        while ($BitArray.Length -gt 0) {
            $ba_tempBitArray = [System.Collections.BitArray]::new($BitArray.Length - 8);
            $int_binaryValue = 0;
            if ($BitArray[0]) { $int_binaryValue += 1 };
            if ($BitArray[1]) { $int_binaryValue += 2 };
            if ($BitArray[2]) { $int_binaryValue += 4 };
            if ($BitArray[3]) { $int_binaryValue += 8 };
            if ($BitArray[4]) { $int_binaryValue += 16 };
            if ($BitArray[5]) { $int_binaryValue += 32 };
            if ($BitArray[6]) { $int_binaryValue += 64 };
            if ($BitArray[7]) { $int_binaryValue += 128 };
            $finalString += [Char]::ConvertFromUtf32($int_binaryValue);
            $int_counter = 0;
            for ($i = 8; $i -lt $BitArray.Length; $i++) {
                $ba_tempBitArray[$int_counter++] = $BitArray[$i];
            }
            $BitArray = $ba_tempBitArray;
        }
        return $finalString;
    }
    [string]static BytesToBinStR([byte[]]$Bytes) {
        return [XConvert]::BytesToBinStR($Bytes, $true);
    }
    [string]static BytesToBinStR([byte[]]$Bytes, [bool]$Tidy) {
        $bitArray = [System.Collections.BitArray]::new($Bytes);
        return [XConvert]::BinaryToBinStR($bitArray, $Tidy);
    }
    [Byte[]]static BytesFromBinStR([string]$binary) {
        $binary = [string]::Join('', $binary.Split())
        $length = $binary.Length; if ($length % 8 -ne 0) {
            Throw [System.IO.InvalidDataException]::new("Your string is invalid. Make sure it has no typos.")
        }
        $list = [System.Collections.Generic.List[Byte]]::new()
        for ($i = 0; $i -lt $length; $i += 8) {
            [string]$binStr = $binary.Substring($i, 8)
            [void]$list.Add([Convert]::ToByte($binStr, 2));
        }
        return $list.ToArray();
    }
    [Byte[]]static BytesFromBinary([System.Collections.BitArray]$binary) {
        return [XConvert]::BytesFromBinStR([xconvert]::BinaryToBinStR($binary))
    }
    [string]static BinaryToBinStR([System.Collections.BitArray]$binary) {
        $BinStR = [string]::Empty # (Binary String)
        for ($i = 0; $i -lt $binary.Length; $i++) {
            if ($binary[$i]) {
                $BinStR += "1 ";
            } else {
                $BinStR += "0 ";
            }
        }
        return $BinStR.Trim()
    }
    [string]static BinaryToBinStR([System.Collections.BitArray]$binary, [bool]$Tidy) {
        [string]$binStr = [xconvert]::BinaryToBinStR($binary)
        if ($Tidy) { $binStr = [string]::Join('', $binStr.Split()) }
        return $binStr
    }
    [System.Collections.BitArray]static BinaryFromBinStR([string]$binary) {
        return [System.Collections.BitArray]::new([xconvert]::BytesFromBinStR($binary))
    }
    [void]static ObjectToFile($Object, [string]$OutFile) {
        [xconvert]::ObjectToFile($Object, $OutFile, $false);
    }
    [void]static ObjectToFile($Object, [string]$OutFile, [bool]$encrypt) {
        try {
            $OutFile = [xgen]::UnResolvedPath($OutFile)
            try {
                $resolved = [xgen]::ResolvedPath($OutFile);
                if ($?) { $OutFile = $resolved }
            } catch [System.Management.Automation.ItemNotFoundException] {
                New-Item -Path $OutFile -ItemType File | Out-Null
            } catch {
                throw $_
            }
            Export-Clixml -InputObject $Object -Path $OutFile
            if ($encrypt) { $(Get-Item $OutFile).Encrypt() }
        } catch {
            Write-Error $_
        }
    }
    [Object[]]static ToOrdered($InputObject) {
        $obj = $InputObject
        $convert = [scriptBlock]::Create({
                Param($obj)
                if ($obj -is [System.Management.Automation.PSCustomObject]) {
                    # a custom object: recurse on its properties
                    $oht = [ordered]@{}
                    foreach ($prop in $obj.psobject.Properties) {
                        $oht.Add($prop.Name, $(Invoke-Command -ScriptBlock $convert -ArgumentList $prop.Value))
                    }
                    return $oht
                } elseif ($obj -isnot [string] -and $obj -is [System.Collections.IEnumerable] -and $obj -isnot [System.Collections.IDictionary]) {
                    # A collection of sorts (other than a string or dictionary (hash table)), recurse on its elements.
                    return @(foreach ($el in $obj) { Invoke-Command -ScriptBlock $convert -ArgumentList $el })
                } else {
                    # a non-custom object, including .NET primitives and strings: use as-is.
                    return $obj
                }
            }
        )
        return $(Invoke-Command -ScriptBlock $convert -ArgumentList $obj)
    }
    [object]static ObjectFromFile([string]$FilePath) {
        return [XConvert]::ObjectFromFile($FilePath, $false)
    }
    [object]static ObjectFromFile([string]$FilePath, [string]$Type) {
        return [XConvert]::ObjectFromFile($FilePath, $Type, $false);
    }
    [object]static ObjectFromFile([string]$FilePath, [bool]$Decrypt) {
        $FilePath = [xgen]::ResolvedPath($FilePath); $Object = $null
        try {
            if ($Decrypt) { $(Get-Item $FilePath).Decrypt() }
            $Object = Import-Clixml -Path $FilePath
        } catch {
            Write-Error $_
        }
        return $Object
    }
    [object]static ObjectFromFile([string]$FilePath, [string]$Type, [bool]$Decrypt) {
        $FilePath = [xgen]::ResolvedPath($FilePath); $Object = $null
        try {
            if ($Decrypt) { $(Get-Item $FilePath).Decrypt() }
            $Object = (Import-Clixml -Path $FilePath) -as "$Type"
        } catch {
            Write-Error $_
        }
        return $Object
    }
    [byte[]]static StreamToByteArray([System.IO.Stream]$Stream) {
        $ms = [System.IO.MemoryStream]::new();
        $Stream.CopyTo($ms);
        $arr = $ms.ToArray();
        if ($null -ne $ms) { $ms.Flush(); $ms.Close(); $ms.Dispose() } else { Write-Warning "[x] MemoryStream was Not closed!" };
        return $arr;
    }
    [string]hidden static Reverse([string]$text) {
        [char[]]$array = $text.ToCharArray(); [array]::Reverse($array);
        return [String]::new($array);
    }
}
#endregion Custom_Converters

#region    PBKDF2_Hashing
<#
.SYNOPSIS
    Password String Hashing Helper Class.
.DESCRIPTION
    when a user inputs a password, instead of storing the password in cleartext, we hash the password and store the username and hash pair in the database table.
    When the user logs in, we hash the password sent and compare it to the hash connected with the provided username.
.EXAMPLE
    ## Usage Example:

    # STEP 1. Create Hash and Store it somewhere secure.
    [byte[]]$hashBytes = [PasswordHash]::new("MypasswordString").ToArray();
    [xconvert]::BytesToHex($hashBytes) | Out-File $ReallySecureFilePath;
    $(Get-Item $ReallySecureFilePath).Encrypt();

    # STEP 2. Check Password against a Stored hash.
    [byte[]]$hashBytes = [xconvert]::BytesFromHex($(Get-Content $ReallySecureFilePath));
    $hash = [PasswordHash]::new($hashBytes);
    if(!$hash.Verify("newly entered password")) { throw [System.UnauthorizedAccessException]::new() };
.NOTES
    https://stackoverflow.com/questions/51941509/what-is-the-process-of-checking-passwords-in-databases/51961121#51961121
#>
class PasswordHash {
    [byte[]]$hash # The pbkdf2 Hash
    [byte[]]$salt
    [ValidateNotNullOrEmpty()][int]hidden $SaltSize = 16
    [ValidateNotNullOrEmpty()][int]hidden $HashSize = 20 # 20 bytes length is 160 bits
    [ValidateNotNullOrEmpty()][int]hidden $HashIter = 10000 # Number of pbkdf2 iterations

    PasswordHash([string]$passw0rd) {
        $this.salt = [byte[]]::new($this.SaltSize)
        [void][System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes($this.salt)
        $this.hash = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passw0rd, $this.salt, $this.HashIter).GetBytes($this.HashSize)
    }
    PasswordHash([byte[]]$hashBytes) {
        $this.hash = [byte[]]::new($this.HashSize)
        $this.salt = [byte[]]::new($this.SaltSize)
        [void][Array]::Copy($hashBytes, 0, $this.salt, 0, $this.SaltSize)
        [void][Array]::Copy($hashBytes, $this.SaltSize, $this.hash, 0, $this.HashSize)
    }
    PasswordHash([byte[]]$salt, [byte[]]$hash) {
        $this.hash = [byte[]]::new($this.HashSize)
        $this.salt = [byte[]]::new($this.SaltSize)
        [void][Array]::Copy($salt, 0, $this.salt, 0, $this.SaltSize)
        [void][Array]::Copy($hash, 0, $this.hash, 0, $this.HashSize)
    }
    [byte[]]ToArray() {
        [byte[]]$hashBytes = [byte[]]::new($this.SaltSize + $this.HashSize);
        [void][Array]::Copy($this.salt, 0, $hashBytes, 0, $this.SaltSize);
        [void][Array]::Copy($this.hash, 0, $hashBytes, $this.SaltSize, $this.HashSize)
        return $hashBytes;
    }
    [byte[]]GetSalt() {
        return $this.salt.Clone();
    }
    [byte[]]GetHash() {
        return $this.hash.Clone();
    }
    [bool]Verify([string]$passw0rd) {
        [byte[]]$test = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passw0rd, $this.salt, $this.HashIter).GetBytes($this.HashSize); [bool]$rs = $true;
        for ($i = 0; $i -lt $this.HashSize; $i++) {
            $rs = $rs -and $(if ($test[$i] -ne $this.hash[$i]) { $false }else { $true })
        }
        return $rs
    }
}
#endregion PBKDF2_Hashing

#region    Object
# This is the Object I'll be playing around with in the [Nerdcrypt] Class.
# Its basically a wrapper to protect object bytes I use in this script.
class NcObject {
    [Type]hidden $OGType;
    [byte[]]hidden $Bytes;
    [Object]hidden $Object;
    [SdCategory]hidden $Category;
    [ProtectionScope]hidden $Scope = [ProtectionScope]::CurrentUser;

    NcObject() {}
    NcObject($Object) {
        $type = (($Object | Get-Member).Typename | Sort-Object -Unique)
        if ($type.count -eq 1) {
            $this.OGType = $type -as 'type'
        } else {
            $this.OGType = $Object.GetType();
        }
        if ($type.Equals("System.Byte")) {
            $this.Bytes = [byte[]]$Object;
        } else {
            $this.SetBytes($Object);
        }
    }
    [void]SetBytes() {
        if ([string]::IsNullOrEmpty($this.Object)) {
            throw [System.ArgumentException]::new('Object')
        }
        $this.SetBytes($this.Object);
    }
    [void]SetBytes([byte[]]$Bytes) {
        $this.Bytes = $Bytes;
    }
    [void]SetBytes([Object]$Object) {
        $this.SetBytes([xconvert]::BytesFromObject($Object));
    }
    [byte[]]GetBytes([int]$value) {
        return $this.ToLittleEndian([System.BitConverter]::GetBytes($value));
    }
    [byte[]]GetBytes([bool]$value) {
        return $this.ToLittleEndian([System.BitConverter]::GetBytes($value));
    }
    [byte[]]GetBytes([float]$value) {
        return $this.ToLittleEndian([System.BitConverter]::GetBytes($value));
    }
    [byte[]]GetBytes([double]$value) {
        return $this.ToLittleEndian([System.BitConverter]::GetBytes($value));
    }
    [byte[]]GetBytes([char]$value) {
        return $this.ToLittleEndian([System.BitConverter]::GetBytes($value));
    }
    [byte[]]GetBytes([string]$value) {
        return $this.ToLittleEndian([xconvert]::BytesFromObject($value))
    }
    [byte[]]ToLittleEndian([byte[]]$value) {
        if (![System.BitConverter]::IsLittleEndian) { [array]::Reverse($value) }
        return $value
    }
    [Byte[]]Prepend([Byte[]]$bytes, [byte[]]$bytesToPrepend) {
        $tmp = New-Object byte[] $($bytes.Length + $bytesToPrepend.Length);
        #$tmp = [Byte[]] (, 0xFF * ($bytes.Length + $bytesToPrepend.Length));
        $bytesToPrepend.CopyTo($tmp, 0);
        $bytes.CopyTo($tmp, $bytesToPrepend.Length);
        return $tmp;
    }
    [byte[][]]Shift([byte[]]$bytes, [int]$size) {
        $left = New-Object byte[] $size;
        $right = New-Object byte[] $($bytes.Length - $size);
        [Array]::Copy($bytes, 0, $left, 0, $left.Length);
        [Array]::Copy($bytes, $left.Length, $right, 0, $right.Length);
        return ($left, $right);
    }
    [void]Protect() { $this.Protect(1) }
    [void]Protect([int]$iterations) {
        $_bytes = $this.Bytes; $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15]
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Protect Round [$i/$iterations]"
            $_bytes = [xconvert]::ToProtected($_bytes, $Entropy, $this.Scope)
        }
        $this.SetBytes($_bytes)
    }
    [void]UnProtect() { $this.UnProtect(1) }
    [void]UnProtect([int]$iterations) {
        $_bytes = $this.Bytes; $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15]
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] UnProtect Round [$i/$iterations]"
            $_bytes = [xconvert]::ToUnProtected($_bytes, $Entropy, $this.Scope)
        }
        $this.SetBytes($_bytes)
    }
}
#endregion Object

#region    SecureCredential
class SecureCred {
    [bool]hidden $IsProtected = $false;
    [ValidateNotNullOrEmpty()][string]$UserName = [Environment]::GetEnvironmentVariable('Username');
    [ValidateNotNullOrEmpty()][securestring]$Password = [securestring]::new();
    [ValidateNotNullOrEmpty()][string]hidden $Domain = [Environment]::GetEnvironmentVariable('USERDOMAIN');
    [ValidateSet('CurrentUser', 'LocalMachine')][ValidateNotNullOrEmpty()][string]hidden $Scope = 'CurrentUser';

    SecureCred() {}
    SecureCred([PSCredential]$PSCredential) {
        ($this.UserName, $this.Password) = ($PSCredential.UserName, $PSCredential.Password)
    }
    [void]Protect() {
        $_scope_ = [ProtectionScope]$this.Scope
        $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
        foreach ($n in $_Props_) {
            $OBJ = $this.$n
            if ($n.Equals('Password')) {
                $this.$n = [XConvert]::ToSecurestring([xconvert]::StringToCustomCipher([xconvert]::ToProtected([xconvert]::Tostring($OBJ), $_scope_)))
            } else {
                $this.$n = [xconvert]::ToProtected($OBJ, $_scope_)
            }
        }
        Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                    $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $true }))
                }
            )
        )
    }
    [void]UnProtect() {
        $_scope_ = [ProtectionScope]$this.Scope
        $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
        foreach ($n in $_Props_) {
            $OBJ = $this.$n
            if ($n.Equals('Password')) {
                $this.$n = [xconvert]::ToSecurestring([xconvert]::ToUnProtected([xconvert]::StringFromCustomCipher([xconvert]::Tostring($OBJ)), $_scope_));
            } else {
                $this.$n = [xconvert]::ToUnProtected($OBJ, $_scope_);
            }
        }
        Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                    $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $false }))
                }
            )
        )
    }
    [void]SaveToVault() {}
    [string]ToString() {
        $str = $this.UserName
        if ($str.Length -gt 9) { $str = $str.Substring(0, 6) + '...' }
        return $str
    }
}
#endregion SecureCredential

#region    securecodes~Expirity
Class Expirity {
    [Datetime]$Date
    [Timespan]$TimeSpan
    [String]$TimeStamp
    [ExpType]$Type

    Expirity() {
        $this.TimeSpan = [Timespan]::FromMilliseconds([DateTime]::Now.Millisecond)
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expirity([int]$Years) {
        # ($Months, $Years) = if ($Years -eq 1) { (12, 0) }else { (0, $Years) };
        # $CrDate = [datetime]::Now;
        # $Months = [int]($CrDate.Month + $Months); if ($Months -gt 12) { $Months -= 12 };
        $this.TimeSpan = [Timespan]::new((365 * $years), 0, 0, 0);
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expirity([int]$Years, [int]$Months) {
        $this.TimeSpan = [Timespan]::new((365 * $years + $Months * 30), 0, 0, 0);
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expirity([datetime]$date) {
        $this.Date = $date
        $this.TimeSpan = $date - [datetime]::Now;
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expirity([System.TimeSpan]$TimeSpan) {
        $this.TimeSpan = $TimeSpan;
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expirity([int]$hours, [int]$minutes, [int]$seconds) {
        $this.TimeSpan = [Timespan]::new($hours, $minutes, $seconds);
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expirity([int]$days, [int]$hours, [int]$minutes, [int]$seconds) {
        $this.TimeSpan = [Timespan]::new($days, $hours, $minutes, $seconds)
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    [void]setTimeStamp([System.TimeSpan]$TimeSpan) {
        if ($null -eq $this.Date) {
            $this.TimeStamp = [DateTime]::Now.Add([Timespan]::FromMilliseconds($TimeSpan.TotalMilliseconds)).ToString("yyyyMMddHHmmssffff");
        } else {
            $this.TimeStamp = $this.Date.ToString("yyyyMMddHHmmssffff")
        }
    }
    [void]hidden setExpType([Timespan]$TimeSpan) {
        $this.Type = switch ($true) {
            ($TimeSpan.Days -ge 365) { [ExpType]::Years; break }
            ($TimeSpan.Days -ge 30) { [ExpType]::Months; break }
            ($TimeSpan.Days -ge 1) { [ExpType]::Days; break }
            ($TimeSpan.Hours -ge 1) { [ExpType]::Hours; break }
            ($TimeSpan.Minutes -ge 1) { [ExpType]::Minutes; break }
            ($TimeSpan.Seconds -ge 1) { [ExpType]::Seconds; break }
            Default { [ExpType]::Milliseconds; break }
        }
    }
    [int]GetDays () {
        return $this.TimeSpan.Days
    }
    [int]GetMonths () {
        return [int]($this.TimeSpan.Days / 30)
    }
    [int]GetYears () {
        return [int]($this.TimeSpan.Days / 365)
    }
    [string]ToString() {
        if ($null -eq $this.Date) { return [string]::Empty }
        return $this.Date.ToString();
    }
}
#endregion securecodes~Expirity

#region    Usual~Algorithms

#region    Aes~algo
class AesLg {
    [ValidateNotNullOrEmpty()][byte[]]hidden static $Bytes;
    [ValidateNotNullOrEmpty()][System.Security.Cryptography.Aes]hidden static $Algo;
    [ValidateNotNullOrEmpty()][byte[]]hidden static $rgbSalt;

    AesLg() {
        [AesLg]::rgbSalt = [System.Text.Encoding]::UTF7.GetBytes('^;aq8nP#*A(j 8u[HiFH.Fm,7ykX5F$pEk,baM;m^"j<DYCj":8GTN)BGlA)zWP@C#D|O/A!Ccm8o\|(mRcnX_ qTj=;iY3+.u9CNv[/aHgObS\smT$39<4F=k">r"6dM-"VmSE}Y8s#>3geZnPE&}KNseg(-X{LU2v"i9kV>g:s8{;<4;9fTzG=n/ARV#Cq69]SBhj^-D@K<ci)Gv]G');
    }
    AesLg([System.Object]$Obj) {
        [AesLg]::SetBytes($Obj); [void][AesLg]::Create();
    }
    AesLg([System.Security.Cryptography.Aes]$aes) {
        [AesLg]::Algo = $aes; [void][AesLg]::Create();
    }
    AesLg([System.Object]$Obj, [System.Security.Cryptography.Aes]$aes) {
        [AesLg]::SetBytes($Obj); [AesLg]::Algo = $aes; [void][AesLg]::Create();
    }
    [void]static SetBytes([byte[]]$Bytes) {
        [AesLg]::Bytes = $Bytes;
    }
    [void]static SetBytes([Object]$Object) {
        [AesLg]::SetBytes([xconvert]::BytesFromObject($Object));
    }
    [byte[]]static Encrypt() {
        return [AesLg]::Encrypt(1);
    }
    [byte[]]static Encrypt([int]$iterations) {
        $d3faultP4ssW0rd = $null; Set-Variable -Name P4ssW0rd -Scope Local -Visibility Private -Option Private -Value ([xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.PasswordDeriveBytes]::new([xgen]::UniqueMachineId(), [AesLg]::rgbSalt, 'SHA1', 2).GetBytes(256 / 8))));
        $3nc = [AesLg]::Encrypt($iterations, $d3faultP4ssW0rd); Remove-Variable -Name d3faultP4ssW0rd -Scope Local -Force
        return $3nc;
    }
    [byte[]]static Encrypt([int]$iterations, [securestring]$Password) {
        return [AesLg]::Encrypt($iterations, $Password, [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_'))
    }
    [byte[]]static Encrypt([int]$iterations, [securestring]$Password, [byte[]]$Salt) {
        if ($null -eq [AesLg]::Bytes) { throw [System.ArgumentNullException]::new('bytes', 'Bytes Value cannot be null. Please first use setbytes()') }
        $_bytes = [AesLg]::Bytes;
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Encryption [$i/$iterations] ...$(
                $_bytes = [AesLg]::Encrypt($_bytes, $Password, $Salt)
            ) Done."
        }; [AesLg]::SetBytes($_bytes)
        return [AesLg]::Bytes;
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password) {
        return [AesLg]::Encrypt($Bytes, $Password, [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_'));
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        $_bytes = $Bytes; $Salt = [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_')
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Encryption [$i/$iterations] ...$(
                $_bytes = [AesLg]::Encrypt($_bytes, $Password, $Salt)
            ) Done."
        };
        return $_bytes;
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$Protect) {
        return [AesLg]::Encrypt($Bytes, $Password, [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_'), 'Gzip', $Protect);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesLg]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $false);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$Protect) {
        return [AesLg]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $Protect);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
        return [AesLg]::Encrypt($Bytes, $Password, [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_'), $Compression, $false);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
        return [AesLg]::Encrypt($Bytes, $Password, $Salt, $Compression, $false);
    }
    #A simple method that takes plainBytes and Password then return an AES encrypted bytes.
    #No other Technical parameters or anything, just your Plaintext and [securestring]Password. The password is used to generate derived Key.
    #The encryption uses AES-256 (The str0ng3st Encryption In z3 WOrLd!) and uses SHA1 to hash since it has been proven to be more secure than MD5.
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$Protect) {
        [int]$PasswordIterations = 2; [int]$KeySize = 256; $CryptoProvider = $null; $EncrBytes = $null
        if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") }
        Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
        $CryptoProvider.KeySize = [int]$KeySize;
        $CryptoProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $CryptoProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $CryptoProvider.Key = [System.Security.Cryptography.PasswordDeriveBytes]::new([xconvert]::ToString($Password), $Salt, "SHA1", $PasswordIterations).GetBytes($KeySize / 8);
        $CryptoProvider.IV = [System.Text.Encoding]::ASCII.GetBytes([xconvert]::Reverse($('c#*Y!/JVe?d)b' + [convert]::ToBase64String($Salt))))[0..15];
        Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.IV + $CryptoProvider.CreateEncryptor().TransformFinalBlock($Bytes, 0, $Bytes.Length));
        if ($Protect) { $EncrBytes = [xconvert]::ToProtected($EncrBytes, $Salt, [ProtectionScope]::CurrentUser) }
        Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToCompressed($EncrBytes, $Compression));
        $CryptoProvider.Clear(); $CryptoProvider.Dispose()
        return $EncrBytes
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [System.Security.Cryptography.Aes]$aes) {
        return [AesLg]::Encrypt($Bytes, $aes, 'Gzip', 1);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [System.Security.Cryptography.Aes]$aes, [int]$iterations) {
        return [AesLg]::Encrypt($Bytes, $aes, 'Gzip', $iterations);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [System.Security.Cryptography.Aes]$aes, [string]$Compression, [int]$iterations) {
        Write-Verbose "[+] Starting Encryption..$(
            if ($null -eq $aes) { throw [System.ArgumentNullException]::new('SymetricAlgorithm') }
            if ($null -eq $bytes) { throw [System.ArgumentNullException]::new('Bytes to Encrypt', 'Bytes Value cannot be null. Please first set bytes variable.') }
            if ($iterations -le 0) { throw [System.ArgumentException]::new('Zero or Negative iteration counts are not alowed!', [System.ArgumentException]::new()) }
        )Done."
        $_bytes = $bytes; $CryptoProvider = $null; $EncrBytes = $null
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Encryption [$i/$iterations] ...$(
                    Set-Variable -Name _bytes -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToCompressed(
                        $(  if ($null -eq $_Bytes) { Throw [System.ArgumentNullException]::New('Bytes') }
                            Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
                            Get-Member -InputObject $CryptoProvider | Where-Object {$_.MemberType -eq 'Property' -and $_.Name -notin ('LegalBlockSizes', 'LegalKeySizes')} | ForEach-Object {$CryptoProvider.($_.Name) = $aes.($_.Name)}
                            Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value ($CryptoProvider.IV + $CryptoProvider.CreateEncryptor($aes.Key, $aes.IV).TransformFinalBlock($_Bytes, 0, $_Bytes.Length))
                            $CryptoProvider.Clear(); $CryptoProvider.Dispose(); $EncrBytes
                        ), $Compression
                    )
                );
            ) Done.";
        }
        if ($bytes.Equals($_bytes)) { $_bytes = $null }
        return $_bytes;
    }

    [byte[]]static Decrypt() {
        return [AesLg]::Decrypt(1)
    }
    [byte[]]static Decrypt([int]$iterations) {
        $d3faultP4ssW0rd = $null; Set-Variable -Name P4ssW0rd -Scope Local -Visibility Private -Option Private -Value ([xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.PasswordDeriveBytes]::new([xgen]::UniqueMachineId(), [AesLg]::rgbSalt, 'SHA1', 2).GetBytes(256 / 8))));
        $d3c = [AesLg]::Decrypt($iterations, $d3faultP4ssW0rd); Remove-Variable -Name d3faultP4ssW0rd -Scope Local -Force
        return $d3c
    }
    [byte[]]static Decrypt([int]$iterations, [securestring]$Password) {
        return [AesLg]::Decrypt($iterations, $Password, [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_'))
    }
    [byte[]]static Decrypt([int]$iterations, [SecureString]$Password, [byte[]]$salt) {
        if ($null -eq [AesLg]::Bytes) { throw [System.ArgumentNullException]::new('bytes', 'Bytes Value cannot be null. Please first use setbytes()') }
        $_bytes = [AesLg]::Bytes;
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Decryption [$i/$iterations] ...$(
                $_bytes = [AesLg]::Decrypt($_bytes, $Password, $salt)
            ) Done"
        }; [AesLg]::SetBytes($_bytes);
        return [AesLg]::Bytes;
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password) {
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, 'Gzip');
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [int]$iterations) {
        $_bytes = $bytesToDecrypt; $Salt = [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_')
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Decryption [$i/$iterations] ...$(
                $_bytes = [AesLg]::Decrypt($_bytes, $Password, $Salt)
            ) Done."
        };
        return $_bytes;
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [bool]$UnProtect) {
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_'), 'GZip', $UnProtect);
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [byte[]]$Salt) {
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, $Salt, 'GZip', $false);
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [byte[]]$Salt, [bool]$UnProtect) {
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, $Salt, 'GZip', $UnProtect);
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, $Salt, $Compression, $false);
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [string]$Compression) {
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, [System.Text.Encoding]::ASCII.GetBytes('o=;.f9^#d]mVB<]_'), $Compression, $false);
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$UnProtect) {
        [int]$PasswordIterations = 2; [int]$KeySize = 256; $CryptoProvider = $null; $DEcrBytes = $null; $_Bytes = $null
        $_Bytes = [XConvert]::ToDeCompressed($bytesToDecrypt, $Compression);
        if ($UnProtect) { $_Bytes = [xconvert]::ToUnProtected($_Bytes, $Salt, [ProtectionScope]::CurrentUser) }
        Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
        $CryptoProvider.KeySize = $KeySize;
        $CryptoProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $CryptoProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $CryptoProvider.Key = [System.Security.Cryptography.PasswordDeriveBytes]::new([xconvert]::ToString($Password), $Salt, "SHA1", $PasswordIterations).GetBytes($KeySize / 8);
        $CryptoProvider.IV = $_Bytes[0..15];
        Set-Variable -Name DEcrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.CreateDecryptor().TransformFinalBlock($_Bytes, 16, $_Bytes.Length - 16))
        $CryptoProvider.Clear(); $CryptoProvider.Dispose();
        return $DEcrBytes
    }
    [byte[]]static Decrypt([byte[]]$Bytes, [System.Security.Cryptography.Aes]$aes) {
        return [AesLg]::Decrypt($Bytes, $aes, 'Gzip', 1);
    }
    [byte[]]static Decrypt([byte[]]$Bytes, [System.Security.Cryptography.Aes]$aes, [int]$iterations) {
        return [AesLg]::Decrypt($Bytes, $aes, 'Gzip', $iterations)
    }
    [byte[]]static Decrypt([byte[]]$Bytes, [System.Security.Cryptography.Aes]$aes, [string]$Compression, [int]$iterations) {
        Write-Verbose "[+] Starting Decryption..$(
            if ($null -eq $aes) {throw [System.ArgumentNullException]::new('SymetricAlgorithm')}
            if ($null -eq $bytes) { throw [System.ArgumentNullException]::new('Bytes to Decrypt', 'Bytes Value cannot be null. Please first set bytes variable.') }
            if ($iterations -le 0) { throw [System.ArgumentException]::new('Zero or Negative iteration counts are not alowed!', [System.ArgumentException]::new()) }
        )Done."
        $_bytes = $bytes; $CryptoProvider = $null; $DEcrBytes = $null
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            if ($null -eq $_bytes) { Throw [System.ArgumentNullException]::New('Bytes') }
            Write-Verbose "[+] Decryption [$i/$iterations] ...$(
                    Set-Variable -Name _bytes -Scope Local -Visibility Private -Option Private -Value $(
                        Set-Variable -Name _bytes -Scope Local -Visibility Private -Option Private -Value ([xconvert]::ToDeCompressed($_Bytes, $Compression));
                        Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
                        Get-Member -InputObject $CryptoProvider | Where-Object {$_.MemberType -eq 'Property' -and $_.Name -notin ('LegalBlockSizes', 'LegalKeySizes')} | ForEach-Object {$CryptoProvider.($_.Name) = $aes.($_.Name)}
                        Set-Variable -Name DEcrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.CreateDecryptor($aes.Key, $aes.IV).TransformFinalBlock($_bytes, 16, $_bytes.Length - 16))
                        $CryptoProvider.Clear(); $CryptoProvider.Dispose(); $DEcrBytes
                    );
                ) Done.";
        }
        if ($bytes.Equals($_bytes)) { $_bytes = $null }
        return $_bytes;
    }
    [AesLg]static Create() { return [AesLg]::new() }
    [bool]hidden IsValid() {
        return [bool]$(try { [AesLg]::CheckProps($this); $? } catch { $false })
    }
    [void]static CheckProps([AesLg]$AesLg) {
        $MissingProps = @(); $throw = $false
        Write-Verbose "[+] Checking Encryption Properties ... $(('Mode','Padding', 'keysize', 'BlockSize') | ForEach-Object { if ($null -eq $AesLg.Algo.$_) { $MissingProps += $_ } };
            if ($MissingProps.Count -eq 0) { "Done. All AES Props are Good." } else { $throw = $true; "System.ArgumentNullException: $([string]::Join(', ', $MissingProps)) cannot be null." }
        )"
        if ($throw) { throw [System.ArgumentNullException]::new([string]::Join(', ', $MissingProps)) }
    }
    [string]Tostring() {
        if ($null -eq [AesLg]::Bytes) { return [string]::Empty }
        return [string][xconvert]::ToString([AesLg]::Bytes, '');
    }
}
#endregion Aes~algo

#region    rng~algo
class RNGlg : NcObject {
    [string]hidden $String;
    [string]hidden $Password;
    [byte[]]hidden $IV;
    [System.Security.Cryptography.Rfc2898DeriveBytes]hidden $K2; # tod0: Find a way to store in vault as base64key

    RNGlg () {
        # if ($null -eq $this.Bytes) { $this.SetBytes("This is plaintext message.") } # Uncomment, when Testing stuff
    }

    [byte[]]Encrypt() {
        if ($null -eq $this.Bytes) {
            throw ([System.ArgumentNullException]::new('$this.Bytes'));
        }
        $this.SetBytes($this.Encrypt($this.Bytes, $this.String));
        return $this.Bytes;
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt) {
        if ([string]::IsNullOrEmpty($this.String)) {
            $this.SetString();
            # $this.Password
        }
        return $this.Encrypt($bytesToEncrypt, $this.String);
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring[]]$passwordargs) {
        return $($this.Encrypt($bytesToEncrypt, $passwordargs, 1000));
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring[]]$passwordargs, [int]$Iterations) {
        $passCodeargs = [string[]][XConvert]::ToString($passwordargs[0]); # I just USE THE FIRST one in the array (For now).
        return $($this.Encrypt($bytesToEncrypt, $passCodeargs, $Iterations));
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [string[]]$passCodeargs) {
        return $this.Encrypt($bytesToEncrypt, $passCodeargs, 1000);
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [string[]]$passCodeargs, [int]$Iterations) {
        if ($passCodeargs.Length -eq 0) {
            throw "`nYou must specify the password for encryption.`n";
        }
        [string]$pwd1 = $passCodeargs[0]; # I just USE THE FIRST one in the array (For now).
        [byte[]]$salt1 = [byte[]]::new(8); # Create a byte array to hold the random value.
        $rngCsp = [System.Security.Cryptography.RNGCryptoServiceProvider]::new();
        $rngCsp.GetBytes($salt1); # Fill the array with a random value.
        # The default iteration count is 1000 so the two methods use the same iteration count.
        $k1 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($pwd1, $salt1, $Iterations);
        $this.K2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($pwd1, $salt1); # The real key to use when decrypting.
        # Encrypt the data.
        $encAlg = [System.Security.Cryptography.AesCng]::Create(); # Create enc~ algorithm
        $encAlg.Key = $k1.GetBytes(16);
        $this.IV = $encAlg.IV;
        $encryptionStream = [System.IO.MemoryStream]::new();
        $encrypt = [System.Security.Cryptography.CryptoStream]::new($encryptionStream, $encAlg.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write);
        # $bytesToEncrypt = [byte[]]$utfD1 = new System.Text.UTF8Encoding($false).GetBytes($data1);
        $encrypt.Write($bytesToEncrypt, 0, $bytesToEncrypt.Length);
        $encrypt.FlushFinalBlock();
        $encrypt.Close();
        [byte[]]$edata1 = [byte[]]$encryptionStream.ToArray();
        $k1.Reset();
        return $edata1
    }
    [byte[]]Decrypt() {
        return $this.Decrypt($this.Bytes);
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt) {
        return $this.Decrypt($bytesToDecrypt, $this.K2.GetBytes(16));
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt, [byte[]]$key) {
        $decAlg = [System.Security.Cryptography.AesCng]::Create(); # Create enc~ algorithm
        $decAlg.Key = $key;
        $decAlg.IV = $this.IV;
        $decryptionStream = [System.IO.MemoryStream]::new();
        $decrypt = [System.Security.Cryptography.CryptoStream]::new($decryptionStream, $decAlg.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write);
        $decrypt.Write($bytesToDecrypt, 0, $bytesToDecrypt.Length);
        $decrypt.Flush();
        $decrypt.Close();
        $this.K2.Reset();
        return [byte[]]($decryptionStream.ToArray());
    }
    [string]Tostring() {
        if ($null -eq $this.Bytes) { return [string]::Empty }
        return [string][NcObject]::new().ToString($this.Bytes);
    }
}
#endregion rng~algo

#region    RSA~algo
class RSAlg : NcObject {
    [string]$String
    [ValidateNotNullOrEmpty()][X509cr]$X509cr
    RSAlg () {
        $this._init()
    }
    RSAlg ([byte[]]$Bytes) {
        $this.Bytes = $Bytes
        $this._init()
    }
    RSAlg ([X509cr]$X509cr) {
        $this.X509cr = $X509cr
        $this._init()
    }
    RSAlg ([System.Security.Cryptography.X509Certificates.X509Certificate2]$X509Certificate2) {
        $this._init()
        $this.X509cr.Cert = $X509Certificate2
    }
    RSAlg ([System.Security.Cryptography.X509Certificates.X509Certificate2]$X509Certificate2, [System.Security.Cryptography.RSAEncryptionPadding]$Padding) {
        $this._init()
        ($this.X509cr.Cert, $this.X509cr.KeyPadding) = ($X509Certificate2, $Padding)
    }
    [byte[]]Encrypt() {
        if ($null -eq $this.Bytes) { $this.SetBytes() };
        $this.SetBytes($this.Encrypt($this.Bytes, $this.X509cr.Cert));
        return $this.Bytes;
    }
    [byte[]]Decrypt() {
        if ($null -eq $this.Bytes) { throw [System.ArgumentException]::new('Null Byte array can not be decrypted!', 'Bytes') };
        if ($null -eq $this.X509cr.Cert) { throw [System.ArgumentException]::new('Can not use Null X509Certificate', 'X509cr.Cert') };
        $this.SetBytes($this.Decrypt($this.Bytes, $this.X509cr.Cert))
        return $this.Bytes;
    }
    [byte[]]Encrypt([byte[]]$PlainBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        if ($null -eq $this.X509cr.KeyPadding) {
            Write-Verbose "[+] Use a Random 'RSAEncryption KeyPadding' ..."
            $this.X509cr.KeyPadding = [X509cr]::GetRSAPadding();
        }
        [byte[]]$encryptedBytes = $Cert.PublicKey.Key.Encrypt($PlainBytes, $this.X509cr.KeyPadding);
        return $encryptedBytes
    }
    [byte[]]Decrypt([string]$Base64String, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        [byte[]]$encryptedBytes = [Convert]::FromBase64String($Base64String);
        return $this.Decrypt($encryptedBytes, $Cert);
    }
    [byte[]]Decrypt([byte[]]$encryptedBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        $PrivateKey = $Cert.PrivateKey;
        [byte[]]$decryptedBytes = $PrivateKey.Decrypt($encryptedBytes, $this.X509cr.KeyPadding);
        return $decryptedBytes
    }
    [void]hidden _init () {
        if ($null -eq $this.X509cr) { $this.X509cr = [X509cr]::new() }
        if ($null -eq $this.X509cr.Cert) { $this.X509cr.CreateCertificate() }
        if ([string]::IsNullOrEmpty($this.String)) {
            $this.String = "TestSTR:$([xgen]::RandomName(69))"; # For Testing Purposes
        }
    }
}

[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class X509cr {
    [string]$Type = 'Custom';
    [securestring]$Pin;
    [string]hidden $upn = "alain.1337dev@outlook.com";
    [string]$StoreLocation;
    [System.Int32]hidden $KeyLength = 2048;
    [System.DateTime]hidden $NotAfter;
    [string]$Subject = "Nerdcrypt"
    [System.Security.Cryptography.RSAEncryptionPadding]$KeyPadding;
    [System.Security.Cryptography.X509Certificates.X509ExtensionCollection]$Extensions;
    [ValidateSet('NonExportable', 'ExportableEncrypted', 'Exportable')][string]$KeyExportPolicy;
    [ValidateSet('None', 'Protect', 'ProtectHigh', 'ProtectFingerPrint')][string]$KeyProtection;
    [ValidateNotNullOrEmpty()][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert;
    [ValidateSet('None', 'EncipherOnly', 'CRLSign', 'CertSign', 'KeyAgreement', 'DataEncipherment', 'KeyEncipherment', 'NonRepudiation', 'DigitalSignature', 'DecipherOnly')][string]$KeyUsage;
    [string[]]hidden static $_validRSAPaddings_ = 'Pkcs1', 'OaepSHA1', 'OaepSHA256', 'OaepSHA384', 'OaepSHA512'
    [string]$Path

    X509cr () {
        $this._init()
    }
    X509cr ([string]$Type, [securestring]$Pin) {
        ($this.Type, $this.Pin) = ($Type, $Pin)
        $this._init()
    }
    X509cr ([string]$Type, [string]$CertStoreLocation, [securestring]$Pin) {
        ($this.Type, $this.StoreLocation, $this.Pin) = ($Type, $CertStoreLocation, $Pin)
        $this._init()
    }
    X509cr ([string]$Type, [string]$Subject, [string]$CertStoreLocation, [securestring]$Pin) {
        ($this.Type, $this.Subject, $this.StoreLocation, $this.Pin) = ($Type, $Subject, $CertStoreLocation, $Pin)
        $this._init()
    }
    X509cr ([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
        $this.Cert = $Certificate
        $this._init()
    }
    X509cr ([string]$Type, [string]$Subject, [string]$CertStoreLocation, [securestring]$Pin, [System.DateTime]$ExpirityDate) {
        ($this.Type, $this.Subject, $this.StoreLocation, $this.Pin, $this.Expirity) = ($Type, $Subject, $CertStoreLocation, $Pin, $ExpirityDate)
        $this._init()
    }
    [System.Security.Cryptography.X509Certificates.X509Certificate2]CreateCertificate() {
        if (![bool]("Microsoft.CertificateServices.Commands.KeyExportPolicy" -as [Type])) {
            Write-Verbose "[+] Load all necessary assemblies." # By Creating a dumy cert and delete it. This loads all necessary assemblies to create certificates; It worked for me!
            $DummyName = 'dummy-' + [Guid]::NewGuid().Guid; $DummyCert = New-SelfSignedCertificate -Type Custom -Subject "CN=$DummyName" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=dummy@contoso.com") -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My";
            $DummyCert.Dispose(); Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.subject -eq "CN=$DummyName" } | Remove-Item
        }
        Write-Verbose "[+] Creating New SelfSigned Certificate ..."
        $Params = @{
            Type              = $this.Type
            Subject           = "CN=$($this.subject)"
            TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=$($this.upn)")
            KeyExportPolicy   = Invoke-Expression "[Microsoft.CertificateServices.Commands.KeyExportPolicy]::$($this.KeyExportPolicy)"
            KeyUsage          = Invoke-Expression "[Microsoft.CertificateServices.Commands.KeyUsage]::$($this.KeyUsage)"
            KeyAlgorithm      = 'RSA'
            KeyLength         = $this.KeyLength
            CertStoreLocation = $this.StoreLocation
            KeyProtection     = Invoke-Expression "[Microsoft.CertificateServices.Commands.KeyProtection]::$($this.KeyProtection)"
            Pin               = if ($null -eq $this.Pin) { Read-Host -Prompt "New Certificate PIN" -AsSecureString } else { [securestring]$this.Pin }
            NotAfter          = [System.DateTime]$this.NotAfter
        }
        $this.Cert = New-SelfSignedCertificate @Params
        $this.Path = "{0}\{1}" -f $this.StoreLocation, $this.Cert.Thumbprint
        Write-Verbose "[+] Created $($this.Path)"
        return $this.Cert
    }
    [System.Security.Cryptography.RSAEncryptionPadding]static GetRSAPadding () {
        return $(Invoke-Expression "[System.Security.Cryptography.RSAEncryptionPadding]::$([X509cr]::_validRSAPaddings_ | Get-Random)")
    }
    [System.Security.Cryptography.RSAEncryptionPadding]static GetRSAPadding([string]$Padding) {
        if ($Padding -notin [X509cr]::_validRSAPaddings_) {
            throw "Value Not in Validateset."
        } else {
            return $(Invoke-Expression "[System.Security.Cryptography.RSAEncryptionPadding]::$Padding")
        }
    }
    [System.Security.Cryptography.RSAEncryptionPadding]static GetRSAPadding([System.Security.Cryptography.RSAEncryptionPadding]$Padding) {
        $validPaddings = [X509cr]::_validRSAPaddings_ | ForEach-Object { "{0}$_" }; Set-Variable -Name validPaddings -Visibility Public -Scope Local -Option ReadOnly -Value $($validPaddings | ForEach-Object { Invoke-Expression ($_ -f "[System.Security.Cryptography.RSAEncryptionPadding]::") });
        if ($Padding -notin $validPaddings) {
            throw "Value Not in Validateset."
        } else {
            return $Padding
        }
    }
    [void]hidden _init() {
        if ($null -eq $this.Pin) { $this.Pin = [xconvert]::ToSecurestring([xgen]::RandomSTR('01233456789', 3, 4, 4)) } # Use A random PIN
        if ($null -eq $this.KeyExportPolicy) { $this.KeyExportPolicy = 'ExportableEncrypted' }
        if ($null -eq $this.KeyProtection) { $this.KeyProtection = 'ProtectHigh' }
        if ($null -eq $this.KeyUsage) { $this.KeyUsage = 'DataEncipherment' }
        if ($null -eq $this.KeyPadding) { $this.KeyPadding = [X509cr]::GetRSAPadding() }
        if ($null -eq $this.NotAfter) { $this.NotAfter = [Expirity]::new(0, 1).Date } # 30 Days
        if ($null -eq $this.StoreLocation) { $this.StoreLocation = "Cert:\CurrentUser\My" }
        if ($null -eq $this.Path) { $this.Path = "{0}\{1}" -f $this.StoreLocation, $this.Cert.Thumbprint }
    }
}
#endregion RSA~algo

#region    TripleDES
class TDES : NcObject {
    [string]hidden $String = "This is plaintext message.";
    [byte[]]hidden $Key
    [byte[]]hidden $IV
    TDES() {
        if ($null -eq $this.Bytes) { $this.SetBytes($this.String) } # Uncomment, when Testing stuff
    }
    [byte[]]Encrypt() {
        return $this.Encrypt(1);
    }
    [byte[]]Decrypt() {
        return $this.Decrypt(1);
    }
    [byte[]]Encrypt([int]$iterations) {
        if ($null -eq $this.Bytes) { throw ([System.ArgumentNullException]::new('$this.Bytes')) }
        return $this.Encrypt($this.Bytes, $this.Key, $this.IV, $iterations)
    }
    [byte[]]Decrypt([int]$iterations) {
        if ($null -eq $this.Bytes) { throw ([System.ArgumentNullException]::new('$this.Bytes')) }
        if ($null -eq $this.Key) { throw ([System.ArgumentNullException]::new('$this.Key')) }
        if ($null -eq $this.IV) { throw ([System.ArgumentNullException]::new('$this.IV')) }
        return $this.Decrypt($this.Bytes, $this.Key, $this.IV, $iterations)
    }
    [byte[]]Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
        return $this.Encrypt($data, $Key, $IV, 1)
    }
    [byte[]]Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
        for ($i = 1; $i -le $iterations; $i++) {
            $this.SetBytes($this.Get_ED($data, $Key, $IV, $true));
        }
        return $this.Bytes
    }
    [byte[]]Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
        return $this.Decrypt($data, $Key, $IV, 1);
    }
    [byte[]]Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
        for ($i = 1; $i -le $iterations; $i++) {
            $this.SetBytes($this.Get_ED($data, $Key, $IV, $false));
        }
        return $this.Bytes
    }
    [byte[]]hidden Get_ED([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [bool]$IEncryption) {
        $ms = [System.IO.MemoryStream]::new(); $cs = $null
        $result = [byte[]]::new(0)
        try {
            $tdes = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::new()
            ($tdes.Key, $tdes.IV) = ($this.Key, $this.IV) = $(if ($null -eq $Key -or $null -eq $IV) { [void]$tdes.GenerateKey(); [void]$tdes.GenerateIV(); ($tdes.Key, $tdes.IV) } else { ($Key, $IV) })
            $CryptoTransform = [System.Security.Cryptography.ICryptoTransform]$(if ($IEncryption) { $tdes.CreateEncryptor() }else { $tdes.CreateDecryptor() })
            $cs = [System.Security.Cryptography.CryptoStream]::new($ms, $CryptoTransform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            [void]$cs.Write($data, 0, $data.Length)
            [void]$cs.FlushFinalBlock()
            $ms.Position = 0
            $result = [Byte[]]::new($ms.Length)
            [void]$ms.Read($result, 0, $ms.Length)
        } catch [System.Security.Cryptography.CryptographicException] {
            if ($_.exception.message -notlike "*data is not a complete block*") { throw $_.exception }
        } finally {
            Invoke-Command -ScriptBlock { $cs.Close(); $ms.Dispose() } -ErrorAction SilentlyContinue
        }
        return $result
    }
}
#endregion TripleDES

#region    XOR
class XOR {
    [ValidateNotNullOrEmpty()][NcObject]$Object;
    [ValidateNotNullOrEmpty()][SecureString]$Password;
    [ValidateNotNullOrEmpty()][byte[]]static hidden $Salt = [System.Text.Encoding]::UTF7.GetBytes('\SBOv!^L?XuCFlJ%*[6(pUVp5GeR^|U=NH3FaK#XECOaM}ExV)3_bkd:eG;Z,tWZRMg;.A!,:-k6D!CP>74G+TW7?(\6;Li]lA**2P(a2XxL}<.*oJY7bOx+lD>%DVVa');
    XOR() {
        $this.Object = [NcObject]::new();
        $this.Password = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.PasswordDeriveBytes]::new([xgen]::UniqueMachineId(), [XOR]::Salt, 'SHA1', 2).GetBytes(256 / 8)))
    }
    XOR([Object]$object) {
        $this.Object = [NcObject]::new($object);
        $this.Password = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.PasswordDeriveBytes]::new([xgen]::UniqueMachineId(), [XOR]::Salt, 'SHA1', 2).GetBytes(256 / 8)))
    }
    [byte[]]Encrypt() {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
        $this.Object.Bytes = [byte[]][XOR]::Encrypt($this.Object.Bytes, $this.Password);
        return $this.Object.Bytes
    }
    [byte[]]Encrypt([int]$iterations) {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('key')) }
        $this.Object.Bytes = [byte[]][XOR]::Encrypt($this.Object.Bytes, $this.Password, $iterations)
        return $this.Object.Bytes
    }
    [byte[]]static Encrypt([byte[]]$bytes, [String]$Passw0rd) {
        return [XOR]::Encrypt($bytes, [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.PasswordDeriveBytes]::new($Passw0rd, [XOR]::Salt, 'SHA1', 2).GetBytes(256 / 8))), 1)
    }
    [byte[]]static Encrypt([byte[]]$bytes, [SecureString]$password) {
        return [XOR]::Encrypt($bytes, $password, 1)
    }
    [byte[]]static Encrypt([byte[]]$bytes, [SecureString]$password, [int]$iterations) {
        $xorkey = [xconvert]::BytesFromObject([xconvert]::ToString($password));
        $_bytes = $bytes;
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            $_bytes = [XOR]::Get_ED($_bytes, $xorkey);
        }; if ($_bytes.Equals($bytes)) { $_bytes = $null }
        return $_bytes
    }
    [byte[]]Decrypt() {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
        $this.Object.Bytes = [byte[]][XOR]::Decrypt($this.Object.Bytes, $this.Password);
        return $this.Object.Bytes
    }
    [byte[]]Decrypt([int]$iterations) {
        if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
        if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
        $this.Object.Bytes = [byte[]][XOR]::Decrypt($this.Object.Bytes, $this.Password, $iterations);
        return $this.Object.Bytes
    }
    #!Not Recommended!
    [byte[]]static Decrypt([byte[]]$bytes, [String]$Passw0rd) {
        return [XOR]::Decrypt($bytes, [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.PasswordDeriveBytes]::new($Passw0rd, [XOR]::Salt, 'SHA1', 2).GetBytes(256 / 8))), 1);
    }
    [byte[]]static Decrypt([byte[]]$bytes, [SecureString]$password) {
        return [XOR]::Decrypt($bytes, $password, 1);
    }
    [byte[]]static Decrypt([byte[]]$bytes, [SecureString]$password, [int]$iterations) {
        $xorkey = [xconvert]::BytesFromObject([XConvert]::ToString($password))
        $_bytes = $bytes; for ($i = 1; $i -lt $iterations + 1; $i++) {
            $_bytes = [XOR]::Get_ED($_bytes, $xorkey)
        };
        return $_bytes;
    }
    [byte[]]static hidden Get_ED([byte[]]$bytes, [byte[]]$key) {
        return $(for ($i = 0; $i -lt $bytes.length) {
                for ($j = 0; $j -lt $key.length; $j++) {
                    $bytes[$i] -bxor $key[$j]
                    $i++
                    if ($i -ge $bytes.Length) {
                        $j = $key.length
                    }
                }
            }
        )
    }
}
#endregion XOR

#endregion Usual~Algorithms

#region    FileCryptography
# AES Encrypt-decrypt files.
Class FileCrypt {
    [ValidateNotNullOrEmpty()][System.IO.FileInfo]static $File
    [ValidateNotNullOrEmpty()][securestring]static $Password
    [System.string]hidden static $Compression = 'Gzip';

    FileCrypt() {}
    FileCrypt([string]$Path) {
        [FileCrypt]::File = [System.IO.FileInfo]::new([xgen]::ResolvedPath($Path))
    }
    FileCrypt([string]$Path, [SecureString]$Password) {
        [FileCrypt]::Password = $Password;
        [FileCrypt]::File = [System.IO.FileInfo]::new([xgen]::ResolvedPath($Path))
    }
    [void]static Encrypt() {
        [FileCrypt]::File = [FileCrypt]::File
        [FileCrypt]::Password = [FileCrypt]::Password
        [FileCrypt]::Encrypt([FileCrypt]::File, [FileCrypt]::File, [FileCrypt]::Password)
    }
    [void]static Encrypt([SecureString]$Password) {
        [FileCrypt]::File = [FileCrypt]::File
        [FileCrypt]::Encrypt([FileCrypt]::File, [FileCrypt]::File, $Password)
    }
    [void]static Encrypt([string]$OutFile, [SecureString]$Password) {
        [FileCrypt]::File = [FileCrypt]::File
        [FileCrypt]::Encrypt([FileCrypt]::File, $OutFile, $Password)
    }
    [void]static Encrypt([string]$InFile, [string]$OutFile, [SecureString]$Password) {
        if ($null -eq $InFile) { throw [System.ArgumentNullException]::new("InFile") }
        if ($null -eq $OutFile) { throw [System.ArgumentNullException]::new("OutFile") }
        if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
        try {
            $aes = [System.Security.Cryptography.Aes]::Create();
            $InFile = [xgen]::ResolvedPath($InFile); $OutFile = [xgen]::UnResolvedPath($OutFile)
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; # Use (Cipher Blocker Chaining) as its a more advanced block cipher encryption than the old ECB.
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
            $aes.keysize = 256; $aes.BlockSize = 128;
            $aes.Key = [xgen]::Key($Password); $aes.IV = [xgen]::RandomEntropy();
            [byte[]]$Enc = [aeslg]::Encrypt([System.IO.File]::ReadAllBytes($InFile), $aes, [FileCrypt]::Compression, 1);
            [System.IO.FileStream]$fs = [System.IO.File]::Create($OutFile);
            $fs.Write($Enc, 0, $Enc.Length)
            $fs.Flush(); $fs.Dispose()
        } catch {
            Write-Warning "Encryption failed!"
            throw $_
        } finally {
            if ($null -ne $aes) { $aes.Clear(); $aes.Dispose() }
        }
    }
    [void]static Decrypt() {
        [FileCrypt]::File = [FileCrypt]::File
        [FileCrypt]::Password = [FileCrypt]::Password
        [FileCrypt]::Decrypt([FileCrypt]::File, [FileCrypt]::File, [FileCrypt]::Password)
    }
    [void]static Decrypt([SecureString]$Password) {
        [FileCrypt]::File = [FileCrypt]::File
        [FileCrypt]::Decrypt([FileCrypt]::File, [FileCrypt]::File, $Password)
    }
    [void]static Decrypt([string]$OutFile, [SecureString]$Password) {
        [FileCrypt]::File = [FileCrypt]::File
        [FileCrypt]::Decrypt([FileCrypt]::File, $OutFile, $Password)
    }
    [void]static Decrypt([string]$InFile, [string]$OutFile, [SecureString]$Password) {
        if ($null -eq $InFile) { throw [System.ArgumentNullException]::new("InFile") }
        if ($null -eq $OutFile) { throw [System.ArgumentNullException]::new("OutFile") }
        if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
        try {
            $aes = [System.Security.Cryptography.Aes]::Create();
            $InFile = [xgen]::ResolvedPath($InFile); $OutFile = [xgen]::UnResolvedPath($OutFile)
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC;
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
            $aes.keysize = 256; $aes.BlockSize = 128;
            $aes.Key = [xgen]::Key($Password); $enc = [System.IO.File]::ReadAllBytes($InFile)
            $aes.IV = $enc[0..15]; [byte[]]$dec = [aeslg]::Decrypt($enc, $aes, [FileCrypt]::Compression, 1);
            [System.IO.FileStream]$fs = [System.IO.File]::Create($OutFile)
            $fs.Write($dec, 0, $dec.Length)
            $fs.Flush(); $fs.Dispose()
        } catch {
            Write-Warning "Decryption failed!"
            throw $_
        } finally {
            if ($null -ne $aes) { $aes.Clear(); $aes.Dispose() }
        }
    }
}
#endregion FileCryptography

#region    Custom_Cryptography_Wrapper
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class K3Y {
    [ValidateNotNullOrEmpty()][SecureCred]$User;
    [ValidateNotNullOrEmpty()][Expirity]$Expirity = [Expirity]::new(0, 1); # Default is 30 days
    [ValidateNotNullOrEmpty()][keyStoreMode]hidden $StorageMode = [KeyStoreMode]::Securestring;
    [ValidateNotNullOrEmpty()][int]hidden $_PID = $(Get-Variable -Name PID).value;
    [ValidateNotNullOrEmpty()][securestring]hidden $UID;
    [ValidateNotNullOrEmpty()][byte[]]hidden $rgbSalt = [System.Text.Encoding]::UTF7.GetBytes('hR#ho"rK6FMu mdZFXp}JMY\?NC]9(.:6;>oB5U>.GkYC-JD;@;XRgXBgsEi|%MqU>_+w/RpUJ}Kt.>vWr[WZ;[e8GM@P@YKuT947Z-]ho>E2"c6H%_L2A:O5:E)6Fv^uVE; aN\4t\|(*;rPRndSOS(7& xXLRKX)VL\/+ZB4q.iY { %Ko^<!sW9n@r8ihj*=T $+Cca-Nvv#JnaZh');

    K3Y() {
        $this.User = [SecureCred]::new([pscredential]::new($env:USERNAME, [securestring]::new())); $this.SetK3YUID();
    }
    K3Y([Datetime]$Expirity) {
        $this.User = [SecureCred]::new([pscredential]::new($env:USERNAME, [securestring]::new()));
        $this.Expirity = [Expirity]::new($Expirity); $this.SetK3YUID();
    }
    K3Y([pscredential]$User, [Datetime]$Expirity) {
        ($this.User, $this.Expirity) = ([SecureCred]::new($User), [Expirity]::new($Expirity)); $this.SetK3YUID();
    }
    K3Y([string]$UserName, [securestring]$Password) {
        $this.User = [SecureCred]::new([pscredential]::new($UserName, $Password)); $this.SetK3YUID();
    }
    K3Y([string]$UserName, [securestring]$Password, [Datetime]$Expirity) {
        ($this.User, $this.Expirity) = ([SecureCred]::new([pscredential]::new($UserName, $Password)), [Expirity]::new($Expirity)); $this.SetK3YUID();
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt) {
        return $this.Encrypt($bytesToEncrypt, [K3Y]::GetPassword());
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring]$password) {
        return $this.Encrypt($bytesToEncrypt, $password, $this.rgbSalt, 'Gzip', $this.Expirity.Date);
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring]$password, [Datetime]$Expirity) {
        return $this.Encrypt($bytesToEncrypt, $password, $this.rgbSalt, 'Gzip', $Expirity);
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring]$password, [byte[]]$salt, [string]$Compression, [Datetime]$Expirity) {
        $Password = [securestring]$this.ResolvePassword($Password);
        if (!$this.HasPasswordHash()) { $this.SetK3YUID($Password, $Expirity, $Compression, $this._PID) }
        Write-Host $([xconvert]::Tostring($Password))
        return [AesLg]::Encrypt($bytesToEncrypt, $Password, $salt);
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt) {
        return $this.Decrypt($bytesToDecrypt, [K3Y]::GetPassword());
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt, [securestring]$Password) {
        return $this.Decrypt($bytesToDecrypt, $Password, $this.rgbSalt);
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt, [securestring]$Password, [byte[]]$salt) {
        $Password = [securestring]$this.ResolvePassword($Password); # (Get The real Password)
        if (!$this.IsValid()) { throw [System.Management.Automation.PSInvalidOperationException]::new("The Operation is not valid due to Expired K3Y.") }
        $Compression = [k3Y]::AnalyseK3YUID($this, $Password)[2];
        Write-Host $([xconvert]::Tostring($Password))
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, $salt, $Compression);
    }
    [string]GetK3YIdSTR() {
        return [K3Y]::GetK3YIdSTR($this.User.Password, $this.Expirity.Date, $(Get-Random ([Enum]::GetNames('Compression' -as 'Type'))), $this._PID)
    }
    [string]static GetK3YIdSTR([securestring]$Password, [datetime]$Expirity, [string]$Compression, [int]$_PID) {
        return [string][xconvert]::BytesToHex([System.Text.Encoding]::UTF7.GetBytes([xconvert]::ToCompressed([xconvert]::StringToCustomCipher(
                        [string][K3Y]::CreateUIDstring([byte[]][XConvert]::BytesFromObject([PSCustomObject]@{
                                    KeyInfo = [xconvert]::BytesFromObject([PSCustomObject]@{
                                            Expirity = $Expirity
                                            Version  = [version]::new("1.0.0.1")
                                            User     = $env:USERNAME
                                            PID      = $_PID
                                        }
                                    )
                                    BytesCT = [AesLg]::Encrypt([System.Text.Encoding]::UTF7.GetBytes($Compression), $Password)
                                }
                            )
                        )
                    )
                )
            )
        )
    }
    [void]hidden SetK3YUID() {
        $this.UID = [securestring][xconvert]::ToSecurestring($this.GetK3YIdSTR());
    }
    [void]hidden SetK3YUID([securestring]$Password, [datetime]$Expirity, [string]$Compression, [int]$_PID) {
        # If ($null -ne $this.UID) { Write-Verbose "[+] Update UID ..." }
        # The K3Y 'UID' is a fancy way of storing the Key version, user, Compressiontype and Other Information about the most recent encryption and the person who did it, so that it can be analyzed later to verify some rules before decryption.
        $this.UID = [securestring][xconvert]::ToSecurestring([string][K3Y]::GetK3YIdSTR($Password, $Expirity, $Compression, $_PID));
    }
    [securestring]static GetPassword() {
        $ThrowOnFailure = $true
        return [K3Y]::GetPassword($ThrowOnFailure);
    }
    [securestring]static GetPassword([bool]$ThrowOnFailure) {
        $Password = $null; Set-Variable -Name Password -Scope Local -Visibility Private -Option Private -Value ($(Get-Variable Host).value.UI.PromptForCredential('NerdCrypt', "Please Enter Your Password", $env:UserName, $env:COMPUTERNAME).Password);
        if ($ThrowOnFailure -and ($null -eq $Password -or $([string]::IsNullOrWhiteSpace([xconvert]::ToString($Password))))) {
            throw [System.InvalidOperationException]::new("Please Provide a Password that is not Null Or WhiteSpace.", [System.ArgumentNullException]::new("Password"));
        }
        return $Password
    }
    [securestring]ResolvePassword([securestring]$Password) {
        $SecHash = $this.User.Password;
        if (!$this.HasPasswordHash()) {
            Invoke-Command -InputObject $this.User -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                        $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::BytesToHex(([PasswordHash]::new([xconvert]::ToString($password)).ToArray())));
                        Invoke-Expression "`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))";
                    }
                )
            )
            $SecHash = $this.User.Password;
        }
        return $this.ResolvePassword($Password, $SecHash);
    }
    [securestring]ResolvePassword([securestring]$Password, [securestring]$SecHash) {
        Write-Verbose "[+] Get Password Hash ...";
        $Passw0rd = [string]::Empty; Set-Variable -Name Passw0rd -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToString($Password));
        if ($this.VerifyPassword($Passw0rd, $SecHash)) {
            $Hash = [xconvert]::Tostring($this.User.Password);
            Write-Verbose "[-] Successfully Checked Hash: $Hash";
            # Use a 'UTF7 PasswordDerivation' instead of the real 'Password' (Just to be extra cautious.)
            return [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.PasswordDeriveBytes]::new($Passw0rd, $this.rgbSalt, 'SHA1', 2).GetBytes(256 / 8)));
        } else {
            Write-Verbose "[x] Wrong Password!";
            Throw [System.UnauthorizedAccessException]::new('Wrong Password.')
        }
    }
    [bool]HasPasswordHash() {
        return $this.HasPasswordHash($false);
    }
    [bool]static HasPasswordHash([K3Y]$k3y) {
        $ThrowOnFailure = $false
        return [K3Y]::HasPasswordHash($k3y, $ThrowOnFailure);
    }
    [bool]HasPasswordHash([bool]$ThrowOnFailure) {
        return [K3Y]::HasPasswordHash($this, $ThrowOnFailure);
    }
    [bool]static HasPasswordHash([K3Y]$k3y, [bool]$ThrowOnFailure) {
        # Verifies if The password has already been set.
        [securestring]$p = $k3y.User.Password; [bool]$HasPasswordHash = $false;
        try {
            $k3y.User.Password = [securestring]::new()
        } catch [System.Management.Automation.SetValueException] {
            $HasPasswordHash = $true
        }
        if (!$HasPasswordHash) {
            $k3y.User.Password = $p
            if ($ThrowOnFailure) {
                throw [System.ArgumentNullException]::new('Password Value cannot be null.', [System.ArgumentNullException]::new('Password'))
            }
        }
        return $HasPasswordHash
    }
    [bool]VerifyPassword([string]$Passw0rd) {
        return $this.VerifyPassword($Passw0rd, $this.User.Password, $true); # (ie: $this.User.Password is not the actual password its just a 'read-only hash' of the password used during Encryption.)
    }
    [bool]VerifyPassword([string]$Passw0rd, [securestring]$SecHash) {
        return $this.VerifyPassword($Passw0rd, $SecHash, $true);
    }
    [bool]VerifyPassword([string]$Passw0rd, [securestring]$SecHash, [bool]$ThrowOnFailure) {
        $hash = $null; [bool]$IsValid = $false; $Isvalid_Hex = $false; $_Hex = [string]::Empty ; $InnerException = [System.UnauthorizedAccessException]::new('Wrong Password.');
        try {
            Set-Variable -Name _Hex -Scope Local -Visibility Private -Option Private -Value ([xconvert]::ToString($SecHash));
            $Isvalid_Hex = [regex]::IsMatch($_Hex, "^[A-Fa-f0-9]{72}$")
            if (!$Isvalid_Hex) { Throw [System.FormatException]::new("Securestring Hash was in an invalid format.") }
            Set-Variable -Name hash -Scope Local -Visibility Private -Option Private -Value ([PasswordHash]::new([byte[]][xconvert]::BytesFromHex($_Hex)));
            if ($hash.Verify([string]$Passw0rd)) { $IsValid = $true }else {
                throw $InnerException
            }
        } catch {
            $InnerException = $_.Exception
        } finally {
            if ($ThrowOnFailure -and !$IsValid) {
                throw [System.Management.Automation.RuntimeException]::new('Error. UnauthorizedAccess', $InnerException)
            }
        }
        return $IsValid
    }
    [string]hidden static CreateUIDstring([byte[]]$bytes) {
        # 'UIDstring' containing the timestamp, expiry, Compression, rgbSalt, and other information for later analysis.
        $Key_Info = $null; $UIDstr = [string]::Empty; Set-Variable -Name Key_Info -Scope Local -Visibility Private -Option Private -Value ([XConvert]::BytesToObject($bytes));
        $Encr_BCT = [byte[]]$Key_Info.BytesCT # (Encrypted.)
        $keyInfoB = [byte[]]$Key_Info.KeyInfo # (Not Encrypted.)
        $KeyI_Obj = $null; Set-Variable -Name KeyI_Obj -Scope Local -Visibility Private -Option Private -Value ([XConvert]::BytesToObject($keyInfoB));
        $Last_PID = [int]$KeyI_Obj.PID # (Also not Encrypted.)
        if ($null -eq $Encr_BCT) { throw [System.MissingMemberException]::new('Attempted to access a missing member.', [System.ArgumentNullException]::new('Compression')) };
        if ($null -eq $Last_PID) { throw [System.MissingMemberException]::new('Attempted to access a missing member.', [System.ArgumentNullException]::new('PID')) };
        $Prefix = [string]::Empty;
        $Splitr = [string]::Empty;
        $keyUID = [string]::Empty;
        $key_Ex = [Expirity]::new($KeyI_Obj.Expirity);
        $bc = [string]::Empty; $kc = [string]::Empty;
        # Add a prefix String so that I can tell how old the K3YString is just by looking at it.
        ($Prefix, $Splitr) = switch ($key_Ex.Type.ToString()) {
            "Years" { ('xy\', [string]::Join('', $((Get-Date -UFormat %Y).ToCharArray() | ForEach-Object { [char]([int][string]$_ + 97) }))) }
            "Months" { ('xm\' , [string]::Join('', $((Get-Date -UFormat %m).ToCharArray() | ForEach-Object { [char]([int][string]$_ + 97) }))) }
            "Days" { ('xd\', [string]::Join('', $((Get-Date -UFormat %d).ToCharArray() | ForEach-Object { [char]([int][string]$_ + 97) }))) }
            Default { ('', 'ne') }
        }
        Set-Variable -Name 'kc' -Scope Local -Visibility Private -Option Private -Value $([xconvert]::BytesToRnStr($keyInfoB));
        Set-Variable -Name 'bc' -Scope Local -Visibility Private -Option Private -Value $([xconvert]::BytesToRnStr($Encr_BCT));
        $a = $(Get-Date -Format o).Replace('+', '').Replace('-', '').Replace(':', '').Replace('T', $Splitr).Split('.')[0].Replace([string]$(Get-Date -UFormat %Y), [string]$Last_PID).ToCharArray(); [array]::Reverse($a)
        $keyUID = [string]::Join('', $a); # Hopefully it doesn't look like a normal timestamp.
        Set-Variable -Name UIDstr -Scope Local -Visibility Private -Option Private -Value ($($Prefix + $([string]($bc + $keyUID.split($Splitr)[1]).length + $Splitr + [string]($keyUID + $bc).length + $Splitr + [string]$bc.length + $Splitr + $kc + $keyUID + $bc)).Trim());
        return $UIDstr
    }
    [Object[]]static AnalyseK3YUID([K3Y]$K3Y) {
        return [K3Y]::AnalyseK3YUID($K3Y, [K3Y]::GetPassword());
    }
    [Object[]]static AnalyseK3YUID([K3Y]$K3Y, [securestring]$Password) {
        $ThrowOnFailure = $true
        return [K3Y]::AnalyseK3YUID($K3Y, $Password, $ThrowOnFailure);
    }
    [Object[]]static AnalyseK3YUID([K3Y]$K3Y, [securestring]$Password, [bool]$ThrowOnFailure) {
        $CreateReport = $false
        return [K3Y]::AnalyseK3YUID($K3Y, $Password, $ThrowOnFailure, $CreateReport);
    }
    [Object[]]static AnalyseK3YUID([K3Y]$K3Y, [securestring]$Password, [bool]$ThrowOnFailure, [bool]$CreateReport) {
        $KIDstring = [string]::Empty; $Output = @()
        try {
            Set-Variable -Name KIDstring -Scope Local -Visibility Private -Option Private -Value $([xconvert]::StringFromCustomCipher([xconvert]::ToDeCompressed([System.Text.Encoding]::UTF7.GetString([xconvert]::BytesFromHex([xconvert]::ToString($K3Y.UID))))));
        } catch { throw [System.Management.Automation.PSInvalidOperationException]::new("The Operation Failed due to invalid K3Y.", $_.Exception) };
        [bool]$Is_Valid = $false; [datetime]$EncrDate = Get-Date -Month 1 -Day 1 -Hour 0 -Minute 0 -Year 1; $Info_Obj = $null; $B_C_type = [string]::Empty; $skID = [string]::Empty; #Key ID string (Plaintext)
        try {
            Set-Variable -Name 'skID' -Scope Local -Visibility Private -Option Private -Value $KIDstring;
            if ($skID.StartsWith('xy\')) {
                $SplitStr = $([string]::Join('', $((Get-Date -UFormat %Y).ToCharArray() | ForEach-Object { [char]([int][string]$_ + 97) })))
                Set-Variable -Name 'skID' -Scope Local -Visibility Private -Value $skID.Substring('3')
            } elseif ($skID.StartsWith('xm\')) {
                $SplitStr = $([string]::Join('', $((Get-Date -UFormat %m).ToCharArray() | ForEach-Object { [char]([int][string]$_ + 97) })))
                Set-Variable -Name 'skID' -Scope Local -Visibility Private -Value $skID.Substring('3')
            } elseif ($skID.StartsWith('xd\')) {
                $SplitStr = $([string]::Join('', $((Get-Date -UFormat %d).ToCharArray() | ForEach-Object { [char]([int][string]$_ + 97) })))
                Set-Variable -Name 'skID' -Scope Local -Visibility Private -Value $skID.Substring('3')
            } else {
                $SplitStr = 'ne';
            }
            $_is = for ($i = 0; $i -lt $skID.Split($SplitStr).Count; $i++) { if ($(try { [int]$skID.Split($SplitStr)[$i] -ne 0 } catch [System.Management.Automation.RuntimeException], [System.Management.Automation.PSInvalidCastException], [System.FormatException] { $false } catch { throw $_ })) { $i } }
            $_rc = $skID.Substring($($skID.Length - $skID.Split($SplitStr)[$($_is[2])]));
            $_Id = $skID.Substring($($skID.Length - $skID.Split($SplitStr)[$($_is[1])])).Replace($_rc, '');
            $_rk = $skID.Replace([string]($_Id + $_rc), '').Substring($([string]($_rc + $_Id.split($SplitStr)[1]).length + $SplitStr + [string]($_Id + $_rc).length + $SplitStr + [string]$_rc.length + $SplitStr).Length);
            # Get Real Time Stamp
            $spl = $SplitStr.ToCharArray(); [array]::Reverse($spl); $SplitStr = [string]::Join('', $spl);
            $tsr = [string[]]$($_Id.split($SplitStr) | ForEach-Object { if (![string]::IsNullOrEmpty($_)) { $_ } }); $t = $tsr[1][0..3]; [array]::Reverse($t); $c = $tsr[0].ToCharArray(); [array]::Reverse($c);
            $Mon = [int][string]::Join('', $t[0..1])
            $Day = [int][string]::Join('', $t[2..3])
            $Hrs = [int][string]::Join('', $c[0..1])
            $Min = [int][string]::Join('', $c[2..3])
            $ebc = [byte[]][xconvert]::BytesFromRnStr($_rc)
            $Info_Obj = [xconvert]::BytesToObject([xconvert]::BytesFromRnStr($_rk))
            $Is_Valid = $($Info_Obj.Expirity - [datetime]::Now) -ge [timespan]::new(0)
            $B_C_type = $(try { [System.Text.Encoding]::UTF7.GetString([AesLg]::Decrypt($ebc, $Password)) }catch { if ($ThrowOnFailure) { throw [System.InvalidOperationException]::new("Please Provide a valid Password.", [System.UnauthorizedAccessException]::new('Wrong Password')) }else { [string]::Empty } }); # (Byte Compression Type)
            $EncrDate = Get-Date -Month $Mon -Day $Day -Hour $Hrs -Minute $Min # An estimate of when was the last encryption Done
            $Output = ($Is_Valid, $Info_Obj, $B_C_type, $EncrDate);
        } catch {
            if ($ThrowOnFailure) { throw $_.Exception }
        }
        if ($CreateReport) {
            return [PSCustomObject]@{
                Summary        = "K3Y $(if ([K3Y]::HasPasswordHash($K3Y)) { 'Last used' }else { 'created' }) on: $($Output[3]), PID: $($Output[1].PID), by: $($Output[1].User)."
                Version        = $Output[1].Version
                ExpirationDate = $Output[1].Expirity.date
                Compression    = $Output[2]
                LastUsedOn     = $Output[3]
                UserName       = $Output[1].User
                IsValid        = $Output[0]
            }
        } else {
            return $Output
        }
    }
    [K3Y]static Create() {
        return [K3Y]::new()
    }
    [K3Y]static Create([string]$K3yString) {
        $Obj = $null; Set-Variable -Name Obj -Scope Local -Visibility Private -Option Private -Value ([xconvert]::BytesToObject([convert]::FromBase64String([xconvert]::ToDeCompressed($K3yString))));
        $K3Y = [K3Y][xconvert]::ToPSObject($Obj);
        Invoke-Command -InputObject $K3Y.User.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                    Invoke-Expression "`$K3Y.User.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return `$$($K3Y.User.IsProtected) }))";
                }
            )
        )
        return $K3Y
    }
    [void]Export([string]$FilePath) {
        $this.Export($FilePath, $false);
    }
    [void]Export([string]$FilePath, [bool]$encrypt) {
        if (![IO.File]::Exists($FilePath)) { New-Item -Path $FilePath -ItemType File | Out-Null }
        Set-Content -Path $FilePath -Value ([xconvert]::Tostring($this)) -Encoding UTF8 -NoNewline;
        if ($encrypt) { $(Get-Item $FilePath).Encrypt() }
    }
    [K3Y]Import([string]$StringK3y) {
        $K3Y = $null; Set-Variable -Name K3Y -Scope Local -Visibility Private -Option Private -Value ([K3Y]::Create($StringK3y));
        if ([bool]$K3Y.User.IsProtected) { $K3Y.User.UnProtect() }
        $this | Get-Member -MemberType Properties | ForEach-Object { $Prop = $_.Name; $this.$Prop = $K3Y.$Prop };
        $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::ToString($this.User.Password));
        if ([regex]::IsMatch($hashSTR, "^[A-Fa-f0-9]{72}$")) {
            Invoke-Command -InputObject $this.User -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                        Invoke-Expression "`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))";
                    }
                )
            )
        }
        return $K3Y
    }
    [bool]IsValid() {
        $ThrowOnFailure = $false; $IsStillValid = [k3Y]::AnalyseK3YUID($this, $this.User.Password, $ThrowOnFailure)[0];
        return $IsStillValid
    }
    [void]SaveToVault() {
        if (-not [bool]("Windows.Security.Credentials.PasswordVault" -as 'Type')) {
            [Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
        }
        $_ResN = 'NerdK3y'
        $vault = New-Object Windows.Security.Credentials.PasswordVault
        $vault.Add((New-Object Windows.Security.Credentials.PasswordCredential -ArgumentList ($_ResN, $this.User.UserName, [xconvert]::Tostring($this))))
    }
}
#endregion Custom_Cryptography_Wrapper

#endregion Helpers

#region    MainClass
class NerdCrypt {
    [K3Y]hidden $key = [K3Y]::new();
    [NcObject]$Object = [NcObject]::new();
    [System.Collections.Hashtable]hidden static $PSVersion = $(Get-Variable -Name PSVersionTable).Value;

    NerdCrypt() {
        $this.Object = [NcObject]::new();
    }
    NerdCrypt([Object]$Object) {
        $this.Object = [NcObject]::new($Object);
    }
    NerdCrypt([Object]$Object, [string]$PublicKey) {
        $this.Object = [NcObject]::new($Object);
        $this.SetNerdKey($PublicKey);
    }
    NerdCrypt([Object]$Object, [string]$User, [string]$PublicKey) {
        $this.Object = [NcObject]::new($Object);
        $this.SetNerdKey($PublicKey);
        $this.User.UserName = $User;
    }
    NerdCrypt([Object]$Object, [string]$User, [securestring]$PrivateKey, [string]$PublicKey) {
        $this.Object = [NcObject]::new($Object);
        $this.User.UserName = $User;
        $this.SetNerdKey($PublicKey);
        $this.SetCredentials([pscredential]::new($User, $PrivateKey));
    }
    [void]SetBytes([byte[]]$bytes) {
        $this.Object.Bytes = $bytes;
    }
    [void]SetBytes([Object]$Object) {
        $this.Object.Bytes = [XConvert]::BytesFromObject($Object);
    }
    [void]SetBytes([securestring]$securestring) {
        $this.SetBytes([xconvert]::BytesFromObject([XConvert]::ToString($securestring)));
    }
    [void]SetCredentials() {
        $this.SetCredentials((Get-Variable Host).Value.UI.PromptForCredential("NerdCrypt needs your credentials.", "Please enter your UserName and Password.", "$env:UserName", ""));
    }
    [void]SetCredentials([System.Management.Automation.PSCredential]$Credentials) {
        $this.key.User.UserName = $Credentials.UserName
        $this.key.User.Password = $Credentials.Password
    }
    #
    # TODO: Add option to encrypt using KEys From Azure KeyVault (The process has to be INTERACTIVE).
    # https://docs.microsoft.com/en-us/azure/key-vault/secrets/quick-create-powershell
    #
    #region    ParanoidCrypto
    [void]Encrypt() {
        $this.SetBytes($this.Encrypt($this.Object.Bytes, [K3Y]::GetPassword()))
    }
    [byte[]]Encrypt([int]$iterations) {
        $this.SetBytes($this.Encrypt($this.Object.Bytes, [K3Y]::GetPassword(), $iterations));
        return $this.Object.Bytes
    }
    [byte[]]Encrypt([byte[]]$bytes, [securestring]$Password) {
        return $this.Encrypt($bytes, $Password, 1);
    }
    [byte[]]Encrypt([securestring]$Password, [int]$Iterations) {
        $this.SetBytes($this.Encrypt($this.Object.Bytes, $Password, $iterations));
        return $this.Object.Bytes
    }
    [byte[]]Encrypt([byte[]]$bytes, [securestring]$Password, [int]$Iterations) {
        $_bytes = $bytes
        for ($i = 1; $i -lt $Iterations + 1; $i++) {
            Write-Verbose "[+] Encryption [$i/$Iterations] ...$(
                $_bytes = $this.key.Encrypt($_bytes, $Password);
            ) Done."
        }; if ($_bytes.Equals($bytes)) { $_bytes = $null }
        return $_bytes
    }
    [void]Decrypt() {
        $this.SetBytes($this.Decrypt($this.Object.Bytes, [K3Y]::GetPassword()))
    }
    [byte[]]Decrypt([int]$iterations) {
        $this.SetBytes($this.Decrypt($this.Object.Bytes, [K3Y]::GetPassword(), $Iterations));
        return $this.Object.Bytes
    }
    [byte[]]Decrypt([byte[]]$bytes, [securestring]$Password) {
        return $this.Decrypt($bytes, $Password, 1);
    }
    [byte[]]Decrypt([securestring]$Password, [int]$Iterations) {
        $this.SetBytes($this.Decrypt($this.Object.Bytes, $Password, $Iterations));
        return $this.Object.Bytes
    }
    [byte[]]Decrypt([byte[]]$bytes, [securestring]$Password, [int]$Iterations) {
        $_bytes = $bytes
        for ($i = 1; $i -lt $Iterations + 1; $i++) {
            Write-Verbose "[+] Decryption [$i/$Iterations] ...$(
                $_bytes = $this.key.Decrypt($_bytes, $Password);
            ) Done."
        }; if ($_bytes.Equals($bytes)) { $_bytes = $null }
        return $_bytes
    }
    #endregion ParanoidCrypto
    [void]SetNerdKey([string]$StringK3y) {
        [void]$this.key.Import($StringK3y);
    }
    [Securestring]Securestring() {
        return $(if ($null -eq $this.Object.Bytes) { [Securestring]::new() }else {
                [xconvert]::ToSecurestring([xconvert]::ToString($this.Object.Bytes, ''))
            }
        )
    }
}
#endregion MainClass

#region    Usage_&&_Playground_Examples
<#
# if (-not [bool]("Windows.Security.Credentials.PasswordVault" -as 'Type')) {
#     [Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
# }
# $vault = [Windows.Security.Credentials.PasswordVault]::new()
# $res = $vault.RetrieveAll().Resource; if ($res.count -gt 0) { $res | ForEach-Object { Write-Verbose "Removing $_" -Verbose; $vault.Remove($vault.Retrieve($_, $Env:USERNAME)) } }
# $vault.RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ }
# # More Examples will go here
#>
#endregion Usage_&&_Playground_Examples

#region    Functions
#The funtions I really use (Exported During Build)
function Encrypt-Object {
    <#
    .SYNOPSIS
        A nerdy function for perform paranoid encryption.
    .DESCRIPTION
        Perform multiple encryptions to an Object.
        Any object that can be transformed to byte array can be enrypted, decrpted and transformed(serialized) back to that object.
        Currently this functions can encrypt Objects (I mean [System.Object]$Object) and files.
        The function uses Rijndael AES-256, Rivest-Shamir-Adleman encryption (RSA) algorithms combined with MD5 Tripledes and other Stuff.
        Yeah, It gets Pretty paranoid!

        Its dangerous to Print/send sensitive info to the terminal/console or via RMM,
        better to use nerdy non-standard (That you only know how to decrypt) encrypted String.
        The encryption Key(s) are stored in windows Password vault so that
        The Decryptor Function (Decrypt-Object) Uses them to decrypt without need of The user entering them again.
    .NOTES
        1. Obviusly the biggest weakness of this script is that its a script (Non-Obfuscated, cleartext script!),
            If you or some hacker can't get the password but have the source code you can reverse engineer to findout why you are not getting clear output.
            Thus allowing to bruteforce untill you get cleartext. Even if that scenario is almost imposssible, In production make sure its a compiled binary.
            Ex: Using tools like PS2Exe

        2. Sometimes even your local password vault is not secure enough!
            https://www.hackingarticles.in/credential-dumping-windows-credential-manager/
            So If you feel unsafe Retrieve Your stuff (Store them on a Goober or somethin).
            Then Remove them, Example:
            if (-not [bool]("Windows.Security.Credentials.PasswordVault" -as 'Type')) {
                [Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
            }
            $vault = [Windows.Security.Credentials.PasswordVault]::new()
            $vault.Remove($vault.Retrieve("ResourceName", "NameOtheKey"))
            # ie:
            PS\> $vault.Remove

            OverloadDefinitions
            -------------------
            void Remove(Windows.Security.Credentials.PasswordCredential credential)

        3. Storing Keys in windows PasswordVault Is not Yet Supported in PS 7
        # On `ResourceName` I usually use it as description.
    .LINK
        https://github.com/alainQtec/.files/blob/main/src/scripts/Security/NerdCrypt/NerdCrypt.ps1
    .LINK
        Decrypt-Object
    .EXAMPLE
        $enc = Encrypt-Object -Object "Hello World!" -Password $(Read-Host -AsSecureString -Prompt 'Password') -KeyOutFile .\PublicKee.txt

        $dec = Decrypt-Object -InputBytes $enc -Password $(Read-Host -AsSecureString -Prompt 'Password') -PublicKey $(cat .\PublicKee.txt)

    .EXAMPLE
        Encrypt-Object "This is my email, don't show it to anyone. alain.1337dev@outlook.com"

        ynOESoZ41NLD4tqxkE74HtRYK+iJmjk4/wX8SJ2wFrJUrvV....

        Decrypt-Object "ynOESoZ41NLD4tqxkE74HtRYK+iJmjk4/wX8SJ2wFrJUrvV...."

        This is my email, don't show it to anyone. alain.1337dev@outlook.com
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [OutputType([byte[]])]
    param (
        # The Object you want to encrypt
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllParameterSets')]
        [Alias('InputObj')]
        $Object,

        # Use a strong password. It will be used Lock Your local Key (ConvertTo-SecureString -String "Message" -SecureKey [System.Security.SecureString]) before storing in vault.
        # Add this if you want 3rd layer of security. Useful when someone(Ex: Hacker) has somehow gained admin priviledges of your PC;
        # With a locked local Password vault it will require much more than just guessing The password, or any BruteForce tool.
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithSecureKey')]
        [Alias('Password', 'Securestring')]
        [SecureString]$PrivateKey = ([K3Y]::GetPassword()),

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

        # So not worth it! Unless youre too lazy to create a SecureString, Or your Password is temporal (Ex: Gets changed by your Password Generator, every 60 seconds).
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithPlainKey')]
        [Alias('PlainPassword')]
        [string]$PlainPass,

        # Source or the Encryption Key. Full/Path of the keyfile you already have. It will be used to lock your keys. (ConvertTo-SecureString -String "Message" -Key [Byte[]])
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$Key,

        # Path OF the KeyFile (Containing You saved key base64String Key)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKeyFile')]
        [ValidateNotNullOrEmpty()]
        [string]$KeyFile,

        # FilePath to store your keys. Saves keys as base64 in an enrypted file. Ex: some_random_Name.key (Not recomended)
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = '__AllParameterSets')]
        [Alias('ExportFile')]
        [string]$KeyOutFile,

        # How long you want the encryption to last. Default to one month (!Caution Your data will be LOST Forever if you do not decrypt before the expirity date!)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithVault')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithPlainKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('KeyExpirity')]
        [datetime]$Expirity = ([Datetime]::Now + [TimeSpan]::new(30, 0, 0, 0)),

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithSecureKey')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithPlainKey')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithVault')]
        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [int]$Iterations = 2
    )

    DynamicParam {
        $DynamicParams = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
        [bool]$IsPossiblefileType = $false
        [bool]$IsArrayObject = $false
        [int]$P = 6 #(Position)
        try {
            if ($Object.count -gt 1) {
                $InputType = @()
                $IsArrayObject = $true
                foreach ($Obj in $Object) {
                    $InputType += $Obj.GetType()
                }
                $InputType = $InputType | Sort-Object -Unique
            } else {
                $InputType = $Object.GetType()
            }
        } catch { $InputType = [string]::Empty }
        $IsPossiblefileTypes = @('string', 'string[]', 'System.IO.FileInfo', 'System.IO.FileInfo[]', 'System.Object', 'System.Object[]')
        if ($IsArrayObject) {
            foreach ($type in $InputType) {
                $IsPossiblefileType = [bool]($type -in $IsPossiblefileTypes) -or $IsPossiblefileType
            }
        } else {
            $IsPossiblefileType = [bool]($InputType -in $IsPossiblefileTypes)
        }
        #region OutFile
        if ($IsPossiblefileType) {
            $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
            $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
                Position                        = $P
                ParameterSetName                = '__AllParameterSets'
                Mandatory                       = $False
                ValueFromPipeline               = $false
                ValueFromPipelineByPropertyName = $false
                ValueFromRemainingArguments     = $false
                HelpMessage                     = 'Use to specify Output File, if inputObject is a file.'
                DontShow                        = $False
            }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
            $attributeCollection.Add($attributes);
            $attributeCollection.Add([System.Management.Automation.ValidateNotNullOrEmptyAttribute]::new())
            $attributeCollection.Add([System.Management.Automation.AliasAttribute]::new([System.String[]]('OutPutFile', 'DestinationFile')))
            $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("OutFile", [Object], $attributeCollection)
            $DynamicParams.Add("OutFile", $RuntimeParam)
            $P++
        }
        #endregion OutFile

        #region IgnoredArguments
        $attributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
        $attributes = [System.Management.Automation.ParameterAttribute]::new(); $attHash = @{
            Position                        = $P
            ParameterSetName                = '__AllParameterSets'
            Mandatory                       = $False
            ValueFromPipeline               = $true
            ValueFromPipelineByPropertyName = $true
            ValueFromRemainingArguments     = $true
            HelpMessage                     = 'Allows splatting with arguments that do not apply. Do not use directly.'
            DontShow                        = $False
        }; $attHash.Keys | ForEach-Object { $attributes.$_ = $attHash.$_ }
        $attributeCollection.Add($attributes)
        $RuntimeParam = [System.Management.Automation.RuntimeDefinedParameter]::new("IgnoredArguments", [Object[]], $attributeCollection)
        $DynamicParams.Add("IgnoredArguments", $RuntimeParam)
        #endregion IgnoredArguments
        return $DynamicParams
    }

    begin {
        $eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
        $PsCmdlet.MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value -ea 'SilentlyContinue' }
        $PsW = [securestring]::new(); $nc = $null;
        $fxn = ('[' + $MyInvocation.MyCommand.Name + ']')
        # Write-Invocation $MyInvocation
    }

    process {
        Write-Verbose "[+] $fxn $($PsCmdlet.ParameterSetName) ..."
        Set-Variable -Name PsW -Scope Local -Visibility Private -Option Private -Value $(switch ($PsCmdlet.ParameterSetName) {
                'WithKey' {  }
                'WithVault' {  }
                'WithPlainKey' { [xconvert]::ToSecurestring($PlainPass) }
                'WithSecureKey' { $PrivateKey }
                Default {
                    throw 'Error!'
                }
            }
        );
        Set-Variable -Name nc -Scope Local -Visibility Private -Option Private -Value $([nerdcrypt]::new($Object));
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Expirity')) {
            $nc.key.Expirity = [Expirity]::new($Expirity);
        }
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('PublicKey')) {
            $nc.SetNerdKey($PublicKey);
        } else {
            Write-Verbose "[+] Create PublicKey ...";
            $nc.SetNerdKey($(New-NerdKey -UserName $nc.key.User.UserName -Password $PsW -Expirity $nc.key.Expirity.date -Protect));
        }
        $bytes = $nc.Object.Bytes
        [void]$nc.Encrypt($PsW, $Iterations)
        if ($PsCmdlet.ParameterSetName -ne 'WithKey') {
            if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('KeyOutFile')) {
                Write-Verbose "[i] Export PublicKey ..."
                $nc.key.Export($KeyOutFile, $true);
            } else {
                Write-Verbose "[i] Used PublicKey:`n$([xconvert]::Tostring($nc.key))"
            }
        }
        $bytes = $(if ($bytes.Equals($nc.Object.Bytes)) { $null }else { $nc.Object.Bytes })
    }

    end {
        $ErrorActionPreference = $eap
        return $bytes
    }
}
function Decrypt-Object {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [SecureString]$PrivateKey = [K3Y]::GetPassword(),

        [Parameter(Mandatory = $true, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

        # So not worth it! Unless youre too lazy to create a SecureString, Or your Password is temporal (Ex: Gets changed by your Password Generator, every 60 seconds).
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithPlainKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('PlainPassword')]
        [string]$PlainPass,

        # Source or the Encryption Key. Full/Path of the keyfile you already have. It will be used to lock your keys. (ConvertTo-SecureString -String "Message" -Key [Byte[]])
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKey')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]$Key,

        # Path OF the KeyFile (Containing You saved key base64String Key)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithKeyFile')]
        [ValidateNotNullOrEmpty()]
        [string]$KeyFile,

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [int]$Iterations = 2
    )

    begin {
        $eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
        $fxn = ('[' + $MyInvocation.MyCommand.Name + ']');
        # Write-Invocation $MyInvocation
    }

    process {
        Write-Verbose "[+] $fxn $($PsCmdlet.ParameterSetName) ..."
        $PsW = switch ($PsCmdlet.ParameterSetName) {
            'WithKey' {  }
            'WithVault' {  }
            'WithPlainKey' { [xconvert]::ToSecurestring($PlainPass) }
            'WithSecureKey' { $PrivateKey }
            Default {
                throw 'Error!'
            }
        }
        $nc = [nerdcrypt]::new($InputBytes, $PublicKey);
        $bytes = $nc.Object.Bytes
        [void]$nc.Decrypt($PsW, $Iterations)
        if ($PsCmdlet.ParameterSetName -ne 'WithKey' -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('KeyOutFile')) {
            if (![string]::IsNullOrEmpty($KeyOutFile)) {
                Write-Verbose "[-] Export PublicKey ..."
                $nc.key.Export($KeyOutFile, $true)
            }
        }
        $bytes = $(if ($bytes.Equals($nc.Object.Bytes)) { $null }else { $nc.Object.Bytes })
    }

    end {
        $ErrorActionPreference = $eap
        return $bytes
    }
}
function New-NerdKey {
    <#
    .SYNOPSIS
        Create [K3Y] Object and Outputs it as a string.
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        Information or caveats about the function e.g. 'This function is not supported in Linux'
    .LINK
        Specify a URI to a help page, this will show when Get-Help -Online is used.
    .EXAMPLE
        Test-MyTestFunction -Verbose
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'Params')]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'FromK3Y')]
        [ValidateNotNullOrEmpty()][K3Y]$K3YoBJ,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'FromK3Y')]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Params')]
        [ValidateNotNullOrEmpty()][string]$UserName = $env:USERNAME,

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'FromK3Y')]
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'Params')]
        [Alias('Password', 'Securestring')]
        [ValidateNotNullOrEmpty()][securestring]$PrivateKey,

        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'FromK3Y')]
        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'Params')]
        [ValidateNotNullOrEmpty()][datetime]$Expirity = ([Datetime]::Now + [TimeSpan]::new(30, 0, 0, 0)), # One month

        [Parameter(Mandatory = $false, ParameterSetName = 'Params')]
        [switch]$Protect = $false
    )

    process {
        $k = $null
        if ($PSCmdlet.ParameterSetName -eq 'Params') {
            $k = [K3Y]::new($UserName, $PrivateKey, $Expirity); if ($Protect) { $k.User.Protect() };
            $k = [string][xconvert]::Tostring($k);
        } elseif ($PSCmdlet.ParameterSetName -eq 'FromK3Y') {
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('UserName')) {
                $K3YoBJ.User.UserName = $UserName;
            }
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('PrivateKey')) {
                [void]$K3YoBJ.ResolvePassword($PrivateKey);
            }
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Expirity')) {
                $K3YoBJ.Expirity = [Expirity]::new($Expirity);
            }
            $k = [xconvert]::Tostring($K3YoBJ);
        } else {
            throw [System.Management.Automation.ParameterBindingException]::new("Could Not Resolve ParameterSetname.");
        }
    }

    end {
        return $k
    }
}
#region    DataProtection
function Protect-Data {
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'Bytes', SupportsShouldProcess = $true)]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Xml')]
        [ValidateNotNullOrEmpty()]
        [Alias('XmlDoc')]
        [xml]$InputXml,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__AllParameterSets')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [ValidateNotNullOrEmpty()]
        [string]$Scope
    )

    begin {
        #Load The Assemblies
        if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Xml') {
            $InputBytes = [xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))
        }
        if ($PSCmdlet.ShouldProcess("InputObj", "Protect")) {
            $ProtectedD = [xconvert]::ToProtected([byte[]]$InputBytes, [byte[]]$Entropy, [ProtectionScope]$ProtectionScope)
        }
    }

    end {
        return $ProtectedD
    }
}
function UnProtect-Data {
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'Bytes', SupportsShouldProcess = $true)]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Xml')]
        [ValidateNotNullOrEmpty()]
        [Alias('XmlDoc')]
        [xml]$InputXml,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__AllParameterSets')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [ValidateNotNullOrEmpty()]
        [string]$ProtectionScope
    )

    begin {
        #Load The Assemblies
        if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Xml') {
            $InputBytes = [xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))
        }
        if ($PSCmdlet.ShouldProcess("InputBytes", "Unprotect")) {
            $UnProtected = [xconvert]::ToUnProtected([byte[]]$InputBytes, [byte[]]$Entropy, [ProtectionScope]$ProtectionScope)
        }
    }

    end {
        return $UnProtected
    }
}
#endregion DataProtection

#endregion Functions

# Credential Vault:
$code = @"
using System.Text;
using System;
using System.Runtime.InteropServices;

namespace CredManager {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CredentialMem {
        public int flags;
        public int type;
        public string targetName;
        public string comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME lastWritten;
        public int credentialBlobSize;
        public IntPtr credentialBlob;
        public int persist;
        public int attributeCount;
        public IntPtr credAttribute;
        public string targetAlias;
        public string userName;
    }

    public class Credential {
        public string target;
        public string username;
        public string password;
        public Credential(string target, string username, string password) {
        this.target = target;
        this.username = username;
        this.password = password;
        }
    }

    public class Util {
        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

        public static Credential GetUserCredential(string target) {
            CredentialMem credMem;
            IntPtr credPtr;

            if (CredRead(target, 1, 0, out credPtr)) {
                credMem = Marshal.PtrToStructure<CredentialMem>(credPtr);
                byte[] passwordBytes = new byte[credMem.credentialBlobSize];
                Marshal.Copy(credMem.credentialBlob, passwordBytes, 0, credMem.credentialBlobSize);
                Credential cred = new Credential(credMem.targetName, credMem.userName, Encoding.Unicode.GetString(passwordBytes));
                return cred;
            } else {
                throw new Exception("Failed to retrieve credentials");
            }
        }

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
        private static extern bool CredWrite([In] ref CredentialMem userCredential, [In] int flags);

        public static void SetUserCredential(string target, string userName, string password) {
            CredentialMem userCredential = new CredentialMem();

            userCredential.targetName = target;
            userCredential.type = 1;
            userCredential.userName = userName;
            userCredential.attributeCount = 0;
            userCredential.persist = 3;
            byte[] bpassword = Encoding.Unicode.GetBytes(password);
            userCredential.credentialBlobSize = (int)bpassword.Length;
            userCredential.credentialBlob = Marshal.StringToCoTaskMemUni(password);
            if (!CredWrite(ref userCredential, 0)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }
}
"@
if (![bool]("CredManager.Util" -as "type")) {
    Add-Type -TypeDefinition $code -Language CSharp
}
# How to store credentials
# [CredManager.Util]::SetUserCredential("Application Name", "Username", "Password")
# # How to retrieve credentials
# [CredManager.Util]::GetUserCredential("Application Name")
# # How to just get the password
# [CredManager.Util]::GetUserCredential("Application Name").password