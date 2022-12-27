<#
.SYNOPSIS
    PowerShell classes and functions for Cryptography.
.DESCRIPTION
    Nerdcrypt is an all in one Encryption Decryption Powerhell Class.
    All ../Nerdcrypt.psm1 functions are built based on these classes.
.NOTES
    [+] Most of the methods work. (Most).
    [+] This file is over 2000 lines of code (All in One), so use regions code folding if your editor supports it.
.LINK
    https://gist.github.com/alainQtec/217860de99e8ddb89a8820add6f6980f
.EXAMPLE
    PS C:\> # Try this:
    PS C:\> iex $((Invoke-RestMethod -Method Get https://api.github.com/gists/217860de99e8ddb89a8820add6f6980f).files.'Nerdcrypt.Core.ps1'.content)
    PS C:\> $Obj = [NerdCrypt]::new("Crypt0gr4Phy Rocks!");
    PS C:\> $eOb = $Obj.Encrypt(3); # Encrypt 3 times
    PS C:\> $dOb = $Obj.Decrypt(3); # Decrypt 3 times
    PS C:\> echo ([xconvert]::BytesToObject($dOb))
    PS C:\> #You get back: Crypt0gr4Phy Rocks!
#>
# Import the necessary assemblies
Add-Type -AssemblyName System.Security;
Add-Type -AssemblyName System.Runtime.InteropServices;

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
# Only Encryption algorithms that are widely trusted and used in real-world
enum CryptoAlgorithm {
    AES # Advanced Encryption Standard
    RSA # RSA
    ECC # Elliptic Curve Cryptography
}
# System.Security.Cryptography.RSAEncryptionPadding Names
enum RSAPadding {
    Pkcs1
    OaepSHA1
    OaepSHA256
    OaepSHA384
    OaepSHA512
}
enum Compression {
    Gzip
    Deflate
    ZLib
    # Zstd # Todo: Add Zstandard. (The one from faceboo. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
}
# [xgen]::Enumerator('ExpType', ('Milliseconds', 'Years', 'Months', 'Days', 'Hours', 'Minutes', 'Seconds'))

enum CredFlags {
    None = 0x0
    PromptNow = 0x2
    UsernameTarget = 0x4
}

enum CredType {
    Generic = 1
    DomainPassword = 2
    DomainCertificate = 3
    DomainVisiblePassword = 4
    GenericCertificate = 5
    DomainExtended = 6
    Maximum = 7
    MaximumEx = 1007 # (Maximum + 1000)
}

enum CredentialPersistence {
    Session = 1
    LocalComputer = 2
    Enterprise = 3
}
#endregion enums

#region    Custom_Stuff_generators
#!ALL methods shouldbe/are Static!
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class xgen {
    xgen() {}
    [string]static RandomName() {
        return [xgen]::RandomName((Get-Random -min 16 -max 80));
    }
    [string]static RandomName([int]$Length) {
        return [string][xgen]::RandomName($Length, $Length);
    }
    [string]static RandomName([bool]$IncludeNumbers) {
        $Length = Get-Random -min 16 -max 80
        return [string][xgen]::RandomName($Length, $Length, $IncludeNumbers);
    }
    [string]static RandomName([int]$Length, [bool]$IncludeNumbers) {
        return [string][xgen]::RandomName($Length, $Length, $IncludeNumbers);
    }
    [string]static RandomName([int]$minLength, [int]$maxLength) {
        return [string][xgen]::RandomName($minLength, $maxLength, $false);
    }
    [string]static RandomName([int]$minLength, [int]$maxLength, [bool]$IncludeNumbers) {
        [int]$iterations = 2; $MinrL = 3; $MaxrL = 999 #Gotta have some restrictions, or one typo could slow down an entire script.
        if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'String Length'. Try $MinrL or greater." ; Break }
        if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'String Length'. Try $MaxrL or lower." ; Break }
        $samplekeys = if ($IncludeNumbers) {
            [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }) + (0..9))
        } else {
            [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }))
        }
        return [string][xgen]::RandomSTR($samplekeys, $iterations, $minLength, $maxLength);
    }
    [byte[]]static Salt() {
        return [byte[]][xconvert]::BytesFromObject([xgen]::RandomName(16));
    }
    [byte[]]static Salt([int]$iterations) {
        return [byte[]]$(1..$iterations | ForEach-Object { [xgen]::Salt() });
    }
    [byte[]]static Key() {
        return [xgen]::Key(2);
    }
    [byte[]]static Key([int]$iterations) {
        $password = $null; $salt = $null;
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToSecurestring([PasswordManager]::GeneratePassword($Iterations)));
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
        return $entropy;
        #Used to generate random IV
    }
    [string]static UniqueMachineId() {
        $Id = [string]($Env:MachineId)
        $vp = (Get-Variable VerbosePreference).Value
        #  Creates a Custom Short Code, but its slow!
        #  $Bios_Id = (Get-CimInstance -Class Win32_BIOS -Verbose:$false | ForEach-Object { ([string]$_.Manufacturer, [string]$_.SerialNumber) }) -join ':'
        #  $Proc_Id = (Get-CimInstance -Class CIM_Processor -Verbose:$false).ProcessorId # 2 seconds faster than $([System.Management.ManagementObjectCollection][wmiclass]::new("win32_processor").GetInstances() | Select-Object -ExpandProperty ProcessorId))
        #  $disk_Id = (Get-CimInstance -Class Win32_LogicalDisk -Verbose:$false | Where-Object { $_.DeviceID -eq "C:" }).VolumeSerialNumber
        #  Set-Item -Path Env:\MachineId -Value ([string]::Join(':', $($Bios_Id, $Proc_Id, $disk_Id)));
        try {
            Set-Variable VerbosePreference -Value $([System.Management.Automation.ActionPreference]::SilentlyContinue)
            if ([string]::IsNullOrWhiteSpace($Id)) {
                # Use the Windows Management Instrumentation (WMI) to get the machine's unique ID
                $machineId = Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
                # Use a cryptographic hash function (SHA-256) to generate a unique machine ID
                $sha256 = [System.Security.Cryptography.SHA256]::Create()
                Set-Item -Path Env:\MachineId -Value $([convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($machineId))));
                $sha256.Clear(); $sha256.Dispose()
                $Id = [string]($Env:MachineId)
            }
        } catch {
            throw $_
        } finally {
            Set-Variable VerbosePreference -Value $vp
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
    # Only Works On ps v5 or below
    # [void]static Enumerator([string]$Name, [string[]]$Members) {
    #     # Ex:
    #     # [xgen]::Enumerator("my.colors", ('blue', 'red', 'yellow'));
    #     # [Enum]::GetNames([my.colors]);
    #     try {
    #         $assembly = New-Object 'System.Reflection.AssemblyName'
    #         $assembly.Name = "EmittedEnum"
    #         #Create [System.Reflection.Emit.AssemblyBuilder]
    #         $assemblyBuilder = [System.Threading.Thread]::GetDomain().DefineDynamicAssembly($assembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Save -bor [System.Reflection.Emit.AssemblyBuilderAccess]::Run);
    #         $moduleBuilder = $assemblyBuilder.DefineDynamicModule("DynamicModule", "DynamicModule.mod");
    #         $enumBuilder = $moduleBuilder.DefineEnum($name, [System.Reflection.TypeAttributes]::Public, [System.Int32]);
    #         for ($i = 0; $i -lt $Members.count; $i++) { [void]$enumBuilder.DefineLiteral($Members[$i], $i) }
    #         [void]$enumBuilder.CreateType()
    #     } catch {
    #         throw $_
    #     }
    # }
    [System.Security.Cryptography.Aes]static Aes() { return [xgen]::Aes(1) }
    [System.Security.Cryptography.Aes]static Aes([int]$Iterations) {
        $salt = $null; $password = $null;
        Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToSecurestring([PasswordManager]::GeneratePassword($Iterations)));
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

#region    Custom_ObjectConverter
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class XConvert {
    XConvert() {}
    [string]static Tostring([k3Y]$K3Y) {
        if ($null -eq $K3Y) { return [string]::Empty };
        $NotNullProps = ('User', 'UID', 'Expiration');
        $K3Y | Get-Member -MemberType Properties | ForEach-Object { $Prop = $_.Name; if ($null -eq $K3Y.$Prop -and $Prop -in $NotNullProps) { throw [System.ArgumentNullException]::new($Prop) } };
        $CustomObject = [xconvert]::ToPSObject($K3Y);
        return [string][xconvert]::ToCompressed([System.Convert]::ToBase64String([XConvert]::BytesFromObject($CustomObject)));
    }
    [string]static ToString([byte[]]$Bytes) {
        # We could do: $CharCodes = [int[]]$Bytes; [xconvert]::Tostring($CharCodes); but lots of data is lost when decoding back ...
        return [string][System.Convert]::ToBase64String($Bytes);
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
        $St = [System.string]::Join('', $($Inpbytes | ForEach-Object { [string][char]$rn.Next(97, 122) + $_ }));
        return $St
    }
    [byte[]]static BytesFromRnStr ([string]$rnString) {
        $az = [int[]](97..122) | ForEach-Object { [string][char]$_ };
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
    [byte[]]static ToProtected([byte[]]$bytes) {
        $Scope = [ProtectionScope]::CurrentUser
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15];
        return [xconvert]::ToProtected($bytes, $Entropy, $Scope)
    }
    [byte[]]static ToProtected([byte[]]$bytes, [ProtectionScope]$Scope) {
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15];
        return [xconvert]::ToProtected($bytes, $Entropy, $Scope)
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
    [string]static ToUnProtected([string]$string) {
        $Scope = [ProtectionScope]::CurrentUser
        $Entropy = [System.Text.Encoding]::UTF8.GetBytes([xgen]::UniqueMachineId())[0..15];
        return [xconvert]::BytesToObject([XConvert]::ToUnProtected([xconvert]::BytesFromObject($string), $Entropy, $Scope))
    }
    [string]static ToUnProtected([string]$string, [ProtectionScope]$Scope) {
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
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
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
        if (("$Compression" -as 'Compression') -isnot 'Compression') {
            Throw [System.InvalidCastException]::new("Compression type '$Compression' is unknown! Valid values: $([Enum]::GetNames([compression]) -join ', ')");
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
            $bytes = [XConvert]::ToSerialized($obj)
        }
        if ($protect) {
            # Protecteddata: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata.unprotect?
            $bytes = [byte[]][xconvert]::ToProtected($bytes);
        }
        return $bytes
    }
    [Object[]]static BytesToObject([byte[]]$Bytes) {
        if ($null -eq $Bytes) { return $null }
        # Deserialize the byte array
        return [XConvert]::ToDeserialized($Bytes)
    }
    [Object[]]static BytesToObject([byte[]]$Bytes, [bool]$Unprotect) {
        if ($Unprotect) {
            $Bytes = [byte[]][xconvert]::ToUnProtected($Bytes)
        }
        return [XConvert]::BytesToObject($Bytes);
    }
    [byte[]]static ToSerialized($Obj) {
        return [XConvert]::ToSerialized($Obj, $false)
    }
    [byte[]]static ToSerialized($Obj, [bool]$Force) {
        $bytes = $null
        try {
            # Serialize the object using binaryFormatter: https://docs.microsoft.com/en-us/dotnet/api/system.runtime.serialization.formatters.binary.binaryformatter?
            $formatter = New-Object -TypeName System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
            $stream = New-Object -TypeName System.IO.MemoryStream
            $formatter.Serialize($stream, $Obj) # Serialise the graph
            $bytes = $stream.ToArray(); $stream.Close(); $stream.Dispose()
        } catch [System.Management.Automation.MethodInvocationException], [System.Runtime.Serialization.SerializationException] {
            #Object can't be serialized, Lets try Marshalling: https://docs.microsoft.com/en-us/dotnet/api/System.Runtime.InteropServices.Marshal?
            $TypeName = $obj.GetType().Name; $obj = $obj -as $TypeName
            if ($obj -isnot [System.Runtime.Serialization.ISerializable] -and $TypeName -in ("securestring", "Pscredential", "CredManaged")) { throw [System.Management.Automation.MethodInvocationException]::new("Cannot serialize an unmanaged structure") }
            if ($Force) {
                # Import the System.Runtime.InteropServices.Marshal namespace
                Add-Type -AssemblyName System.Runtime
                [int]$size = [System.Runtime.InteropServices.Marshal]::SizeOf($obj); $bytes = [byte[]]::new($size);
                [IntPtr]$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size);
                [void][System.Runtime.InteropServices.Marshal]::StructureToPtr($obj, $ptr, $false);
                [void][System.Runtime.InteropServices.Marshal]::Copy($ptr, $bytes, 0, $size);
                [void][System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr); # Free the memory allocated for the serialized object
            } else {
                throw [System.Runtime.Serialization.SerializationException]::new("Serialization error. Make sure the object is marked with the [System.SerializableAttribute] or is Serializable.")
            }
        } catch {
            throw $_.Exception
        }
        return $bytes
    }
    [Object[]]static ToDeserialized([byte[]]$data) {
        $bf = [System.Runtime.Serialization.Formatters.Binary.BinaryFormatter]::new()
        $ms = [System.IO.MemoryStream]::new(); $Obj = $null
        $ms.Write($data, 0, $data.Length);
        [void]$ms.Seek(0, [System.IO.SeekOrigin]::Begin);
        try {
            $Obj = [object]$bf.Deserialize($ms)
        } catch [System.Management.Automation.MethodInvocationException], [System.Runtime.Serialization.SerializationException] {
            $Obj = $ms.ToArray()
        } catch {
            throw $_.Exception
        } finally {
            $ms.Dispose(); $ms.Close()
        }
        # Output the deserialized object
        return $Obj
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
#endregion Custom_ObjectConverter

#region    _Passwords
class PasswordManager {
    [securestring]static GetPassword() {
        $ThrowOnFailure = $true
        return [PasswordManager]::GetPassword($ThrowOnFailure);
    }
    [securestring]static GetPassword([bool]$ThrowOnFailure) {
        $Password = $null; Set-Variable -Name Password -Scope Local -Visibility Private -Option Private -Value ($(Get-Variable Host).value.UI.PromptForCredential('NerdCrypt', "Please Enter Your Password", $Env:UserName, $Env:COMPUTERNAME).Password);
        if ($ThrowOnFailure -and ($null -eq $Password -or $([string]::IsNullOrWhiteSpace([xconvert]::ToString($Password))))) {
            throw [InvalidPasswordException]::new("Please Provide a Password that isn't Null and not a WhiteSpace.", $Password, [System.ArgumentNullException]::new("Password"))
        }
        return $Password
    }
    # Method to validate the password: This just checks if its a good enough password
    [bool]static ValidatePassword([SecureString]$password) {
        $IsValid = $false; $minLength = 8; $handle = [System.IntPtr]::new(0); $Passw0rd = [string]::Empty;
        try {
            Add-Type -AssemblyName System.Runtime.InteropServices
            Set-Variable -Name Passw0rd -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToString($Password));
            Set-Variable -Name handle -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Passw0rd));
            # Set the required character types
            $requiredCharTypes = [System.Text.RegularExpressions.Regex]::Matches("$Passw0rd", "[A-Za-z]|[0-9]|[^A-Za-z0-9]") | Select-Object -ExpandProperty Value
            # Check if the password meets the minimum length requirement and includes at least one of each required character type
            $IsValid = ($Passw0rd.Length -ge $minLength -and $requiredCharTypes.Count -ge 3)
        } catch {
            throw $_.Exeption
        } finally {
            Remove-Variable Passw0rd -Force -ErrorAction SilentlyContinue
            # Zero out the memory used by the variable.
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($handle);
            Remove-Variable handle -Force -ErrorAction SilentlyContinue
        }
        return $IsValid
    }
    [string]static GeneratePassword() {
        return [string][PasswordManager]::GeneratePassword(1);
    }
    [string]static GeneratePassword([int]$iterations) {
        return [string][PasswordManager]::GeneratePassword($iterations, 24, 80);
    }
    [string]static GeneratePassword([int]$iterations, [int]$Length) {
        return [string][PasswordManager]::GeneratePassword($iterations, $Length, $Length);
    }
    [string]static GeneratePassword([int]$iterations, [int]$minLength, [int]$maxLength) {
        # https://stackoverflow.com/questions/55556/characters-to-avoid-in-automatically-generated-passwords
        $Passw0rd = [string]::Empty; [string]$possibleCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;':\`",./<>?";
        $MinrL = 8; $MaxrL = 999 # Gotta have some restrictions, or one typo could endup creating insanely long or small Passwords, ex 30000 intead of 30.
        if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'Password Length'. Try $MinrL or greater." ; Break }
        if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'Password Length'. Try $MaxrL or lower." ; Break }
        if ($minLength -lt 130) {
            $Passw0rd = [string][xgen]::RandomSTR($possibleCharacters, $iterations, $minLength, $maxLength)
        } else {
            #This person Wants a really good password, so We retry Until we get a 60% strong password.
            do {
                $Passw0rd = [string][xgen]::RandomSTR($possibleCharacters, $iterations, $minLength, $maxLength)
            } until ([int][PasswordManager]::GetPasswordStrength($Passw0rd) -gt 60)
        }
        return $Passw0rd;
    }
    [int]static GetPasswordStrength([string]$passw0rd) {
        # Inspired by: https://www.security.org/how-secure-is-my-password/
        $passwordDigits = [System.Text.RegularExpressions.Regex]::new("\d", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordNonWord = [System.Text.RegularExpressions.Regex]::new("\W", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordUppercase = [System.Text.RegularExpressions.Regex]::new("[A-Z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        $passwordLowercase = [System.Text.RegularExpressions.Regex]::new("[a-z]", [System.Text.RegularExpressions.RegexOptions]::Compiled);
        [int]$strength = 0; $digits = $passwordDigits.Matches($passw0rd); $NonWords = $passwordNonWord.Matches($passw0rd); $Uppercases = $passwordUppercase.Matches($passw0rd); $Lowercases = $passwordLowercase.Matches($passw0rd);
        if ($digits.Count -ge 2) { $strength += 10 };
        if ($digits.Count -ge 5) { $strength += 10 };
        if ($NonWords.Count -ge 2) { $strength += 10 };
        if ($NonWords.Count -ge 5) { $strength += 10 };
        if ($passw0rd.Length -gt 8) { $strength += 10 };
        if ($passw0rd.Length -ge 16) { $strength += 10 };
        if ($Lowercases.Count -ge 2) { $strength += 10 };
        if ($Lowercases.Count -ge 5) { $strength += 10 };
        if ($Uppercases.Count -ge 2) { $strength += 10 };
        if ($Uppercases.Count -ge 5) { $strength += 10 };
        return $strength;
    }
    # Method to save the password to sql database
    [void]Static SavePasswordHash([string]$username, [SecureString]$password, [string]$connectionString) {
        $passw0rdHash = [string]::Empty
        # Hash the password using the SHA-3 algorithm
        if ('System.Security.Cryptography.SHA3Managed' -is 'type') {
            $passw0rdHash = (New-Object System.Security.Cryptography.SHA3Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes([xconvert]::Tostring($password)))
        } else {
            # Hash the password using an online SHA-3 hash generator
            $passw0rdHash = ((Invoke-WebRequest -Method Post -Uri "https://passwordsgenerator.net/sha3-hash-generator/" -Body "text=$([xconvert]::Tostring($password))").Content | ConvertFrom-Json).sha3
        }
        # Connect to the database
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        # Create a SQL command to update the password hash in the database
        $command = New-Object System.Data.SqlClient.SqlCommand("UPDATE Users SET PasswordHash = @PasswordHash WHERE Username = @Username", $connection)
        $command.Parameters.AddWithValue("@Username", $username)
        $command.Parameters.AddWithValue("@PasswordHash", $passw0rdHash)

        # Execute the command
        $command.ExecuteNonQuery()

        # Close the connection
        $connection.Close()
    }
    # Method to retieve the passwordHash from sql database
    # Create an instance of the PasswordManager class
    # $manager = [PasswordManager]::new("username", "")
    # Load the password hash from the database
    # $manager.LoadPasswordHash("username", "Server=localhost;Database=MyDatabase;Trusted_Connection=True;")
    [string]static LoadPasswordHash([string]$username, [string]$connectionString) {
        # Connect to the database
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        # Create a SQL command to retrieve the password hash from the database
        $command = New-Object System.Data.SqlClient.SqlCommand("SELECT PasswordHash FROM Users WHERE Username = @Username", $connection)
        $command.Parameters.AddWithValue("@Username", $username)

        # Execute the command and retrieve the password hash
        $reader = $command.ExecuteReader()
        $reader.Read()
        $Passw0rdHash = $reader["PasswordHash"]

        # Close the connection
        $connection.Close()
        return $Passw0rdHash
    }
    [string]static GetPasswordHash([string]$Passw0rd) {
        return [xconvert]::BytesToHex([PasswordHash]::new($Passw0rd).ToArray())
    }
    [bool]static VerifyPasswordHash([string]$Passw0rd, [string]$hashSTR) {
        return [PasswordManager]::VerifyPasswordHash($Passw0rd, $hashSTR, $false)
    }
    [bool]static VerifyPasswordHash([string]$Passw0rd, [string]$hashSTR, [bool]$ThrowOnFailure) {
        if ([string]::IsNullOrEmpty($Passw0rd)) {
            throw [System.ArgumentNullException]::new('password', [InvalidPasswordException]::New('Please input a valid Password'));
        }
        if ([string]::IsNullOrWhiteSpace($hashSTR)) {
            throw [System.ArgumentNullException]::new('hashSTR');
        }
        Add-Type -AssemblyName System.Runtime.InteropServices
        Set-Variable -Name handle -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Passw0rd));
        $handle = [System.IntPtr]::new(0); [bool]$result = $false; $Isvalid_Hex = [regex]::IsMatch($hashSTR, "^[A-Fa-f0-9]{72}$")
        try {
            if (!$Isvalid_Hex) { Throw [System.FormatException]::new("Hash string was in invalid format.") }
            $hashBytes = $null; Set-Variable -Name hashBytes -Scope Local -Visibility Private -Option Private -Value ([xconvert]::BytesFromHex($hashSTR));
            if ([PasswordHash]::new($hashBytes).Verify($Passw0rd)) {
                $result = $true
            } elseif ($ThrowOnFailure) {
                throw [System.UnauthorizedAccessException]::new('Wrong Password.');
            } else {
                $result = $false
            }
        } catch {
            throw $_
        } finally {
            Remove-Variable hashBytes -Force -ErrorAction SilentlyContinue
            [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($handle);
        }
        return $result
    }
}

#region    FipsHMACSHA256
# .SYNOPSIS
#     A PowerShell class to provide a FIPS compliant alternative to the built-in [System.Security.Cryptography.HMACSHA256]
# .DESCRIPTION
#     FIPS (Federal Information Processing Standard) is a set of guidelines that specify the security requirements for cryptographic algorithms and protocols used in the United States government.
#     A FIPS compliant algorithm is one that has been reviewed and approved by the National Institute of Standards and Technology (NIST) to meet certain security standards.
#     The HMAC is a type of message authentication code that uses a secret key to verify the authenticity and integrity of a message.
#     It is based on a hash function, such as SHA-256, which is a cryptographic function that produces a fixed-size output (called a hash or message digest) from a variable-size input.
#     The built-in HMACSHA256 class in .NET Framework and PowerShell is a class that implements the HMAC using the SHA-256 hash function.
#     However, in older versions of these platforms the HMACSHA256 class may not be FIPS compliant.
# .EXAMPLE
#     [FipsHmacSha256]::new() ....
#     Explanation of the ... or .... result
class FipsHmacSha256 : System.Security.Cryptography.HMAC {
    static hidden $rng
    FipsHmacSha256() {
        $this._Init();
        $this.Key = [FipsHmacSha256]::GetRandomBytes(64);
    }

    FipsHmacSha256([Byte[]] $key) {
        $this._Init();
        $this.Key = $key;
    }
    static [Byte[]] GetRandomBytes($keyLength) {
        [Byte[]] $array = New-Object Byte[] $keyLength
        [FipsHmacSha256].RNG.GetBytes($array)
        return $array
    }
    [void]hidden _Init() {
        if ($null -eq [FipsHmacSha256].RNG) {
            [FipsHmacSha256].psobject.Properties.Add([psscriptproperty]::new('RNG',
                    { return [System.Security.Cryptography.RNGCryptoServiceProvider]::new() }
                )
            )
        }
        $flags = [Reflection.BindingFlags]'Instance, NonPublic'
        [Reflection.FieldInfo]$m_hashName = [System.Security.Cryptography.HMAC].GetField('m_hashName', $flags)
        [Reflection.FieldInfo]$m_hash1 = [System.Security.Cryptography.HMAC].GetField('m_hash1', $flags)
        [Reflection.FieldInfo]$m_hash2 = [System.Security.Cryptography.HMAC].GetField('m_hash2', $flags)
        $m_hashName.SetValue($this, 'SHA256')
        $m_hash1.SetValue($this, [System.Security.Cryptography.SHA256CryptoServiceProvider]::new())
        $m_hash2.SetValue($this, [System.Security.Cryptography.SHA256CryptoServiceProvider]::new())
        $this.HashSizeValue = 256
    }
}
#endregion FipsHMACSHA256

# .SYNOPSIS
#     PBKDF2 Password String Hashing Class.
# .DESCRIPTION
#     when a user inputs a password, instead of storing the password in cleartext, we hash the password and store the username and hash pair in the database table.
#     When the user logs in, we hash the password sent and compare it to the hash connected with the provided username.
# .EXAMPLE
#     ## Usage Example:
#
#     # STEP 1. Create Hash and Store it somewhere secure.
#     [byte[]]$hashBytes = [PasswordHash]::new("MypasswordString").ToArray();
#     [xconvert]::BytesToHex($hashBytes) | Out-File $ReallySecureFilePath;
#     $(Get-Item $ReallySecureFilePath).Encrypt();
#
#     # STEP 2. Check Password against a Stored hash.
#     [byte[]]$hashBytes = [xconvert]::BytesFromHex($(Get-Content $ReallySecureFilePath));
#     $hash = [PasswordHash]::new($hashBytes);
#     if(!$hash.Verify("newly entered password")) { throw [System.UnauthorizedAccessException]::new() };
# .NOTES
#     https://stackoverflow.com/questions/51941509/what-is-the-process-of-checking-passwords-in-databases/51961121#51961121
class PasswordHash {
    [byte[]]$hash # The pbkdf2 Hash
    [byte[]]$salt
    [ValidateNotNullOrEmpty()][int]hidden $SaltSize = 16
    [ValidateNotNullOrEmpty()][int]hidden $HashSize = 20 # 20 bytes length is 160 bits
    [ValidateNotNullOrEmpty()][int]hidden $HashIter = 10000 # Number of pbkdf2 iterations

    PasswordHash([string]$passw0rd) {
        $this.salt = [byte[]]::new($this.SaltSize) # todo: Not tested yet but maybe I could use [xgen]::NewSalt($SaltSize) as the default salt
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
class InvalidPasswordException : System.Exception {
    [string]$Message; [string]hidden $Passw0rd; [securestring]hidden $Password; [System.Exception]$InnerException
    InvalidPasswordException() { $this.Message = "Invalid password" }
    InvalidPasswordException([string]$Message) { $this.message = $Message }
    InvalidPasswordException([string]$Message, [string]$Passw0rd) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, [System.Exception]::new($Message)) }
    InvalidPasswordException([string]$Message, [securestring]$Password) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, [System.Exception]::new($Message)) }
    InvalidPasswordException([string]$Message, [string]$Passw0rd, [System.Exception]$InnerException) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, $InnerException) }
    InvalidPasswordException([string]$Message, [securestring]$Password, [System.Exception]$InnerException) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, $InnerException) }
}
#endregion _Passwords

#region    Object
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

#region    VaultStuff
# A managed credential object. Makes it easy to protect, convert, save and stuff ..
class CredManaged {
    [string]$target
    [CredType]hidden $type;
    [bool]hidden $IsProtected = $false;
    [ValidateNotNullOrEmpty()][string]$UserName = [Environment]::GetEnvironmentVariable('Username');
    [ValidateNotNullOrEmpty()][securestring]$Password = [securestring]::new();
    [ValidateNotNullOrEmpty()][string]hidden $Domain = [Environment]::GetEnvironmentVariable('USERDOMAIN');
    [ValidateSet('CurrentUser', 'LocalMachine')][ValidateNotNullOrEmpty()][string]hidden $Scope = 'CurrentUser';

    CredManaged() {}
    CredManaged([string]$target, [string]$username, [SecureString]$password) {
        ($this.target, $this.username, $this.password) = ($target, $username, $password)
    }
    CredManaged([string]$target, [string]$username, [SecureString]$password, [CredType]$type) {
        ($this.target, $this.username, $this.password, $this.type) = ($target, $username, $password, $type)
    }
    CredManaged([PSCredential]$PSCredential) {
        ($this.UserName, $this.Password) = ($PSCredential.UserName, $PSCredential.Password)
    }
    CredManaged([string]$target, [PSCredential]$PSCredential) {
        ($this.target, $this.UserName, $this.Password) = ($target, $PSCredential.UserName, $PSCredential.Password)
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
    [void]SaveToVault() {
        $CredMan = [CredentialManager]::new();
        [void]$CredMan.SaveCredential($this.target, $this.UserName, $this.Password);
    }
    [string]ToString() {
        $str = $this.UserName
        if ($str.Length -gt 9) { $str = $str.Substring(0, 6) + '...' }
        return $str
    }
}
class NativeCredential {
    [System.Int32]$AttributeCount
    [UInt32]$CredentialBlobSize
    [IntPtr]$CredentialBlob
    [IntPtr]$TargetAlias
    [System.Int32]$Type
    [IntPtr]$TargetName
    [IntPtr]$Attributes
    [IntPtr]$UserName
    [UInt32]$Persist
    [IntPtr]$Comment

    NativeCredential([CredManaged]$Cr3dential) {
        $this._init_();
        $this.CredentialBlobSize = [UInt32](($Cr3dential.password.Length + 1) * 2)
        $this.TargetName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($Cr3dential.target)
        $this.CredentialBlob = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Cr3dential.password)
        $this.UserName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($Cr3dential.username)
    }
    NativeCredential([string]$target, [string]$username, [securestring]$password) {
        $this._init_();
        $this.CredentialBlobSize = [UInt32](($password.Length + 1) * 2);
        $this.TargetName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($target);
        $this.CredentialBlob = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password);
        $this.UserName = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($username);
    }
    hidden _init_() {
        $this.AttributeCount = 0
        $this.Comment = [IntPtr]::Zero
        $this.Attributes = [IntPtr]::Zero
        $this.TargetAlias = [IntPtr]::Zero
        $this.Type = [CredType]::Generic.value__
        $this.Persist = [UInt32] [CredentialPersistence]::LocalComputer
    }
}
# Static class for calling the native credential functions
class CredentialNotFoundException : System.Exception, System.Runtime.Serialization.ISerializable {
    [string]$Message; [Exception]$InnerException; hidden $Info; hidden $Context
    CredentialNotFoundException() { $this.Message = 'CredentialNotFound' }
    CredentialNotFoundException([string]$message) { $this.Message = $message }
    CredentialNotFoundException([string]$message, [Exception]$InnerException) { ($this.Message, $this.InnerException) = ($message, $InnerException) }
    CredentialNotFoundException([System.Runtime.Serialization.SerializationInfo]$info, [System.Runtime.Serialization.StreamingContext]$context) { ($this.Info, $this.Context) = ($info, $context) }
}

class CredentialManager {
    static $LastErrorCode
    CredentialManager() {
        $CONSTANTS = [psobject]::new()
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_SUCCESS', { return 0 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_NOT_FOUND', { return 1168 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_INVALID_FLAGS', { return 1004 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_PERSIST_LOCAL_MACHINE', { return 2 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_USERNAME_LENGTH', { return 514 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_CREDENTIAL_BLOB_SIZE', { return 512 }))
        $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_GENERIC_TARGET_LENGTH', { return 32767 }))
        [CredentialManager].psobject.Properties.Add([psscriptproperty]::new('CONSTANTS', { return $CONSTANTS }))
        # Import native functions from Advapi32.dll
        # No other choice but to use Add-Type. ie: https://stackoverflow.com/questions/64405866/invoke-runtime-interopservices-dllimportattribute
        # So CredentialManager.Advapi32+functionName it is!
        if (![bool]('CredentialManager.Advapi32' -as 'type')) { Add-Type -Namespace CredentialManager -Name Advapi32 -MemberDefinition ([xconvert]::ToDeCompressed('H4sIAAAAAAAEALVUS2/aQBC+91eMOIFqWQT6kIo4UB4VKkQohuYQ5bDYA1lpvUt31zSk6n/vrB+AMW1a2vhge+f5ffONDQCwSZaCh4AyiaGvMZrvNggfIOHSwvdXkF+fUKKmsC5ceTBQMeNyxoz5pnREtlZh66O2fMVDZpHM7cL8hRu+FHiU8cYrSpZT3hYpw0eLMkIX+86DKXvkMQHswvv9YfhIx3rheQ1XzWazkQL+kd5Pic1QG25slVuAxnAlM24TFTIxZeEDl5gxG0qLeqO5SSkdNbgLrE5CO2E7ldh69vjMZeQH+DVBaTkTHvQfmA7QUmr+5i8kD1WEjftjlCYtleLMMg/w8ogU9EiwtekUpr1c7tY5KsXlGuZMr9Fes7ji6as4piZ784BGP+cxwoQZe6u5pcl3Sm1JOKdbwJ8qxQpN9/ZgZyzGNIMwoVK77AWDLDo7VHKO5cmfZQA9S/nLxGJfJUfIx9LOrD54zfkh9ARnFdfCoE6n87KKXjPLt3jQFS4XNmd7RtjccypsLsUNjYzk9cdukdUmQL3lIRqfwl1944/Gk+F8PB3+egEO+D8KtSztQdG7FHGyPv9F0hL9sqS566ykAyHG8UZpW6/1oi3b8HbLj4SopR+23s2UA9OFmiNwgyy6rf1GYo822LopDbVWmvwkMul+0JzUpl8O/bu0hKVSAoqy9buxvC92z6YcPEhte7Et3XKbw6SR6GwxcqvhAW1iQTPcj5pOjc7f03QS4wvwTOtmRDWuqqufEKHDMae6IFbtFqzcB3AJmZFGrF2G16VmcKuTdS3wD6Z7pu85lAMU+MzMn4Wb1fi3RWp0fgKYas6b9AcAAA==')) }
        if (Get-Service vaultsvc -ErrorAction SilentlyContinue) { Start-Service vaultsvc -ErrorAction Stop }
        #Load the Credentials and PasswordVault assemblies (!not tested!)
        #if (![bool]('Windows.Security.Credentials.PasswordVault' -as 'type')) {
        #    [void][Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType = WindowsRuntime]
        #}
    }
    [object]static hidden Advapi32() {
        return (New-Object -TypeName CredentialManager.Advapi32)
    }
    [void]static SaveCredential([string]$title, [SecureString]$SecureString) {
        $UserName = [System.Environment]::GetEnvironmentVariable('UserName');
        [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
    }
    [void]static SaveCredential([string]$title, [string]$UserName, [SecureString]$SecureString) {
        [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
    }
    [void]static SaveCredential([CredManaged]$Object) {
        # Create the native credential object.
        $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
        foreach ($prop in ([NativeCredential]::new($Object).PsObject.properties)) {
            $NativeCredential."$($prop.Name)" = $prop.Value
        }
        # Save Generic credential to the Windows Credential Vault.
        $result = [CredentialManager]::Advapi32()::CredWrite([ref]$NativeCredential, 0)
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (!$result) {
            throw [Exception]::new("Error saving credential: 0x" + "{0}" -f [CredentialManager]::LastErrorCode)
        }
        # Clean up memory allocated for the native credential object.
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.TargetName)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.CredentialBlob)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.UserName)
    }
    [bool]static Remove([string]$target, [CredType]$type) {
        $Isdeleted = [CredentialManager]::Advapi32()::CredDelete($target, $type, 0);
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (!$Isdeleted) {
            if ([CredentialManager]::LastErrorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
                throw [CredentialNotFoundException]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode) (credential not found).");
            } else {
                throw [Exception]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode).");
            }
        }
        return $Isdeleted
    }
    [CredManaged]static GetCredential([string]$target) {
        #uses the default $env:username
        return [CredentialManager]::GetCredential($target, (Get-Item Env:\USERNAME).Value);
    }
    [CredManaged]static GetCredential([string]$target, [string]$username) {
        return [CredentialManager]::GetCredential($target, [CredType]::Generic, $username);
    }
    # Method for retrieving a saved credential from the Windows Credential Vault.
    [CredManaged]static GetCredential([string]$target, [CredType]$type, [string]$username) {
        $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
        foreach ($prop in ([NativeCredential]::new($target, $username, [securestring]::new()).PsObject.properties)) {
            $NativeCredential."$($prop.Name)" = $prop.Value
        }
        # Declare variables
        $AdvAPI32 = [CredentialManager]::Advapi32()
        $outCredential = [IntPtr]::Zero # To hold the retrieved native credential object.
        # Try to retrieve the credential from the Windows Credential Vault.
        $result = $AdvAPI32::CredRead($target, $type.value__, 0, [ref]$outCredential)
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (!$result) {
            $errorCode = [CredentialManager]::LastErrorCode
            if ($errorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
                $(Get-Variable host).value.UI.WriteErrorLine("`nERROR_NOT_FOUND: Credential '$target' not found in Windows Credential Vault. Returning Empty Object ...`n");
                return [CredManaged]::new();
            } else {
                throw [Exception]::new("Error reading '{0}' in Windows Credential Vault. ErrorCode: 0x{1}" -f $target, $errorCode)
            }
        }
        # Convert the retrieved native credential object to a managed Credential object & Get the Credential from the mem location
        $NativeCredential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($outCredential, [Type]"CredentialManager.Advapi32+NativeCredential") -as 'CredentialManager.Advapi32+NativeCredential'
        [System.GC]::Collect();
        $target = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.TargetName)
        $password = [Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.CredentialBlob)
        $targetuser = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.UserName)
        $credential = [CredManaged]::new($target, $targetuser, [xconvert]::ToSecurestring($password));
        # Clean up memory allocated for the native credential object.
        [void]$AdvAPI32::CredFree($outCredential); [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        # Return the managed Credential object.
        return $credential
    }
    [System.Collections.ObjectModel.Collection[CredManaged]]static RetreiveAll() {
        $Credentials = [System.Collections.ObjectModel.Collection[CredManaged]]::new();
        # CredEnumerate is slow af so, I ditched it.
        $credList = [CredentialManager]::get_StoredCreds();
        foreach ($cred in $credList) {
            Write-Verbose "CredentialManager.GetCredential($($cred.Target))";
            $Credentials.Add([CredManaged]([CredentialManager]::GetCredential($cred.Target, $cred.Type, $cred.User)));
        }
        return $Credentials
    }
    [Psobject[]]static hidden get_StoredCreds() {
        # until I know the existance of a [wrapper module](https://learn.microsoft.com/en-us/powershell/utility-modules/crescendo/overview?view=ps-modules), I'll stick to this Hack.
        $cmdkey = (Get-Command cmdkey -ErrorAction SilentlyContinue).Source
        if ([string]::IsNullOrEmpty($cmdkey)) { throw [System.Exception]::new('get_StoredCreds() Failed.') }
        $outputLines = (&$cmdkey /list) -split "`n"
        [CredentialManager]::LastErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if ($outputLines) {
        } else {
            throw $error[0].Exception.Message
        }
        $target = $type = $user = $perst = $null
        $credList = $(foreach ($line in $outputLines) {
                if ($line -match "^\s*Target:\s*(.+)$") {
                    $target = $matches[1]
                } elseif ($line -match "^\s*Type:\s*(.+)$") {
                    $type = $matches[1]
                } elseif ($line -match "^\s*User:\s*(.+)$") {
                    $user = $matches[1]
                } elseif ($line -match "^\s*Local machine persistence$") {
                    $perst = "LocalComputer"
                } elseif ($line -match "^\s*Enterprise persistence$") {
                    $perst = 'Enterprise'
                }
                if ($target -and $type -and $user -and ![string]::IsNullOrEmpty($perst)) {
                    [PSCustomObject]@{
                        Target      = [string]$target
                        Type        = [CredType]$type
                        User        = [string]$user
                        Persistence = [CredentialPersistence]$perst
                    }
                    $target = $type = $user = $perst = $null
                }
            }
        ) | Select-Object @{l = 'Target'; e = { $_.target.replace('LegacyGeneric:target=', '').replace('WindowsLive:target=', '') } }, Type, User, Persistence | Where-Object { $_.target -ne 'virtualapp/didlogical' };
        return $credList
    }
}
#endregion vaultStuff

#region    securecodes~Expiration
Class Expiration {
    [Datetime]$Date
    [Timespan]$TimeSpan
    [String]$TimeStamp
    [ExpType]$Type

    Expiration() {
        $this.TimeSpan = [Timespan]::FromMilliseconds([DateTime]::Now.Millisecond)
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$Years) {
        # ($Months, $Years) = if ($Years -eq 1) { (12, 0) }else { (0, $Years) };
        # $CrDate = [datetime]::Now;
        # $Months = [int]($CrDate.Month + $Months); if ($Months -gt 12) { $Months -= 12 };
        $this.TimeSpan = [Timespan]::new((365 * $years), 0, 0, 0);
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$Years, [int]$Months) {
        $this.TimeSpan = [Timespan]::new((365 * $years + $Months * 30), 0, 0, 0);
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([datetime]$date) {
        $this.Date = $date
        $this.TimeSpan = $date - [datetime]::Now;
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([System.TimeSpan]$TimeSpan) {
        $this.TimeSpan = $TimeSpan;
        $this.Date = [datetime]::Now + $this.TimeSpan
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$hours, [int]$minutes, [int]$seconds) {
        $this.TimeSpan = [Timespan]::new($hours, $minutes, $seconds);
        $this.setExpType($this.TimeSpan);
        $this.setTimeStamp($this.TimeSpan);
    }
    Expiration([int]$days, [int]$hours, [int]$minutes, [int]$seconds) {
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
#endregion securecodes~Expiration

#region    Usual~Algorithms

#region    Aes~algo
# .SYNOPSIS
#     AES (System.Security.Cryptography.Aes) wrapper class
# .DESCRIPTION
#     A symmetric-key encryption algorithm that is used to protect a variety of sensitive data, including financial transactions, medical records, and government communications.
#     It is considered to be very secure, and has been adopted as a standard by many governments and organizations around the world.
#
#     By default the encrypt method uses CBC ciphermode, AES-256 (The str0ng3st Encryption In z3 WOrLd!), uses SHA1 to hash since it has been proven to be more secure than MD5.
#     aand the result is compressed. plus there is the option to stack encryptions by iteration. (But beware when you iterate much it produces larger output)
class AesLg {
    [ValidateNotNullOrEmpty()][byte[]]hidden static $Bytes;

    AesLg() {}
    AesLg([System.Object]$Obj) {
        [AesLg]::SetBytes($Obj); [void][AesLg]::Create();
    }
    [void]static SetBytes([byte[]]$Bytes) {
        [AesLg]::Bytes = $Bytes;
    }
    [void]static SetBytes([Object]$Object) {
        [AesLg]::SetBytes([xconvert]::BytesFromObject($Object));
    }
    [byte[]]static Encrypt() {
        if ($null -eq [AesLg]::Bytes) {
            throw [Exception]::new('Please Set Bytes First');
        }
        return [AesLg]::Encrypt(1);
    }
    [byte[]]static Encrypt([int]$iterations) {
        $eNcrypt3dBytes = $null; $d3faultP4ssW0rd = $null;
        try {
            Set-Variable -Name d3faultP4ssW0rd -Scope Local -Visibility Private -Option Private -Value ([xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xgen]::UniqueMachineId(), [byte[]](166, 153, 228, 202, 200, 222, 126, 88, 90, 201, 219, 176), 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8))));
            $eNcrypt3dBytes = [AesLg]::Encrypt($iterations, $d3faultP4ssW0rd);
        } catch {
            throw $_.Exeption # todo: create a custom exception for this.
        } finally {
            Remove-Variable d3faultP4ssW0rd -Force -ErrorAction SilentlyContinue
        }
        return $eNcrypt3dBytes;
    }
    [byte[]]static Encrypt([int]$iterations, [securestring]$Password) {
        return [AesLg]::Encrypt($iterations, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='))
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
        return [AesLg]::Encrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='));
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
        $_bytes = $Bytes; $Salt = [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw==')
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Encryption [$i/$iterations] ...$(
                $_bytes = [AesLg]::Encrypt($_bytes, $Password, $Salt)
            ) Done."
        };
        return $_bytes;
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$Protect) {
        return [AesLg]::Encrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), 'Gzip', $Protect);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
        return [AesLg]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $false);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$Protect) {
        return [AesLg]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $Protect);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
        return [AesLg]::Encrypt($Bytes, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), $Compression, $false);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
        return [AesLg]::Encrypt($Bytes, $Password, $Salt, $Compression, $false);
    }
    [byte[]]static Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$Protect) {
        [int]$KeySize = 256; $CryptoProvider = $null; $EncrBytes = $null
        if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { Throw [System.InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") }
        Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
        $CryptoProvider.KeySize = [int]$KeySize;
        $CryptoProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $CryptoProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $CryptoProvider.Key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
        $CryptoProvider.IV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(16);
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
        $d3cryptedBytes = $null; $d3faultP4ssW0rd = $null;
        try {
            Set-Variable -Name d3faultP4ssW0rd -Scope Local -Visibility Private -Option Private -Value ([xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xgen]::UniqueMachineId(), [byte[]](166, 153, 228, 202, 200, 222, 126, 88, 90, 201, 219, 176), 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8))));
            $d3cryptedBytes = [AesLg]::Decrypt($iterations, $d3faultP4ssW0rd);
        } catch {
            throw $_.Exeption
        } finally {
            Remove-Variable d3faultP4ssW0rd -Force -ErrorAction SilentlyContinue
        }
        return $d3cryptedBytes
    }
    [byte[]]static Decrypt([int]$iterations, [securestring]$Password) {
        return [AesLg]::Decrypt($iterations, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='))
    }
    [byte[]]static Decrypt([int]$iterations, [SecureString]$Password, [byte[]]$salt) {
        if ($null -eq [AesLg]::Bytes) { throw [System.ArgumentNullException]::new('bytes', 'Bytes Value cannot be null.') }
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
        $_bytes = $bytesToDecrypt; $Salt = [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw==')
        for ($i = 1; $i -lt $iterations + 1; $i++) {
            Write-Verbose "[+] Decryption [$i/$iterations] ...$(
                $_bytes = [AesLg]::Decrypt($_bytes, $Password, $Salt)
            ) Done."
        };
        return $_bytes;
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [bool]$UnProtect) {
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), 'GZip', $UnProtect);
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
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, [Convert]::FromBase64String('bz07LmY5XiNkXW1WQjxdXw=='), $Compression, $false);
    }
    [byte[]]static Decrypt([byte[]]$bytesToDecrypt, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$UnProtect) {
        [int]$KeySize = 256; $CryptoProvider = $null; $DEcrBytes = $null; $_Bytes = $null
        $_Bytes = [XConvert]::ToDeCompressed($bytesToDecrypt, $Compression);
        if ($UnProtect) { $_Bytes = [xconvert]::ToUnProtected($_Bytes, $Salt, [ProtectionScope]::CurrentUser) }
        Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([System.Security.Cryptography.AesCryptoServiceProvider]::new());
        $CryptoProvider.KeySize = $KeySize;
        $CryptoProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $CryptoProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $CryptoProvider.Key = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::ToString($Password), $Salt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
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
# .SYNOPSIS
#     Powershell class implementation of RSA (Rivest-Shamir-Adleman) algorithm.
# .DESCRIPTION
#     A public-key cryptosystem that is widely used for secure data transmission. It is based on the mathematical concept of factoring large composite numbers into their prime factors. The security of the RSA algorithm is based on the difficulty of factoring large composite numbers, which makes it computationally infeasible for an attacker to determine the private key from the public key.
# .EXAMPLE
#     Test-MyTestFunction -Verbose
#     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
class RSA {
    # Simply Encrypts the specified data using the public key.
    [byte[]]static Encrypt([byte[]]$data, [string]$publicKeyXml) {
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.FromXmlString($publicKeyXml)
        return $rsa.Encrypt($data, $true)
    }

    # Decrypts the specified data using the private key.
    [byte[]]static Decrypt([byte[]]$data, [string]$privateKeyXml) {
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.FromXmlString($privateKeyXml)
        return $rsa.Decrypt($data, $true)
    }

    # The data is encrypted using AES in combination with the password and salt.
    # The encrypted data is then encrypted using RSA.
    [byte[]]static Encrypt([byte[]]$data, [string]$PublicKeyXml, [securestring]$password, [byte[]]$salt) {
        # Generate the AES key and initialization vector from the password and salt
        $aesKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(32);
        $aesIV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(16);

        # Encrypt the data using AES
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new(); ($aes.Key, $aes.IV) = ($aesKey, $aesIV);
        $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

        # Encrypt the AES key and initialization vector using RSA
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.FromXmlString($PublicKeyXml)
        $encryptedKey = $rsa.Encrypt($aesKey, $true)
        $encryptedIV = $rsa.Encrypt($aesIV, $true)

        # Concatenate the encrypted key, encrypted IV, and encrypted data
        # and return the result as a byte array
        return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData));
    }

    # Decrypts the specified data using the private key.
    # The data is first decrypted using RSA to obtain the AES key and initialization vector.
    # The data is then decrypted using AES.
    [byte[]]static Decrypt([byte[]]$data, [string]$privateKeyXml, [securestring]$password) {
        # Extract the encrypted key, encrypted IV, and encrypted data from the input data
        $encryptedKey = $data[0..255]
        $encryptedIV = $data[256..271]
        $encryptedData = $data[272..$data.Length]

        # Decrypt the AES key and initialization vector using RSA
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        # todo: Use the $PASSWORD to decrypt the private key so it can be used
        $rsa.FromXmlString($privateKeyXml)
        $aesKey = $rsa.Decrypt($encryptedKey, $true)
        $aesIV = $rsa.Decrypt($encryptedIV, $true)

        # Decrypt the data using AES
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Key = $aesKey
        $aes.IV = $aesIV
        return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
    }
    # Exports the key pair to a file or string. # This can be useful if you want to save the key pair to a file or string for later use.
    # If a file path is specified, the key pair will be saved to the file.
    # If no file path is specified, the key pair will be returned as a string.
    [void]static ExportKeyPair([xml]$publicKeyXml, [string]$privateKeyXml, [string]$filePath = "") {
        $keyPair = @{
            "PublicKey"  = $publicKeyXml
            "PrivateKey" = $privateKeyXml
        }

        if ([string]::IsNullOrWhiteSpace($filePath)) {
            throw 'Invalid FilePath'
        } else {
            # Save the key pair to the specified file
            $keyPair | ConvertTo-Json | Out-File -FilePath $filePath
        }
    }
    [psobject]static LoadKeyPair([string]$filePath = "" ) {
        if ([string]::IsNullOrWhiteSpace($filePath)) {
            throw [System.ArgumentNullException]::new('filePath')
        }
        return [RSA]::LoadKeyPair((Get-Content $filePath | ConvertFrom-Json))
    }
    [psobject]static LoadKeyPair([string]$filePath = "", [string]$keyPairString = "") {
        return $keyPairString | ConvertFrom-Json
    }

    # Generates a new RSA key pair and returns the public and private key XML strings.
    [string] GenerateKeyPair() {
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        ($publicKey, $privateKey) = ($rsa.ToXmlString($false), $rsa.ToXmlString($true))
        return $publicKey, $privateKey
    }
}
#endregion RSA~algo

#region    X509
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class X509 {
    [string]hidden $String;
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
    [string]$Path

    X509 () {
        $this._init()
    }
    X509 ([string]$Type, [securestring]$Pin) {
        ($this.Type, $this.Pin) = ($Type, $Pin)
        $this._init()
    }
    X509 ([string]$Type, [string]$CertStoreLocation, [securestring]$Pin) {
        ($this.Type, $this.StoreLocation, $this.Pin) = ($Type, $CertStoreLocation, $Pin)
        $this._init()
    }
    X509 ([string]$Type, [string]$Subject, [string]$CertStoreLocation, [securestring]$Pin) {
        ($this.Type, $this.Subject, $this.StoreLocation, $this.Pin) = ($Type, $Subject, $CertStoreLocation, $Pin)
        $this._init()
    }
    X509 ([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
        $this.Cert = $Certificate
        $this._init()
    }
    X509 ([System.Security.Cryptography.X509Certificates.X509Certificate2]$X509Certificate2, [System.Security.Cryptography.RSAEncryptionPadding]$Padding) {
        ($this.Cert, $this.KeyPadding) = ($X509Certificate2, $Padding);
        $this._init()
    }
    X509 ([string]$Type, [string]$Subject, [string]$CertStoreLocation, [securestring]$Pin, [System.DateTime]$ExpirationDate) {
        ($this.Type, $this.Subject, $this.StoreLocation, $this.Pin, $this.Expiration) = ($Type, $Subject, $CertStoreLocation, $Pin, $ExpirationDate)
        $this._init()
    }
    [byte[]]Encrypt([byte[]]$Bytes) {
        if ($null -eq $Bytes) { throw [System.ArgumentException]::new('Null Byte array can not be ecrypted!', 'Bytes') };
        if ($null -eq $this.Cert) { $this.CreateCertificate() }
        return $this.Encrypt($Bytes, $this.Cert);
    }
    [byte[]]Decrypt([byte[]]$Bytes) {
        if ($null -eq $Bytes) { throw [System.ArgumentException]::new('Null Byte array can not be decrypted!', 'Bytes') };
        if ($null -eq $this.Cert) { throw [System.ArgumentException]::new('Can not use Null X509Certificate', 'X509.Cert') };
        return $this.Decrypt($this.Bytes, $this.Cert)
    }
    [byte[]]Encrypt([byte[]]$PlainBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        if ($null -eq $this.KeyPadding) {
            Write-Verbose "[+] Use a Random 'RSAEncryption KeyPadding' ..."
            $this.KeyPadding = [X509]::GetRSAPadding();
        }
        return $Cert.PublicKey.Key.Encrypt($PlainBytes, $this.KeyPadding);
    }
    [byte[]]Decrypt([byte[]]$encryptedBytes, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        $PrivateKey = $Cert.PrivateKey;
        if ($null -eq $PrivateKey) {
            throw [System.ArgumentNullException]::new('PrivateKey')
        }
        return $PrivateKey.Decrypt($encryptedBytes, $this.KeyPadding);
    }
    [byte[]]Decrypt([string]$Base64String, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
        [byte[]]$encryptedBytes = [Convert]::FromBase64String($Base64String); # todo: A try catch would be useful here
        return $this.Decrypt($encryptedBytes, $Cert);
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
        return $(Invoke-Expression "[System.Security.Cryptography.RSAEncryptionPadding]::$([Enum]::GetNames([RSAPadding]) | Get-Random)")
    }
    [System.Security.Cryptography.RSAEncryptionPadding]static GetRSAPadding([string]$Padding) {
        if (!(($Padding -as 'RSAPadding') -is [RSAPadding])) {
            throw "Value Not in Validateset."
        } else {
            return $(Invoke-Expression "[System.Security.Cryptography.RSAEncryptionPadding]::$Padding")
        }
    }
    [System.Security.Cryptography.RSAEncryptionPadding]static GetRSAPadding([System.Security.Cryptography.RSAEncryptionPadding]$Padding) {
        [System.Security.Cryptography.RSAEncryptionPadding[]]$validPaddings = [Enum]::GetNames([RSAPadding]) | ForEach-Object { "{0}$_" }; Set-Variable -Name validPaddings -Visibility Public -Scope Local -Option ReadOnly -Value $($validPaddings | ForEach-Object { Invoke-Expression ($_ -f "[System.Security.Cryptography.RSAEncryptionPadding]::") });
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
        if ($null -eq $this.KeyPadding) { $this.KeyPadding = [X509]::GetRSAPadding() }
        if ($null -eq $this.NotAfter) { $this.NotAfter = [Expiration]::new(0, 1).Date } # 30 Days
        if ($null -eq $this.StoreLocation) { $this.StoreLocation = "Cert:\CurrentUser\My" }
        if ($null -eq $this.Path) { $this.Path = "{0}\{1}" -f $this.StoreLocation, $this.Cert.Thumbprint }
    }
    [void]ImportCertificate() {
        $this.Cert = ''
    }
}
#endregion X509

#region    ecc
# .SYNOPSIS
#     Elliptic Curve Cryptography
# .DESCRIPTION
#     Asymmetric-key encryption algorithms that are known for their strong security and efficient use of resources. They are widely used in a variety of applications, including secure communication, file encryption, and password storage.
# .EXAMPLE
#     $ecc = new ECC($publicKeyXml, $privateKeyXml)
#     $encryptedData = $ecc.Encrypt($data, $password, $salt)
#     $decryptedData = $ecc.Decrypt($encryptedData, $password, $salt)
class ECC {
    $publicKeyXml = [string]::Empty
    $privateKeyXml = [string]::Empty

    # Constructor
    ECC([string]$publicKeyXml, [string]$privateKeyXml) {
        $this.publicKeyXml = $publicKeyXml
        $this.privateKeyXml = $privateKeyXml
    }
    # Encrypts the specified data using the public key.
    # The data is encrypted using AES in combination with the password and salt.
    # Normally I could use System.Security.Cryptography.ECCryptoServiceProvider but for Compatibility reasons
    # I use ECDsaCng class, which provides similar functionality.
    # The encrypted data is then encrypted using ECC.
    # Encrypts the specified data using the public key.
    # The data is encrypted using AES in combination with the password and salt.
    # The encrypted data is then encrypted using ECC.
    [byte[]] Encrypt([byte[]]$data, [securestring]$password, [byte[]]$salt) {
        # Generate the AES key and initialization vector from the password and salt
        $aesKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(32);
        $aesIV = [System.Security.Cryptography.Rfc2898DeriveBytes]::new([xconvert]::Tostring($password), $salt, 1000).GetBytes(16);
        # Encrypt the data using AES
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key = $aesKey
        $aes.IV = $aesIV
        $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

        # Encrypt the AES key and initialization vector using ECC
        $ecc = New-Object System.Security.Cryptography.ECDsaCng
        $ecc.FromXmlString($this.publicKeyXml)
        $encryptedKey = $ecc.Encrypt($aesKey, $true)
        $encryptedIV = $ecc.Encrypt($aesIV, $true)

        # Concatenate the encrypted key, encrypted IV, and encrypted data
        # and return the result as a byte array
        return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData))
        # or:
        # $bytes = New-Object System.Collections.Generic.List[Byte]
        # $bytes.AddRange($encryptedKey)
        # $bytes.AddRange($encryptedIV)
        # $bytes.AddRange($encryptedData)
        # return [byte[]]$bytes
    }
    # Decrypts the specified data using the private key.
    # The data is first decrypted using ECC to obtain the AES key and initialization vector.
    # The data is then decrypted using AES.
    [byte[]] Decrypt([byte[]]$data, [securestring]$password) {
        # Extract the encrypted key, encrypted IV, and encrypted data from the input data
        $encryptedKey = $data[0..255]
        $encryptedIV = $data[256..271]
        $encryptedData = $data[272..$data.Length]

        # Decrypt the AES key and initialization vector using ECC
        $ecc = [System.Security.Cryptography.ECDsaCng]::new();
        $ecc.FromXmlString($this.privateKeyXml)
        $aesKey = $ecc.Decrypt($encryptedKey, $true)
        $aesIV = $ecc.Decrypt($encryptedIV, $true)

        # Decrypt the data using AES
        $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new();
        $aes.Key = $aesKey
        $aes.IV = $aesIV
        return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
    }
    # Generates a new ECC key pair and returns the public and private keys as XML strings.
    [string] GenerateKeyPair() {
        $ecc = [System.Security.Cryptography.ECDsaCng]::new(256)
        ($publicKey, $privateKey) = ($ecc.ToXmlString($false), $ecc.ToXmlString($true))
        return $publicKey, $privateKey
    }
    # Exports the ECC key pair to a file or string.
    # If a file path is specified, the keys are saved to the file.
    # If a string is specified, the keys are returned as a string.
    # Usage:
    # $ECC.ExportKeyPair("C:\keys.xml")
    [string] ExportKeyPair([string]$file = $null) {
        # Create the key pair XML string
        $keyPairXml = "
            <keyPair>
                <publicKey>$($this.publicKeyXml)</publicKey>
                <privateKey>$($this.privateKeyXml)</privateKey>
            </keyPair>
        "
        # Save the key pair XML to a file or return it as a string
        if ($null -ne $file) {
            $keyPairXml | Out-File -Encoding UTF8 $file
            return $null
        } else {
            return $keyPairXml
        }
    }
    # Imports the ECC key pair from a file or string.
    # If a file path is specified, the keys are loaded from the file.
    # If a string is specified, the keys are loaded from the string.
    [void] ImportKeyPair([string]$filePath = $null, [string]$keyPairXml = $null) {
        # Load the key pair XML from a file or string
        if (![string]::IsNullOrWhiteSpace($filePath)) {
            if ([IO.File]::Exists($filePath)) {
                $keyPairXml = Get-Content -Raw -Encoding UTF8 $filePath
            } else {
                throw [System.IO.FileNotFoundException]::new('Unable to find the specified file.', "$filePath")
            }
        } else {
            throw [System.ArgumentNullException]::new('filePath')
        }
        # Extract the public and private key XML strings from the key pair XML
        $publicKey = ([xml]$keyPairXml).keyPair.publicKey
        $privateKey = ([xml]$keyPairXml).keyPair.privateKey

        # Set the public and private key XML strings in the ECC object
        $this.publicKeyXml = $publicKey
        $this.privateKeyXml = $privateKey
    }
}
#endregion ecc

#region    MD5
class MD5 {
    MD5() {}
    [byte[]] static Encrypt([byte[]]$data, [string]$hash) {
        $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
        $encoderShouldEmitUTF8Identifier = $false
        $encoder = [System.Text.UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
        $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
        return [TripleDES]::Encrypt($data, $keys);
    }
    [byte[]] static Decrypt([byte[]]$data, [string]$hash) {
        $md5 = [System.Security.Cryptography.MD5CryptoServiceProvider]::new()
        $encoderShouldEmitUTF8Identifier = $false
        $encoder = [System.Text.UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
        $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
        return [TripleDES]::Decrypt($data, $keys);
    }
}
#endregion MD5

#region    TripleDES
class TripleDES {
    [byte[]] static Encrypt([Byte[]]$data, [Byte[]]$Key) {
        return [TripleDES]::Encrypt($data, $Key, $null, 1)
    }
    [byte[]] static Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
        return [TripleDES]::Encrypt($data, $Key, $IV, 1)
    }
    [byte[]]static Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
        for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $true) }
        return $data
    }
    [byte[]]static Decrypt([Byte[]]$data, [Byte[]]$Key) {
        return [TripleDES]::Decrypt($data, $Key, $null, 1);
    }
    [byte[]]static Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
        return [TripleDES]::Decrypt($data, $Key, $IV, 1);
    }
    [byte[]]static Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
        for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $false) }
        return $data
    }
    [byte[]] static hidden Get_ED([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [bool]$Encrypt) {
        $result = [byte[]]::new(0); $ms = [System.IO.MemoryStream]::new(); $cs = $null
        try {
            $tdes = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::new()
            if ($null -eq $Key) { throw '' }else { $tdes.Key = $Key }
            if ($null -eq $IV) { [void]$tdes.GenerateIV() }else { $tdes.IV = $IV }
            $CryptoTransform = [System.Security.Cryptography.ICryptoTransform]$(if ($Encrypt) { $tdes.CreateEncryptor() }else { $tdes.CreateDecryptor() })
            $cs = [System.Security.Cryptography.CryptoStream]::new($ms, $CryptoTransform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            [void]$cs.Write($data, 0, $data.Length)
            [void]$cs.FlushFinalBlock()
            $ms.Position = 0
            $result = [Byte[]]::new($ms.Length)
            [void]$ms.Read($result, 0, $ms.Length)
        } catch [System.Security.Cryptography.CryptographicException] {
            if ($_.exception.message -notlike "*data is not a complete block*") { throw $_.exception }
        } finally {
            Invoke-Command -ScriptBlock { $tdes.Clear(); $cs.Close(); $ms.Dispose() } -ErrorAction SilentlyContinue
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
        $this.Password = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xgen]::UniqueMachineId(), [XOR]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8)))
    }
    XOR([Object]$object) {
        $this.Object = [NcObject]::new($object);
        $this.Password = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new([xgen]::UniqueMachineId(), [XOR]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8)))
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
        return [XOR]::Encrypt($bytes, [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8))), 1)
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
        return [XOR]::Decrypt($bytes, [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8))), 1);
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

#region    RC4
# .SYNOPSIS
#     PowerShell class implementation of the RC4 algorithm
# .DESCRIPTION
#     "Ron's Code 4" or "Rivest Cipher 4," depending on the source.
#     A symmetric key stream cipher that was developed by Ron Rivest of RSA Security in 1987.
#     It was widely used in the 1990s and early 2000s, but has since been replaced by more secure algorithms in many applications due to vulnerabilities.
# .NOTES
#     RC4 is an old and insecure encryption algorithm.
#     It is recommended to use a more modern and secure algorithm, such as AES or ChaCha20.
#     But if you insist on using this, Just Use really strong passwords.
#     I mean shit like: Wwi@4c5w&@hOtf}Mm_t%&[BXq>5*0:Fm}6L'poyi!8LoZD\!HXPPPvMRas<CWl$yk${vlW9(f:S@w/E
# .EXAMPLE
#     $dat = [xconvert]::BytesFromObject("Hello World")
#     $enc = [rc4]::Encrypt($dat, (Read-Host -AsSecureString -Prompt 'Password'))
#     $dec = [rc4]::Decrypt($enc, (Read-Host -AsSecureString -Prompt 'Password'))
#     [xconvert]::BytesToObject($dec)
class RC4 {
    static [Byte[]] Encrypt([Byte[]]$data, [Byte[]]$passwd) {
        $a = $i = $j = $k = $tmp = [Int]0
        $key = [Int[]]::new(256)
        $box = [Int[]]::new(256)
        $cipher = [Byte[]]::new($data.Length)
        for ($i = 0; $i -lt 256; $i++) {
            $key[$i] = $passwd[$i % $passwd.Length];
            $box[$i] = $i;
        }
        for ($j = $i = 0; $i -lt 256; $i++) {
            $j = ($j + $box[$i] + $key[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }
        for ($a = $j = $i = 0; $i -lt $data.Length; $i++) {
            $a++;
            $a %= 256;
            $j += $box[$a];
            $j %= 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $k = $box[(($box[$a] + $box[$j]) % 256)];
            $cipher[$i] = [Byte]($data[$i] -bxor $k);
        }
        return $cipher;
    }
    static [Byte[]] Decrypt([Byte[]]$data, [Byte[]]$passwd) {
        return [RC4]::Encrypt($data, $passwd);
        # The Decrypt method simply calls the Encrypt method with the same arguments.
        # This is because the RC4 algorithm is symmetric, meaning that the same key is used for both encryption and decryption.
        # Therefore, the encryption and decryption processes are identical.
    }
}
#endregion RC4

#region    CHACHA20
class ChaCha20 {
    [Byte[]]$Key
    [Byte[]]$Nonce

    ChaCha20([Byte[]]$Key, [Byte[]]$Nonce) {
        $this.Key = $Key
        $this.Nonce = $Nonce
    }
    <#
    # todo: finish/make this method work!
    [Byte[]] Encrypt([Byte[]] $Plaintext) {
        $state = @(
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            $this.Key[0], $this.Key[1], $this.Key[2], $this.Key[3],
            $this.Key[4], $this.Key[5], $this.Key[6], $this.Key[7],
            $this.Nonce[0], $this.Nonce[1], $this.Nonce[2], $this.Nonce[3]
        )
        $blockCounter = 0
        $ciphertext = New-Object Byte[] $Plaintext.Length
        for ($i = 0; $i -lt $Plaintext.Length; $i += 64) {
            $block = @(
                $blockCounter, 0,
                $this.Nonce[4], $this.Nonce[5],
                $this.Nonce[6], $this.Nonce[7],
                0, 0
            )
            $blockCounter++
            $state = ($state + $block) | ForEach-Object { $_ -bxor 0x61707865 }
            for ($j = 0; $j -lt 10; $j++) {
                $state = @(
                    ($state[0] + $state[4]) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[1] + $state[5]) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[2] + $state[6]) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[3] + $state[7]) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[12] -xor ($state[0] >> 16) -xor ($state[0] << 16)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[13] -xor ($state[1] >> 16) -xor ($state[1] << 16)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[14] -xor ($state[2] >> 16) -xor ($state[2] << 16)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[15] -xor ($state[3] >> 16) -xor ($state[3] << 16)) | ForEach-Object { [UInt32]$_ -band 0xffffffff }
                )
                $state = @(
                    ($state[0] -xor ($state[12] >> 8) -xor ($state[12] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[1] -xor ($state[13] >> 8) -xor ($state[13] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[2] -xor ($state[14] >> 8) -xor ($state[14] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[3] -xor ($state[15] >> 8) -xor ($state[15] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[4] -xor ($state[0] >> 8) -xor ($state[0] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[5] -xor ($state[1] >> 8) -xor ($state[1] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[6] -xor ($state[2] >> 8) -xor ($state[2] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[7] -xor ($state[3] >> 8) -xor ($state[3] << 24)) | ForEach-Object { [UInt32]$_ -band 0xffffffff }
                )
                $state = @(
                    ($state[0] -xor ($state[5] >> 7) -xor ($state[5] << 25)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[1] -xor ($state[6] >> 7) -xor ($state[6] << 25)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[2] -xor ($state[7] >> 7) -xor ($state[7] << 25)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    ($state[3] -xor ($state[4] >> 7) -xor ($state[4] << 25)) | ForEach-Object { [UInt32]$_ -band 0xffffffff },
                    $state[4],
                    $state[5],
                    $state[6],
                    $state[7]
                )
            }
            $state = ($state + $block) | ForEach-Object { [UInt32]$_ -band 0xffffffff }
            for ($k = 0; $k -lt 16; $k++) {
                [Byte[]] $temp = [BitConverter]::GetBytes(([UInt32]$state[$k] + [UInt32]$block[$k]) -bor 0xffffffff)
                $ciphertext[$i + $k * 4] = $temp[0]
                $ciphertext[$i + $k * 4 + 1] = $temp[1]
                $ciphertext[$i + $k * 4 + 2] = $temp[2]
                $ciphertext[$i + $k * 4 + 3] = $temp[3]
            }
            $ciphertext
        }
    }
#>
}
#endregion CHACHA20

#endregion Usual~Algorithms

#region    FileCrypter
# AES Encrypt-decrypt files.
Class FileCryptr {
    [ValidateNotNullOrEmpty()][System.IO.FileInfo]static $File
    [ValidateNotNullOrEmpty()][securestring]static $Password
    [System.string]hidden static $Compression = 'Gzip';

    FileCryptr() {}
    FileCryptr([string]$Path) {
        [FileCryptr]::File = [System.IO.FileInfo]::new([xgen]::ResolvedPath($Path))
    }
    FileCryptr([string]$Path, [SecureString]$Password) {
        [FileCryptr]::Password = $Password;
        [FileCryptr]::File = [System.IO.FileInfo]::new([xgen]::ResolvedPath($Path))
    }
    [void]static Encrypt() {
        [FileCryptr]::File = [FileCryptr]::File
        [FileCryptr]::Password = [FileCryptr]::Password
        [FileCryptr]::Encrypt([FileCryptr]::File, [FileCryptr]::File, [FileCryptr]::Password)
    }
    [void]static Encrypt([SecureString]$Password) {
        [FileCryptr]::File = [FileCryptr]::File
        [FileCryptr]::Encrypt([FileCryptr]::File, [FileCryptr]::File, $Password)
    }
    [void]static Encrypt([string]$OutFile, [SecureString]$Password) {
        [FileCryptr]::File = [FileCryptr]::File
        [FileCryptr]::Encrypt([FileCryptr]::File, $OutFile, $Password)
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
            [byte[]]$Enc = [aeslg]::Encrypt([System.IO.File]::ReadAllBytes($InFile), $aes, [FileCryptr]::Compression, 1);
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
        [FileCryptr]::File = [FileCryptr]::File
        [FileCryptr]::Password = [FileCryptr]::Password
        [FileCryptr]::Decrypt([FileCryptr]::File, [FileCryptr]::File, [FileCryptr]::Password)
    }
    [void]static Decrypt([SecureString]$Password) {
        [FileCryptr]::File = [FileCryptr]::File
        [FileCryptr]::Decrypt([FileCryptr]::File, [FileCryptr]::File, $Password)
    }
    [void]static Decrypt([string]$OutFile, [SecureString]$Password) {
        [FileCryptr]::File = [FileCryptr]::File
        [FileCryptr]::Decrypt([FileCryptr]::File, $OutFile, $Password)
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
            $aes.IV = $enc[0..15]; [byte[]]$dec = [aeslg]::Decrypt($enc, $aes, [FileCryptr]::Compression, 1);
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
#endregion FileCrypter

#region    Custom_Cryptography_Wrappers
class Encryptor {
    [CryptoAlgorithm]hidden $Algorithm
    Encryptor() {
        $this.Algorithm = [CryptoAlgorithm]::AES
    }
    # Usage Example:
    # $encryptor = $this.CreateEncryptor($bytesToEncrypt, [securestring]$Password, [byte]$salt, [CryptoAlgorithm]$Algorithm); $result = $encryptor.encrypt();
    Encryptor([CryptoAlgorithm]$Algorithm) {
        $this.Algorithm = $Algorithm
        # if alg -eq aes => aes + aesgcm
        # if alg -eq rsa => aes + rsa
        # if alg -eq ecc => aes + ecc
    }
    [byte[]]Encrypt() {
        return [byte[]]::new(2)
    }
}
class Decryptor {
    [CryptoAlgorithm]hidden $Algorithm
    Decryptor() {
        $this.Algorithm = [CryptoAlgorithm]::AES
    }
    Decryptor([CryptoAlgorithm]$Algorithm) {
        $this.Algorithm = $Algorithm
    }
    [byte[]]Decrypt() {
        return [byte[]]::new(2)
    }
}
#region    _The_K3Y
# The K3Y 'UID' [ see .SetK3YUID() method ] is a fancy way of storing the version, user/owner credentials, Compression alg~tm used and Other Info
# about the most recent use and the person who used it; so it can be analyzed later to verify some rules before being used again. This enables the creation of complex expiring encryptions.
# It does not store or use the actual password; instead, it employs its own 'KDF' and retains a 'SHA1' hash string as securestring objects. idk if this is the most secure way to use but it should work.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingInvokeExpression", '')]
class K3Y {
    [ValidateNotNullOrEmpty()][CredManaged]$User;
    [ValidateNotNullOrEmpty()][Expiration]$Expiration = [Expiration]::new(0, 1); # Default is 30 days
    [ValidateNotNullOrEmpty()][keyStoreMode]hidden $StorageMode = [KeyStoreMode]::Securestring;
    [ValidateNotNullOrEmpty()][int]hidden $_PID = $(Get-Variable -Name PID).value;
    [ValidateNotNullOrEmpty()][securestring]hidden $UID;
    [ValidateNotNullOrEmpty()][byte[]]hidden $rgbSalt = [System.Text.Encoding]::UTF7.GetBytes('hR#ho"rK6FMu mdZFXp}JMY\?NC]9(.:6;>oB5U>.GkYC-JD;@;XRgXBgsEi|%MqU>_+w/RpUJ}Kt.>vWr[WZ;[e8GM@P@YKuT947Z-]ho>E2"c6H%_L2A:O5:E)6Fv^uVE; aN\4t\|(*;rPRndSOS(7& xXLRKX)VL\/+ZB4q.iY { %Ko^<!sW9n@r8ihj*=T $+Cca-Nvv#JnaZh'); #this is the default salt, change it if you want.

    K3Y() {
        $this.User = [CredManaged]::new([pscredential]::new($Env:USERNAME, [securestring][xconvert]::ToSecurestring([PasswordManager]::GeneratePassword(1, 64))));
        $this.UID = [securestring][xconvert]::ToSecurestring($this.GetK3YIdSTR());
    }
    K3Y([Datetime]$Expiration) {
        $this.User = [CredManaged]::new([pscredential]::new($Env:USERNAME, [securestring][xconvert]::ToSecurestring([PasswordManager]::GeneratePassword(1, 64))));
        $this.Expiration = [Expiration]::new($Expiration); $this.UID = [securestring][xconvert]::ToSecurestring($this.GetK3YIdSTR());
    }
    K3Y([pscredential]$User, [Datetime]$Expiration) {
        ($this.User, $this.Expiration) = ([CredManaged]::new($User), [Expiration]::new($Expiration)); $this.UID = [securestring][xconvert]::ToSecurestring($this.GetK3YIdSTR());
    }
    K3Y([string]$UserName, [securestring]$Password) {
        $this.User = [CredManaged]::new([pscredential]::new($UserName, $Password)); $this.UID = [securestring][xconvert]::ToSecurestring($this.GetK3YIdSTR());
    }
    K3Y([string]$UserName, [securestring]$Password, [Datetime]$Expiration) {
        ($this.User, $this.Expiration) = ([CredManaged]::new([pscredential]::new($UserName, $Password)), [Expiration]::new($Expiration)); $this.UID = [securestring][xconvert]::ToSecurestring($this.GetK3YIdSTR());
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt) {
        return $this.Encrypt($bytesToEncrypt, [PasswordManager]::GetPassword());
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring]$password) {
        return $this.Encrypt($bytesToEncrypt, $password, $this.rgbSalt, 'Gzip', $this.Expiration.Date);
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring]$password, [Datetime]$Expiration) {
        return $this.Encrypt($bytesToEncrypt, $password, $this.rgbSalt, 'Gzip', $Expiration);
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring]$Password, [byte[]]$salt, [string]$Compression, [Datetime]$Expiration) {
        return $this.Encrypt($bytesToEncrypt, $password, $salt, $Compression, $Expiration, [CryptoAlgorithm]::AES);
    }
    [byte[]]Encrypt([byte[]]$bytesToEncrypt, [securestring]$Password, [byte[]]$salt, [string]$Compression, [Datetime]$Expiration, [CryptoAlgorithm]$Algorithm) {
        $Password = [securestring]$this.ResolvePassword($Password); $this.SetK3YUID($Password, $Expiration, $Compression, $this._PID)
        # $CryptoServiceProvider = [CustomCryptoServiceProvider]::new($bytesToEncrypt, $Password, $salt, [CryptoAlgorithm]$Algorithm)
        # $encryptor = $CryptoServiceProvider.CreateEncryptor(); $result = $encryptor.encrypt();
        return [AesLg]::Encrypt($bytesToEncrypt, $Password, $salt);
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt) {
        return $this.Decrypt($bytesToDecrypt, [PasswordManager]::GetPassword());
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt, [securestring]$Password) {
        return $this.Decrypt($bytesToDecrypt, $Password, $this.rgbSalt);
    }
    [byte[]]Decrypt([byte[]]$bytesToDecrypt, [securestring]$Password, [byte[]]$salt) {
        $Password = [securestring]$this.ResolvePassword($Password); # (Get The real Password)
        ($IsValid, $Compression) = [k3Y]::AnalyseK3YUID($this, $Password, $false)[0, 2];
        if (-not $IsValid) { throw [System.Management.Automation.PSInvalidOperationException]::new("The Operation is not valid due to Expired K3Y.") };
        if ($Compression.Equals('')) { throw [System.Management.Automation.PSInvalidOperationException]::new("The Operation is not valid due to Invalid Compression.", [System.ArgumentNullException]::new('Compression')) };
        # todo: Chose the algorithm
        # if alg -eq RSA then we RSA+AES hybrid
        return [AesLg]::Decrypt($bytesToDecrypt, $Password, $salt, $Compression);
    }
    [bool]IsUsed() { return [K3Y]::IsUsed($this, $false) }
    [bool]IsUsed([bool]$ThrowOnFailure) { return [K3Y]::IsUsed($this, $ThrowOnFailure) }
    [bool]static IsUsed([K3Y]$k3y) { return [K3Y]::IsUsed($k3y, $false) }
    [bool]static IsUsed([K3Y]$K3Y, [bool]$ThrowOnFailure) {
        # Verifies if The password has already been set.
        $IsUsed = $false; [bool]$SetValu3Exception = $false; [securestring]$kUID = $K3Y.UID; $InnerException = [System.Exception]::new()
        try {
            $K3Y.UID = [securestring]::new()
        } catch [System.Management.Automation.SetValueException] {
            $SetValu3Exception = $true
        } catch {
            $InnerException = $_.Exception
        } finally {
            if ($SetValu3Exception) {
                $IsUsed = $true
            } else {
                $K3Y.UID = $kUID
            }
        }
        if ($ThrowOnFailure -and !$IsUsed) {
            throw [System.InvalidOperationException]::new("The key Hasn't been used!`nEncrypt Something with this K3Y at least once or Manually Call SetK3YUID method.", $InnerException)
        }
        return $IsUsed
    }
    [void]hidden SetK3YUID([securestring]$Password, [datetime]$Expiration, [string]$Compression, [int]$_PID) {
        $this.SetK3YUID($Password, $Expiration, $Compression, $_PID, $false);
    }
    [void]hidden SetK3YUID([securestring]$Password, [datetime]$Expiration, [string]$Compression, [int]$_PID, [bool]$ThrowOnFailure) {
        if (!$this.IsUsed()) {
            Invoke-Command -InputObject $this.UID -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                        $K3YIdSTR = [string]::Empty; Set-Variable -Name K3YIdSTR -Scope local -Visibility Private -Option Private -Value $([string][K3Y]::GetK3YIdSTR($Password, $Expiration, $Compression, $_PID));
                        Invoke-Expression "`$this.psobject.Properties.Add([psscriptproperty]::new('UID', { ConvertTo-SecureString -AsPlainText -String '$K3YIdSTR' -Force }))";
                    }
                )
            )
        } else {
            if ($ThrowOnFailure) { throw [System.Management.Automation.SetValueException]::new('This Key already Has a UID.') }
        }
    }
    [string]GetK3YIdSTR() {
        return [K3Y]::GetK3YIdSTR($this.User.Password, $this.Expiration.Date, $(Get-Random ([Enum]::GetNames('Compression' -as 'Type'))), $this._PID)
    }
    [string]static GetK3YIdSTR([securestring]$Password, [datetime]$Expiration, [string]$Compression, [int]$_PID) {
        if ($null -eq $Password -or $([string]::IsNullOrWhiteSpace([xconvert]::ToString($Password)))) {
            throw [InvalidPasswordException]::new("Please Provide a Password that isn't Null and not a WhiteSpace.", $Password, [System.ArgumentNullException]::new("Password"))
        }
        return [string][xconvert]::BytesToHex([System.Text.Encoding]::UTF7.GetBytes([xconvert]::ToCompressed([xconvert]::StringToCustomCipher(
                        [string][K3Y]::CreateUIDstring([byte[]][XConvert]::BytesFromObject([PSCustomObject]@{
                                    KeyInfo = [xconvert]::BytesFromObject([PSCustomObject]@{
                                            Expiration = $Expiration
                                            Version    = [version]::new("1.0.0.1")
                                            User       = $Env:USERNAME
                                            PID        = $_PID
                                        }
                                    )
                                    BytesCT = [AesLg]::Encrypt(([System.Text.Encoding]::UTF7.GetBytes($Compression)), $Password);
                                }
                            )
                        )
                    )
                )
            )
        )
    }
    [securestring]ResolvePassword([securestring]$Password) {
        if (!$this.IsHashed()) {
            Invoke-Command -InputObject $this.User -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                        $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::BytesToHex(([PasswordHash]::new([xconvert]::ToString($password)).ToArray())));
                        Invoke-Expression "`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))";
                    }
                )
            )
        }
        $SecHash = $this.User.Password;
        return $this.ResolvePassword($Password, $SecHash);
    }
    [securestring]ResolvePassword([securestring]$Password, [securestring]$SecHash) {
        $derivedKey = [securestring]::new(); [System.IntPtr]$handle = [System.IntPtr]::new(0); $Passw0rd = [string]::Empty;
        Add-Type -AssemblyName System.Runtime.InteropServices
        Set-Variable -Name Passw0rd -Scope Local -Visibility Private -Option Private -Value $([xconvert]::ToString($Password));
        Set-Variable -Name handle -Scope Local -Visibility Private -Option Private -Value $([System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($Passw0rd));
        if ([PasswordManager]::VerifyPasswordHash($Passw0rd, [xconvert]::ToString($SecHash), $true)) {
            try {
                if ([System.Environment]::UserInteractive) { (Get-Variable host).Value.UI.WriteDebugLine("  [i] Using Password, With Hash: $([xconvert]::Tostring($SecHash))") }
                # This next line is like a KDF. ie: If this was a Powershell function it would be named Get-KeyFromPassword
                $derivedKey = [xconvert]::ToSecurestring([System.Text.Encoding]::UTF7.GetString([System.Security.Cryptography.Rfc2898DeriveBytes]::new($Passw0rd, $this.rgbSalt, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA1).GetBytes(256 / 8)));
                # Most people use utf8, so I use 'UTF7 instead. (Just to be extra cautious)
                # & I could use: System.Security.Cryptography.PasswordDeriveBytes]::new($Passw0rd, $this.rgbSalt, 'SHA1', 2).GetBytes(256 / 8)...
                # Which would be less stress on cpu but sacrificing too much security. so its a Nono
            } catch {
                throw $_.Exeption
            } finally {
                # Zero out the memory used by the variable.
                [void][System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocAnsi($handle);
                # It is usually sufficient to simply use the Remove-Variable but in this situation we Just want to be extra cautious.
            }
            return $derivedKey
        } else {
            if ([System.Environment]::UserInteractive) {
                [System.Console]::Beep(600, 100); [System.Threading.Thread]::Sleep(100); [System.Console]::Beep(600, 200);
                Write-Verbose "[x] Wrong Password!";
            }
            Throw [System.UnauthorizedAccessException]::new('Wrong Password.', [InvalidPasswordException]::new());
        }
    }
    [bool]IsHashed() {
        return $this.IsHashed($false);
    }
    [bool]static IsHashed([K3Y]$k3y) {
        $ThrowOnFailure = $false
        return [K3Y]::IsHashed($k3y, $ThrowOnFailure);
    }
    [bool]IsHashed([bool]$ThrowOnFailure) {
        return [K3Y]::IsHashed($this, $ThrowOnFailure);
    }
    [bool]static IsHashed([K3Y]$k3y, [bool]$ThrowOnFailure) {
        # Verifies if The password (the one only you know) has already been hashed
        [bool]$SetValu3Exception = $false; [securestring]$p = $k3y.User.Password; $InnerException = [System.Exception]::new()
        [bool]$IsHashed = [regex]::IsMatch([string][xconvert]::ToString($k3y.User.Password), "^[A-Fa-f0-9]{72}$");
        try {
            $k3y.User.Password = [securestring]::new() # This will not work if the hash has been set
        } catch [System.Management.Automation.SetValueException] {
            $SetValu3Exception = $true
        } catch {
            $InnerException = $_.Exception
        } finally {
            $IsHashed = $IsHashed -and $SetValu3Exception
        }
        if (!$SetValu3Exception) {
            $k3y.User.Password = $p
        }
        if ($ThrowOnFailure -and !$IsHashed) {
            throw [System.InvalidOperationException]::new('Operation is not valid due to the current state of the object. No password Hash found.', $InnerException)
        }
        return $IsHashed
    }
    [Encryptor] CreateEncryptor([byte[]]$bytesToEncrypt, [securestring]$Password, [byte[]]$salt, [CryptoAlgorithm]$Algorithm) {
        # Usage Example: $encryptor = $this.CreateEncryptor($bytesToEncrypt, $Password, $salt, [CryptoAlgorithm]$Algorithm); $result = $encryptor.encrypt();
        return [Encryptor]::new()
    }
    [Decryptor] CreateDecryptor([byte[]]$bytesToDecrypt, [securestring]$Password, [byte[]]$salt, [CryptoAlgorithm]$Algorithm) {
        return [Decryptor]::new()
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
        $key_Ex = [Expiration]::new($KeyI_Obj.Expiration);
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
        return [K3Y]::AnalyseK3YUID($K3Y, [PasswordManager]::GetPassword());
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
        $KIDstring = [string]::Empty; $Output = @(); $eap = $ErrorActionPreference;
        if ($null -eq $K3Y) { [System.ArgumentNullException]::New('$K3Y') };
        try {
            Set-Variable -Name KIDstring -Scope Local -Visibility Private -Option Private -Value $([xconvert]::StringFromCustomCipher([xconvert]::ToDeCompressed([System.Text.Encoding]::UTF7.GetString([xconvert]::BytesFromHex([xconvert]::ToString($K3Y.UID))))));
        } catch { throw [System.Management.Automation.PSInvalidOperationException]::new("The Operation Failed due to invalid K3Y.", $_.Exception) };
        [bool]$Is_Valid = $false; [datetime]$EncrDate = Get-Date -Month 1 -Day 1 -Hour 0 -Minute 0 -Year 1; $Info_Obj = $null; $B_C_type = [string]::Empty; $skID = [string]::Empty; #Key ID string (Plaintext)
        if ($ThrowOnFailure) { $ErrorActionPreference = 'Stop' }
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
            $Is_Valid = $($Info_Obj.Expiration - [datetime]::Now) -ge [timespan]::new(0)
            $B_C_type = $(try { [System.Text.Encoding]::UTF7.GetString([AesLg]::Decrypt($ebc, $Password)) }catch { if ($ThrowOnFailure) { throw [System.InvalidOperationException]::new("Please Provide a valid Password.", [System.UnauthorizedAccessException]::new('Wrong Password')) }else { [string]::Empty } }); # (Byte Compression Type)
            $EncrDate = Get-Date -Month $Mon -Day $Day -Hour $Hrs -Minute $Min # An estimate of when was the last encryption Done
            $Output = ($Is_Valid, $Info_Obj, $B_C_type, $EncrDate);
        } catch {
            if ($ThrowOnFailure) { throw $_.Exception }
        } finally {
            $ErrorActionPreference = $eap
        }
        if ($CreateReport) {
            return [PSCustomObject]@{
                Summary        = "K3Y $(if ([K3Y]::IsHashed($K3Y)) { 'Last used' }else { 'created' }) on: $($Output[3]), PID: $($Output[1].PID), by: $($Output[1].User)."
                Version        = $Output[1].Version
                ExpirationDate = $Output[1].Expiration.date
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
        $ThrowOnFailure = $true; [void]$this.IsUsed($ThrowOnFailure)
        $FilePath = [xgen]::UnResolvedPath($FilePath)
        if (![IO.File]::Exists($FilePath)) { New-Item -Path $FilePath -ItemType File | Out-Null }
        Set-Content -Path $FilePath -Value ([xconvert]::Tostring($this)) -Encoding UTF8 -NoNewline;
        if ($encrypt) { $(Get-Item $FilePath).Encrypt() }
        # Select the optimal data compression algorithm based on the length of the input string
        #     [string]::Empty $algorithm =[string]::Empty;
        #     if ($inputString.Length -lt 1000){
        #         $algorithm = "Deflate";
        #     } elseif ($inputString.Length -lt 10000) {
        #         $algorithm = "LZMA";
        #     } else {
        #         $algorithm = "Zstandard"; # use zstd.exe to compress the outputfile
        #     }
    }
    [K3Y]Import([string]$StringK3y) {
        $K3Y = $null; Set-Variable -Name K3Y -Scope Local -Visibility Private -Option Private -Value ([K3Y]::Create($StringK3y));
        if ([bool]$K3Y.User.IsProtected) { $K3Y.User.UnProtect() }
        try {
            $this | Get-Member -MemberType Properties | ForEach-Object { $Prop = $_.Name; $this.$Prop = $K3Y.$Prop };
        } catch [System.Management.Automation.SetValueException] {
            throw [System.InvalidOperationException]::New('You can only Import One Key.')
        }
        $Key_UID = [string]::Empty; $hashSTR = [string]::Empty; Set-Variable -Name hashSTR -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::ToString($this.User.Password));
        if ([regex]::IsMatch($hashSTR, "^[A-Fa-f0-9]{72}$")) {
            Invoke-Command -InputObject $this.User -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                        Invoke-Expression "`$this.User.psobject.Properties.Add([psscriptproperty]::new('Password', { ConvertTo-SecureString -AsPlainText -String '$hashSTR' -Force }))";
                    }
                )
            )
            Invoke-Command -InputObject $this -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
                        Set-Variable -Name Key_UID -Scope local -Visibility Private -Option Private -Value $([string][xconvert]::Tostring($K3Y.UID))
                        Invoke-Expression "`$this.psobject.Properties.Add([psscriptproperty]::new('UID', { ConvertTo-SecureString -AsPlainText -String '$Key_UID' -Force }))";
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
        $ThrowOnFailure = $true; [void]$this.IsHashed($ThrowOnFailure)
        $_Hash = [xconvert]::ToString($this.User.Password); $RName = 'PNKey' + $_Hash
        $_Cred = New-Object -TypeName CredManaged -ArgumentList ($RName, $this.User.UserName, [xconvert]::Tostring($this))
        Write-Verbose "[i] Saving $RName To Vault .."
        # Note: Make sure file size does not exceed the limit allowed and cannot be saved.
        $_Cred.SaveToVault()
    }
}
#endregion _The_K3Y

#endregion Custom_Cryptography_Wrappers

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
        $this.SetPNKey($PublicKey);
    }
    NerdCrypt([Object]$Object, [string]$User, [string]$PublicKey) {
        $this.Object = [NcObject]::new($Object);
        $this.SetPNKey($PublicKey);
        $this.User.UserName = $User;
    }
    NerdCrypt([Object]$Object, [string]$User, [securestring]$PrivateKey, [string]$PublicKey) {
        $this.Object = [NcObject]::new($Object);
        $this.User.UserName = $User;
        $this.SetPNKey($PublicKey);
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
        $this.SetCredentials((Get-Variable Host).Value.UI.PromptForCredential("NerdCrypt needs your credentials.", "Please enter your UserName and Password.", "$Env:UserName", ""));
    }
    [void]SetCredentials([System.Management.Automation.PSCredential]$Credentials) {
        $this.key.User.UserName = $Credentials.UserName
        $this.key.User.Password = $Credentials.Password
    }
    #
    # TODO: Add option to encrypt using KEys From Azure KeyVault (The process has to be INTERACTIVE).
    # If($IsInteractive = [Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0) {'Prompt for stuff'} else {'Nope!'}
    # https://docs.microsoft.com/en-us/azure/key-vault/secrets/quick-create-powershell
    #
    #region    ParanoidCrypto
    [void]Encrypt() {
        $this.SetBytes($this.Encrypt($this.Object.Bytes, [PasswordManager]::GetPassword()))
    }
    [byte[]]Encrypt([int]$iterations) {
        $this.SetBytes($this.Encrypt($this.Object.Bytes, [PasswordManager]::GetPassword(), $iterations));
        return $this.Object.Bytes
    }
    [byte[]]Encrypt([byte[]]$bytes, [securestring]$Password) {
        return $this.Encrypt($bytes, $Password, 1);
    }
    [byte[]]Encrypt([securestring]$Password, [int]$Iterations) {
        if ($null -eq $this.Object.Bytes) { [System.ArgumentNullException]::New('Bytes') };
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
        $this.SetBytes($this.Decrypt($this.Object.Bytes, [PasswordManager]::GetPassword()))
    }
    [byte[]]Decrypt([int]$iterations) {
        $this.SetBytes($this.Decrypt($this.Object.Bytes, [PasswordManager]::GetPassword(), $Iterations));
        return $this.Object.Bytes
    }
    [byte[]]Decrypt([byte[]]$bytes, [securestring]$Password) {
        return $this.Decrypt($bytes, $Password, 1);
    }
    [byte[]]Decrypt([securestring]$Password, [int]$Iterations) {
        if ($null -eq $this.Object.Bytes) { [System.ArgumentNullException]::New('Bytes') };
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
    [void]SetPNKey([string]$StringK3y) {
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

#region   Functions
function New-K3Y {
    <#
    .SYNOPSIS
        Creates a new [K3Y] object
    .DESCRIPTION
        Creates a custom k3y object for encryption/decryption.
        The K3Y can only be used to Once, and its 'UID' [ see .SetK3YUID() method ] is a fancy way of storing the version, user/owner credentials, Compression alg~tm used and Other Info
        about the most recent use and the person who used it; so it can be analyzed later to verify some rules before being used again. this allows to create complex expiring encryptions.
    .EXAMPLE
        $K = New-K3Y (Get-Credential -UserName 'Alain Herve' -Message 'New-K3Y')
    .NOTES
        This is a private function, its not meant to be exported, or used alone
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = '')]
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [OutputType([K3Y], [string])]
    param (
        # Parameter help description
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'byPscredential')]
        [Alias('Owner')][ValidateNotNull()]
        [pscredential]$User,

        # Parameter help description
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'default')]
        [string]$UserName,

        # Parameter help description
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'default')]
        [securestring]$Password,

        # Expiration date
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'byPscredential')]
        [datetime]$Expiration,

        # Convert to string (sharable)
        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$AsString,

        [Parameter(Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [switch]$Protect
    )

    begin {
        $k3y = $null
        $params = $PSCmdlet.MyInvocation.BoundParameters
        $IsInteractive = [Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0
    }
    process {
        $k3y = $(if ($PSCmdlet.ParameterSetName -eq 'byPscredential') {
                if ($params.ContainsKey('User') -and $params.ContainsKey('Expiration')) {
                    [K3Y]::New($User, $Expiration);
                } else {
                    # It means: $params.ContainsKey('User') -and !$params.ContainsKey('Expiration')
                    [datetime]$ExpiresOn = if ($IsInteractive) {
                        [int]$days = Read-Host -Prompt "Expires In (replie num of days)"
                        [datetime]::Now + [Timespan]::new($days, 0, 0, 0);
                    } else {
                        [datetime]::Now + [Timespan]::new(30, 0, 0, 0); # ie: expires in 30days
                    }
                    [K3Y]::New($User, $ExpiresOn);
                }
            } elseif ($PSCmdlet.ParameterSetName -eq 'default') {
                if ($params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and $params.ContainsKey('Expiration')) {
                    [K3Y]::New($UserName, $Password, $Expiration);
                } elseif ($params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and !$params.ContainsKey('Expiration')) {
                    [K3Y]::New($UserName, $Password);
                } elseif ($params.ContainsKey('UserName') -and !$params.ContainsKey('Password') -and !$params.ContainsKey('Expiration')) {
                    $passwd = if ($IsInteractive) { Read-Host -AsSecureString -Prompt "Password" } else { [securestring]::new() }
                    [K3Y]::New($UserName, $passwd);
                } elseif (!$params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and !$params.ContainsKey('Expiration')) {
                    $usrName = if ($IsInteractive) { Read-Host -Prompt "UserName" } else { [System.Environment]::GetEnvironmentVariable('UserName') }
                    [K3Y]::New($usrName, $Password);
                } elseif (!$params.ContainsKey('UserName') -and !$params.ContainsKey('Password') -and $params.ContainsKey('Expiration')) {
                    if ($IsInteractive) {
                        $usrName = Read-Host -Prompt "UserName"; $passwd = Read-Host -AsSecureString -Prompt "Password";
                        [K3Y]::New($usrName, $passwd);
                    } else {
                        [K3Y]::New($Expiration);
                    }
                } elseif (!$params.ContainsKey('UserName') -and $params.ContainsKey('Password') -and $params.ContainsKey('Expiration')) {
                    $usrName = if ($IsInteractive) { Read-Host -Prompt "UserName" } else { [System.Environment]::GetEnvironmentVariable('UserName') }
                    [K3Y]::New($usrName, $Password, $Expiration);
                } else {
                    [K3Y]::New();
                }
            } else {
                Write-Verbose "System.Management.Automation.ParameterBindingException: Could Not Resolve ParameterSetname."
                [K3Y]::New();
            }
        )
        if ($Protect.IsPresent) { $k3y.User.Protect() };
    }

    end {
        if ($AsString.IsPresent) {
            return [xconvert]::Tostring($k3y)
        }
        return $k3y
    }
}
function New-Converter {
    <#
    .SYNOPSIS
        Creates a new [XConvert] object
    .DESCRIPTION
        Creates a custom Converter object.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = '')]
    [CmdletBinding()]
    [OutputType([XConvert])]
    param ()

    end {
        return [XConvert]::new()
    }
}
#region     Encrpt-Decrp
function Encrypt-Object {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [Alias('Encrypt')]
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
        [SecureString]$PrivateKey = [PasswordManager]::GetPassword(),

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

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
        [ValidateNotNullOrEmpty()]
        [Alias('ExportFile')]
        [string]$KeyOutFile,

        # How long you want the encryption to last. Default to one month (!Caution Your data will be LOST Forever if you do not decrypt before the Expiration date!)
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithVault')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'WithKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithPlainKey')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('KeyExpiration')]
        [datetime]$Expiration = ([Datetime]::Now + [TimeSpan]::new(30, 0, 0, 0)),

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
        $ExportsPNK = $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('KeyOutFile') -and ![string]::IsNullOrEmpty($KeyOutFile)
        if ($PsCmdlet.ParameterSetName -ne 'WithKey' -and !$ExportsPNK) {
            throw 'Plese specify PublicKey "ExportFile/Outfile" Parameter.'
        }
        # Write-Invocation $MyInvocation
    }

    process {
        Write-Verbose "[+] $fxn $($PsCmdlet.ParameterSetName) ..."
        Set-Variable -Name PsW -Scope Local -Visibility Private -Option Private -Value $(switch ($PsCmdlet.ParameterSetName) {
                'WithKey' {  }
                'WithVault' {  }
                'WithSecureKey' { $PrivateKey }
                Default {
                    throw 'Error!'
                }
            }
        );
        Set-Variable -Name nc -Scope Local -Visibility Private -Option Private -Value $([nerdcrypt]::new($Object));
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Expiration')) { $nc.key.Expiration = [Expiration]::new($Expiration) }
        if ($PsCmdlet.MyInvocation.BoundParameters.ContainsKey('PublicKey')) {
            $nc.SetPNKey($PublicKey);
        } else {
            Write-Verbose "[+] Create PublicKey (K3Y) ...";
            $PNK = New-K3Y -UserName $nc.key.User.UserName -Password $PsW -Expiration $nc.key.Expiration.date -AsString -Protect
            $nc.SetPNKey($PNK);
        }
        $bytes = $nc.Object.Bytes
        [void]$nc.Encrypt($PsW, $Iterations)
        if ($ExportsPNK) {
            Write-Verbose "[i] Export PublicKey (PNK) to $KeyOutFile ..."
            $nc.key.Export($KeyOutFile, $true);
        }
        $bytes = $(if ($bytes.Equals($nc.Object.Bytes)) { $null }else { $nc.Object.Bytes })
    }

    end {
        $ErrorActionPreference = $eap
        return $bytes
    }
}
function Decrypt-Object {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Prefer verb usage')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertSecurestringWithPlainText", '')]
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'WithSecureKey')]
    [Alias('Decrypt')]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'WithSecureKey')]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [SecureString]$PrivateKey = [PasswordManager]::GetPassword(),

        [Parameter(Mandatory = $true, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [string]$PublicKey,

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
                Write-Verbose "[i] Export PublicKey (PNK) to $KeyOutFile ..."
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
function Protect-Data {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'String', SupportsShouldProcess = $true)]
    [Alias('Protect')]
    [OutputType([Object[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'String')]
        [ValidateNotNullOrEmpty()]
        [string]$MSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecureString')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureMSG,

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
        [Alias('ProtectionScope')]
        [string]$Scope = 'CurrentUser',

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Entropy
    )

    begin {
        #Load The Assemblies
        if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
        [bool]$UseCustomEntropy = $null -ne $Entropy -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Entropy')
    }

    process {
        $ProtectedD = switch ($PsCmdlet.ParameterSetName) {
            'Xml' {
                if ($PSCmdlet.ShouldProcess("Xml", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), [ProtectionScope]$Scope)
                    }
                }
            }
            'string' {
                if ($PSCmdlet.ShouldProcess("String", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($Msg, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($Msg, [ProtectionScope]$Scope)
                    }
                }
            }
            'Bytes' {
                if ($PSCmdlet.ShouldProcess("Bytes", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToProtected($Bytes, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToProtected($Bytes, [ProtectionScope]$Scope)
                    }
                }
            }
            'SecureString' { throw 'Yeet!' }
            Default {
                throw 'Error!'
            }
        }
    }

    end {
        return $ProtectedD
    }
}
function UnProtect-Data {
    <#
        .EXTERNALHELP NerdCrypt.psm1-Help.xml
    #>
    [CmdletBinding(ConfirmImpact = "Medium", DefaultParameterSetName = 'string', SupportsShouldProcess = $true)]
    [Alias('UnProtect')]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'String')]
        [ValidateNotNullOrEmpty()]
        [string]$MSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecureString')]
        [ValidateNotNullOrEmpty()]
        [securestring]$SecureMSG,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Bytes')]
        [ValidateNotNullOrEmpty()]
        [Alias('Bytes')]
        [byte[]]$InputBytes,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Xml')]
        [ValidateNotNullOrEmpty()]
        [Alias('XmlDoc')]
        [xml]$InputXml,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = '__A llParameterSets')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [ValidateNotNullOrEmpty()]
        [Alias('ProtectionScope')]
        [string]$Scope = 'CurrentUser',

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = '__AllParameterSets')]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Entropy
    )

    begin {
        #Load The Assemblies
        if (!("System.Security.Cryptography.ProtectedData" -is 'Type')) { Add-Type -AssemblyName System.Security }
        [bool]$UseCustomEntropy = $null -ne $Entropy -and $PsCmdlet.MyInvocation.BoundParameters.ContainsKey('Entropy')
    }

    process {
        $UnProtected = switch ($PsCmdlet.ParameterSetName) {
            'Xml' {
                if ($PSCmdlet.ShouldProcess("Xml", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($([xconvert]::BytesFromObject([xconvert]::ToPSObject($InputXml))), [ProtectionScope]$Scope)
                    }
                }
            }
            'string' {
                if ($PSCmdlet.ShouldProcess("String", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($Msg, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($Msg, [ProtectionScope]$Scope)
                    }
                }
            }
            'Bytes' {
                if ($PSCmdlet.ShouldProcess("Bytes", "Protect")) {
                    if ($UseCustomEntropy) {
                        [xconvert]::ToUnProtected($Bytes, $Entropy, [ProtectionScope]$Scope)
                    } else {
                        [xconvert]::ToUnProtected($Bytes, [ProtectionScope]$Scope)
                    }
                }
            }
            'SecureString' { throw 'Yeet!' }
            Default {
                throw 'Error!'
            }
        }
    }

    end {
        return $UnProtected
    }
}
#endregion  Encrpt-Decrp

#region    Local_Vault
function Get-SavedCredential {
    <#
    .SYNOPSIS
        Get SavedCredential
    .DESCRIPTION
        Gets Saved Credential from credential vault
    .NOTES
        This function is not supported on Linux
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Private/NerdCrypt.Core/NerdCrypt.Core.ps1
    .EXAMPLE
        Get-SavedCredential 'My App'
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [OutputType([CredManaged])]
    param (
        # Target /title /name of the saved credential
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = '__AllParameterSets')]
        [Alias('Name', 'TargetName')][ValidateNotNullOrEmpty()]
        [string]$Target,

        # Username / Owner
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'default')]
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'byCrtyp')]
        [Alias('usrnm')][ValidateNotNullOrEmpty()]
        [string]$UserName,

        # Credential type.
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'byCrtyp')]
        [ValidateSet('Generic', 'DomainPassword', 'DomainCertificate', 'DomainVisiblePassword', 'GenericCertificate', 'DomainExtended', 'Maximum', 'MaximumEx')]
        [Alias('CredType')][ValidateNotNullOrEmpty()]
        [string]$Type = 'Generic'
    )

    begin {
        $CredentialManager = [CredentialManager]::new(); $Savd_Cred = $null
        $params = $PSCmdlet.MyInvocation.BoundParameters;
        $GetTargetName = [scriptblock]::Create({
                if ([Environment]::UserInteractive -and [Environment]::GetCommandLineArgs().Where({ $_ -like '-NonI*' }).Count -eq 0) {
                    $t = Read-Host -Prompt "TargetName"
                    if ([string]::IsNullOrWhiteSpace($t)) {
                        throw 'Null Or WhiteSpace targetName is not valid'
                    }
                    $t
                } else {
                    throw 'Please Input valid Name'
                }
            }
        )
    }

    process {
        $_Target = $(if ($params.ContainsKey('Target') -and [string]::IsNullOrWhiteSpace($Target)) {
                Invoke-Command -ScriptBlock $GetTargetName
            } elseif (!$params.ContainsKey('Target')) {
                Invoke-Command -ScriptBlock $GetTargetName
            } else {
                $Target
            }
        )
        $Savd_Cred = $(if ($PSCmdlet.ParameterSetName -eq 'default') {
                $CredentialManager.GetCredential($_Target, $UserName)
            } elseif ($PSCmdlet.ParameterSetName -eq 'byCrtyp') {
                if ($params.ContainsKey('type')) {
                    $CredentialManager.GetCredential($_Target, $Type, $UserName)
                } else {
                    $CredentialManager.GetCredential($_Target, $Type, $UserName)
                }
            }
        )
        if ([CredentialManager]::LastErrorCode.Equals([CredentialManager]::ERROR_NOT_FOUND)) {
            throw [CredentialNotFoundException]::new("$_Target not found.", [System.Exception]::new("Exception of type 'ERROR_NOT_FOUND' was thrown."))
        }
        if ([string]::IsNullOrWhiteSpace($Savd_Cred.target)) {
            Write-Warning "Could not resolve the target Name for: $_Target"
        }
    }

    end {
        return $Savd_Cred
    }
}
function Get-SavedCredentials {
    <#
    .SYNOPSIS
        Retreives All strored credentials from credential Manager
    .DESCRIPTION
        Retreives All strored credentials and returns an [System.Collections.ObjectModel.Collection[CredManaged]] object
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Private/NerdCrypt.Core/NerdCrypt.Core.ps1
    .EXAMPLE
        Get-SavedCredentials
        Enumerates all SavedCredentials
    #>
    [CmdletBinding()]
    [outputType([System.Collections.ObjectModel.Collection[CredManaged]])]
    param ()

    begin {
        $Credentials = $null
        $CredentialManager = [CredentialManager]::new();
    }

    process {
        $Credentials = $CredentialManager.RetreiveAll();
    }
    end {
        return $Credentials;
    }
}
function Remove-Credential {
    <#
    .SYNOPSIS
        Deletes credential from Windows Credential Mandger
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Private/NerdCrypt.Core/NerdCrypt.Core.psm1
    .EXAMPLE
        Remove-Credential -Verbose
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        # TargetName
        [Parameter(Mandatory = $true)][ValidateLength(1, 32767)]
        [ValidateScript({
                if (![string]::IsNullOrWhiteSpace($_)) {
                    return $true
                }
                throw 'Null or WhiteSpace Inputs are not allowed.'
            }
        )][Alias('Title')]
        [String]$Target,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Generic', 'DomainPassword', 'DomainCertificate', 'DomainVisiblePassword', 'GenericCertificate', 'DomainExtended', 'Maximum', 'MaximumEx')]
        [String]$Type = "GENERIC"
    )

    begin {
        $CredentialManager = [CredentialManager]::new();
    }

    process {
        $CredType = [CredType]"$Type"
        if ($PSCmdlet.ShouldProcess("Removing Credential, target: $Target", '', '')) {
            $IsRemoved = $CredentialManager.Remove($Target, $CredType);
            if (-not $IsRemoved) {
                throw 'Remove-Credential Failed. ErrorCode: 0x' + [CredentialManager]::LastErrorCode
            }
        }
    }
}
function Save-Credential {
    <#
    .SYNOPSIS
        Saves credential to windows credential Manager
    .DESCRIPTION
        A longer description of the function, its purpose, common use cases, etc.
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Private/NerdCrypt.Core/NerdCrypt.Core.ps1
    .EXAMPLE
        Save-Credential youtube.com/@memeL0rd memeL0rd $(Read-Host -AsSecureString -Prompt "memeLord's youtube password")
    #>
    [CmdletBinding(DefaultParameterSetName = 'uts')]
    param (
        # title aka TargetName of the credential you want to save
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'uts')]
        [ValidateScript({
                if (![string]::IsNullOrWhiteSpace($_)) {
                    return $true
                }
                throw 'Null or WhiteSpace targetName is not allowed.'
            }
        )][Alias('target')]
        [string]$Title,
        # UserName
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'uts')]
        [Alias('UserName')]
        [string]$User,

        # Securestring / Password
        [Parameter(Position = 2, Mandatory = $true, ParameterSetName = 'uts')]
        [ValidateNotNull()]
        [securestring]$SecureString,

        # ManagedCredential Object you want to save
        [Parameter(Mandatory = $true, ParameterSetName = 'MC')]
        [Alias('Credential')][ValidateNotNull()]
        [CredManaged]$Obj

    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'uts') {
            $CredentialManager = [CredentialManager]::new();
            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('User')) {
                [void]$CredentialManager.SaveCredential($Title, $User, $SecureString);
            } else {
                [void]$CredentialManager.SaveCredential($Title, $SecureString);
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'MC') {
            $CredentialManager = [CredentialManager]::new();
            [void]$CredentialManager.SaveCredential($Obj);
        }
    }
}
function Show-SavedCredentials {
    <#
    .SYNOPSIS
        Retreives All strored credentials from credential Manager, but no securestrings. (Just showing)
    .DESCRIPTION
        Retreives All strored credentials and returns a PsObject[]
    .NOTES
        This function is supported on windows only
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Private/NerdCrypt.Core/NerdCrypt.Core.ps1
    .EXAMPLE
        Show-SavedCredentials
    #>
    [CmdletBinding()]
    [outputType([PsObject[]])]
    [Alias('ShowCreds')]
    param ()

    end {
        return [CredentialManager]::get_StoredCreds();
    }
}
#endregion Local_Vault

#region    PasswordManagment
function New-Password {
    <#
    .SYNOPSIS
        Creates a password string
    .DESCRIPTION
        Creates a password containing minimum of 8 characters, 1 lowercase, 1 uppercase, 1 numeric, and 1 special character.
        Created password can not exceed 999 characters
    .LINK
        https://github.com/alainQtec/NerdCrypt/blob/main/Private/NerdCrypt.Core/NerdCrypt.Core.psm1
    .EXAMPLE
        New-Password
        Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'No system state is being changed')]
    [CmdletBinding(DefaultParameterSetName = 'ByLength')]
    param (
        # Exact password Length
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'ByLength')]
        [Alias('l')][ValidateRange(9, 999)]
        [int]$Length,
        # Minimum Length
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'ByMinMax')]
        [Alias('min')]
        [int]$minLength,
        # Minimum Length
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'ByMinMax')]
        [Alias('max')]
        [int]$maxLength,
        # Retries / Iterations to randomise results
        [Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'ByLength')]
        [Parameter(Position = 2, Mandatory = $false, ParameterSetName = 'ByMinMax')]
        [Alias('r')][ValidateRange(1, 100)][ValidateNotNullOrEmpty()]
        [int]$Iterations
    )

    begin {
        $Pass = [string]::Empty
        $params = $PSCmdlet.MyInvocation.BoundParameters
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByLength') {
            if ($params.ContainsKey('Length') -and $params.ContainsKey('Iterations')) {
                $Pass = [PasswordManager]::GeneratePassword($Iterations, $Length);
            } elseif ($params.ContainsKey('Length') -and !$params.ContainsKey('Iterations')) {
                $Pass = [PasswordManager]::GeneratePassword(1, $Length);
            } else {
                $Pass = [PasswordManager]::GeneratePassword();
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'ByMinMax') {
            if ($params.ContainsKey('Iterations')) {
                $pass = [PasswordManager]::GeneratePassword($Iterations, $minLength, $maxLength);
            } else {
                $Pass = [PasswordManager]::GeneratePassword(1, $minLength, $maxLength);
            }
        } else {
            throw [System.Management.Automation.ParameterBindingException]::new("Could Not Resolve ParameterSetname.");
        }
    }
    end {
        return $Pass
    }
}
#endregion PasswordManagment

#endregion Functions

<#
public static string Encrypt(string stringToEncrypt)
{
    if (!string.IsNullOrEmpty(stringToEncrypt))
    {
        byte[] keyArray;
        byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(stringToEncrypt);

        System.Configuration.AppSettingsReader settingsReader = new AppSettingsReader();
        // Get the key from config file

        string key = (string)settingsReader.GetValue("SecurityKey", typeof(String));

        //If hashing use get hashcode regards to your key
        MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
        keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
        //Always release the resources and flush data
        // of the Cryptographic service provide. Best Practice

        hashmd5.Clear();

        TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
        //set the secret key for the tripleDES algorithm
        tdes.Key = keyArray;
        //mode of operation. there are other 4 modes.
        //We choose ECB(Electronic code Book)
        tdes.Mode = CipherMode.ECB;
        //padding mode(if any extra byte added)

        tdes.Padding = PaddingMode.PKCS7;

        ICryptoTransform cTransform = tdes.CreateEncryptor();
        //transform the specified region of bytes array to resultArray
        byte[] resultArray =
            cTransform.TransformFinalBlock(toEncryptArray, 0,
            toEncryptArray.Length);
        //Release resources held by TripleDes Encryptor
        tdes.Clear();
        //Return the encrypted data into unreadable string format
        return Convert.ToBase64String(resultArray, 0, resultArray.Length);
    }
    return "";
}


public static string Decrypt(string cipherString)
{
    if(!string.IsNullOrEmpty(cipherString))
    {
        byte[] keyArray;
        //get the byte code of the string

        byte[] toEncryptArray = Convert.FromBase64String(cipherString.Replace(" ", "+"));

        System.Configuration.AppSettingsReader settingsReader = new AppSettingsReader();
        //Get your key from config file to open the lock!
        string key = (string)settingsReader.GetValue("SecurityKey", typeof(String));

        //if hashing was used get the hash code with regards to your key
        MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
        keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
        //release any resource held by the MD5CryptoServiceProvider

        hashmd5.Clear();

        TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
        //set the secret key for the tripleDES algorithm
        tdes.Key = keyArray;
        //mode of operation. there are other 4 modes.
        //We choose ECB(Electronic code Book)

        tdes.Mode = CipherMode.ECB;
        //padding mode(if any extra byte added)
        tdes.Padding = PaddingMode.PKCS7;

        ICryptoTransform cTransform = tdes.CreateDecryptor();
        byte[] resultArray = cTransform.TransformFinalBlock(
                                toEncryptArray, 0, toEncryptArray.Length);
        //Release resources held by TripleDes Encryptor
        tdes.Clear();
        //return the Clear decrypted TEXT
        return UTF8Encoding.UTF8.GetString(resultArray);
    }
    return "";
}
#>
