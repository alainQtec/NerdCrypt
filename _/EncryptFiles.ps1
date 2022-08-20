''
Write-Host 'Provided by sid-500.com.'
Write-Host 'This tool protects your file content with certificates.' -ForegroundColor Green
''
$cert = Read-Host -Prompt 'Do you already have a certificate for encipherment? (Y/N)?'

If ($cert -eq 'Y') {
    ''
    Write-Host 'Select Certificate.'

    $mycert = Get-ChildItem Cert:\CurrentUser\My

    $choicec = $mycert | Where-Object hasprivatekey -EQ 'true' | Select-Object -Property Issuer, Subject, HasPrivateKey | Out-GridView -Title 'Select Certificate' -PassThru
    ''
    Write-Host 'Enter path to the file to encrypt (e.g. C:\temp\pw.txt)' -ForegroundColor Yellow
    ''
    $path = Read-Host -Prompt 'File Path'
    ''
    Write-Host 'Please wait. Encrypting content ... Once completed notepad will open your encrypted file.'
    ''
    Get-Content $path | Protect-CmsMessage -To $choicec.Subject -OutFile $path

    notepad $path

}

If ($cert -eq 'n') {
    ''
    Write-Host 'This section creates a new self signed certificate. Provide certificate name.'
    ''
    $newcert = Read-Host 'Enter Certificate Name'

    New-SelfSignedCertificate -DnsName $newcert -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage KeyEncipherment, DataEncipherment, KeyAgreement -Type DocumentEncryptionCert

    $cert = Get-ChildItem -Path Cert:\CurrentUser\My\ | Where-Object subject -Like "*$newcert*"
    $thumb = $cert.thumbprint
    ''
    Write-Host 'Certificate created'
    ''
    Write-Host 'Saving certificate to users profile' -ForegroundColor Green
    ''
    $pwcert = ConvertTo-SecureString -String (Read-Host 'Enter Password for cert file' -AsSecureString)
    ''
    Write-Host 'Certificate Export completed' -ForegroundColor Green
    Export-PfxCertificate -Cert Cert:\CurrentUser\My\$thumb -FilePath $home\"cert_"$env:username".pfx" -Password $pwcert

    Write-Host 'Enter path to the file to encrypt (e.g. C:\temp\pw.txt)' -ForegroundColor Yellow
    ''
    $path = Read-Host -Prompt 'File Path'
    ''
    Write-Host 'Please wait. Encrypting content ... Once completed notepad will open your encrypted file.'
    ''
    Get-Content $path | Protect-CmsMessage -To $cert.Subject -OutFile $path

    notepad $path

}
