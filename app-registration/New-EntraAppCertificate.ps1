# Windows PowerShell 5.1 / PowerShell 7 on Windows. ASCII source.
<#
.SYNOPSIS
Crea un certificato autofirmato per un'app Entra ed esporta CER e PFX.
.DESCRIPTION
Procedura interattiva: nome app, validita in mesi, password PFX con conferma.
RSA 2048 / SHA256; chiave privata esportabile nello store CurrentUser\My.
PFX protetto con AES256_SHA256. Verifica CER e PFX, compresa la chiave privata.
Non carica certificati in Entra e non modifica credenziali esistenti.
La password non viene stampata, salvata nel riepilogo o copiata negli appunti.
.PARAMETER OutputDirectory
Cartella base. Default: LOCALAPPDATA\EntraOperations\Certificati.
Ogni esecuzione crea una sottocartella distinta con app, data e identificativo.
.EXAMPLE
.\New-EntraAppCertificate.ps1
.EXAMPLE
.\New-EntraAppCertificate.ps1 -AppName nome-app -ValidityMonths 12
#>
[CmdletBinding()]
param(
    [string]$AppName,
    [ValidateRange(0,60)][int]$ValidityMonths = 0,
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-CertSection([string]$Title) {
    Write-Host ''
    Write-Host ('  ' + ('-' * 76)) -ForegroundColor DarkCyan
    Write-Host ('  ' + $Title) -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 76)) -ForegroundColor DarkCyan
}
function Write-CertStatus([string]$State,[string]$Text) {
    $color = switch ($State) { 'OK' { 'Green' } 'KO' { 'Red' } default { 'Yellow' } }
    Write-Host ('  [{0}] ' -f $State) -ForegroundColor $color -NoNewline
    Write-Host $Text
}
function Write-CertValue([string]$Label,[string]$Value) {
    Write-Host ('  {0,-21} ' -f $Label) -ForegroundColor Gray -NoNewline
    Write-Host $Value
}
function Assert-AppCertificateName([string]$Name) {
    if ($Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._ -]{0,79}$' -or $Name.EndsWith('.') -or $Name.EndsWith(' ')) {
        throw 'Nome non valido: usare 1-80 caratteri, lettere, numeri, spazi, punti, trattini o underscore; iniziare con lettera o numero e non terminare con punto/spazio.'
    }
}
function Test-EqualSecurePassword([Security.SecureString]$First,[Security.SecureString]$Second) {
    if ($First.Length -ne $Second.Length) { return $false }
    $a = [IntPtr]::Zero; $b = [IntPtr]::Zero
    try {
        $a = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        $difference = 0
        for ($i=0; $i -lt $First.Length; $i++) {
            $difference = $difference -bor (
                [Runtime.InteropServices.Marshal]::ReadInt16($a,2*$i) -bxor
                [Runtime.InteropServices.Marshal]::ReadInt16($b,2*$i))
        }
        return ($difference -eq 0)
    }
    finally {
        if ($a -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($a) }
        if ($b -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }
}
function Read-CertificatePassword {
    while ($true) {
        $first = Read-Host '  Password PFX (almeno 12 caratteri)' -AsSecureString
        if ($first.Length -lt 12) {
            $first.Dispose()
            Write-CertStatus 'ATTENZIONE' 'Servono almeno 12 caratteri. Conserva la password nel gestore aziendale.'
            continue
        }
        $second = $null
        try {
            $second = Read-Host '  Ripeti la password PFX' -AsSecureString
            if (Test-EqualSecurePassword $first $second) { return $first }
            Write-CertStatus 'ATTENZIONE' 'Le password non coincidono. Reinseriscile.'
        }
        catch { $first.Dispose(); throw }
        finally { if ($null -ne $second) { $second.Dispose() } }
        $first.Dispose()
    }
}
function Assert-CertificateRuntime {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Eseguire su Windows con Windows PowerShell 5.1 o PowerShell 7.'
    }
    Import-Module PKI -ErrorAction Stop
    foreach ($name in @('New-SelfSignedCertificate','Export-Certificate','Export-PfxCertificate')) {
        $null = Get-Command $name -ErrorAction Stop
    }
}
function Test-CertificateExports([string]$CerPath,[string]$PfxPath,[Security.SecureString]$Password,[string]$Thumbprint) {
    $publicCert = $null; $privateCert = $null
    try {
        $publicCert = [Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($CerPath))
        $privateCert = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [IO.File]::ReadAllBytes($PfxPath), $Password,
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        if ($publicCert.Thumbprint -ne $Thumbprint -or $privateCert.Thumbprint -ne $Thumbprint) {
            throw 'Thumbprint dei file esportati non coerente con il certificato creato.'
        }
        if ($publicCert.HasPrivateKey -or -not $privateCert.HasPrivateKey) {
            throw 'Verifica chiave privata fallita: deve essere presente solo nel PFX.'
        }
    }
    finally {
        if ($null -ne $publicCert) { $publicCert.Dispose() }
        if ($null -ne $privateCert) { $privateCert.Dispose() }
    }
}
function Invoke-AppCertificateCreation([string]$Name,[int]$Months,[string]$Folder) {
    $password = $null; $certificate = $null; $runFolder = $null
    try {
        Write-Host ''
        Write-Host ('  ' + ('=' * 76)) -ForegroundColor Cyan
        Write-Host '  MICROSOFT ENTRA | CERTIFICATO APPLICATIVO | v1.0' -ForegroundColor White
        Write-Host '  Creazione guidata - CER pubblico e PFX protetto da password' -ForegroundColor Cyan
        Write-Host ('  ' + ('=' * 76)) -ForegroundColor Cyan
        Write-CertSection '1 / 5 | DATI DEL CERTIFICATO'
        Assert-CertificateRuntime
        if ([string]::IsNullOrWhiteSpace($Name)) {
            do { $Name = (Read-Host '  Nome della tua app registration (es. nome-app)').Trim() }
            while ([string]::IsNullOrWhiteSpace($Name))
        }
        $Name = $Name.Trim()
        Assert-AppCertificateName $Name
        if ($Months -eq 0) {
            do {
                $inputMonths = (Read-Host '  Validita in mesi, da 1 a 60 [12]').Trim()
                if (-not $inputMonths) { $inputMonths = '12' }
                $parsedMonths = 0
                $valid = [int]::TryParse($inputMonths,[ref]$parsedMonths) -and $parsedMonths -ge 1 -and $parsedMonths -le 60
                if (-not $valid) { Write-CertStatus 'ATTENZIONE' 'Inserire un numero intero da 1 a 60.' }
            } while (-not $valid)
            $Months = $parsedMonths
        }
        if ($Months -lt 1 -or $Months -gt 60) { throw 'Validita non ammessa: usare da 1 a 60 mesi.' }
        if ([string]::IsNullOrWhiteSpace($Folder)) {
            $localRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
            if (-not $localRoot) { throw 'Cartella LocalApplicationData non disponibile: indicare -OutputDirectory.' }
            $Folder = Join-Path $localRoot 'EntraOperations\Certificati'
        }
        $Folder = [IO.Path]::GetFullPath($Folder)
        Write-CertValue 'Applicazione' $Name
        Write-CertValue 'Validita' ($Months.ToString() + ' mesi')
        Write-CertValue 'Algoritmo' 'RSA 2048 / SHA256'
        Write-CertValue 'Store locale' 'Cert:\CurrentUser\My'
        Write-CertValue 'Cartella base' $Folder

        Write-CertSection '2 / 5 | PASSWORD DEL FILE PFX'
        Write-Host '  Scegli e conserva la password nel gestore aziendale prima di procedere.'
        Write-Host '  La password protegge il PFX; non e un client secret di Entra.'
        $password = Read-CertificatePassword
        Write-CertStatus 'OK' 'Password confermata. Non verra stampata o salvata nel riepilogo.'

        Write-CertSection '3 / 5 | CREAZIONE ED ESPORTAZIONE'
        $unique = [Guid]::NewGuid().ToString('N').Substring(0,8)
        $runName = '{0}_{1}_{2}' -f $Name.Replace(' ','_'),(Get-Date -Format 'yyyyMMdd_HHmmss'),$unique
        $runFolder = Join-Path $Folder $runName
        $null = New-Item -ItemType Directory -Path $runFolder -ErrorAction Stop
        $certParams = @{
            Type='Custom'; Subject=('CN='+$Name); FriendlyName=($Name+' - autenticazione applicativa')
            CertStoreLocation='Cert:\CurrentUser\My'
            Provider='Microsoft Enhanced RSA and AES Cryptographic Provider'
            KeyAlgorithm='RSA'; KeyLength=2048; HashAlgorithm='SHA256'
            KeySpec='Signature'; KeyUsage='DigitalSignature'; KeyExportPolicy='Exportable'
            NotAfter=(Get-Date).AddMonths($Months)
        }
        Write-CertStatus 'ATTESA' 'Generazione del certificato autofirmato...'
        $certificate = New-SelfSignedCertificate @certParams
        if (-not $certificate.HasPrivateKey) { throw 'Il certificato creato non dispone della chiave privata.' }
        Write-CertStatus 'OK' 'Certificato creato nello store della tua utenza.'
        $cerPath = Join-Path $runFolder ($Name.Replace(' ','_')+'.cer')
        $pfxPath = Join-Path $runFolder ($Name.Replace(' ','_')+'.pfx')
        $null = Export-Certificate -Cert $certificate -FilePath $cerPath -Type CERT -NoClobber
        $pfxParams = @{
            Cert=$certificate; FilePath=$pfxPath; Password=$password
            CryptoAlgorithmOption='AES256_SHA256'; ChainOption='EndEntityCertOnly'
            NoProperties=$true; NoClobber=$true
        }
        $null = Export-PfxCertificate @pfxParams
        Write-CertStatus 'OK' 'Esportati CER pubblico e PFX con chiave privata.'

        Write-CertSection '4 / 5 | VERIFICA DEI FILE'
        Test-CertificateExports $cerPath $pfxPath $password $certificate.Thumbprint
        Write-CertStatus 'OK' 'PFX riaperto con la password; chiave privata presente.'
        Write-CertStatus 'OK' 'CER privo di chiave privata; thumbprint coerente in entrambi i file.'
        $reportPath = Join-Path $runFolder 'Riepilogo-certificato.txt'
        $report = @(
            'CERTIFICATO APPLICATIVO ENTRA - RIEPILOGO PUBBLICO'
            ('Applicazione: '+$Name)
            ('Subject: '+$certificate.Subject)
            ('Thumbprint: '+$certificate.Thumbprint)
            ('Valido dal (ora locale PC): '+$certificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss zzz'))
            ('Scadenza (ora locale PC): '+$certificate.NotAfter.ToString('yyyy-MM-dd HH:mm:ss zzz'))
            'Tipo: autofirmato; RSA 2048; SHA256; PFX AES256_SHA256'
            ('Store: Cert:\CurrentUser\My\'+$certificate.Thumbprint)
            ('CER: '+$cerPath)
            ('PFX: '+$pfxPath)
            'Verifica locale: CER e PFX coerenti; PFX leggibile con password e chiave privata presente.'
            'La password non e contenuta in questo riepilogo.'
            'Caricare soltanto il CER in App registrations > app corretta > Certificates & secrets > Certificates.'
            'Fornire PFX al servizio applicativo e password tramite canale separato.'
            'Upload in Entra e autenticazione del servizio: da eseguire; non verificati dallo script.'
        )
        $report | Set-Content -LiteralPath $reportPath -Encoding UTF8

        Write-CertSection '5 / 5 | COMPLETATO - FILE DA UTILIZZARE'
        Write-CertValue 'Applicazione' $Name
        Write-CertValue 'Thumbprint' $certificate.Thumbprint
        Write-CertValue 'Valido dal' ($certificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss zzz'))
        Write-CertValue 'Scadenza' ($certificate.NotAfter.ToString('yyyy-MM-dd HH:mm:ss zzz'))
        Write-CertValue 'CARTELLA OUTPUT' $runFolder
        Write-CertValue 'CER per Entra' $cerPath
        Write-CertValue 'PFX per il servizio' $pfxPath
        Write-CertValue 'Riepilogo pubblico' $reportPath
        Write-Host ''
        Write-Host '  1. Carica il CER nell app registration corretta e confronta il thumbprint.'
        Write-Host '  2. Consegna PFX al team applicativo; comunica la password separatamente.'
        Write-Host '  3. Verifica l autenticazione del servizio prima di ritirare un vecchio certificato.'
        Write-Host '  La chiave privata rimane anche nello store CurrentUser\My del PC.'
        Write-CertStatus 'OK' 'Creazione e verifiche locali completate.'
        return [pscustomobject]@{Folder=$runFolder;CerPath=$cerPath;PfxPath=$pfxPath;ReportPath=$reportPath;Thumbprint=$certificate.Thumbprint}
    }
    catch {
        Write-CertStatus 'KO' $_.Exception.Message
        if ($null -ne $certificate) {
            Write-CertValue 'Certificato creato' ('Cert:\CurrentUser\My\'+$certificate.Thumbprint)
        }
        if ($runFolder) { Write-CertValue 'Cartella tentativo' $runFolder }
        Write-Host '  Operazione non completata. Eventuali file parziali non sono dichiarati verificati.'
        throw
    }
    finally {
        if ($null -ne $password) { $password.Dispose() }
        if ($null -ne $certificate -and $certificate -is [IDisposable]) { $certificate.Dispose() }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-AppCertificateCreation -Name $AppName -Months $ValidityMonths -Folder $OutputDirectory | Out-Null }
    catch { exit 1 }
}
