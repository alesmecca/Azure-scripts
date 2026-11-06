# Windows PowerShell 5.1 / PowerShell 7 on Windows. ASCII source by design.
<#
.SYNOPSIS
Acquisisce oppure analizza un JWT di collaudo Microsoft Entra External ID.
.DESCRIPTION
Configurazione guidata senza tenant o applicazioni preimpostati. Acquire usa
Authorization Code + PKCE S256 dal pannello Run user flow. Analyze decodifica
un token gia emesso, senza rete. Controlla claim e tempi, NON la firma JWT.
Nessuna modifica al tenant, nessuna chiamata al backend, nessun file di default.
.PARAMETER Mode
Acquire: scambio code/access token. Analyze: analisi locale di ID/access token.
.PARAMETER ClientType
Spa: Origin ricavato dal redirect. Public: client desktop/mobile senza Origin.
La scelta deve corrispondere alla piattaforma realmente registrata in Entra.
Le applicazioni Web confidential che richiedono secret non sono supportate.
.PARAMETER ExpectedIssuer
Issuer atteso esatto dal metadata OIDC verificato indipendentemente. Facoltativo.
.PARAMETER ExpectedScope
Nomi scope attesi nel claim scp, separati da spazi (es. access_as_user).
.PARAMETER RequestedApiScope
Scope API completo da verificare nell'URL authorize. Obbligatorio in Acquire.
.PARAMETER CopyToken
Copia il token completo negli appunti solo su richiesta. Non lo stampa.
.PARAMETER SaveReport
Salva un report selettivo senza token o identificativi personali standard.
.EXAMPLE
.\Test-ExternalIdToken.ps1
.EXAMPLE
.\Test-ExternalIdToken.ps1 -Mode Analyze -TokenKind Id
.EXAMPLE
.\Test-ExternalIdToken.ps1 -Mode Acquire -ClientType Spa -CopyToken
#>
[CmdletBinding()]
param(
    [ValidateSet('Acquire','Analyze')][string]$Mode,
    [ValidateSet('Access','Id')][string]$TokenKind,
    [ValidateSet('Spa','Public')][string]$ClientType,
    [string]$TenantId,
    [string]$AuthorityHost,
    [string]$ClientId,
    [string]$ExpectedAudience,
    [string]$RequestedApiScope,
    [string]$ExpectedScope,
    [string]$ExpectedProfile,
    [string]$ProfileClaim,
    [string]$ExpectedIssuer,
    [string]$ExpectedVersion,
    [Alias('CopyAccessToken')][switch]$CopyToken,
    [switch]$SaveReport,
    [switch]$ShowJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Web

function Read-PrivateText([string]$Prompt) {
    $secret = Read-Host -Prompt $Prompt -AsSecureString
    try { return [System.Net.NetworkCredential]::new('', $secret).Password.Trim() }
    finally { $secret.Dispose() }
}
function Read-Setting([string]$Value, [string]$Prompt, [switch]$Required) {
    if ([string]::IsNullOrWhiteSpace($Value)) { $Value = (Read-Host $Prompt).Trim() }
    if ($Required -and [string]::IsNullOrWhiteSpace($Value)) { throw ('Campo obbligatorio: ' + $Prompt) }
    return $Value.Trim()
}
function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('  ' + ('-' * 76)) -ForegroundColor DarkCyan
    Write-Host ('  ' + $Title) -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 76)) -ForegroundColor DarkCyan
}
function Write-Status([string]$Label, [string]$Text) {
    $color = switch ($Label) { 'OK' { 'Green' } 'KO' { 'Red' } default { 'Yellow' } }
    Write-Host ('  [{0}] ' -f $Label) -ForegroundColor $color -NoNewline
    Write-Host $Text
}
function Write-Value([string]$Label, $Value) {
    $line = if ($null -eq $Value) { '(assente)' }
        elseif ($Value -is [array]) { ConvertTo-Json -InputObject $Value -Compress -Depth 4 }
        elseif ([string]::IsNullOrEmpty([string]$Value)) { '(assente)' }
        else { [string]$Value }
    Write-Host ('  {0,-20} ' -f $Label) -ForegroundColor Gray -NoNewline
    while ($line.Length -gt 55) {
        Write-Host $line.Substring(0,55)
        Write-Host (' ' * 23) -NoNewline
        $line = $line.Substring(55)
    }
    Write-Host $line
}
function Get-Claim($Object, [string]$Name) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }
    return $null
}
function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
function Read-JwtPart([string]$Part) {
    if ($Part -cnotmatch '^[A-Za-z0-9_-]+$') { throw 'Segmento JWT non valido.' }
    $base64 = $Part.Replace('-','+').Replace('_','/')
    switch ($base64.Length % 4) {
        0 { } 2 { $base64 += '==' } 3 { $base64 += '=' }
        default { throw 'Lunghezza segmento JWT non valida.' }
    }
    try { $result = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64)) | ConvertFrom-Json }
    catch { throw 'Il segmento JWT non contiene JSON decodificabile.' }
    if ($null -eq $result -or $result -isnot [pscustomobject]) { throw 'Header e payload JWT devono essere oggetti JSON.' }
    return $result
}
function Get-AbsoluteUri([string]$Text) {
    $parsed = $null
    if (-not [Uri]::TryCreate($Text,[UriKind]::Absolute,[ref]$parsed) -or $parsed.UserInfo) {
        throw 'URL non valido: copiare direttamente il valore senza escape o credenziali.'
    }
    return $parsed
}
function Assert-SingleParameters($Parameters) {
    foreach ($key in $Parameters.AllKeys) {
        if ($null -eq $key -or @($Parameters.GetValues($key)).Count -ne 1) {
            throw 'La URL contiene parametri duplicati o senza nome.'
        }
    }
}
function Format-Timestamp($Value) {
    if ($null -eq $Value) { return '(assente)' }
    try { return [DateTimeOffset]::FromUnixTimeSeconds([long]$Value).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss UTC') }
    catch { return '(timestamp non valido)' }
}

Write-Host ''
Write-Host ('  ' + ('=' * 76)) -ForegroundColor Cyan
Write-Host '  EXTERNAL ID | COLLAUDO TOKEN | v2.0' -ForegroundColor White
Write-Host '  Acquisizione PKCE e analisi diagnostica delle claim' -ForegroundColor Cyan
Write-Host ('  ' + ('=' * 76)) -ForegroundColor Cyan
Write-Host '  Nessun tenant preimpostato. Nessuna modifica alle configurazioni.'
Write-Host '  Output in console; salvataggio e appunti solo se richiesti.'
Write-Section '1 | CONFIGURAZIONE DEL COLLAUDO'
if (-not $Mode) {
    $choice = Read-Host '  Modalita: 1 = acquisisci access token; 2 = analizza JWT [1]'
    $Mode = switch ($choice.Trim()) { '' { 'Acquire' } '1' { 'Acquire' } '2' { 'Analyze' } default { throw 'Scegliere 1 oppure 2.' } }
}
if ($Mode -eq 'Acquire') {
    if ($TokenKind -eq 'Id') { throw 'Acquire acquisisce un access token API. Per ID token usare Analyze.' }
    $TokenKind = 'Access'
} elseif (-not $TokenKind) {
    $choice = Read-Host '  Token da analizzare: 1 = access token; 2 = ID token [1]'
    $TokenKind = switch ($choice.Trim()) { '' { 'Access' } '1' { 'Access' } '2' { 'Id' } default { throw 'Scegliere 1 oppure 2.' } }
}
$TenantId = Read-Setting $TenantId '  Tenant ID atteso (GUID)' -Required
$tenantGuid = [guid]::Empty
if (-not [guid]::TryParse($TenantId,[ref]$tenantGuid)) { throw 'Tenant ID non valido: usare il GUID del tenant.' }
$TenantId = $tenantGuid.ToString()
$ClientId = Read-Setting $ClientId '  Client ID della applicazione chiamante (GUID)' -Required
$clientGuid = [guid]::Empty
if (-not [guid]::TryParse($ClientId,[ref]$clientGuid)) { throw 'Client ID non valido: usare il GUID della app.' }
$ClientId = $clientGuid.ToString()
if ($TokenKind -eq 'Id') {
    if ($ExpectedAudience -and $ExpectedAudience -ne $ClientId) { throw 'Per ID token la audience attesa deve coincidere con il Client ID.' }
    $ExpectedAudience = $ClientId
} else {
    $ExpectedAudience = Read-Setting $ExpectedAudience '  Audience API attesa (claim aud, GUID o URI)' -Required
    if (-not $PSBoundParameters.ContainsKey('ExpectedScope')) {
        $ExpectedScope = Read-Setting $ExpectedScope '  Scope attesi nel claim scp, separati da spazi (vuoto = non controllare)'
    }
}
if (-not $ProfileClaim) { $ProfileClaim = Read-Setting $ProfileClaim '  Nome claim profilo [profileTypes]' }
if (-not $ProfileClaim) { $ProfileClaim = 'profileTypes' }
if ($ProfileClaim -cnotmatch '^[A-Za-z_][A-Za-z0-9_.-]{0,127}$') { throw 'Nome claim profilo non valido.' }
# A custom profile field must not turn the report into a personal-data dump.
if ($ProfileClaim -in @('email','emails','name','given_name','family_name','oid','sub','upn','preferred_username','unique_name','nonce','aio','rh','uti')) {
    throw 'Il nome scelto e un identificativo personale/sessione, non un claim di profilo.'
}
if (-not $PSBoundParameters.ContainsKey('ExpectedProfile')) {
    $ExpectedProfile = Read-Setting $ExpectedProfile '  Valore profilo atteso (vuoto = non controllare)'
}
if (-not $PSBoundParameters.ContainsKey('ExpectedIssuer')) {
    $ExpectedIssuer = Read-Setting $ExpectedIssuer '  Issuer atteso dal metadata OIDC (vuoto = non controllare)'
}
if (-not $PSBoundParameters.ContainsKey('ExpectedVersion')) {
    $ExpectedVersion = Read-Setting $ExpectedVersion '  Versione token attesa [2.0]; scrivi - per non controllare'
    if (-not $ExpectedVersion) { $ExpectedVersion = '2.0' }
    if ($ExpectedVersion -eq '-') { $ExpectedVersion = '' }
}

$token = $null
$tokenResponse = $null
$post = $null
$verifier = $null
$code = $null
$returnText = $null
try {
    if ($Mode -eq 'Acquire') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $AuthorityHost = Read-Setting $AuthorityHost '  Host authority (es. nome-tenant.ciamlogin.com, senza https://)' -Required
        if ($AuthorityHost -notmatch '^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$' -or $AuthorityHost -notmatch '\.') {
            throw 'Host authority non valido: inserire solo il nome DNS verificato del tenant.'
        }
        $RequestedApiScope = Read-Setting $RequestedApiScope '  Scope API completo della tua applicazione, come presente nella richiesta authorize' -Required
        if ($RequestedApiScope -match '\s' -or $RequestedApiScope -notmatch '.+/.+') { throw 'Inserire un solo scope API completo.' }
        if (-not $ClientType) {
            $choice = Read-Host '  Piattaforma del redirect: 1 = SPA; 2 = public client desktop/mobile [1]'
            $ClientType = switch ($choice.Trim()) { '' { 'Spa' } '1' { 'Spa' } '2' { 'Public' } default { throw 'Scegliere 1 oppure 2.' } }
        }
        Write-Value 'Piattaforma' $ClientType
        Write-Host '  La scelta deve corrispondere al redirect registrato in Entra.'
        Write-Host '  Web confidential non supportata. Non inserire secret o password qui.'
        Write-Section '2 | RICHIESTA DAL PORTALE E CONTROLLO PKCE'
        Write-Host '  Nel Run user flow: seleziona la API, response type code e PKCE S256.'
        Write-Host '  Mantieni aperto lo stesso pannello fino al termine del login.'
        $authorizeUri = Get-AbsoluteUri ((Read-Host '  Incolla Run user flow endpoint').Trim())
        if ($authorizeUri.Scheme -ne 'https' -or $authorizeUri.Host -ne $AuthorityHost -or $authorizeUri.Port -ne 443 -or
            $authorizeUri.AbsolutePath -cne "/$TenantId/oauth2/v2.0/authorize" -or $authorizeUri.Fragment) {
            throw 'Endpoint authorize diverso dal tenant/host configurati o percorso v2.0 inatteso.'
        }
        $request = [System.Web.HttpUtility]::ParseQueryString($authorizeUri.Query)
        Assert-SingleParameters $request
        if ($request['client_id'] -ne $ClientId -or $request['response_type'] -cne 'code' -or $request['code_challenge_method'] -cne 'S256') {
            throw 'Client ID, response_type code o PKCE S256 non corrispondono.'
        }
        if ($request['response_mode'] -and $request['response_mode'] -notin @('query','fragment')) {
            throw 'Questo collaudo manuale richiede response_mode query oppure fragment, non form_post.'
        }
        $scope = $request['scope']
        $requestedScopes = @($scope -split '\s+')
        if ($requestedScopes -cnotcontains $RequestedApiScope) { throw 'Scope API completo atteso assente nella richiesta authorize.' }
        $redirectUri = Get-AbsoluteUri $request['redirect_uri']
        if ($redirectUri.Query -or $redirectUri.Fragment -or
            ($redirectUri.Scheme -ne 'https' -and -not ($ClientType -eq 'Public' -and $redirectUri.Scheme -eq 'http' -and $redirectUri.IsLoopback))) {
            throw 'Redirect supportati: HTTPS senza query/fragment, oppure HTTP loopback per public client.'
        }
        Write-Value 'Redirect URI' $request['redirect_uri']
        Write-Value 'Scope richiesti' $scope
        if (-not $request['state']) { Write-Status 'NOTA' 'State assente nella URL del portale: correlazione del ritorno non verificabile.' }
        $verifier = Read-PrivateText '  Code Verifier dello stesso pannello (nascosto)'
        if ($verifier -cnotmatch '^[A-Za-z0-9._~-]{43,128}$') { throw 'Code Verifier non valido: non inserire il Code Challenge o un URL.' }
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try { $challenge = ConvertTo-Base64Url ($sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))) }
        finally { $sha256.Dispose() }
        if ($challenge -cne $request['code_challenge']) { throw 'Verifier e challenge non corrispondono. Copiarli dallo stesso pannello.' }
        Write-Status 'OK' 'Client, endpoint, scope e PKCE coerenti con i valori attesi.'
        Write-Section '3 | ACCESSO UTENTE'
        Write-Host '  Apri lo stesso Run user flow endpoint in una finestra privata.'
        Write-Host '  Completa il login, poi copia la URL di ritorno contenente code=.'
        $returnText = Read-PrivateText '  URL completa di ritorno (nascosta)'
        $returnUri = Get-AbsoluteUri $returnText
        if ($returnUri.Scheme -ne $redirectUri.Scheme -or $returnUri.Host -ne $redirectUri.Host -or
            $returnUri.Port -ne $redirectUri.Port -or $returnUri.AbsolutePath -cne $redirectUri.AbsolutePath) {
            throw 'URL di ritorno diversa dal redirect_uri della richiesta.'
        }
        if ($returnUri.Query -and $returnUri.Fragment.TrimStart('#')) { throw 'Parametri presenti sia in query sia in fragment: ritorno ambiguo.' }
        # Assign within each branch: avoids NameValueCollection pipeline enumeration.
        if ($returnUri.Query) { $response = [System.Web.HttpUtility]::ParseQueryString($returnUri.Query) }
        else { $response = [System.Web.HttpUtility]::ParseQueryString($returnUri.Fragment.TrimStart('#')) }
        Assert-SingleParameters $response
        if ($response['error']) { throw ('Errore di autorizzazione: ' + $response['error']) }
        if ($request['state'] -and $response['state'] -cne $request['state']) { throw 'State del ritorno diverso dalla richiesta.' }
        $code = $response['code']
        if ([string]::IsNullOrWhiteSpace($code)) { throw 'Nessun code nella URL. Ripetere con response_type code.' }
        Write-Section '4 | ACQUISIZIONE ACCESS TOKEN'
        $post = @{
            Method = 'Post'
            Uri = "https://$AuthorityHost/$TenantId/oauth2/v2.0/token"
            ContentType = 'application/x-www-form-urlencoded'
            MaximumRedirection = 0
            Body = @{
                client_id = $ClientId; grant_type = 'authorization_code'; code = $code
                redirect_uri = $request['redirect_uri']; code_verifier = $verifier; scope = $scope
            }
        }
        if ($ClientType -eq 'Spa') { $post.Headers = @{ Origin = $redirectUri.GetLeftPart([UriPartial]::Authority) } }
        Write-Status 'ATTESA' 'Scambio code con il token endpoint configurato...'
        try { $tokenResponse = Invoke-RestMethod @post }
        catch {
            $oauthError = $null
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                try { $oauthError = $_.ErrorDetails.Message | ConvertFrom-Json } catch { }
            }
            if ($oauthError) {
                $description = [string](Get-Claim $oauthError 'error_description')
                $errorCode = [string](Get-Claim $oauthError 'error')
                if ($description -match 'AADSTS9002326') {
                    throw 'AADSTS9002326: il redirect non risulta SPA. Verificare la piattaforma registrata; poi ripetere login e PKCE con un nuovo code.'
                }
                if ($description -match 'AADSTS7000218') {
                    throw 'AADSTS7000218: Entra richiede credenziali confidential. Verificare piattaforma/client; questo script non gestisce secret.'
                }
                Write-Value 'Correlation ID' (Get-Claim $oauthError 'correlation_id')
                $aadCode = [regex]::Match($description,'AADSTS\d+').Value
                throw ('Token endpoint: {0} {1}. Ripetere con un nuovo code; verificare configurazione e log Entra.' -f $errorCode,$aadCode)
            }
            throw 'Scambio token non riuscito. Verificare rete/proxy, endpoint e log Entra; nessun token acquisito.'
        }
        $token = [string](Get-Claim $tokenResponse 'access_token')
        if (-not $token) { throw 'La risposta non contiene access_token.' }
        Write-Status 'OK' 'Access token ricevuto.'
    } else {
        Write-Section '2 | ANALISI LOCALE DEL JWT'
        Write-Host '  Incolla solo il JWT completo, non la URL di jwt.ms. Nessuna rete.'
        $token = Read-PrivateText '  JWT da analizzare (nascosto)'
    }

    $parts = $token.Split('.')
    if ($parts.Length -ne 3) { throw 'Formato non supportato: servono tre segmenti JWT. Token opachi/JWE non sono decodificati.' }
    $header = Read-JwtPart $parts[0]
    $claims = Read-JwtPart $parts[1]
    $checks = [Collections.Generic.List[object]]::new()
    function Add-Check([string]$Name, [bool]$Passed, [bool]$Configured = $true) {
        $status = if (-not $Configured) { 'SKIP' } elseif ($Passed) { 'OK' } else { 'KO' }
        $checks.Add([pscustomobject]@{ name = $Name; status = $status })
    }
    Add-Check 'Audience attesa' (@(Get-Claim $claims 'aud') -ccontains $ExpectedAudience)
    Add-Check 'Tenant atteso' ((Get-Claim $claims 'tid') -eq $TenantId)
    if ($TokenKind -eq 'Access') {
        $caller = Get-Claim $claims 'azp'
        if (-not $caller) { $caller = Get-Claim $claims 'appid' }
        Add-Check 'Client chiamante atteso' ($caller -eq $ClientId)
        $actualScopes = @(([string](Get-Claim $claims 'scp')) -split '\s+')
        $scopeMatch = $true
        foreach ($item in @($ExpectedScope -split '\s+' | Where-Object { $_ })) {
            if ($actualScopes -cnotcontains $item) { $scopeMatch = $false }
        }
        Add-Check 'Scope delegati attesi' $scopeMatch (-not [string]::IsNullOrWhiteSpace($ExpectedScope))
    }
    Add-Check 'Profilo atteso' (@(Get-Claim $claims $ProfileClaim) -ccontains $ExpectedProfile) (-not [string]::IsNullOrWhiteSpace($ExpectedProfile))
    Add-Check 'Issuer atteso (solo confronto stringa)' ((Get-Claim $claims 'iss') -ceq $ExpectedIssuer) (-not [string]::IsNullOrWhiteSpace($ExpectedIssuer))
    Add-Check 'Versione token attesa' ((Get-Claim $claims 'ver') -ceq $ExpectedVersion) (-not [string]::IsNullOrWhiteSpace($ExpectedVersion))
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $exp = Get-Claim $claims 'exp'
    $nbf = Get-Claim $claims 'nbf'
    $expiryOk = $false; $notBeforeOk = $false
    try { $expiryOk = ($null -ne $exp -and [string]$exp -match '^\d+$' -and [long]$exp -gt $now) } catch { }
    try { $notBeforeOk = ($null -ne $nbf -and [string]$nbf -match '^\d+$' -and [long]$nbf -le $now) } catch { }
    Add-Check 'Token non scaduto (orologio locale UTC)' $expiryOk
    Add-Check 'nbf raggiunto (orologio locale UTC)' $notBeforeOk ($null -ne $nbf)

    $selected = [ordered]@{}
    foreach ($name in @('iss','aud','azp','appid','tid','ver','scp','idp',$ProfileClaim,'iat','nbf','exp') | Select-Object -Unique) {
        $property = $claims.PSObject.Properties[$name]
        if ($null -eq $property) { $selected[$name] = $null }
        else { $selected[$name] = $property.Value }
    }
    $report = [ordered]@{
        tool = 'Test-ExternalIdToken'; version = '2.0'; mode = $Mode; tokenKind = $TokenKind
        checkedAtUtc = [DateTime]::UtcNow.ToString('o')
        limitation = 'Diagnostica di claim e tempi. Firma JWT, attendibilita issuer, accesso e autorizzazione backend NON validati.'
        expected = [ordered]@{ tenant = $TenantId; client = $ClientId; audience = $ExpectedAudience; scope = $ExpectedScope; profileClaim = $ProfileClaim; profile = $ExpectedProfile; issuer = $ExpectedIssuer; tokenVersion = $ExpectedVersion }
        header = [ordered]@{ alg = (Get-Claim $header 'alg'); kid = (Get-Claim $header 'kid') }
        claims = $selected; checks = @($checks.ToArray())
    }
    Write-Section 'RISULTATI | CONFRONTO DELLE CLAIM'
    foreach ($check in $checks) { Write-Status $check.status $check.name }
    $passed = @($checks | Where-Object { $_.status -eq 'OK' }).Count
    $failed = @($checks | Where-Object { $_.status -eq 'KO' }).Count
    $skipped = @($checks | Where-Object { $_.status -eq 'SKIP' }).Count
    Write-Host ''
    Write-Status $(if ($failed) { 'KO' } else { 'OK' }) ("Confronti: $passed conformi, $failed non conformi, $skipped non configurati/non applicabili.")
    Write-Section 'CLAIM SELEZIONATE | DATI PERSONALI STANDARD ESCLUSI'
    foreach ($entry in $selected.GetEnumerator()) { Write-Value $entry.Key $entry.Value }
    $profileProperty = $claims.PSObject.Properties[$ProfileClaim]
    $profileFormat = if ($null -eq $profileProperty -or $null -eq $profileProperty.Value) { 'Assente' }
        elseif ($profileProperty.Value -is [array]) { 'Array JSON' }
        elseif ($profileProperty.Value -is [string]) { 'Stringa JSON' }
        else { $profileProperty.Value.GetType().Name }
    Write-Value 'Formato profilo' $profileFormat
    Write-Value 'Algoritmo header' (Get-Claim $header 'alg')
    Write-Section 'TEMPI | UTC'
    foreach ($name in @('iat','nbf','exp')) { Write-Value $name (Format-Timestamp (Get-Claim $claims $name)) }
    $issued = Get-Claim $claims 'iat'
    if ($null -ne $issued -and $null -ne $exp) {
        try { Write-Value 'Intervallo exp-iat' ('{0:N2} minuti (campione)' -f (([long]$exp - [long]$issued)/60.0)) } catch { }
    }
    Write-Status 'LIMITE' 'Decodifica diagnostica: nessuna validazione crittografica della firma.'
    Write-Status 'DA COLLAUDARE' 'Accesso alla applicazione e controlli della API sul backend.'
    if ($Mode -eq 'Analyze') { Write-Host '  La provenienza e il tipo del JWT sono quelli dichiarati dall operatore.' }
    $reportJson = $report | ConvertTo-Json -Depth 8
    if ($SaveReport) {
        $reportDirectory = Join-Path $PSScriptRoot 'risultati'
        $null = New-Item -ItemType Directory -Force -Path $reportDirectory
        $reportFile = Join-Path $reportDirectory ('ExternalId-token-{0}.json' -f [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
        $reportJson | Set-Content -LiteralPath $reportFile -Encoding UTF8
        Write-Value 'Report salvato' $reportFile
    }
    if ($ShowJson) { Write-Output $reportJson }
    if ($CopyToken) {
        Set-Clipboard -Value $token
        Write-Status 'APPUNTI' 'Token completo copiato su richiesta. Non condividerlo nelle evidenze.'
    }
}
finally {
    if ($null -ne $post) { $post.Body.Clear() }
    $token = $null; $tokenResponse = $null; $verifier = $null; $code = $null; $returnText = $null
    # Null references reduce accidental reuse; this is not guaranteed memory erasure.
}
