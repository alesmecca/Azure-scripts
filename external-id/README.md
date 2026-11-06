# External ID — collaudo token

[Indice della raccolta](../README.md) · [Script](Test-ExternalIdToken.ps1)

## Requisiti e avvio

Windows PowerShell 5.1 oppure PowerShell 7 su Windows. Per acquisire un token servono una configurazione Entra già predisposta e accesso agli endpoint di autenticazione.

Aprire PowerShell in questa cartella ed eseguire:

```powershell
.\Test-ExternalIdToken.ps1
Get-Help .\Test-ExternalIdToken.ps1 -Full
```

## Collaudo token External ID

**Acquire** usa il pannello **Run user flow**: selezionare client, API, redirect registrato, response type `code` e PKCE `S256`. Lo script richiede tenant, client, audience, scope e gli altri valori attesi; confronta endpoint e verifier dello stesso tentativo, quindi scambia il codice restituito dopo il login.

**Analyze** decodifica localmente un token già emesso:

```powershell
.\Test-ExternalIdToken.ps1 -Mode Analyze -TokenKind Access
.\Test-ExternalIdToken.ps1 -Mode Analyze -TokenKind Id
```

Per un ID token, l'audience attesa è il client ID dell'applicazione; per un access token è la risorsa API. La piattaforma SPA/Public deve corrispondere al redirect registrato. Lo script non supporta client Web confidential che richiedono un secret.

I risultati sono mostrati in console. `-SaveReport` salva un report selettivo nella sottocartella `risultati`; `-ShowJson` lo stampa anche come JSON; `-CopyToken` copia esplicitamente il token completo negli appunti.

**La lettura delle claim non verifica la firma del JWT e non prova l'autorizzazione sul backend.** Per completare il collaudo occorre verificare l'applicazione e le chiamate API reali, anche tramite gli strumenti di sviluppo del browser, scheda Network.
