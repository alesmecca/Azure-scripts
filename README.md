# Azure Scripts

**Raccolta personale di Alessandro Smecca** — script PowerShell per attività operative, automazione e collaudo in ambito Microsoft Entra e cloud.

La raccolta è organizzata per argomento e verrà estesa con nuovi script. È un progetto personale: non rappresenta una pubblicazione ufficiale di un'azienda o di un cliente.

## Script disponibili

| Area | Script | Cosa fa |
|---|---|---|
| External ID | [Test-ExternalIdToken.ps1](external-id/Test-ExternalIdToken.ps1) | Acquisisce un access token tramite Authorization Code + PKCE oppure analizza un JWT già emesso. |
| App registration | [New-EntraAppCertificate.ps1](app-registration/New-EntraAppCertificate.ps1) | Genera un certificato autofirmato, esporta CER/PFX e verifica i file prodotti. |

I dati richiesti vengono inseriti dall'operatore. Gli esempi sono generici e non contengono configurazioni di tenant o applicazioni del progetto.

## Requisiti e avvio

- Windows con Windows PowerShell 5.1 oppure PowerShell 7.
- Per il certificato, disponibilità dei comandi del modulo Windows PKI e accesso allo store dell'utente.
- Per acquisire token, una configurazione Entra già predisposta e accesso agli endpoint di autenticazione.

Scaricare la repository, leggere lo script e aprire PowerShell nella cartella principale. Rispettare le policy aziendali di esecuzione: non è necessario disabilitarle per usare questa raccolta.

```powershell
# Collaudo token: scelta guidata della modalità e dei parametri
.\external-id\Test-ExternalIdToken.ps1

# Certificato: nome app, validità e password richiesti a video
.\app-registration\New-EntraAppCertificate.ps1
```

L'help è disponibile anche localmente:

```powershell
Get-Help .\external-id\Test-ExternalIdToken.ps1 -Full
Get-Help .\app-registration\New-EntraAppCertificate.ps1 -Full
```

## Collaudo token External ID

**Acquire** usa il pannello **Run user flow**: selezionare client, API, redirect registrato, response type `code` e PKCE `S256`. Lo script richiede tenant, client, audience, scope e gli altri valori attesi; confronta endpoint e verifier dello stesso tentativo, quindi scambia il codice restituito dopo il login.

**Analyze** decodifica localmente un token già emesso:

```powershell
.\external-id\Test-ExternalIdToken.ps1 -Mode Analyze -TokenKind Access
.\external-id\Test-ExternalIdToken.ps1 -Mode Analyze -TokenKind Id
```

Per un ID token, l'audience attesa è il client ID dell'applicazione; per un access token è la risorsa API. La piattaforma SPA/Public deve corrispondere al redirect registrato. Lo script non supporta client Web confidential che richiedono un secret.

I risultati sono mostrati in console. `-SaveReport` salva un report selettivo nella sottocartella `risultati`; `-ShowJson` lo stampa anche come JSON; `-CopyToken` copia esplicitamente il token completo negli appunti.

**La lettura delle claim non verifica la firma del JWT e non prova l'autorizzazione sul backend.** Per completare il collaudo occorre verificare l'applicazione e le chiamate API reali, anche tramite gli strumenti di sviluppo del browser, scheda Network.

## Certificati per app registration

Lo script richiede nome applicazione, validità in mesi e password PFX con conferma. Genera RSA 2048 / SHA256 e un PFX protetto con AES256_SHA256. La password non viene stampata né salvata nel riepilogo.

```powershell
.\app-registration\New-EntraAppCertificate.ps1 -AppName nome-app -ValidityMonths 12
.\app-registration\New-EntraAppCertificate.ps1 -OutputDirectory C:\Temp\Certificati
```

La cartella predefinita è `%LOCALAPPDATA%\EntraOperations\Certificati`. Ogni esecuzione crea una sottocartella distinta e mostra percorso completo, thumbprint e date.

| Output | Utilizzo |
|---|---|
| `.cer` | Certificato pubblico da caricare nell'app registration corretta. |
| `.pfx` | Certificato con chiave privata, destinato al servizio che deve autenticarsi. |
| `Riepilogo-certificato.txt` | Metadati del certificato e percorsi dei file, senza password. |

Il certificato rimane anche nello store `Cert:\CurrentUser\My`. Lo script non crea app registration, non carica il CER in Entra e non modifica permessi. Consegnare PFX e password su canali separati e verificare compatibilità e requisiti aziendali per i certificati autofirmati.

## Segnalazioni

Per segnalare un problema, aprire una issue indicando la versione di PowerShell, i passaggi eseguiti e il messaggio di errore. Rimuovere dai dettagli condivisi password, token, chiavi private e dati personali.

**Autore:** [Alessandro Smecca](https://github.com/alesmecca).
