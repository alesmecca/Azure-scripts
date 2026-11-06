# App registration — creazione certificati

[Indice della raccolta](../README.md) · [Script](New-EntraAppCertificate.ps1)

## Requisiti e avvio

Windows PowerShell 5.1 oppure PowerShell 7 su Windows, con i comandi del modulo Windows PKI disponibili e accesso allo store certificati dell'utente.

Aprire PowerShell in questa cartella ed eseguire:

```powershell
.\New-EntraAppCertificate.ps1
Get-Help .\New-EntraAppCertificate.ps1 -Full
```

## Certificati per app registration

Lo script richiede nome applicazione, validità in mesi e password PFX con conferma. Genera RSA 2048 / SHA256 e un PFX protetto con AES256_SHA256. La password non viene stampata né salvata nel riepilogo.

```powershell
.\New-EntraAppCertificate.ps1 -AppName nome-app -ValidityMonths 12
.\New-EntraAppCertificate.ps1 -OutputDirectory C:\Temp\Certificati
```

La cartella predefinita è `%LOCALAPPDATA%\EntraOperations\Certificati`. Ogni esecuzione crea una sottocartella distinta e mostra percorso completo, thumbprint e date.

| Output | Utilizzo |
|---|---|
| `.cer` | Certificato pubblico da caricare nell'app registration corretta. |
| `.pfx` | Certificato con chiave privata, destinato al servizio che deve autenticarsi. |
| `Riepilogo-certificato.txt` | Metadati del certificato e percorsi dei file, senza password. |

Il certificato rimane anche nello store `Cert:\CurrentUser\My`. Lo script non crea app registration, non carica il CER in Entra e non modifica permessi. Consegnare PFX e password su canali separati e verificare compatibilità e requisiti aziendali per i certificati autofirmati.
