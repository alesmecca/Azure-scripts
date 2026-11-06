# Azure Scripts

**Raccolta personale di Alessandro Smecca** — script PowerShell per attività operative, automazione e collaudo in ambito Microsoft Entra e cloud.

La raccolta è organizzata per argomento e verrà estesa con nuovi script. È un progetto personale: non rappresenta una pubblicazione ufficiale di un'azienda o di un cliente.

## Script disponibili

| Area | Script | Cosa fa | Guida |
|---|---|---|---|
| External ID | [Test-ExternalIdToken.ps1](external-id/Test-ExternalIdToken.ps1) | Acquisisce un access token tramite Authorization Code + PKCE oppure analizza un JWT già emesso. | [Requisiti e utilizzo](external-id/README.md) |
| App registration | [New-EntraAppCertificate.ps1](app-registration/New-EntraAppCertificate.ps1) | Genera un certificato autofirmato, esporta CER/PFX e verifica i file prodotti. | [Requisiti e utilizzo](app-registration/README.md) |

## Come usare la raccolta

Scaricare il repository e aprire la guida dello script desiderato: ogni cartella contiene requisiti, comandi di avvio, parametri principali e descrizione degli output.

I dati vengono richiesti all'operatore. Prima dell'esecuzione, leggere lo script e rispettare le policy del proprio ambiente.

## Segnalazioni

Per segnalare un problema, aprire una issue indicando lo script, la versione di PowerShell, i passaggi eseguiti e il messaggio di errore. Rimuovere dai dettagli condivisi password, token, chiavi private e dati personali.

**Autore:** [Alessandro Smecca](https://github.com/alesmecca).
