# Entra Operations Scripts

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

## Chi può modificare la repository

La repository è pubblica: chiunque può consultarla, scaricarla o creare un fork. Questo **non concede il permesso di scrivere nella repository originale**. Le pull request sono proposte: non vengono incorporate automaticamente.

La manutenzione è curata da [Alessandro Smecca (@alesmecca)](https://github.com/alesmecca). Per mantenerla personale, non concedere accesso in scrittura a terzi. Nelle repository personali, i collaboratori invitati hanno anche accesso in scrittura: controllare **Settings → Collaborators**, comprese le richieste di invito pendenti. [Permessi dei collaboratori](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository).

Un fork è una copia separata: le protezioni della repository originale non impediscono a chi la scarica di modificare la propria copia.

## Protezioni da configurare su GitHub

Queste sono istruzioni per il proprietario: la presenza del README non attiva automaticamente le impostazioni.

### 1. Proteggere il ramo principale

In **Settings → Rules → Rulesets → New branch ruleset**, creare due regole attive sul ramo `main`:

| Ruleset | Impostazioni | Bypass |
|---|---|---|
| `main-integrity` | **Restrict deletions**, **Block force pushes** | Nessuno: impedisce anche al proprietario le operazioni accidentali finché la regola è attiva. |
| `main-maintainer` | **Restrict updates** | **Repository admin**, modalità **Always**: il proprietario mantiene la possibilità di aggiornare gli script. |

Impostare **Enforcement status: Active** e verificare il ramo selezionato prima di salvare. Controllare chi dispone effettivamente dei privilegi admin/bypass, comprese eventuali GitHub Apps. Le regole sono modificabili da chi ha i privilegi amministrativi e non proteggono da un account amministratore compromesso.

I branch ruleset sono disponibili anche sulle repository pubbliche con GitHub Free. Non imporre approvazioni di altri revisori se la raccolta viene mantenuta da una sola persona. [Creazione dei ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository), [significato delle regole](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

### 2. Proteggere l'account e le integrazioni

- Abilitare l'autenticazione a due fattori nelle impostazioni dell'account e conservare i codici di recupero fuori dalla repository.
- Rivedere periodicamente token, chiavi SSH, applicazioni autorizzate e **Settings → Deploy keys**. Concedere soltanto gli accessi necessari e revocare quelli non più utilizzati.
- Se non vengono utilizzati workflow, disabilitare GitHub Actions da **Settings → Actions → General**. Se in futuro verranno introdotti, mantenere i permessi del workflow in sola lettura salvo necessità specifiche e non eseguire codice di contributori esterni con credenziali privilegiate.

### 3. Evitare la pubblicazione di credenziali

Controllare **Settings → Advanced Security** e le opzioni disponibili per **Secret scanning** e **Push protection**. Verificare anche la protezione personale in **Account Settings → Code security → Push protection for yourself**.

Questi controlli riconoscono determinati tipi di segreti: non rilevano ogni password, dato cliente o informazione riservata. Occorre sempre leggere le modifiche prima di pubblicarle. [Impostazioni di sicurezza della repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-security-and-analysis-settings-for-your-repository), [push protection personale](https://docs.github.com/en/code-security/how-tos/secure-your-secrets/prevent-future-leaks/manage-user-push-protection).

## File da mantenere soltanto sul PC

Non pubblicare credenziali, chiavi private, PFX, token completi, URL di ritorno contenenti codici di autorizzazione, report reali o screenshot con dati riservati. La console può mostrare identificativi di tenant/app, profili e percorsi locali: rivederli prima di condividerli.

Per mantenere le esclusioni soltanto sul PC, aggiungere questi pattern al file **`.git/info/exclude`** della propria copia:

```gitignore
*.pfx
*.p12
*.pem
*.key
*.cer
*.crt
*.p7b
*.p7c
.env
.env.*
Riepilogo-certificato.txt
risultati/
*.log
*.zip
*.tmp
```

La repository non pubblica un file `.gitignore`: questa è una scelta organizzativa. **Le esclusioni locali non vengono trasferite con il clone**, non proteggono i caricamenti via browser e non rimuovono file già tracciati o presenti nella cronologia. Chi scarica la raccolta deve impostarle nella propria copia. [Documentazione Git sulle esclusioni](https://git-scm.com/docs/gitignore).

Se viene pubblicata una credenziale reale, revocarla o ruotarla subito: cancellare il file con un nuovo commit non la rimuove dai commit precedenti. La riscrittura della cronologia non elimina eventuali copie già scaricate. [Procedura GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).

## Aggiungere nuovi script

1. Usare una cartella che descriva l'argomento e un nome PowerShell chiaro, ad esempio `Get-…`, `Test-…` o `New-…`.
2. Inserire una breve guida nello script con scopo, requisiti, parametri, output e modifiche eventualmente effettuate.
3. Richiedere i dati all'operatore; utilizzare esempi sintetici e password con input nascosto. Non inserire nomi, indirizzi o identificativi reali del cliente nel codice.
4. Verificare lo script in un ambiente di collaudo e aggiornare la tabella iniziale del README.
5. Aggiungere esplicitamente soltanto i file da pubblicare e controllare il contenuto del commit.

```powershell
git status --short
git add -- percorso/Nuovo-Script.ps1 README.md
git diff --cached --stat
git diff --cached
git commit -m "Aggiunge nuovo script"
git push origin main
```

Il percorso nell'esempio è un segnaposto. Non includere le cartelle di output. Una nuova modifica crea un nuovo commit: la cronologia crescerà normalmente, mantenendo come origine il commit iniziale della repository ricreata.

## Segnalazioni e manutenzione

Per problemi funzionali, aprire una issue con versione PowerShell, passaggi per riprodurre il problema ed errore anonimizzato. Non allegare credenziali o token. Le modifiche proposte restano soggette alla valutazione del manutentore.

Se è disponibile **Security → Report a vulnerability**, usare il canale privato per le vulnerabilità. Non pubblicare nelle issue dettagli riservati. Questa raccolta non costituisce un servizio di assistenza aziendale.

**Manutentore:** [Alessandro Smecca](https://github.com/alesmecca). Nessuna licenza di riutilizzo specifica è stata aggiunta al progetto.
