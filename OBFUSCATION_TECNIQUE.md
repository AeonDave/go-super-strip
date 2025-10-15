# OBFUSCATION TECNIQUE (PE & ELF)

Questo documento spiega come go-super-strip applica l’offuscamento (fase "obfuscate" -o) ai binari PE (Windows) ed ELF (Linux). L’obiettivo è ridurre la riconoscibilità dei binari senza romperne il caricamento: rinomina sezioni, randomizza padding tra sezioni, modifica alcune stringhe di runtime e, per ELF, normalizza campi header non critici. Include differenze tra modalità "safe" (predefinita) e "force".

Indice
- Terminologia e pipeline operativa
- Principi di sicurezza (safe vs force)
- Obfuscation PE
  - Ridenominazione sezioni
  - Randomizzazione padding tra sezioni
  - Sostituzione stringhe runtime (a pari lunghezza)
  - (Opzionale, risky) variazione ImageBase — attualmente disabilitata
  - Dettagli implementativi (codice)
- Obfuscation ELF
  - Ridenominazione sezioni con ricostruzione SHT
  - Randomizzazione padding senza toccare i segmenti PT_LOAD
  - Offuscamento campi header riservati (EI_PAD, e_flags)
  - Sostituzione stringhe runtime (evitando .dynstr/.strtab)
  - (Opzionale, risky) randomizzazione indirizzi base/entry — attualmente disabilitata
  - Dettagli implementativi (codice)
- Verifiche e best practices
- Esempi pratici
- Riferimenti codice


## Terminologia e pipeline operativa

Il progetto applica le operazioni in ordine rigoroso:

1) strip → 2) compact → 3) obfuscate → 4) insert/overlay → 5) regex → 6) pack (se attivato)

In questo documento trattiamo "obfuscate" (fase 3), che mantiene le dimensioni/posizioni (salvo padding) e punta alla plausibilità dei metadati.

Concetti chiave:
- Obfuscation: tecniche non distruttive per confondere analisi statiche (nomi sezione, padding casuale, stringhe neutre) e ridurre fingerprint.
- Safe: non intacca elementi necessari al loader.
- Force: abilita tecniche più invasive; i percorsi attualmente rischiosi sono presenti in codice ma disabilitati di default.


## Principi di sicurezza (safe vs force)

- Safe (predefinito):
  - PE: rinomina sezioni con nomi realistici, randomizza padding tra sezioni, sostituisce alcune stringhe in `.data/.rdata` a pari lunghezza.
  - ELF: rinomina sezioni (eccetto `.shstrtab`), ricostruisce la SHT, randomizza padding evitando sovrapposizione a segmenti `PT_LOAD`, randomizza `EI_PAD` e porta `e_flags` a zero.
- Force (abilitato con `-o=force=true`):
  - Codice include funzioni per randomizzare indirizzi base (PE/ELF), potenzialmente rischiose. Al momento le invocazioni sono commentate: "disabilitate" per default per minimizzare regressioni.


## Obfuscation PE

### Ridenominazione sezioni

- Sostituisce i nomi di sezione con un set di nomi realistici (es. `.text`, `.data`, `.rdata`, `.pdata`, `.rsrc`, …). Evita duplicati scegliendo nomi non usati.
- Aggiorna sia l’header on-disk sia la struttura in memoria.

```go
// perw/obfuscate.go
func (p *PEFile) ObfuscateSectionNames() *common.OperationResult {
    realisticNames := []string{".text", ".data", ".rdata", ".pdata", ".rsrc", ".reloc", ...}
    // per ogni sezione: sceglie un nome plausibile non già usato; scrive 8 byte nel Section Header
}
```

### Randomizzazione padding tra sezioni

- Cerca gap tra fine di una sezione e inizio della successiva (entro `maxPaddingSize`), quindi li riempie con byte casuali.
- Non modifica i contenuti delle sezioni.

```go
// perw/obfuscate.go
for i := 0; i < len(p.Sections)-1; i++ {
    end := cur.Offset + cur.Size
    start := next.Offset
    if start > end && start-end < 0x10000 { copy(p.RawData[end:start], randBytes) }
}
```

### Sostituzione stringhe runtime (a pari lunghezza)

- Limita l’intervento a sezioni dati (`data`, `rdata`).
- Sostituisce pattern ben noti con equivalenti stessa lunghezza (es.: `fprintf→foutput`, `printf→output`, `WinMain→AppMain`). Le sostituzioni avvengono preferendo sequenze terminate da `\0` per sicurezza.

```go
// perw/obfuscate.go
search := []byte{'\x00','f','p','r','i','n','t','f','\x00'}
repl   := []byte{'\x00','f','o','u','t','p','u','t','\x00'}
```

### (Opzionale, risky) variazione ImageBase — attualmente disabilitata

- È presente `ObfuscateBaseAddresses()` che cambierebbe l’`ImageBase` entro range/align sicuri solo se esistono reloc (controllo `hasBaseRelocations`).
- L’invocazione è commentata in `ObfuscateAll` (quindi non attiva). Se/quando verrà abilitata, resterà marcata come rischiosa.

```go
// perw/obfuscate.go (commentato in ObfuscateAll)
// if force { if res := p.ObfuscateBaseAddresses(); res.Applied { ... } }
```

### Dettagli implementativi (codice)

- `ObfuscateAll`: orchestra le operazioni e salva il file.
- `ObfuscateSectionNames`, `ObfuscateSectionPadding`, `ObfuscateRuntimeStrings`.
- (Potenziale) `ObfuscateBaseAddresses` con guardie su reloc e range.


## Obfuscation ELF

### Ridenominazione sezioni con ricostruzione SHT

- Rinomina tutti i nomi sezione realistici tranne `.shstrtab` e quelle nulle; evita duplicati usando un set predefinito.
- Ricostruisce la Section Header Table (SHT) e aggiorna la cache dei name offsets.

```go
// elfrw/obfuscate.go
func (e *ELFFile) obfuscateSectionNames() *common.OperationResult {
    realistic := []string{".text", ".data", ".rodata", ".bss", ".dynsym", ".dynstr", ...}
    // aggiorna e.Sezioni[i].Name e poi e.rebuildSectionHeaderTable()
}
```

### Randomizzazione padding senza toccare i segmenti PT_LOAD

- Ordina le sezioni per offset e identifica i gap (< 64KB).
- Evita di toccare gap che intersecano segmenti caricabili (`PT_LOAD`).

```go
// elfrw/obfuscate.go
for ogni gap tra sezioni: se non interseca PT_LOAD, riempi con rand
```

### Offuscamento campi header riservati (EI_PAD, e_flags)

- Randomizza `e_ident[9..15]` (padding) — sicuro.
- Imposta `e_flags` a 0 (non randomizza flag CPU/OS) — sicuro.

```go
// elfrw/obfuscate.go
copy(e.RawData[9:16], rand7)
writeAtOffset(E_FLAGS, uint32(0))
```

### Sostituzione stringhe runtime (evitando .dynstr/.strtab)

- Salta `.dynstr` e `.strtab` (tabelle stringhe del linker/loader).
- Agisce su sezioni con nome che contiene `data`, `rodata` o `.str`.
- Sostituzioni a pari lunghezza; se la nuova stringa è più corta, viene padded con `\0`.

```go
// elfrw/obfuscate.go
if len(repl) < len(orig) { repl = padWithNulls(repl) } else if len(repl) > len(orig) { continue }
```

### (Opzionale, risky) randomizzazione indirizzi base/entry — attualmente disabilitata

- Presente `obfuscateBaseAddresses()` che incrementa di un offset random page-aligned `p_vaddr`, `p_paddr` dei segmenti caricabili e l’entry point (`e_entry`).
- L’invocazione è commentata in `ObfuscateAll` e rimane classificata “risky”.

```go
// elfrw/obfuscate.go (commentato in ObfuscateAll)
// if force { if res := e.obfuscateBaseAddresses(); ... }
```

### Dettagli implementativi (codice)

- `ObfuscateAll`: coordina e salva con/ senza header se necessario.
- `obfuscateSectionNames`, `obfuscateSectionPadding`, `obfuscateReservedHeaderFields`, `obfuscateRuntimeStrings`.
- (Potenziale) `obfuscateBaseAddresses` per indirizzi di segmenti ed entry.


## Verifiche e best practices

- Usare prima senza `force`; l’effetto di obfuscation dovrebbe conservare il comportamento del binario.
- Evitare di ampliare le sostituzioni stringhe a pattern sensibili a runtime.
- Per ELF, non toccare `.dynstr`/`.strtab` e mantenere `e_flags=0`.
- Se in futuro si abilita la randomizzazione di indirizzi (force), testare su più distro/loader.


## Esempi pratici

PE (Windows):
```powershell
# Obfuscation safe
.tgosstrip.exe -o testfiles\simple_go.exe

# Obfuscation con force (al momento nessuna tecnica risky attiva per default)
.tgosstrip.exe -o=force=true testfiles\simple_go.exe
```

ELF (WSL/Linux):
```bash
# Compila un sample
wsl bash -lc "cd /mnt/d/Sources/go-super-strip/testfiles && gcc simple.c -o simple_elf -lm"

# Obfuscation safe
go run . -o testfiles\simple_elf

# Obfuscation con force (indirizzi base/entry rischiosi attualmente disabilitati)
go run . -o=force=true testfiles\simple_elf
```

Output atteso (estratto):
- PE: "renamed N sections", "randomized padding in ...", "offuscati X tipi di stringhe ...".
- ELF: "renamed N sections", "randomized padding in ...", "obfuscated reserved header fields ...", "obfuscated X string patterns ...".


## Riferimenti codice
- PE: `perw/obfuscate.go`
- ELF: `elfrw/obfuscate.go`
- Comuni: `common/` (utility di random, scritture, ecc.)

Note: questo documento riflette l’implementazione corrente. Eventuali modifiche future (nuove tecniche/guardie) dovranno essere riportate qui per mantenere la documentazione allineata al comportamento del tool.
