# COMPACT TECNIQUE (PE & ELF)

Questo documento illustra in modo tecnico come go-super-strip effettua la compattazione dei binari (fase di "compact" -c) per i formati PE (Windows) ed ELF (Linux). La compattazione rimuove fisicamente sezioni e aree non necessarie dal file, aggiorna le intestazioni e può rifilare l'overlay. Include panoramica, criteri di sicurezza, parti di codice esemplificative e differenze tra modalità "safe" (predefinita) e "force" (più aggressiva).

Indice
- Terminologia e pipeline operativa
- Principi di sicurezza (safe vs force)
- Compact PE
  - Criteri per selezione sezioni rimuovibili
  - Protezioni (Data Directories e sezioni critiche)
  - Algoritmo di rimozione fisica e riallineamento
  - Aggiornamento header, SizeOfImage/Headers, CheckSum e overlay
  - Dettagli implementativi (codice)
- Compact ELF
  - Criteri per selezione sezioni rimuovibili e guardie
  - Rimozione fisica, aggiornamento Program Headers e SHT
  - Opzione force: rimozione/disable della Section Header Table
  - Dettagli implementativi (codice)
- Verifiche e best practices
- Esempi pratici
- Riferimenti codice


## Terminologia e pipeline operativa

Il progetto applica le operazioni in ordine rigoroso:

1) strip → 2) compact → 3) obfuscate → 4) insert/overlay → 5) regex → 6) pack (se attivato)

In questo documento trattiamo "compact" (fase 2), che rimuove fisicamente sezioni e aggiorna gli header, a differenza dello "strip" (fase 1) che si limita ad azzerare bytes in-place.

Concetti chiave:
- Strip: azzera contenuti in aree mirate senza spostare sezioni.
- Compact: elimina sezioni e ne ricostruisce le tabelle, aggiornando dimensioni/offset e talvolta rifilando il file.
- Obfuscate: modifica nomi di sezione, padding, stringhe, ecc. (non coperto qui).


## Principi di sicurezza (safe vs force)

- Safe (predefinito): rimuove soltanto sezioni chiaramente non essenziali, evitando quelle critiche per il loader/runtime. Rispetta le referenze nel PE Optional Header (Data Directories) e le sezioni chiave in ELF.
- Force (abilitato con `-c=force=true`): consente rimozioni più aggressive (es. sezioni vuote/nulle, SHT negli ELF). Rimangono attive guardie per non rompere binari dinamici o firmati.

Nota: un binario rotto sotto `force` è tollerato per policy del progetto se esistono casi in cui funziona; la modalità predefinita mira a zero regressioni.


## Compact PE

### Criteri per selezione sezioni rimuovibili

La selezione usa le stesse regole di categorizzazione del modulo di strip, tramite `perw/strip_types.go` → `GetSectionStripRule()`, ma qui le sezioni individuate vengono rimosse fisicamente.

- Categorie SAFE: DebugSections (`.debug*`, `.zdebug*`, `.stab`, `.stabstr`, …), Symbol/Build/NonEssential/Runtime (commenti, note, marker toolchain come `.go.*`, `.gnu_debuglink`, ecc.).
- Categorie RISKY (solo con `force`): ExceptionSections (`.pdata`, `.xdata`, `.eh_frame*`), RelocationSections (`.reloc`), TLSSections (`.tls`), CertificateSections (`.certificate`).
- Inoltre vengono rimossi elementi manifestamente corrotti: nomi anomali (es. `<coff_ref_`, slash), caratteri invalidi, size/offets incoerenti.
- Con `force` possono essere rimossi anche segmenti “null/zero” (sezione con size piccola e tutto 0).

Codice (estratti):
```go
// perw/compact.go
func (p *PEFile) identifyStripSections(force bool) (removable, keepable []int) {
    rules := GetSectionStripRule()
    protected := p.sectionsReferencedByDataDirectories()
    critical := p.identifyCriticalSections()
    // ... decide removable in base a regole, force e controlli di corruzione/null
}
```

### Protezioni (Data Directories e sezioni critiche)

- Data Directories: tutte le sezioni referenziate dalle DataDirectory dell’Optional Header sono marcate “keep”.
- Sezioni critiche sempre preservate: `.text/.code`, `.data/.rdata`, `.idata/.edata`, `.pdata/.xdata`, `.tls`, `.reloc`, ed ogni sezione che contiene `go.`, `runtime`, `eh_frame`, `.ctors`, `.dtors`.

```go
// perw/compact.go
func (p *PEFile) sectionsReferencedByDataDirectories() map[int]struct{} { /* scansione 16 directory, mappa RVA→sezione */ }
func (p *PEFile) identifyCriticalSections() map[int]struct{} { /* elenco sezioni imprescindibili */ }
```

### Algoritmo di rimozione fisica e riallineamento

- Le sezioni da rimuovere sono ordinate in ordine decrescente di indice per evitare problemi di shifting.
- Per ogni sezione: si calcola la size allineata a FileAlignment, si taglia lo slice `RawData`, si aggiornano gli offset delle sezioni successive.
- Si decrementa `NumberOfSections` e si ricostruisce la tabella sezioni con `VirtualSize` coerente.
- Si puliscono eventuali DataDirectory che puntavano ad aree rimosse.

```go
// perw/compact.go
for _, idx := range removableSectionIndices {
    _ = p.removeSingleSection(idx, &totalRemovedSize, fileAlignment)
}
_ = p.updateNumberOfSections(...)
newSections := p.buildNewSectionsWithCorrectVirtualSize(...)
_ = p.updateSectionTableWithNewSections(newSections)
_ = p.clearDataDirectoriesForRemovedRVAs(removedRVAs)
```

### Aggiornamento header, SizeOfImage/Headers, CheckSum e overlay

- `SizeOfImage` è ricalcolato come massimo `VirtualAddress + aligned(VirtualSize|Size)`, usando `SectionAlignment` (fallback a default se mancante).
- `SizeOfHeaders` è allineato a `FileAlignment` e calcolato sul primo offset raw di sezione o fine tabella header.
- `CheckSum` viene azzerato (binari non firmati). Se la Security Directory è vuota (nessuna Authenticode), l’overlay in coda viene rimosso.

```go
// perw/compact.go
_ = WriteAtOffset(p.RawData, sizeOfImageOff, maxEndVA)
_ = WriteAtOffset(p.RawData, sizeOfHeadersOff, sizeOfHeaders)
_ = WriteAtOffset(p.RawData, checkSumOff, uint32(0))
// se SecurityDir è 0, rifila overlay (tail > max end dei dati di sezione)
```

### Dettagli implementativi (codice)

1) Estrazione FileAlignment e rimozione di una singola sezione
```go
func (p *PEFile) extractFileAlignment() (uint32, error)
func (p *PEFile) removeSingleSection(sectionIdx int, totalRemovedSize *int64, fileAlignment uint32) error
```
2) Ricostruzione Section Table e pulizia DataDirectories
```go
func (p *PEFile) buildNewSectionsWithCorrectVirtualSize(...)
func (p *PEFile) updateSectionTableWithNewSections(newSections []Section) error
func (p *PEFile) clearDataDirectoriesForRemovedRVAs(removedRVAs map[uint32]bool) error
```


## Compact ELF

### Criteri per selezione sezioni rimuovibili e guardie

- Sezioni critiche sempre preservate: `.text`, `.data`, `.rodata`, `.bss`, `.init/.fini`, `.plt/.got(.plt)`, `.dynamic`, `.dynsym/.dynstr`, `.hash/.gnu.hash`, `.interp`, `.ctors/.dtors/.init_array/.fini_array`, `.eh_frame(_hdr)`, `.gcc_except_table`, `.gopclntab`, `.typelink`, `.itablink`, `.tdata/.tbss`.
- Esclusioni ulteriori: `.shstrtab`, `.strtab`, `.dynstr`, tipo `SHT_NOBITS` (niente dati da rimuovere).
- Rimuovibili: sezioni corrotte (offset/size fuori limiti), già vuote, già stripppate (size=0 e offset=0), sezioni “null/zero” (contenuto tutto 0, entro limite 64KB) se `force`.

```go
// elfrw/compact.go
func (e *ELFFile) identifyCompactableSections(force bool) []int { /* vedi regole sopra */ }
```

### Rimozione fisica, aggiornamento Program Headers e SHT

- Le sezioni selezionate vengono tagliate fisicamente da `RawData` con riallineamento locale; tutti gli offset successivi vengono decrementati della size rimossa.
- I Program Header (`Segments`) che si trovano dopo l’area rimossa vengono aggiornati con i nuovi offset.
- L’offset della Section Header Table (SHT) viene aggiornato se si trova dopo la rimozione; quindi la SHT viene ricostruita coerentemente.
- Eventuale overlay oltre l’ultimo segmento `PT_LOAD` viene rifilato.

```go
// elfrw/compact.go
_ = e.removeCompactSection(idx, &totalRemoved)
e.updateSections(removable)
_ = e.updateSectionHeaderTableOffset(section.Offset, removedSize)
_ = e.rebuildSectionHeaderTable()
```

### Opzione force: rimozione/disable della Section Header Table

Con `-c=force=true`, se presente, la Section Header Table può essere disabilitata (puntatori azzerati in header) e, se si trova in coda al file, fisicamente rimossa. Il loader ELF usa i Program Header, quindi l’eseguibile resta avviabile, ma strumenti che dipendono dalle sezioni (es. debugger) non avranno informazioni.

```go
// elfrw/compact.go (force)
// azzera shoff/shnum/shstrndx; se SHT è in coda: truncate fisico
e.writeAtOffset(shoffPos, uint64(0))
```

### Dettagli implementativi (codice)

1) Rimozione fisica e aggiornamento offset
```go
func (e *ELFFile) removeCompactSection(sectionIdx int, totalRemovedSize *int64) error
func (e *ELFFile) updateProgramHeaderOffsets(removedOffset, removedSize int64)
func (e *ELFFile) updateSectionHeaderTableOffset(removedOffset, removedSize int64) error
```
2) Ricostruzione SHT e contatori
```go
func (e *ELFFile) rebuildSectionHeaderTable() error
func (e *ELFFile) updateELFHeaderSectionCount(sectionCount uint16) error
```


## Verifiche e best practices

- Provare prima senza `force`; usare `-c=force=true` solo se si accetta la perdita di informazioni/strumentabilità.
- Su PE: evitare di rimuovere `.pdata/.xdata/.reloc/.tls` se non strettamente necessario; anch’esse sono marcate “risky”. Valutare l’impatto su ASLR/SEH.
- Su ELF: la rimozione della SHT sotto `force` è potente ma invasiva. Assicurarsi che gli strumenti target non richiedano le sezioni.
- Sempre verificare l’avvio dell’eseguibile e, per PE firmati, ricordare che rifilare l’overlay invalida eventuali firme se presenti (la Security Directory protegge il caso firmato).


## Esempi pratici

PE (Windows):
```powershell
# Compattazione safe
.tgosstrip.exe -c testfiles\simple_go.exe

# Compattazione aggressiva (risky)
.tgosstrip.exe -c=force=true testfiles\simple_go.exe
```

ELF (WSL/Linux):
```bash
# Compila un sample
wsl bash -lc "cd /mnt/d/Sources/go-super-strip/testfiles && gcc simple.c -o simple_elf -lm"

# Compattazione safe
go run . -c testfiles\simple_elf

# Compattazione aggressiva: può disabilitare/rimuovere SHT
go run . -c=force=true testfiles\simple_elf
```

Output atteso (estratto):
- PE: "removed N sections", "size reduced ...", "trimmed overlay ...", "updated PE headers ...".
- ELF: "removed N sections", "randomized padding in ..." (se presente), messaggi su SHT sotto force.


## Riferimenti codice
- PE: `perw/compact.go`, `perw/strip_types.go`, `perw/read.go`, `perw/write.go`
- ELF: `elfrw/compact.go`, `elfrw/strip_types.go`, `elfrw/write.go`

Note: questo documento riflette l’implementazione corrente. Eventuali modifiche future (nuove regole, nuove guardie) dovranno essere riportate qui per mantenere la documentazione allineata al comportamento del tool.
