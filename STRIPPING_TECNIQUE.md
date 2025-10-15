# STRIPPING TECNIQUE (PE & ELF)

Questo documento illustra in modo tecnico come go-super-strip effettua lo stripping (pulizia dei binari) per i formati PE (Windows) ed ELF (Linux). Include panoramica, criteri di sicurezza, parti di codice esemplificative e differenze tra modalità "safe" (predefinita) e "force" (più aggressiva).

Indice
- Terminologia e pipeline operativa
- Principi di sicurezza (safe vs force)
- Stripping PE
  - Regole di corrispondenza sezioni
  - Stripping di header e directory
  - Stripping per pattern (regex)
  - Dettagli implementativi (codice)
- Stripping ELF
  - Regole di corrispondenza sezioni e guardie per binari dinamici/PIE
  - Stripping degli header e Note/PT_NOTE
  - Stripping per pattern (regex)
  - Dettagli implementativi (codice)
- Verifiche e best practices
- Esempi pratici di utilizzo


## Terminologia e pipeline operativa

Il progetto applica le operazioni in ordine rigoroso:

1) strip → 2) compact → 3) obfuscate → 4) insert/overlay → 5) regex → 6) pack (se attivato)

In questo documento trattiamo "strip" (fase 1), che azzera contenuti superflui o sensibili senza rimuovere fisicamente le entry dal Section Table (quello è compito di "compact").

Concetti chiave:
- Strip (fase 1): azzera bytes in place in sezioni/aree mirate (ZeroFill o RandomFill). Non sposta le sezioni.
- Compact (fase 2): rimuove fisicamente intere sezioni e aggiorna intestazioni/tabelle.
- Obfuscate (fase 3): rinomina sezioni, randomizza padding, modifica stringhe con sostituzioni a pari lunghezza, ecc.


## Principi di sicurezza (safe vs force)

- Safe (predefinito): limita lo stripping a contenuti di debug, simboli, metadati e campi non essenziali. Evita elementi critici per il loader o il runtime.
- Force (abilitato con `-s=force=true`): consente operazioni più invasive (es. rimozione eccezioni/reloc in alcuni casi per PE; su ELF solo ciò che non compromette il runtime dinamico). I percorsi pericolosi sono sempre protetti da guardie contestuali.

Nota: un binario rotto sotto `force` è tollerato per policy del progetto solo se esistono casi in cui funziona; lo stripping di default mira a zero regressioni.


## Stripping PE

### Regole di corrispondenza sezioni

Le regole sono definite in `perw/strip_types.go` (funzione `GetSectionStripRule`). Macro-categorie:
- DebugSections: `.debug*`, `.zdebug*`, `.stab`, `.stabstr`, `.gnu.debuglto_` (safe)
- SymbolSections: tabelle simboli e stringhe (safe). NB: il tool effettua "self-heal" del COFF se serve (vedi sotto).
- NonEssentialSections: `.comment`, `.note*`, `.drectve`, `.shared`, `.sxdata`, `.gnu_debuglink`, ecc. (safe)
- BuildInfoSections: marker toolchain (Go/Rust/C++), prefissi `.go.`/`.gopkg.` ecc. (safe)
- ExceptionSections: `.pdata`, `.xdata`, prefissi `.eh_frame` (risky; per default non applicate)
- RelocationSections: `.reloc` (risky)
- TLSSections: `.tls` (risky)
- CertificateSections: `.certificate` (risky; directory Security gestita separatamente)

Il flag `force` abilita le regole marcate "risky" solo quando esplicitamente richiesto. Inoltre vengono applicate valutazioni "shouldStripForFileType" per distinguere EXE/DLL.

### Stripping di header e directory

Implementato in `perw/strip.go`:
- Header DOS: azzeramento dei campi riservati (offset 0x1C..e_lfanew-1)
- COFF TimeDateStamp: azzerato (evita fingerprint temporali)
- Rich Header: identificato (DanS..Rich) e azzerato quando presente
- Data Directories (se presenti):
  - Debug Directory: azzera offset/size nell’Optional Header
  - Resource Dir: azzera timestamp/version del root directory
  - Load Config Dir: azzera timestamp/version minimi

Tutti gli azzeramenti sono bounds-checked.

### Stripping per pattern (regex)

Regole in `perw/strip_types.go` → `GetRegexStripRules()`:
- Marker build Go (Go build ID, go1.x, percorsi mod golang), GCC/MinGW, C++, Rust, .NET PDB/sorgenti, user/host, metadati build, firme packer note, path sorgenti, info linker.
- Ogni pattern viene cercato sezione per sezione e azzerato a pari lunghezza.

### Dettagli implementativi (codice)

1) Riempimento regioni (ZeroFill/RandomFill)
```go
// perw/strip.go
func (p *PEFile) fillRegion(offset int64, size int, mode FillMode) error {
    if offset < 0 || size <= 0 || offset+int64(size) > int64(len(p.RawData)) {
        return fmt.Errorf("invalid region")
    }
    region := p.RawData[offset:offset+int64(size)]
    switch mode {
    case ZeroFill:
        common.ZeroFillData(region)
    case RandomFill:
        _ = common.RandomFillData(region)
    }
    return nil
}
```

2) Stripping per regex
```go
// perw/strip.go
func (p *PEFile) StripByPattern(pattern *regexp.Regexp, fillMode FillMode) (int, error) {
    total := 0
    for _, sec := range p.Sections {
        if sec.Offset <= 0 || sec.Size <= 0 { continue }
        data := p.RawData[sec.Offset:sec.Offset+sec.Size]
        for _, m := range pattern.FindAllIndex(data, -1) {
            start, end := m[0], m[1]
            _ = p.fillRegion(sec.Offset+int64(start), end-start, fillMode)
            total++
        }
    }
    return total, nil
}
```

3) Self-heal COFF dopo stripping della .symtab
```go
// perw/strip.go
func (p *PEFile) fixCOFFHeaderAfterStripping() error {
    // Se PointerToSymbolTable/NumberOfSymbols puntano a una string table incongruente,
    // azzera i due campi per prevenire errori dei parser.
    // (Calcolo di stringTableOffset e verifica size)
    // ... se corrotto → WriteAtOffset(..., 0)
    return nil
}
```

4) Esempio: RVA → offset fisico (usato per Export/Dirs)
```go
func (p *PEFile) rvaToPhysical(rva uint64) (uint64, error) {
    for _, s := range p.Sections {
        if rva >= uint64(s.VirtualAddress) && rva < uint64(s.VirtualAddress+s.VirtualSize) {
            return uint64(s.Offset) + (rva - uint64(s.VirtualAddress)), nil
        }
    }
    return 0, fmt.Errorf("RVA not found")
}
```


## Stripping ELF

### Regole sezioni e guardie per dinamici/PIE

Definite in `elfrw/strip_types.go` + `elfrw/strip.go`:
- DebugSections: `.debug*`, `.zdebug*` (safe)
- SymbolSections: `.symtab`, `.strtab` (safe per eseguibili; conservate per SO)
- NonEssentialSections: `.comment`, `.note.*`, `.gnu_debuglink`, `.gnu_debugaltlink` (safe)
- ExceptionSections (risky): `.eh_frame`, `.eh_frame_hdr`, `.gcc_except_table`
- RelocationSections (risky): prefissi `.rel.` e `.rela.`
- TLSSections (risky): `.tdata`, `.tbss` (in genere preservate)
- RuntimeSections: `.rust*`, `.llvm*`, ecc. (safe)

Guardia fondamentale: per binari dinamici/PIE (presenza PT_DYNAMIC o PT_INTERP) le sezioni di relocation (`.rel*`, `.rela*`) NON vengono stripppate anche con `force`. Questo evita crash in ld.so.

```go
// elfrw/strip.go
if sectionType == RelocationSections && (e.isDynamic || e.hasInterpreter) {
    return common.NewSkipped("relocation sections are required for dynamically linked binaries; skipping")
}
```

### Stripping degli header e PT_NOTE

In `elfrw/strip.go`:
- ELF Header: azzeramento campi non critici (e_flags → 0, e_ident[ABI version], EI_PAD 9..15) — sicuro
- Program Headers: per `PT_NOTE` con contenuto, azzera i bytes (rimozione timestamp/metadata)

```go
// e_flags a zero e padding randomizzato
if e.Is64Bit { flagsOffset = ELF64_E_FLAGS } else { flagsOffset = ELF32_E_FLAGS }
_ = e.writeAtOffset(flagsOffset, uint32(0))
// EI_PAD (9..15)
rand := make([]byte, 7); copy(e.RawData[9:16], rand)
```

### Stripping per pattern (regex)

Analoghe regole PE in `common` vengono applicate sezione-per-sezione (o all’intero file se privo di sezioni). Sostituzioni a pari lunghezza con ZeroFill/RandomFill.

```go
// elfrw/strip.go
func (e *ELFFile) StripByteRegex(pattern *regexp.Regexp, useRandom bool) (int, error) {
    total := 0
    for _, sec := range e.Sections {
        if sec.Offset <= 0 || sec.Size <= 0 { continue }
        base := uint64(sec.Offset)
        data := e.RawData[base: base+uint64(sec.Size)]
        for _, m := range pattern.FindAllIndex(data, -1) {
            start, end := m[0], m[1]
            _ = e.fillRegion(base+uint64(start), end-start, useRandom)
            total++
        }
    }
    return total, nil
}
```

### Dettagli implementativi (codice)

1) Riempimento regioni in ELF
```go
func (e *ELFFile) fillRegion(offset uint64, size int, useRandom bool) error {
    if offset+uint64(size) > uint64(len(e.RawData)) { return fmt.Errorf("OOB") }
    if useRandom {
        b := make([]byte, size); _, _ = rand.Read(b); copy(e.RawData[offset:offset+uint64(size)], b)
    } else {
        copy(e.RawData[offset:offset+uint64(size)], make([]byte, size))
    }
    return nil
}
```

2) Aggiornamento headers di sezione dopo stripping
```go
// elfrw/strip.go → updateSectionHeaders()
// Scrive nei Section Headers i nuovi Offset/Size delle sezioni con size=0
```


## Verifiche e best practices

- Sempre provare prima senza `force`. Usare `-s=force=true` solo quando si accetta il rischio.
- Per ELF dinamici/PIE non rimuovere relocazioni: la guardia è già implementata.
- Per PE, la rimozione di `.pdata/.xdata/.reloc` è classificata "risky" e normalmente sconsigliata. È preferibile lasciare tali operazioni a `strip` (zeroing) e non a `compact`.
- Regex: i pattern sono pensati per metadati. Se un binario Go dovesse andare in panic dopo regex aggressive, limitare i pattern alla modalità `force` o escludere regioni sensibili.


## Esempi pratici

PE (Windows):
```powershell
# Stripping safe
.\tgosstrip.exe -s testfiles\simple_go.exe

# Stripping aggressivo (risky)
.\tgosstrip.exe -s=force=true testfiles\simple_go.exe
```

ELF (WSL/Linux):
```bash
# Compila un sample
wsl bash -lc "cd /mnt/d/Sources/go-super-strip/testfiles && gcc simple.c -o simple_elf -lm"

# Stripping safe
go run . -s testfiles\simple_elf

# Stripping aggressivo (mantiene relocation se dinamico/PIE)
go run . -s=force=true testfiles\simple_elf
```

Output atteso (estratto):
- PE: blocco "SECTIONS STRIPPED" con conteggio, "Header strip completed" e regex applicate.
- ELF: "ELF strip completed: N bytes processed", dettagli per SECTIONS/PATTERNS/OTHER.


## Riferimenti codice
- PE: `perw/strip.go`, `perw/strip_types.go`, `perw/read.go` (self-heal COFF)
- ELF: `elfrw/strip.go`, `elfrw/strip_types.go`, `elfrw/write.go`
- Regex comuni: `common/string_filter.go`, `perw/strip_types.go`


Note: questo documento riflette l’implementazione corrente. Eventuali modifiche future (es. nuovi pattern o guardie) dovranno essere riportate qui per mantenere la documentazione allineata al comportamento del tool.