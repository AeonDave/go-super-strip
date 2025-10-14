# Pack Module

Il modulo `pack` fornisce funzionalità avanzate di packing eseguibili con compressione, cifratura e stub polimorfici.

## Struttura dei File

### File Principali

- **`pack.go`**: Entry point principale per le operazioni di packing
- **`config.go`**: Gestione configurazione e parsing opzioni
- **`common.go`**: Tipi e strutture comuni (PackResult, PayloadMetadata, etc.)
- **`helpers.go`**: Funzioni helper generiche (hash, serializzazione, etc.)

### Compressione e Cifratura

- **`compression.go`**: Algoritmi di compressione (XZ, LZMA, zlib)
- **`encryption.go`**: Algoritmi di cifratura (XOR, AES-256-GCM, ChaCha20-Poly1305)

### Packing per Formato

- **`pack_elf.go`**: Packer per eseguibili ELF (Linux)
- **`pack_pe.go`**: Packer per eseguibili PE (Windows)

### Stub Templates

- **`stub_template_elf.go`**: Template Go per stub ELF (self-extracting)
- **`stub_template_pe.go`**: Template Go per stub PE (self-extracting)
- **`stub_compiler.go`**: Compilazione stub e embedding metadata

### Polimorfismo

- **`polymorphic.go`**: Engine per generare stub polimorfici con hash unici

### Test

- **`config_test.go`**: Test per parsing configurazione
- **`pack_test.go`**: Test per compressione, cifratura, polimorfismo

## Utilizzo

### Opzioni Disponibili

```go
config, err := pack.ParseOptions("comp=xz,encr=chacha20,level=9,poly=true")
```

**Compressione:**
- `comp=xz` - XZ compression (default)
- `comp=lzma` - LZMA compression (raw stream)
- `comp=none` - No compression

**Cifratura:**
- `encr=xor` - XOR encryption (semplice, veloce)
- `encr=aes` - AES-256-GCM (sicuro, alias: aes-256-gcm)
- `encr=chacha20` - ChaCha20-Poly1305 (sicuro, veloce)
- `encr=none` - No encryption

**Livello Compressione:**
- `level=0` - Veloce, poca compressione
- `level=9` - Lento, massima compressione
- `level=6` - Default (bilanciato)

**Polimorfismo:**
- `poly=true` - Abilita stub polimorfico (hash unico per build)
- `poly=false` - Stub statico
- `junkdensity=0.5` - Densità junk code (0.0-1.0)

**Esecuzione:**
- `inmemory=true` - Esecuzione in-memory (memfd_create/process hollowing)
- `inmemory=false` - Esecuzione da file temporaneo (default)

**Anti-Analysis:**
- `antidebug=true` - Check anti-debug
- `antivm=true` - Check anti-VM

**Padding:**
- `padding=true` - Aggiunge padding casuale (default)
- `padding=false` - Nessun padding

**Verbose:**
- `verbose=true` - Output dettagliato

### Esempio Completo

```go
package main

import (
    "fmt"
    "gosstrip/pack"
)

func main() {
    // Parse opzioni
    config, err := pack.ParseOptions("comp=lzma,encr=chacha20,level=9,poly=true,verbose=true")
    if err != nil {
        panic(err)
    }
    
    // Valida configurazione
    if err := config.Validate(); err != nil {
        panic(err)
    }
    
    // Pack file
    result, err := pack.Pack("input.elf", config)
    if err != nil {
        panic(err)
    }
    
    fmt.Println(result.String())
}
```

## Architettura

### Flusso di Packing

1. **Lettura**: Legge il file originale
2. **Padding**: (Opzionale) Aggiunge padding casuale
3. **Compressione**: Comprime il payload
4. **Cifratura**: Cifra il payload compresso
5. **Metadata**: Crea metadata structure (algoritmi, chiavi, dimensioni)
6. **Stub Compilation**: Compila stub Go self-extracting
7. **Polimorfismo**: (Opzionale) Applica tecniche polimorfiche al binario
8. **Assembly**: Appende payload + metadata al stub
9. **Output**: Scrive il file packed finale

### Formato File Packed

```
[ Stub Binary ]
[ Encrypted Payload ]
[ Metadata (algoritmi, chiavi, nonce, etc.) ]
[ Metadata Size (8 bytes, little-endian) ]
```

Lo stub legge gli ultimi 8 bytes per determinare la dimensione del metadata, poi legge il metadata e il payload dalla fine del file.

### Stub Self-Extracting

Lo stub compilato:
1. Legge se stesso per trovare metadata e payload
2. Decifra il payload usando la chiave embedded
3. Decomprime il payload
4. Esegue il payload originale:
   - **Linux**: `memfd_create` (in-memory) o file temporaneo
   - **Windows**: Process hollowing o file temporaneo

## Test Coverage

I test coprono:
- ✅ Parsing configurazione e validazione
- ✅ Compressione/decompressione (XZ, LZMA)
- ✅ Cifratura/decifratura (XOR, AES, ChaCha20)
- ✅ Generazione stub polimorfico
- ✅ Hash unici per ogni build
- ✅ PackResult formatting

Per eseguire i test:

```bash
go test ./pack/... -v
```

## Dipendenze

- `github.com/ulikunitz/xz` - XZ/LZMA compression
- `golang.org/x/crypto/chacha20poly1305` - ChaCha20-Poly1305 encryption

## Note di Implementazione

### Polimorfismo

Il polimorfismo attuale inserisce junk code casuale nel binario per variare l'hash. Implementazioni avanzate future potrebbero includere:
- Permutazione registri a livello assembly
- Sostituzione istruzioni equivalenti
- Mutazione control flow

### In-Memory Execution

L'esecuzione in-memory è implementata come placeholder:
- **Linux**: `memfd_create` syscall per FD anonimo in memoria
- **Windows**: Process hollowing (crea processo sospeso, unmap, inject)

Per implementazioni complete, vedere:
- [goffloader](https://github.com/Praetorian-Labs/goffloader) - Manual PE mapping
- [Process-Hollowing-in-Go](https://github.com/D3Ext/Process-Hollowing-in-Go) - Process hollowing

## TODO

- [ ] Assembly-level polymorphism con capstone/keystone
- [ ] Real anti-debug/anti-VM checks
- [ ] Complete memfd_create implementation
- [ ] Complete process hollowing implementation
- [ ] Supporto ARM64/ARM32
- [ ] Obfuscation stringhe nello stub
- [ ] Code signing preservation
