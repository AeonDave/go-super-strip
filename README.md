# Go-SStrip

Go-SStrip è una riscrittura in Go del progetto sstrip (Super Strip) che rimuove stringhe e tutto il possibile da un file ELF senza influenzare l'immagine di memoria del file.

## Struttura del Progetto

Il progetto è organizzato nei seguenti file:

- `main.go`: Contiene la logica principale del programma, inclusa la gestione degli argomenti della riga di comando.
- `elfrw/read.go`: Implementa le funzioni per la lettura dei file ELF.
- `elfrw/write.go`: Implementa le funzioni per la scrittura delle intestazioni ELF modificate.
- `elfrw/strip.go`: Contiene le funzioni di stripping e altre utilità per la manipolazione dei file ELF.
- `elfrw/utils.go`: Contiene funzioni di utilità per lavorare con i file ELF.

## Funzionalità

- Rimozione di tutte le informazioni non essenziali dai file ELF eseguibili
- Opzione per rimuovere anche i byte zero finali
- Struttura modulare che permette facile espansione con nuove tecniche di stripping
- Compatibilità con Linux e potenzialmente con Windows

## Requisiti

- Go 1.20 o superiore
- La libreria `github.com/yalue/elf_reader` per la lettura dei file ELF

## Installazione

1. Clona il repository
2. Assicurati di avere Go installato
3. Installa la dipendenza: `go get github.com/yalue/elf_reader`
4. Compila il progetto: `go build -o go-sstrip`

## Utilizzo

```
go-sstrip [OPZIONI] FILE...

Opzioni:
  -z, --zeroes        Rimuove anche i byte zero finali
      --help          Mostra l'aiuto ed esce
      --version       Mostra le informazioni sulla versione ed esce
```

## Estensione

Il progetto è stato progettato per essere facilmente estendibile. Per aggiungere nuove tecniche di stripping:

1. Aggiungi nuove funzioni nel file `elfrw/strip.go`
2. Integra le nuove funzioni nel flusso principale in `main.go`

## Note sull'Implementazione

- L'implementazione utilizza la libreria `github.com/yalue/elf_reader` per la lettura dei file ELF
- La scrittura delle intestazioni ELF è gestita manualmente per garantire la massima flessibilità
- Sono state predisposte funzioni segnaposto per future estensioni (StripDebugInfo, StripSymbols, ecc.)
