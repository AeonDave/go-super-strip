package pack

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// PolymorphicEngine gestisce la generazione di stub polimorfici
type PolymorphicEngine struct {
	Config *PackConfig
	Seed   []byte
}

// NewPolymorphicEngine crea un nuovo engine polimorfico
func NewPolymorphicEngine(config *PackConfig) *PolymorphicEngine {
	seed := randomBytes(32)
	return &PolymorphicEngine{
		Config: config,
		Seed:   seed,
	}
}

// GenerateStub genera uno stub polimorfico
func (pe *PolymorphicEngine) GenerateStub(template *StubTemplate, payload []byte, metadata *PayloadMetadata) (*PolymorphicStub, error) {
	if !pe.Config.PolymorphicStub {
		// Nessun polimorfismo, ritorna stub base
		return pe.generateBasicStub(template, payload, metadata)
	}

	// Applica trasformazioni polimorfiche
	code := template.BaseCode
	techniques := []string{}

	// 1. Inserisci junk code
	if pe.Config.JunkCodeDensity > 0 {
		code = pe.insertJunkCode(code)
		techniques = append(techniques, "junk_code")
	}

	// 2. Permuta registri (placeholder per implementazione futura)
	if pe.Config.RegisterPermutation {
		// Richiede disassembler/assembler
		techniques = append(techniques, "register_permutation")
	}

	// 3. Muta control flow (placeholder)
	if pe.Config.ControlFlowMutation {
		techniques = append(techniques, "control_flow_mutation")
	}

	// 4. Sostituisci istruzioni (placeholder)
	if pe.Config.InstructionSubst {
		techniques = append(techniques, "instruction_substitution")
	}

	// 5. Aggiungi anti-debug checks
	if pe.Config.AntiDebug {
		code = pe.addAntiDebugChecks(code)
		techniques = append(techniques, "anti_debug")
	}

	// 6. Aggiungi anti-VM checks
	if pe.Config.AntiVM {
		code = pe.addAntiVMChecks(code)
		techniques = append(techniques, "anti_vm")
	}

	stub := &PolymorphicStub{
		Code:             code,
		EntryPointOffset: 0, // Da calcolare in base al template
		PayloadOffset:    len(code),
		MetadataOffset:   len(code) - len(metadata.EncryptionKey) - 100, // Approssimazione
		Hash:             ComputeHash(code),
		Techniques:       techniques,
	}

	return stub, nil
}

// generateBasicStub genera uno stub senza polimorfismo
func (pe *PolymorphicEngine) generateBasicStub(template *StubTemplate, payload []byte, metadata *PayloadMetadata) (*PolymorphicStub, error) {
	stub := &PolymorphicStub{
		Code:             template.BaseCode,
		EntryPointOffset: 0,
		PayloadOffset:    len(template.BaseCode),
		MetadataOffset:   len(template.BaseCode) - 100,
		Hash:             ComputeHash(template.BaseCode),
		Techniques:       []string{"basic"},
	}

	return stub, nil
}

// insertJunkCode inserisce junk code nello stub
func (pe *PolymorphicEngine) insertJunkCode(code []byte) []byte {
	// Questa è una versione semplificata
	// In produzione, si analizzerebbe il bytecode e si inserirebbe junk tra le istruzioni

	density := pe.Config.JunkCodeDensity
	if density <= 0 {
		return code
	}

	// Calcola quanti byte di junk inserire
	junkSize := int(float64(len(code)) * density)

	// Genera junk bytes casuali
	// In produzione, questi dovrebbero essere istruzioni valide ma inutili (NOP, PUSH/POP, ecc.)
	junk := randomBytes(junkSize)

	// Inserisci junk in posizioni casuali
	// Per semplicità, aggiungiamo all'inizio (in produzione, si distribuirebbe nel codice)
	result := make([]byte, 0, len(code)+len(junk))
	result = append(result, junk...)
	result = append(result, code...)

	return result
}

// addAntiDebugChecks aggiunge check anti-debug
func (pe *PolymorphicEngine) addAntiDebugChecks(code []byte) []byte {
	// Placeholder: in produzione, si aggiungerebbero check come:
	// - IsDebuggerPresent() su Windows
	// - ptrace(PTRACE_TRACEME) su Linux
	// - Check su /proc/self/status

	// Per ora, aggiungiamo solo un marker
	marker := []byte("ANTIDEBUG_PLACEHOLDER")
	return append(marker, code...)
}

// addAntiVMChecks aggiunge check anti-VM
func (pe *PolymorphicEngine) addAntiVMChecks(code []byte) []byte {
	// Placeholder: in produzione, si aggiungerebbero check come:
	// - CPUID checks per hypervisor bit
	// - Check su DMI/SMBIOS per "VMware", "VirtualBox", "QEMU"
	// - Timing attacks (RDTSC)

	// Per ora, aggiungiamo solo un marker
	marker := []byte("ANTIVM_PLACEHOLDER")
	return append(marker, code...)
}

// randomBytes genera byte casuali
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return b
}

// randomInt genera un int casuale tra 0 e max-1
func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(fmt.Sprintf("failed to generate random int: %v", err))
	}
	return int(n.Int64())
}
