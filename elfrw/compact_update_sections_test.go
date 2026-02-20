package elfrw

import "testing"

func TestELFCompact_updateSections_RemapLinkAndInfo(t *testing.T) {
	e := &ELFFile{}
	e.Sections = []Section{
		{Name: "", Type: SHT_NULL, Index: 0},
		{Name: ".note.gnu.build-id", Type: SHT_NOTE, Index: 1},
		{Name: ".dynsym", Type: SHT_DYNSYM, Index: 2},
		{Name: ".dynstr", Type: SHT_STRTAB, Index: 3},
		// Relocation section that links to .dynsym and targets (.plt) via sh_info.
		{Name: ".rela.plt", Type: SHT_RELA, Index: 4, Link: 2, Info: 5},
		{Name: ".plt", Type: SHT_PROGBITS, Index: 5},
	}

	// Remove only the .note.* section. This shifts indices down by 1 for all later sections.
	e.updateSections([]int{1})

	if got, want := len(e.Sections), 5; got != want {
		t.Fatalf("unexpected section count: got %d want %d", got, want)
	}

	// After removal, expected old→new mapping:
	// 0→0, 2→1 (.dynsym), 3→2 (.dynstr), 4→3 (.rela.plt), 5→4 (.plt)
	var dynsym, relaplt, plt Section
	for _, s := range e.Sections {
		switch s.Name {
		case ".dynsym":
			dynsym = s
		case ".rela.plt":
			relaplt = s
		case ".plt":
			plt = s
		}
	}

	if dynsym.Name != ".dynsym" {
		t.Fatalf(".dynsym missing after update")
	}
	if got, want := dynsym.Index, 1; got != want {
		t.Fatalf(".dynsym index not updated: got %d want %d", got, want)
	}

	if relaplt.Name != ".rela.plt" {
		t.Fatalf(".rela.plt missing after update")
	}
	if got, want := relaplt.Index, 3; got != want {
		t.Fatalf(".rela.plt index not updated: got %d want %d", got, want)
	}
	if got, want := relaplt.Link, uint32(1); got != want {
		t.Fatalf(".rela.plt sh_link not remapped: got %d want %d", got, want)
	}
	if got, want := relaplt.Info, uint32(4); got != want {
		t.Fatalf(".rela.plt sh_info not remapped: got %d want %d", got, want)
	}

	if plt.Name != ".plt" {
		t.Fatalf(".plt missing after update")
	}
	if got, want := plt.Index, 4; got != want {
		t.Fatalf(".plt index not updated: got %d want %d", got, want)
	}
}
