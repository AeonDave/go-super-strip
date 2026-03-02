# Research: go-super-strip vs State-of-the-Art — AV/EDR Stealth Analysis

> **Date**: 2025-07  
> **Scope**: Compare go-super-strip strip/obfuscate/compact techniques with sstrip, Astral-PE, ELF-Toolchain (IdanRosenzweig), RelocBonus. Identify what raises AV/EDR flags, what has no real benefit, and what should be improved.

---

## 1. External Tool Summary

### 1.1 sstrip (ELFkickers — Brian Raiter)
**Approach**: Minimalist. Truncates ELF file beyond last loaded segment, removing section header table and all non-runtime content.

| Technique | Detail |
|-----------|--------|
| Section header table removal | Truncates file at end of last PT_LOAD |
| Trailing zero strip | Optional `-z`, can break ELFs |
| No obfuscation | Zero mutation of remaining data |

**Key Insight**: sstrip produces **valid, canonical-looking** binaries. They just lack optional metadata. This is **not suspicious** because `strip -s` is a standard deployment practice.

### 1.2 Astral-PE (DosX-dev)
**Approach**: Surgical metadata mutator. Does NOT pack/encrypt. Rewrites structural PE metadata post-compilation.

| Technique | Detail | AV Impact |
|-----------|--------|-----------|
| **Timestamp** | Zeroed (not randomized) | SAFE — Zeroed timestamp is common in release builds |
| **Rich Header** | Fully removed (zeroed) | SAFE — Breaks toolchain fingerprinting without raising flags |
| **Section Names** | **Wiped to NULL** (not renamed) | NUANCED — Null names are suspicious but used by legitimate protectors |
| **Checksum** | Reset to zero | SAFE — Most PE files already have zero checksum |
| **Import Table** | DLL names mutated: case randomization + `./` path prefix | CLEVER — Windows loader is case-insensitive; `./ prefix is valid |
| **Export Table** | **Faked if absent** — baits certain scanners | AGGRESSIVE — Could attract attention |
| **Permissions** | R/W/X applied to ALL sections | **HIGH RISK** — RWX sections are a major AV/EDR heuristic |
| **DOS Stub** | Reset to clean MZ, patched e_lfanew | SAFE — Clean DOS stub is normal |
| **Entry Point** | Prologue shuffle/redirect | MODERATE — Changes EP without adding suspicious instructions |
| **Debug Info** | PDB paths wiped, Debug Directory erased | SAFE — Release builds often lack debug info |
| **Relocations** | Removed if unused | SAFE — Standard optimization |
| **Load Config** | Deleted if CFG not present | SAFE — Many bins lack Load Config |
| **Subsystem Version** | Set to zero | NUANCED — Uncommon but not flagged by most AV |

### 1.3 IdanRosenzweig/ELF-Toolchain
**Approach**: Aggressive packer/obfuscator. Produces **INVALID** ELFs that require custom loader.

| Technique | Detail |
|-----------|--------|
| Strip | Keep only PT_LOAD + PT_GNU_STACK + SHT_STRTAB/SHT_SYMTAB. Removes everything else |
| Obfuscate | `random_shuffle(segments)` — literally just shuffles segment order |
| Pack | Encrypt + compress + custom loader (most value comes from the loader idea) |

**Key Insight**: This is an **academic/malware research** tool. Its outputs don't work with standard OS loaders. **Not a model for stealth**.

### 1.4 RelocBonus (Nick Cano — DEF CON 26)
**Approach**: Weaponize Windows Loader's relocation mechanism as a decryption engine.

| Technique | Detail |
|-----------|--------|
| ASLR Preselection | Force specific ImageBase (0x10000 or 0xFFFF0000) |
| Content mangling | XOR/subtract entire binary content with relocation delta |
| Relocation table rebuild | Generate new .reloc table that "fixes" mangled bytes on load |
| Result | File on disk is garbled, becomes valid in memory after loader applies relocations |

**Key Insight**: Brilliant anti-static-analysis. **Not applicable to our tool** — this is a packer technique, not a stripping/metadata technique. It requires ASLR manipulation which is itself flaggable.

---

## 2. AV/EDR Detection Heuristics (Research Findings)

### 2.1 Static Analysis Indicators (Used by AV Signature Engines)

| Indicator | Weight | Source |
|-----------|--------|--------|
| **Unknown/unusual section names** | HIGH | Academic papers: "section names not in standard list + not in known packer list → suspicious" |
| **Null/empty section names** | MEDIUM | Some scanners flag, others ignore. Astral-PE does this anyway. |
| **Section names with non-printable chars** | HIGH | Clear packing indicator |
| **Sections with RWX permissions** | HIGH | Top heuristic for packed/injected code |
| **High entropy in .text section** (>7.0) | HIGH | Indicates packed/encrypted code |
| **Missing Rich Header** | LOW | ~80% of packers keep Rich Header. Missing ≠ malicious, but noted |
| **Random/unrealistic timestamps** | MEDIUM | Timestamps far in future or with impossible values stand out |
| **Zeroed timestamps** | LOW | Common in legitimate release builds |
| **Entry point in last section** | HIGH | Classic packer indicator |
| **Entry point not in .text** | MEDIUM | Unusual for normal compilers |
| **Minimal imports (only LoadLibrary/GetProcAddress)** | HIGH | Packed loader signature |
| **Import table descriptor shuffle** | LOW-MEDIUM | Unusual ordering can be noted |
| **Debug directory present but with invalid data** | MEDIUM | Fake RSDS records are detectable |
| **File size anomalies (VirtualSize >> SizeOfRawData)** | MEDIUM | Packing indicator |
| **ImageBase at unusual address** | MEDIUM | Standard is 0x400000 (EXE) or 0x10000000 (DLL) |

### 2.2 ELF-Specific Heuristics

| Indicator | Weight |
|-----------|--------|
| **Missing section header table** | LOW | sstrip does this; many deployed binaries lack it |
| **e_shoff = 0 with non-zero e_shnum** | MEDIUM | Inconsistency = tampering |
| **Random hex section names** (e.g., `.sec0a1b2c`) | HIGH | No real toolchain produces these |
| **Randomized EI_PAD bytes** (e_ident[9:16]) | MEDIUM | Standard tools zero these |
| **PT_LOAD segments in reverse order** | MEDIUM | No compiler does this |
| **Random physical addresses on segments** | LOW | p_paddr is ignored on most systems |
| **Altered load alignment** | MEDIUM | If alignment breaks congruence rules |

### 2.3 ML/Behavioral Indicators

Modern AV/EDR extracts 500+ features from PE headers. Key features include:
- Section count, entropy per section, section name encoding
- Import count, import hash (ImpHash), API categories
- Rich Header presence/content
- Header field distributions (compared to training data from millions of samples)
- File size vs code size ratio

---

## 3. go-super-strip Technique-by-Technique Audit

### 3.1 PE Strip (`perw/strip.go`, `strip_types.go`)

| Technique | Our Approach | Assessment | Recommendation |
|-----------|-------------|------------|----------------|
| **Section stripping** | Remove by type (debug/symbol/buildinfo etc.) | ✅ GOOD — Matches what `strip` does | KEEP |
| **Rich Header removal** | Zero the DanS..Rich region | ✅ GOOD — Breaks toolchain fingerprinting. Astral-PE does the same | KEEP |
| **TimeDateStamp** | Zero the COFF timestamp | ✅ GOOD — Zeroed is standard for release builds. Astral-PE does the same | KEEP |
| **DOS reserved fields** | Zero bytes 0x1C to e_lfanew | ✅ GOOD — Clean, standard | KEEP |
| **Secondary timestamps** | Regex match `19xx`/`20xx` in .rsrc/.data/.rdata | ⚠️ RISKY — Too broad. Will match version strings, copyright notices, addresses containing "2024" | **IMPROVE**: Only match actual timestamp structures (32-bit epoch values), not ASCII year patterns |
| **Debug Directory** | Zero the directory entry | ✅ GOOD | KEEP |
| **Load Config Directory** | Strip entirely | ⚠️ CAUTION — Load Config contains CFG data on modern binaries | **IMPROVE**: Only strip if CFG/RF_GUARD not enabled (like Astral-PE) |
| **Regex patterns** | Large set targeting Go/GCC/C++/Rust/.NET/packer signatures | ⚠️ MIXED — Good for cleaning build fingerprints, but some patterns are too aggressive | **REVIEW**: See §3.4 |

### 3.2 PE Obfuscation (`perw/obfuscate.go`)

| Technique | Our Approach | Assessment | Recommendation |
|-----------|-------------|------------|----------------|
| **Section name obfuscation** | Replace with names from 34-name pool (.text, .data, .pdata etc.) | ⚠️ FINGERPRINT RISK — Fixed pool → all binaries look similar. Renaming .rsrc to .pdata is suspicious when section characteristics don't match | **CHANGE**: Follow Astral-PE: **wipe to NULL** or **keep original names**. If renaming, only rename non-essential names and match real characteristics |
| **Section padding fill** | Fill inter-section gaps with random bytes | ✅ GOOD — Prevents data leaks. Natural approach | KEEP |
| **Runtime string replacement** | `fprintf→foutput`, `printf→output`, `WinMain→AppMain`, etc. (6 pairs) | ❌ WEAK — Too few replacements, predictable substitutions, easy to detect pattern "foutput" as signature of go-super-strip | **REMOVE or IMPROVE**: Either expand massively or remove entirely. Zeroing is better than replacing with detectable strings |
| **Header metadata randomization** | Random linker version (0-255), random timestamp | ❌ **AV FLAG** — Linker version 237.42 doesn't correspond to any real toolchain. AV ML models train on field distributions. Random = statistical outlier | **CHANGE**: Use realistic values. Set linker version to common MSVC versions (14.0, 14.29, 14.38). Astral-PE **zeroes** linker version info instead |
| **Subsystem/DLL characteristics mutation** (force) | Randomize subsystem, DLL characteristics | ❌ **HIGH RISK** — Changing subsystem from GUI to Console or vice versa breaks execution or is immediately suspicious | **REMOVE** — No benefit, high breakage risk |
| **Import table descriptor shuffle** | Shuffle IMAGE_IMPORT_DESCRIPTOR order | ⚠️ LOW VALUE — Descriptor order doesn't affect execution, but most tools sort alphabetically. Unusual ordering noted by some analyzers | **KEEP but LOW PRIORITY** — Minimal risk, minimal benefit |
| **Import thunk shuffle** (force) | Shuffle thunk entries within a descriptor | ❌ **DANGEROUS** — Can break ordinal-bound imports, and reordering function pointers within a descriptor is extremely suspicious to IAT analysis | **REMOVE** — Too risky, marginal benefit |
| **Executable padding (NOP patterns)** | Replace zero runs in .text with multi-byte NOPs | ⚠️ MIXED — NOP slides are a classic shellcode indicator, but multi-byte NOPs (0F 1F xx) mimic compiler alignment padding | **IMPROVE**: Only use compiler-realistic NOP patterns (66 90, 0F 1F 44 00 00). Avoid 0x90 slides >4 bytes. Limit to inter-function alignment regions |
| **Debug directory noise injection** (force) | Append fake CodeView RSDS record with random GUID | ❌ **AV FLAG** — Adding data beyond PE sections, creating debug entries with fake PDB paths. AV checks RSDS GUID consistency | **REMOVE** — Adds detectable anomaly with zero stealth benefit |
| **ImageBase mutation** | Small random offset to ImageBase (only with relocations) | ⚠️ MIXED — If relocations exist, this works. But unusual ImageBase values (not 0x400000/0x10000000) are noted by ML classifiers | **IMPROVE**: Only use standard ImageBase values (0x400000, 0x10000000, 0x180000000) or shift by page-aligned amounts |

### 3.3 PE Compact (`perw/compact.go`)

| Technique | Our Approach | Assessment | Recommendation |
|-----------|-------------|------------|----------------|
| **Section removal** | Remove non-critical sections, protect runtime-essential ones | ✅ GOOD — Well-implemented with critical section protection | KEEP |
| **Restore timestamp** | Restore original timestamp after compact | ✅ GOOD — Prevents compact from introducing anomalies | KEEP |
| **Header scrub** (force) | Zero various header fields | ⚠️ CAUTION — In force mode only, acceptable | KEEP with CAUTION |
| **Overlay trim** (force) | Trim overlay data | ✅ FIXED — Previously broke Go binaries, now gated behind force | KEEP as-is |

### 3.4 Regex Strip Rules (`perw/strip_types.go`, `elfrw/strip_types.go`)

| Rule Category | Assessment | Recommendation |
|---------------|------------|----------------|
| **Go markers** (go1.xx, GOROOT) | ✅ GOOD — Removes compiler fingerprint | KEEP |
| **GCC/MinGW markers** | ✅ GOOD | KEEP |
| **C++ markers** (demangled names) | ✅ GOOD | KEEP |
| **Rust markers** | ✅ GOOD | KEEP |
| **.NET/C# PDB paths** | ✅ GOOD | KEEP |
| **User/Host identifiers** | ✅ GOOD — Critical for operational security | KEEP |
| **Build metadata** | ⚠️ BROAD — `version [0-9]+\.[0-9]+\.[0-9]+` matches too many things including resources, DLL version info, config files | **NARROW**: Restrict to known build string contexts, skip .rsrc section |
| **Packer signatures** | ⚠️ COUNTERPRODUCTIVE — Removing UPX/VMProtect signatures can break the packer's internal unpacking logic | **IMPROVE**: Only strip packer signatures if confirmed binary is NOT currently packed (check if IsPacked flag is set) |

### 3.5 ELF Strip (`elfrw/strip.go`)

| Technique | Assessment | Recommendation |
|-----------|------------|----------------|
| **Section stripping** | ✅ GOOD — Same approach as sstrip | KEEP |
| **Protected string tables** | ✅ GOOD — Snapshot/restore mechanism | KEEP |
| **Regex byte stripping** | ✅ GOOD with protected ranges | KEEP |

### 3.6 ELF Obfuscation (`elfrw/obfuscate.go`)

| Technique | Our Approach | Assessment | Recommendation |
|-----------|-------------|------------|----------------|
| **Section name obfuscation** | Generate `.sec0a1b2c` hex names | ❌ **AV FLAG** — No real toolchain produces hex-randomized section names. Immediate indicator of tampering | **CHANGE**: **Zero section names** (write null bytes) or use standard names. sstrip removes section headers entirely — zeroed names in surviving headers is more plausible |
| **Section padding fill** | Fill gaps with random data, skip loadable segment gaps | ✅ GOOD — Correct safety logic | KEEP |
| **Reserved header fields** | Randomize e_ident[9:16], zero e_flags | ⚠️ MIXED — e_flags zeroing is fine, but randomizing EI_PAD is unusual. Standard tools write zeros | **CHANGE**: **Zero** EI_PAD instead of randomizing. Random bytes in reserved fields are a tampering indicator |
| **Program header mutations** | Rotate PT_NOTE, reverse PT_LOAD (force), randomize alignment/paddr, relocate metadata segments (force) | ⚠️ AGGRESSIVE — Reversing PT_LOAD order is dangerous and detectable. Randomizing alignment can break things | **SIMPLIFY**: Keep PT_NOTE rotation (low risk). Remove PT_LOAD reversal. Remove alignment randomization. Keep paddr randomization (p_paddr is unused) |
| **Dynamic symbol shuffle** (force) | Shuffle .dynsym entries | ❌ **DANGEROUS** — Can break dynamic linking | **REMOVE** in safe mode, keep only in force with clear warnings |
| **String table scramble/wipe** (force) | Scramble or wipe section string table | ⚠️ FORCE ONLY — Acceptable for force mode | KEEP as force-only |

---

## 4. Critical Comparison: What Others Do Better

### 4.1 Astral-PE's Import Mutation (We Should Adopt)
Astral-PE mutates DLL names using **case randomization** (`KERNEL32.dll` → `kErNeL32.dll`) and **path prefix** (`./kernel32.dll`). This exploits the Windows loader's case-insensitive file resolution and relative path support.

**Our current approach** (descriptor shuffle) is less effective and riskier. We should:
1. **Add DLL name case mutation** — Windows loader handles it transparently
2. **Add `./` or `.\` path prefix** — Valid, breaks naive string matching
3. **Keep descriptor shuffle** as secondary
4. **Remove thunk shuffle entirely**

### 4.2 Astral-PE's Timestamp Strategy (We Should Adopt)
Astral-PE **zeroes** timestamps. We currently **randomize** them. Zeroed is better because:
- Many release builds have zeroed timestamps (deterministic builds)
- Random timestamps are statistical outliers
- AV ML models flag non-zero timestamps that don't match known build tool ranges

### 4.3 sstrip's Minimalism (Philosophy We Should Emulate)
sstrip's approach is: **remove non-essential data, change nothing else**. The binary looks like a standard `strip -s` output plus section header removal. The lesson:

**The best obfuscation looks like normal compilation output.**

### 4.4 Things Only We Do (That Create Unique Fingerprints)

These go-super-strip behaviors create a **detectable fingerprint** of our tool:

1. **`foutput`/`output` replacement strings** — If AV vendors sample our tool, these become signatures
2. **`.sec0a1b2c` ELF section names** — Unique to our tool, trivially detectable
3. **Random linker versions** — No real compiler produces version 237.42
4. **Fake RSDS debug records** — Detectable by GUID validation
5. **NOP slides in data sections** — Can be fingerprinted

---

## 5. Prioritized Action Items

### P0 — MUST FIX (Currently raising flags)

| # | Action | File | Effort |
|---|--------|------|--------|
| 1 | **PE section names**: Change from pool-based renaming to **NULL wiping** (like Astral-PE) | `perw/obfuscate.go` | Small |
| 2 | **ELF section names**: Change from `.secXXXXXX` hex names to **NULL wiping** | `elfrw/obfuscate.go` | Small |
| 3 | **Linker version**: Change from random to **zero** or realistic MSVC values (14.0/14.29/14.38/14.40) | `perw/obfuscate.go` | Small |
| 4 | **EI_PAD randomization**: Change to **zeroing** | `elfrw/obfuscate.go` | Small |
| 5 | **Remove InjectDebugDirectoryNoise** entirely | `perw/obfuscate.go` | Small |
| 6 | **Remove ObfuscateRuntimeStrings** or replace with zeroing | `perw/obfuscate.go` | Small |

### P1 — SHOULD FIX (Danger/low value)

| # | Action | File | Effort |
|---|--------|------|--------|
| 7 | **Remove thunk shuffle** from ObfuscateImportTable | `perw/obfuscate.go` | Small |
| 8 | **Remove subsystem/DLL characteristics mutation** from force mode | `perw/obfuscate.go` | Small |
| 9 | **Remove PT_LOAD reversal** from ELF obfuscation | `elfrw/obfuscate.go` | Small |
| 10 | **Remove alignment randomization** for PT_LOAD segments | `elfrw/obfuscate.go` | Medium |
| 11 | **Guard packer signature regex rules** behind IsPacked check | `perw/strip_types.go`, `strip.go` | Small |

### P2 — SHOULD ADD (New high-value techniques from research)

| # | Action | File | Effort |
|---|--------|------|--------|
| 12 | **Add DLL name case mutation** (Astral-PE technique) | `perw/obfuscate.go` | Medium |
| 13 | **Add `./` path prefix to DLL names** (Astral-PE technique) | `perw/obfuscate.go` | Medium |
| 14 | **Add Rich Header removal to strip pipeline** (already exists, ensure it runs before obfuscate) | `perw/strip.go` | Small |
| 15 | **Add DOS stub cleaning** (reset to minimal MZ, zero between DOS header and PE header) | `perw/strip.go` or `obfuscate.go` | Medium |
| 16 | **Add checksum zeroing** to PE strip | `perw/strip.go` | Small |
| 17 | **Add export table faker** (Astral-PE: add fake export if none exists to bait scanners) | `perw/obfuscate.go` | Medium |
| 18 | **ELF: Option to remove section header table entirely** (sstrip approach) | `elfrw/compact.go` | Medium |

### P3 — NICE TO HAVE

| # | Action | File | Effort |
|---|--------|------|--------|
| 19 | **Narrow build metadata regex** to skip .rsrc section | `perw/strip_types.go` | Small |
| 20 | **ImageBase mutation**: Restrict to standard values | `perw/obfuscate.go` | Small |
| 21 | **NOP pattern improvement**: Only use compiler-realistic patterns, no 0x90 slides | `perw/obfuscate.go` | Medium |
| 22 | **Import descriptor TimeDateStamp/ForwarderChain noise** (Astral-PE adds random values here) | `perw/obfuscate.go` | Small |

---

## 6. What to Keep Unchanged

These techniques are well-implemented and provide good value with low detection risk:

- ✅ Section-based stripping (both PE and ELF)
- ✅ Rich Header removal
- ✅ COFF TimeDateStamp zeroing  
- ✅ DOS reserved fields zeroing
- ✅ Debug directory stripping
- ✅ Section padding randomization
- ✅ Critical section protection in compact
- ✅ Overlay protection (force-gated)
- ✅ Protected ranges for regex stripping
- ✅ String table protection in ELF strip
- ✅ Go/GCC/Rust/C++ build marker regex rules
- ✅ User/Host identifier regex rules
- ✅ Program header paddr randomization (on non-LOAD segments)
- ✅ PT_NOTE segment rotation

---

## 7. Research Sources

| Source | URL | Confidence |
|--------|-----|------------|
| sstrip manpage (ELFkickers) | https://man.archlinux.org/man/extra/elfkickers/sstrip.1.en | HIGH |
| Astral-PE source code | https://github.com/DosX-dev/Astral-PE | HIGH |
| RelocBonus (DEF CON 26) | https://github.com/nickcano/RelocBonus | HIGH |
| IdanRosenzweig/ELF-Toolchain | https://github.com/IdanRosenzweig/ELF-Toolchain | HIGH |
| Rich Header anomalies (VirusBulletin 2019) | https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/ | HIGH |
| PE heuristics for packed detection | https://article.nadiapub.com/IJSIA/vol7_no5/24.pdf | MEDIUM |
| ML classifiers on PE features (NDSS 2020) | https://www.ndss-symposium.org/wp-content/uploads/2020/02/24310.pdf | HIGH |
| EDR bypass techniques compendium | https://blog.deeb.ch/posts/how-edr-works/ | HIGH |
| AV/EDR bypass methodology | https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/ | MEDIUM |
| PE entropy-based detection | https://buymeacoffee.com/cyberwarzone/detecting-obfuscated-pe-executable-using-entropy-analysis | MEDIUM |
| Relocation obfuscation on ARM64/Win11 | https://ffri.github.io/ProjectChameleon/arm64x_reloc_obfuscation/ | HIGH |
| Malware detection via PE format mining | https://pmc.ncbi.nlm.nih.gov/articles/PMC4060536/ | HIGH |
| Robust PE malware analysis | https://papers.put.as/papers/malware/2014/masterthesiskatja.pdf | MEDIUM |
