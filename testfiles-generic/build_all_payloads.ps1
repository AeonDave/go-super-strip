# build_all_payloads.ps1
# Build script for payload test executables (Windows PE + Linux ELF)
# Covers: C, C++, Go with MinGW, MSVC, and Linux via WSL

param(
    [switch]$Clean,
    [switch]$MinGWOnly,
    [switch]$MSVCOnly,
    [switch]$GoOnly,
    [switch]$Linux,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$Script:TotalBuilt = 0
$Script:TotalFailed = 0
$Script:BuildResults = @()
$Script:VSEnvironmentLoaded = $false

function Write-Section {
    param([string]$Title)
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Error-Message {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Yellow
}

function Test-Command {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Find-VisualStudio {
    Write-Info "Searching for Visual Studio installation..."
    
    # Method 1: Try vswhere.exe (official Microsoft tool)
    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswherePath) {
        Write-Info "Found vswhere.exe, querying for installations..."
        $vsInstallPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
        if ($vsInstallPath) {
            $vcvarsPath = Join-Path $vsInstallPath "VC\Auxiliary\Build\vcvars64.bat"
            if (Test-Path $vcvarsPath) {
                Write-Success "Found Visual Studio via vswhere: $vcvarsPath"
                return $vcvarsPath
            }
        }
    }
    
    # Method 2: Common Visual Studio paths (including Build Tools)
    $vsPaths = @(
        # Visual Studio 2022
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        
        # Visual Studio 2019
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        
        # Visual Studio 2017
        "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
        "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    )
    
    foreach ($path in $vsPaths) {
        if (Test-Path $path) {
            Write-Success "Found Visual Studio: $path"
            return $path
        }
    }
    
    # Method 3: Search recursively in VS base directories
    Write-Info "Performing recursive search in Visual Studio directories..."
    $vsBasePaths = @(
        "C:\Program Files\Microsoft Visual Studio",
        "C:\Program Files (x86)\Microsoft Visual Studio"
    )
    
    foreach ($basePath in $vsBasePaths) {
        if (Test-Path $basePath) {
            $found = Get-ChildItem -Path $basePath -Recurse -Filter "vcvars64.bat" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match "VC\\Auxiliary\\Build" } |
                Select-Object -First 1
            
            if ($found) {
                Write-Success "Found Visual Studio via recursive search: $($found.FullName)"
                return $found.FullName
            }
        }
    }
    
    return $null
}

function Initialize-MSVC {
    # Only skip init when cl.exe is present AND the include path is already loaded.
    # If INCLUDE is empty, vcvars hasn't been sourced yet even if cl is on PATH.
    if ((Test-Command "cl") -and (-not [string]::IsNullOrEmpty($env:INCLUDE))) {
        Write-Success "MSVC already available in environment"
        $Script:VSEnvironmentLoaded = $true
        return $true
    }
    
    # Find Visual Studio
    $vsPath = Find-VisualStudio
    if (-not $vsPath) {
        Write-Error-Message "Visual Studio not found. Install Visual Studio 2019/2022 with C++ workload"
        return $false
    }
    
    # Load Visual Studio environment
    Write-Info "Loading Visual Studio environment..."
    $tempBatch = [System.IO.Path]::GetTempFileName() + ".cmd"
    
    @"
@echo off
call "$vsPath" >nul 2>&1
if errorlevel 1 exit /b 1
set
"@ | Out-File -FilePath $tempBatch -Encoding ASCII
    
    $output = & cmd /c $tempBatch
    Remove-Item $tempBatch -Force
    
    # Parse environment variables
    foreach ($line in $output) {
        if ($line -match '^([^=]+)=(.*)$') {
            $name = $matches[1]
            $value = $matches[2]
            # Update important paths
            if ($name -eq "PATH" -or $name -eq "INCLUDE" -or $name -eq "LIB") {
                [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
            }
        }
    }
    
    # Verify cl.exe is now available
    if (Test-Command "cl") {
        Write-Success "MSVC environment loaded successfully"
        $Script:VSEnvironmentLoaded = $true
        return $true
    } else {
        Write-Error-Message "Failed to load MSVC environment"
        return $false
    }
}

function Clean-IntermediateFiles {
    Write-Info "Cleaning intermediate build files..."
    
    $patterns = @("*.obj", "*.exp", "*.lib", "*.pdb", "*.ilk")
    $removed = 0
    
    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Filter $pattern -ErrorAction SilentlyContinue
        $removed += $files.Count
        foreach ($file in $files) {
            Remove-Item $file.FullName -Force
        }
    }
    
    if ($removed -gt 0) {
        Write-Success "Removed $removed intermediate files"
    }
}

function Build-Payload {
    param(
        [string]$Name,
        [string]$Source,
        [string]$Output,
        [scriptblock]$BuildCommand,
        [string]$Description
    )
    
    Write-Info "Building: $Output"
    if ($Verbose) {
        Write-Host "  Description: $Description" -ForegroundColor Gray
    }
    
    try {
        & $BuildCommand
        if ($LASTEXITCODE -eq 0 -and (Test-Path $Output)) {
            $size = (Get-Item $Output).Length
            $sizeKB = [math]::Round($size / 1KB, 2)
            Write-Success "Built $Output ($sizeKB KB)"
            $Script:TotalBuilt++
            $Script:BuildResults += [PSCustomObject]@{
                Name = $Name
                Output = $Output
                Size = $sizeKB
                Status = "Success"
            }
        } else {
            throw "Build failed with exit code $LASTEXITCODE"
        }
    } catch {
        Write-Error-Message "Failed to build $Output : $_"
        $Script:TotalFailed++
        $Script:BuildResults += [PSCustomObject]@{
            Name = $Name
            Output = $Output
            Size = 0
            Status = "Failed"
        }
    }
}

function Clean-Payloads {
    Write-Section "Cleaning Previous Builds"
    
    $patterns = @(
        "c_mingw_*.exe",
        "c_msvc_*.exe",
        "cpp_mingw_*.exe",
        "cpp_msvc_*.exe",
        "go_*.exe",
        "*.obj",
        "*.o"
    )
    
    foreach ($pattern in $patterns) {
        $files = Get-ChildItem -Filter $pattern -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            Remove-Item $file.FullName -Force
            Write-Info "Removed: $($file.Name)"
        }
    }
}

function Build-MinGW-Payloads {
    Write-Section "Building MinGW Payloads (C/C++)"
    
    if (-not (Test-Command "x86_64-w64-mingw32-gcc")) {
        Write-Error-Message "MinGW GCC not found. Install MinGW-w64 or skip with -MSVCOnly"
        return
    }
    
    Write-Success "MinGW GCC found: $(x86_64-w64-mingw32-gcc --version | Select-Object -First 1)"
    
    # C MinGW Static
    Build-Payload `
        -Name "C MinGW Static" `
        -Source "c_mingw_static.c" `
        -Output "c_mingw_static.exe" `
        -BuildCommand { 
            x86_64-w64-mingw32-gcc -o c_mingw_static.exe c_mingw_static.c -static -s -mwindows 2>&1 | Out-Null
        } `
        -Description "C with MinGW, static CRT"
    
    # C MinGW Dynamic
    Build-Payload `
        -Name "C MinGW Dynamic" `
        -Source "c_mingw_dynamic.c" `
        -Output "c_mingw_dynamic.exe" `
        -BuildCommand { 
            x86_64-w64-mingw32-gcc -o c_mingw_dynamic.exe c_mingw_dynamic.c -s -mwindows 2>&1 | Out-Null
        } `
        -Description "C with MinGW, dynamic CRT"
    
    # C MinGW No CRT
    Build-Payload `
        -Name "C MinGW NoCRT" `
        -Source "c_mingw_nocrt.c" `
        -Output "c_mingw_nocrt.exe" `
        -BuildCommand { 
            x86_64-w64-mingw32-gcc -o c_mingw_nocrt.exe c_mingw_nocrt.c `
                -nostdlib -lkernel32 -luser32 -s -mwindows `
                "-Wl,--entry=WinMainCRTStartup" 2>&1 | Out-Null
        } `
        -Description "C with MinGW, no CRT"
    
    # C++ MinGW Static
    Build-Payload `
        -Name "C++ MinGW Static" `
        -Source "cpp_mingw_static.cpp" `
        -Output "cpp_mingw_static.exe" `
        -BuildCommand { 
            x86_64-w64-mingw32-g++ -o cpp_mingw_static.exe cpp_mingw_static.cpp `
                -static-libgcc -static-libstdc++ -static -s -mwindows 2>&1 | Out-Null
        } `
        -Description "C++ with MinGW, static STL"
    
    # C++ MinGW Dynamic
    Build-Payload `
        -Name "C++ MinGW Dynamic" `
        -Source "cpp_mingw_dynamic.cpp" `
        -Output "cpp_mingw_dynamic.exe" `
        -BuildCommand { 
            x86_64-w64-mingw32-g++ -o cpp_mingw_dynamic.exe cpp_mingw_dynamic.cpp -s -mwindows 2>&1 | Out-Null
        } `
        -Description "C++ with MinGW, dynamic STL"
    
    # C MinGW TLS
    Build-Payload `
        -Name "C MinGW TLS" `
        -Source "c_mingw_tls.c" `
        -Output "c_mingw_tls.exe" `
        -BuildCommand { 
            x86_64-w64-mingw32-gcc -o c_mingw_tls.exe c_mingw_tls.c -static -s -mwindows 2>&1 | Out-Null
        } `
        -Description "C with MinGW, TLS callback"
}

function Build-MSVC-Payloads {
    Write-Section "Building MSVC Payloads (C/C++)"

    # Load vcvars whenever cl.exe is missing OR INCLUDE is not set.
    # cl.exe can be on PATH without the full VS environment (INCLUDE/LIB) loaded.
    if ((-not (Test-Command "cl")) -or [string]::IsNullOrEmpty($env:INCLUDE)) {
        Write-Info "Initializing MSVC environment..."
        if (-not (Initialize-MSVC)) {
            Write-Error-Message "Could not initialize MSVC environment. Skipping MSVC builds"
            return
        }
    }
    
    Write-Success "MSVC found: $(cl 2>&1 | Select-String 'Version' | Select-Object -First 1)"
    
    # C MSVC Static
    Build-Payload `
        -Name "C MSVC Static" `
        -Source "c_msvc_static.c" `
        -Output "c_msvc_static.exe" `
        -BuildCommand { 
            cl /nologo /MT /O2 /Fe:c_msvc_static.exe c_msvc_static.c /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib 2>&1 | Out-Null
        } `
        -Description "C with MSVC, static CRT (/MT)"
    
    # C MSVC Dynamic
    Build-Payload `
        -Name "C MSVC Dynamic" `
        -Source "c_msvc_dynamic.c" `
        -Output "c_msvc_dynamic.exe" `
        -BuildCommand { 
            cl /nologo /MD /O2 /Fe:c_msvc_dynamic.exe c_msvc_dynamic.c /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib 2>&1 | Out-Null
        } `
        -Description "C with MSVC, dynamic CRT (/MD)"
    
    # C MSVC No CRT
    Build-Payload `
        -Name "C MSVC NoCRT" `
        -Source "c_msvc_nocrt.c" `
        -Output "c_msvc_nocrt.exe" `
        -BuildCommand { 
            cl /nologo /c /O2 /GS- /Zl c_msvc_nocrt.c 2>&1 | Out-Null
            link /NOLOGO /NODEFAULTLIB /ENTRY:WinMainCRTStartup /SUBSYSTEM:WINDOWS `
                /OUT:c_msvc_nocrt.exe c_msvc_nocrt.obj user32.lib kernel32.lib 2>&1 | Out-Null
        } `
        -Description "C with MSVC, no CRT (/Zl)"
    
    # C++ MSVC Static
    Build-Payload `
        -Name "C++ MSVC Static" `
        -Source "cpp_msvc_static.cpp" `
        -Output "cpp_msvc_static.exe" `
        -BuildCommand { 
            cl /nologo /MT /O2 /EHsc /Fe:cpp_msvc_static.exe cpp_msvc_static.cpp /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib 2>&1 | Out-Null
        } `
        -Description "C++ with MSVC, static CRT (/MT)"
    
    # C++ MSVC Dynamic
    Build-Payload `
        -Name "C++ MSVC Dynamic" `
        -Source "cpp_msvc_dynamic.cpp" `
        -Output "cpp_msvc_dynamic.exe" `
        -BuildCommand { 
            cl /nologo /MD /O2 /EHsc /Fe:cpp_msvc_dynamic.exe cpp_msvc_dynamic.cpp /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib 2>&1 | Out-Null
        } `
        -Description "C++ with MSVC, dynamic CRT (/MD)"
    
    # C MSVC TLS
    Build-Payload `
        -Name "C MSVC TLS" `
        -Source "c_msvc_tls.c" `
        -Output "c_msvc_tls.exe" `
        -BuildCommand { 
            cl /nologo /MT /O2 /Fe:c_msvc_tls.exe c_msvc_tls.c /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib 2>&1 | Out-Null
        } `
        -Description "C with MSVC, TLS callback"
}

function Build-Go-Payloads {
    Write-Section "Building Go Payloads"
    
    if (-not (Test-Command "go")) {
        Write-Error-Message "Go compiler not found. Install Go or skip with -MinGWOnly/-MSVCOnly"
        return
    }
    
    Write-Success "Go found: $(go version)"
    
    # Go Native
    Build-Payload `
        -Name "Go Native" `
        -Source "go_native.go" `
        -Output "go_native.exe" `
        -BuildCommand { 
            $env:CGO_ENABLED = "0"
            go build -ldflags="-s -w -H windowsgui" -o go_native.exe go_native.go 2>&1 | Out-Null
        } `
        -Description "Pure Go, no CGO"
    
    # Go CGO
    Build-Payload `
        -Name "Go CGO" `
        -Source "go_cgo.go" `
        -Output "go_cgo.exe" `
        -BuildCommand { 
            $env:CGO_ENABLED = "1"
            go build -ldflags="-s -w -H windowsgui" -o go_cgo.exe go_cgo.go 2>&1 | Out-Null
        } `
        -Description "Go with CGO enabled"
}

function Show-Summary {
    Write-Section "Build Summary"
    
    Write-Host "Total Built: $Script:TotalBuilt" -ForegroundColor Green
    Write-Host "Total Failed: $Script:TotalFailed" -ForegroundColor Red
    Write-Host ""
    
    # Show results table
    $Script:BuildResults | Format-Table -AutoSize
    
    # Show total size
    $totalSize = ($Script:BuildResults | Where-Object { $_.Status -eq "Success" } | Measure-Object -Property Size -Sum).Sum
    Write-Host "Total Size: $([math]::Round($totalSize / 1024, 2)) MB" -ForegroundColor Cyan
    
    if ($Script:TotalFailed -eq 0) {
        Write-Host "`nAll payloads built successfully! 🎉" -ForegroundColor Green
    } else {
        Write-Host "`nSome builds failed. Check errors above." -ForegroundColor Yellow
    }
}

# ──────────────────────────────────────────────────────────────
# Linux build helpers (requires WSL with gcc/g++/go)
# ──────────────────────────────────────────────────────────────

function Test-WSL {
    try {
        $out = wsl.exe -- bash -c "echo ok" 2>&1
        return ($out -match "ok")
    } catch {
        return $false
    }
}

function Convert-ToWSLPath {
    param([string]$WinPath)
    # D:\Sources\... → /mnt/d/Sources/...
    $drive = $WinPath[0].ToString().ToLower()
    $rest  = $WinPath.Substring(2) -replace '\\', '/'
    return "/mnt/$drive$rest"
}

function Build-Linux-Payload {
    param(
        [string]$Name,
        [string]$WslCommand,
        [string]$Output,
        [string]$Description
    )

    Write-Info "Building: $Output"
    if ($Verbose) {
        Write-Host "  Description: $Description" -ForegroundColor Gray
        Write-Host "  Command    : $WslCommand"  -ForegroundColor Gray
    }

    # Use a login shell so profile-based PATH entries (e.g. /usr/local/go/bin) are available.
    $result = wsl.exe -- bash -l -c "$WslCommand" 2>&1
    if ($LASTEXITCODE -eq 0 -and (Test-Path $Output)) {
        $size   = (Get-Item $Output).Length
        $sizeKB = [math]::Round($size / 1KB, 2)
        Write-Success "Built $Output ($sizeKB KB)"
        $Script:TotalBuilt++
        $Script:BuildResults += [PSCustomObject]@{
            Name   = $Name
            Output = $Output
            Size   = $sizeKB
            Status = "Success"
        }
    } else {
        Write-Error-Message "Failed to build $Output (exit $LASTEXITCODE)"
        if ($Verbose -and $result) { Write-Host $result -ForegroundColor DarkGray }
        $Script:TotalFailed++
        $Script:BuildResults += [PSCustomObject]@{
            Name   = $Name
            Output = $Output
            Size   = 0
            Status = "Failed"
        }
    }
}

function Build-Linux-Payloads {
    Write-Section "Building Linux Payloads (ELF)"

    # Ensure output directories exist
    $linuxOut   = Join-Path $PSScriptRoot "out\linux"
    $linuxSoOut = Join-Path $PSScriptRoot "out\linux\so"
    New-Item -ItemType Directory -Force -Path $linuxOut   | Out-Null
    New-Item -ItemType Directory -Force -Path $linuxSoOut | Out-Null

    # Convert Windows paths to WSL mount paths
    $wslRoot  = Convert-ToWSLPath $PSScriptRoot
    $wslOut   = "$wslRoot/out/linux"
    $wslSoOut = "$wslRoot/out/linux/so"

    if (-not (Test-WSL)) {
        Write-Error-Message "WSL (wsl.exe) is not available or not functional. Skipping Linux builds."
        return
    }

    # ── C executables ──────────────────────────────────────────
    # Use login shell for all WSL probes so profile-set PATH entries are visible.
    $hasgcc = (wsl.exe -- bash -l -c "command -v gcc" 2>&1) -ne ""

    if ($hasgcc) {
        Build-Linux-Payload `
            -Name "C Linux Dynamic" `
            -WslCommand "gcc -O2 -o $wslOut/c_linux_dynamic $wslRoot/c_linux_dynamic.c" `
            -Output     (Join-Path $linuxOut "c_linux_dynamic") `
            -Description "C dynamically linked ELF (glibc)"

        Build-Linux-Payload `
            -Name "C Linux Static" `
            -WslCommand "gcc -O2 -static -o $wslOut/c_linux_static $wslRoot/c_linux_static.c" `
            -Output     (Join-Path $linuxOut "c_linux_static") `
            -Description "C statically linked ELF"

        Build-Linux-Payload `
            -Name "C Linux PIE" `
            -WslCommand "gcc -O2 -fpie -pie -o $wslOut/c_linux_pie $wslRoot/c_linux_pie.c" `
            -Output     (Join-Path $linuxOut "c_linux_pie") `
            -Description "C PIE ELF (ASLR-friendly)"

        Build-Linux-Payload `
            -Name "C Linux Thread" `
            -WslCommand "gcc -O2 -static -o $wslOut/c_linux_thread $wslRoot/c_linux_thread.c -lpthread" `
            -Output     (Join-Path $linuxOut "c_linux_thread") `
            -Description "C static ELF with pthreads + TLS"

        # ── Shared objects (placed in out/linux/so/ to avoid exec tests) ─
        Build-Linux-Payload `
            -Name "SO C Linux" `
            -WslCommand "gcc -O2 -shared -fPIC -o $wslSoOut/so_c_linux.so $wslRoot/c_linux_dynamic.c" `
            -Output     (Join-Path $linuxSoOut "so_c_linux.so") `
            -Description "C shared object (.so)"
    } else {
        Write-Error-Message "gcc not found inside WSL — skipping C Linux builds."
    }

    # ── C++ executables ────────────────────────────────────────
    $hasgxx = (wsl.exe -- bash -l -c "command -v g++" 2>&1) -ne ""

    if ($hasgxx) {
        Build-Linux-Payload `
            -Name "C++ Linux Dynamic" `
            -WslCommand "g++ -O2 -o $wslOut/cpp_linux_dynamic $wslRoot/cpp_linux_dynamic.cpp" `
            -Output     (Join-Path $linuxOut "cpp_linux_dynamic") `
            -Description "C++ dynamically linked ELF"

        Build-Linux-Payload `
            -Name "C++ Linux Static" `
            -WslCommand "g++ -O2 -static-libgcc -static-libstdc++ -static -o $wslOut/cpp_linux_static $wslRoot/cpp_linux_static.cpp" `
            -Output     (Join-Path $linuxOut "cpp_linux_static") `
            -Description "C++ statically linked ELF"

        # ── C++ shared object ──────────────────────────────────
        Build-Linux-Payload `
            -Name "SO C++ Linux" `
            -WslCommand "g++ -O2 -shared -fPIC -o $wslSoOut/so_cpp_linux.so $wslRoot/cpp_linux_dynamic.cpp" `
            -Output     (Join-Path $linuxSoOut "so_cpp_linux.so") `
            -Description "C++ shared object (.so)"
    } else {
        Write-Error-Message "g++ not found inside WSL — skipping C++ Linux builds."
    }

    # ── Go pure (cross-compile from Windows host, no WSL needed) ──
    if (Test-Command "go") {
        $goLinuxOut = Join-Path $linuxOut "go_linux"
        Write-Info "Building: $goLinuxOut (cross-compile)"
        $env:GOOS        = "linux"
        $env:GOARCH      = "amd64"
        $env:CGO_ENABLED = "0"
        go build -trimpath -ldflags="-s -w" -o $goLinuxOut (Join-Path $PSScriptRoot "go_linux.go") 2>&1 | Out-Null
        Remove-Item Env:\GOOS
        Remove-Item Env:\GOARCH
        Remove-Item Env:\CGO_ENABLED

        if ($LASTEXITCODE -eq 0 -and (Test-Path $goLinuxOut)) {
            $size   = (Get-Item $goLinuxOut).Length
            $sizeKB = [math]::Round($size / 1KB, 2)
            Write-Success "Built $goLinuxOut ($sizeKB KB)"
            $Script:TotalBuilt++
            $Script:BuildResults += [PSCustomObject]@{
                Name   = "Go Linux Pure"
                Output = $goLinuxOut
                Size   = $sizeKB
                Status = "Success"
            }
        } else {
            Write-Error-Message "Failed to cross-compile go_linux"
            $Script:TotalFailed++
            $Script:BuildResults += [PSCustomObject]@{
                Name   = "Go Linux Pure"
                Output = $goLinuxOut
                Size   = 0
                Status = "Failed"
            }
        }
    } else {
        Write-Error-Message "go not found — skipping Go Linux cross-compile."
    }

    # ── Go CGO (build inside WSL where native gcc is available) ──
    # Use login shell: Go is typically installed to /usr/local/go/bin which is
    # only added to PATH by /etc/profile.d/go.sh (sourced by bash -l).
    $hasGo = ((wsl.exe -- bash -l -c "go version 2>/dev/null") -match "go version")
    if ($hasGo -and $hasgcc) {
        # The module root (go.mod) lives at $PSScriptRoot — map to WSL path
        $wslBuildCmd = "cd '$wslRoot' && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o '$wslOut/go_linux_cgo' go_linux_cgo.go"
        Build-Linux-Payload `
            -Name "Go Linux CGO" `
            -WslCommand $wslBuildCmd `
            -Output     (Join-Path $linuxOut "go_linux_cgo") `
            -Description "Go + CGO ELF (requires native Linux gcc in WSL)"
    } else {
        Write-Info "go or gcc not found inside WSL — skipping Go CGO Linux build."
    }

    Write-Success "Linux build step complete. Binaries: $linuxOut"
}

# Main execution
Write-Host @"
╔════════════════════════════════════════════════════════════╗
║    Payload Test Matrix Build Script                       ║
║    C | C++ | Go | MinGW | MSVC | Linux (WSL)              ║
╚════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

if ($Clean) {
    Clean-Payloads
}

if (-not $MSVCOnly -and -not $GoOnly) {
    Build-MinGW-Payloads
}

if (-not $MinGWOnly -and -not $GoOnly) {
    Build-MSVC-Payloads
}

if (-not $MinGWOnly -and -not $MSVCOnly) {
    Build-Go-Payloads
}

# Build Linux ELF payloads
if ($Linux) {
    Build-Linux-Payloads
}

Show-Summary

# Clean intermediate files
Clean-IntermediateFiles

# Final verification
Write-Section "Payload Verification"

$expectedPayloads = @(
    "c_mingw_static.exe", "c_mingw_dynamic.exe", "c_mingw_nocrt.exe", "c_mingw_tls.exe",
    "c_msvc_static.exe", "c_msvc_dynamic.exe", "c_msvc_nocrt.exe", "c_msvc_tls.exe",
    "cpp_mingw_static.exe", "cpp_mingw_dynamic.exe",
    "cpp_msvc_static.exe", "cpp_msvc_dynamic.exe",
    "go_native.exe", "go_cgo.exe"
)

$missing = @()
$present = @()

foreach ($payload in $expectedPayloads) {
    if (Test-Path $payload) {
        $present += $payload
    } else {
        $missing += $payload
    }
}

Write-Host "`nWindows EXE: $($present.Count)/$($expectedPayloads.Count)" -ForegroundColor Green

if ($missing.Count -gt 0) {
    Write-Host "`nMissing:" -ForegroundColor Yellow
    foreach ($m in $missing) {
        Write-Host "  ❌ $m" -ForegroundColor Red
    }
}

Write-Host "`nDone! All payloads ready for injection testing." -ForegroundColor Green
Write-Host "See PAYLOAD_MATRIX.md for details on each payload.`n" -ForegroundColor Gray

# Linux verification (only when -Linux was requested)
if ($Linux) {
    Write-Section "Linux Payload Verification"

    $linuxDir = Join-Path $PSScriptRoot "out\linux"
    $expectedLinux = @(
        "c_linux_dynamic", "c_linux_static", "c_linux_pie", "c_linux_thread",
        "cpp_linux_dynamic", "cpp_linux_static",
        "go_linux", "go_linux_cgo"
    )

    $linuxPresent = @()
    $linuxMissing = @()

    foreach ($name in $expectedLinux) {
        $full = Join-Path $linuxDir $name
        if (Test-Path $full) {
            $linuxPresent += $name
        } else {
            $linuxMissing += $name
        }
    }

    Write-Host "Linux ELF: $($linuxPresent.Count)/$($expectedLinux.Count)" -ForegroundColor Green
    foreach ($f in $linuxPresent) { Write-Host "  ✅ $f" -ForegroundColor Cyan }
    if ($linuxMissing.Count -gt 0) {
        Write-Host "Missing:" -ForegroundColor Yellow
        foreach ($f in $linuxMissing) { Write-Host "  ❌ $f" -ForegroundColor Red }
    }
}
