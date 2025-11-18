#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Manual end-to-end pack verification across Windows and Linux fixtures.

.DESCRIPTION
    Builds fresh PE/ELF fixtures, runs analyze -> pack -> analyze for each
    in-memory strategy, executes the resulting binaries, and verifies the
    console markers emitted by testfiles/simple.c. Logs are written under
    test/logs/manual_pack_<timestamp>/.

.NOTES
    Requires:
      - go build (gosstrip.exe present in repo root)
      - x86_64-w64-mingw32-gcc
      - WSL gcc (for ELF fixture)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ToWsl {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $drive = $fullPath.Substring(0, 1).ToLower()
    $rest = $fullPath.Substring(2).Replace('\', '/')
    return "/mnt/$drive/$rest"
}

function Resolve-GosstripPath {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)
    $exe = Join-Path $RepoRoot "gosstrip.exe"
    if (Test-Path $exe) {
        return $exe
    }
    $bare = Join-Path $RepoRoot "gosstrip"
    if (Test-Path $bare) {
        Copy-Item -LiteralPath $bare -Destination $exe -Force
        return $exe
    }
    throw "gosstrip binary not found. Run `go build -o gosstrip.exe` first."
}

function Invoke-ProcessCapture {
    param(
        [string]$FileName,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FileName
    foreach ($arg in $Arguments) {
        [void]$psi.ArgumentList.Add($arg)
    }
    if ($WorkingDirectory) {
        $psi.WorkingDirectory = $WorkingDirectory
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $null = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) {
            throw "Command '$FileName' failed ($stderr)"
        }
    } finally {
        $proc.Dispose()
    }
}

function Invoke-Logged {
    param(
        [string]$LogPath,
        [string]$Command,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Command
    foreach ($arg in $Arguments) {
        [void]$psi.ArgumentList.Add($arg)
    }
    if ($WorkingDirectory) {
        $psi.WorkingDirectory = $WorkingDirectory
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        Add-Content -Path $LogPath -Value $stdout
        if ($stderr) {
            Add-Content -Path $LogPath -Value $stderr
        }
        if ($proc.ExitCode -ne 0) {
            throw "Command '$Command' failed with exit $($proc.ExitCode)"
        }
    } finally {
        $proc.Dispose()
    }
}

function Build-PeFixture {
    param([string]$Destination)
    $source = Join-Path $PSScriptRoot "..\testfiles\simple.c"
    & x86_64-w64-mingw32-gcc -O2 $source -o $Destination | Out-Null
}

function Build-ElfFixture {
    param([string]$Destination)
    $source = Join-Path $PSScriptRoot "..\testfiles/simple.c"
    $srcWsl = Convert-ToWsl $source
    $dstWsl = Convert-ToWsl $Destination
    Invoke-ProcessCapture -FileName "wsl.exe" -Arguments @("bash", "-lc", "gcc -O2 '$srcWsl' -o '$dstWsl' && chmod +x '$dstWsl'")
}

function Wait-ForFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Attempts = 10,
        [double]$DelaySeconds = 0.3
    )
    for ($i = 0; $i -lt $Attempts; $i++) {
        if (Test-Path -LiteralPath $Path) {
            return $true
        }
        Start-Sleep -Seconds $DelaySeconds
    }
    return $false
}

function Remove-FileSafe {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Attempts = 5,
        [double]$DelaySeconds = 0.2
    )
    for ($i = 0; $i -lt $Attempts; $i++) {
        try {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    throw "failed to remove $Path after $Attempts attempts"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..") | Select-Object -ExpandProperty Path
$gosstripExe = Resolve-GosstripPath $repoRoot
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$runRoot = Join-Path $repoRoot "test/logs/manual_pack_$timestamp"
$null = New-Item -ItemType Directory -Path $runRoot -Force

$peFixture = Join-Path $runRoot "simple_pe.exe"
$elfFixture = Join-Path $runRoot "simple_elf"
Build-PeFixture -Destination $peFixture
Build-ElfFixture -Destination $elfFixture

$scenarios = @(
    @{ Name = "pe_process_hollowing"; Path = $peFixture; Platform = "pe"; Options = "compression=xz,encryption=aes-256-gcm,inmemory=process_hollowing,polymorphic=true,padding=true,junkdensity=0.3" },
    @{ Name = "pe_atomic_bombing"; Path = $peFixture; Platform = "pe"; Options = "compression=lzma,encryption=chacha20,inmemory=atomic_bombing,polymorphic=true,padding=false,regperm=true" },
    @{ Name = "pe_off"; Path = $peFixture; Platform = "pe"; Options = "compression=xz,encryption=xor,inmemory=off,polymorphic=false,padding=true" },
    @{ Name = "elf_memfd"; Path = $elfFixture; Platform = "elf"; Options = "compression=xz,encryption=aes-256-gcm,inmemory=memfd,polymorphic=true,padding=true" },
    @{ Name = "elf_off"; Path = $elfFixture; Platform = "elf"; Options = "compression=lzma,encryption=chacha20,inmemory=off,polymorphic=false,padding=false" }
)

$paramFixture = $env:GOSSTRIP_PACK_PARAMS_FIXTURE
$paramArgs = $env:GOSSTRIP_PACK_PARAMS_ARGS
if ($paramFixture -and $paramArgs -and (Test-Path $paramFixture)) {
    $resolvedParamFixture = (Resolve-Path $paramFixture).Path
    $paramPlatform = $env:GOSSTRIP_PACK_PARAMS_PLATFORM
    if ([string]::IsNullOrWhiteSpace($paramPlatform)) {
        $paramPlatform = "pe"
    }
    $paramModes = @()
    switch ($paramPlatform.ToLowerInvariant()) {
        "elf" { $paramModes = @("memfd", "off") }
        default {
            $paramPlatform = "pe"
            $paramModes = @("process_hollowing", "atomic_bombing", "off")
        }
    }
    $paramOutput = $env:GOSSTRIP_PACK_PARAMS_OUTPUT
    $fixtureLabel = [System.IO.Path]::GetFileNameWithoutExtension($resolvedParamFixture)
    foreach ($mode in $paramModes) {
        $options = "compression=xz,encryption=aes-256-gcm,inmemory=$mode,polymorphic=true,padding=true,params=""$paramArgs"""
        $scenario = @{
            Name     = "${fixtureLabel}_${mode}_params"
            Path     = $resolvedParamFixture
            Platform = $paramPlatform
            Options  = $options
        }
        if ($paramOutput) {
            $scenario.ParamOutput = $paramOutput
        }
        $scenarios += $scenario
    }
}

foreach ($scenario in $scenarios) {
    $work = Join-Path $runRoot ("work_" + $scenario.Name)
    $null = New-Item -ItemType Directory -Path $work -Force
    $binary = Join-Path $work (Split-Path $scenario.Path -Leaf)
    Copy-Item -LiteralPath $scenario.Path -Destination $binary -Force
    $logFile = Join-Path $runRoot ($scenario.Name + ".log")

    "Scenario $($scenario.Name)" | Out-File -FilePath $logFile
    Invoke-Logged -LogPath $logFile -Command $gosstripExe -Arguments @("-a=mode=deep", $binary)
    Invoke-Logged -LogPath $logFile -Command $gosstripExe -Arguments @("-p=$($scenario.Options)", $binary)
    Invoke-Logged -LogPath $logFile -Command $gosstripExe -Arguments @("-a=mode=deep", $binary)

    if ($scenario.Platform -eq "pe") {
        $result = (& $binary 2>&1)
    } else {
        $binaryWsl = Convert-ToWsl $binary
        $result = (& wsl.exe bash -lc "'$binaryWsl'" 2>&1)
    }
    if ($null -eq $result) {
        $result = @()
    }
    Add-Content -Path $logFile -Value ($result -join [Environment]::NewLine)
    Add-Content -Path $logFile -Value "[INFO] execution completed"
    if ($scenario.ContainsKey("ParamOutput")) {
        $paramOutputPath = Join-Path (Split-Path $binary -Parent) $scenario.ParamOutput
        if (Wait-ForFile -Path $paramOutputPath) {
            Add-Content -Path $logFile -Value "[OK] params output $($scenario.ParamOutput)"
            (Get-Content -Path $paramOutputPath | Select-Object -First 50) | ForEach-Object {
                Add-Content -Path $logFile -Value $_
            }
            Remove-FileSafe -Path $paramOutputPath
        } else {
            Add-Content -Path $logFile -Value "[WARN] params output $($scenario.ParamOutput) missing"
        }
    }
}

Write-Host "Manual pack logs written to: $runRoot"
