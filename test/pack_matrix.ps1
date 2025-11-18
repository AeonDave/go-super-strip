#!/usr/bin/env pwsh

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Convert-ToWslPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $drive = [char][System.Char]::ToLower($fullPath[0])
    $rest = $fullPath.Substring(2).Replace('\', '/')
    return "/mnt/$drive$rest"
}

function Convert-ToBashLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    $single = [char]39
    $double = '"'
    $replacement = "$single$double$single$double$single"
    $escaped = $Value.Replace("$single", $replacement)
    return "$single$escaped$single"
}

function Invoke-ProcessCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FileName
    foreach ($arg in $Arguments) {
        [void]$psi.ArgumentList.Add($arg)
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    if ($WorkingDirectory) {
        $psi.WorkingDirectory = $WorkingDirectory
    }
    $process = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "Command '$FileName' failed (exit $($process.ExitCode)): $stderr$stdout"
        }
    } finally {
        $process.Dispose()
    }
}

function Invoke-LoggedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $cmdLine = $Command
    foreach ($arg in $Arguments) {
        if ($arg -match '\s') {
            $escaped = $arg.Replace('"', '\"')
            $cmdLine += " `"$escaped`""
        } else {
            $cmdLine += " $arg"
        }
    }
    Add-Content -Path $LogPath -Value ""
    Add-Content -Path $LogPath -Value "[$timestamp] CMD:$cmdLine"

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Command
    foreach ($arg in $Arguments) {
        [void]$psi.ArgumentList.Add($arg)
    }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    if ($WorkingDirectory) {
        $psi.WorkingDirectory = $WorkingDirectory
    }

    $process = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($stdout) {
            Add-Content -Path $LogPath -Value $stdout
        }
        if ($stderr) {
            Add-Content -Path $LogPath -Value $stderr
        }
        $exitStamp = Get-Date -Format "HH:mm:ss"
        Add-Content -Path $LogPath -Value "[$exitStamp] EXIT:$($process.ExitCode)"
        if ($process.ExitCode -ne 0) {
            throw "Command '$Command' failed with exit code $($process.ExitCode)"
        }
    } finally {
        $process.Dispose()
    }
}

function Ensure-WslTool {
    param([Parameter(Mandatory = $true)][string]$Tool)
    Invoke-ProcessCapture -FileName "wsl.exe" -Arguments @("bash", "-lc", "command -v $Tool >/dev/null")
}

function Build-WindowsCLI {
    Invoke-ProcessCapture -FileName "go" -Arguments @("build", "-o", $script:WindowsCLI, ".") -WorkingDirectory $script:RepoRoot
}

function Build-LinuxCLI {
    $buildScript = "cd $($script:RepoRootWsl) && GOOS=linux GOARCH=amd64 go build -o $(Convert-ToBashLiteral $script:LinuxCLIWsl) ."
    Invoke-ProcessCapture -FileName "wsl.exe" -Arguments @("bash", "-lc", $buildScript)
}

function Build-PeFixture {
    $source = Join-Path $script:RepoRoot "testfiles/simple.c"
    $output = $script:PEFixture
    $args = @("-O2", $source, "-o", $output)
    $result = & x86_64-w64-mingw32-gcc @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build PE fixture: $result"
    }
}

function Build-ElfFixture {
    $sourceWsl = Convert-ToBashLiteral (Convert-ToWslPath (Join-Path $script:RepoRoot "testfiles/simple.c"))
    $outputWsl = Convert-ToBashLiteral $script:ELFFixtureWsl
    Invoke-ProcessCapture -FileName "wsl.exe" -Arguments @("bash", "-lc", "gcc -O2 $sourceWsl -o $outputWsl")
    Invoke-ProcessCapture -FileName "wsl.exe" -Arguments @("bash", "-lc", "chmod +x $outputWsl")
}

function Format-JunkDensity {
    param([Parameter(Mandatory = $true)][double]$Value)
    return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0:0.0}", $Value)
}

function New-PackScenario {
    param(
        [Parameter(Mandatory = $true)][string]$Compression,
        [Parameter(Mandatory = $true)][string]$Encryption,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][int]$Index
    )

    $poly = if ($Index % 2 -eq 0) { "true" } else { "false" }
    $padding = if ($Index % 3 -eq 0) { "false" } else { "true" }
    $densityValue = if ($poly -eq "true") { [Math]::Min(0.9, (($Index % 5) * 0.25)) } else { 0.0 }
    $junkdensity = Format-JunkDensity -Value $densityValue
    $level = if ($Compression -eq "none") { 0 } elseif ($Index % 2 -eq 0) { 2 } else { 8 }
    $verbose = if ($Encryption -eq "none") { "true" } else { "false" }
    $cleanup = if ($Index % 2 -eq 0) { "true" } else { "false" }
    $regperm = if ($Index % 3 -eq 0) { "true" } else { "false" }
    $cfmutation = if ($Index % 4 -eq 0) { "true" } else { "false" }
    $instrsubst = if ($Index % 5 -eq 0) { "true" } else { "false" }

    $options = @(
        "compression=$Compression"
        "encryption=$Encryption"
        "inmemory=$Mode"
        "polymorphic=$poly"
        "junkdensity=$junkdensity"
        "padding=$padding"
        "level=$level"
        "verbose=$verbose"
        "cleanup=$cleanup"
        "regperm=$regperm"
        "cfmutation=$cfmutation"
        "instrsubst=$instrsubst"
    ) -join ","

    $safeJunk = $junkdensity.Replace(".", "p")
    $name = "{0:D2}_comp-{1}_enc-{2}_mode-{3}_poly-{4}_pad-{5}_junk-{6}" -f $Index, $Compression, $Encryption, $Mode, $poly, $padding, $safeJunk

    return [pscustomobject]@{
        Name    = $name
        Options = $options
    }
}

function Run-PEScenario {
    param([Parameter(Mandatory = $true)][pscustomobject]$Scenario)

    $scenarioDir = Join-Path $script:RunRoot "pe_$($Scenario.Name)"
    [void][System.IO.Directory]::CreateDirectory($scenarioDir)
    $workBin = Join-Path $scenarioDir "pe_simple.exe"
    Copy-Item -LiteralPath $script:PEFixture -Destination $workBin -Force
    $logPath = Join-Path $scenarioDir "pack_flow.log"
    "Scenario: $($Scenario.Name)" | Out-File -FilePath $logPath
    "Options: $($Scenario.Options)" | Out-File -FilePath $logPath -Append

    Invoke-LoggedCommand -LogPath $logPath -Command $script:WindowsCLI -Arguments @("-a=mode=deep", $workBin) -WorkingDirectory $scenarioDir
    Invoke-LoggedCommand -LogPath $logPath -Command $script:WindowsCLI -Arguments @("-p=$($Scenario.Options)", $workBin) -WorkingDirectory $scenarioDir
    Invoke-LoggedCommand -LogPath $logPath -Command $script:WindowsCLI -Arguments @("-a=mode=deep", $workBin) -WorkingDirectory $scenarioDir
    Invoke-LoggedCommand -LogPath $logPath -Command $workBin -WorkingDirectory $scenarioDir
}

function Run-ELFScenario {
    param([Parameter(Mandatory = $true)][pscustomobject]$Scenario)

    $scenarioDir = Join-Path $script:RunRoot "elf_$($Scenario.Name)"
    [void][System.IO.Directory]::CreateDirectory($scenarioDir)
    $workBin = Join-Path $scenarioDir "elf_simple"
    Copy-Item -LiteralPath $script:ELFFixture -Destination $workBin -Force
    $workBinWsl = Convert-ToWslPath $workBin
    Invoke-ProcessCapture -FileName "wsl.exe" -Arguments @("bash", "-lc", "chmod +x $(Convert-ToBashLiteral $workBinWsl)")

    $scenarioDirWsl = Convert-ToWslPath $scenarioDir
    $logPath = Join-Path $scenarioDir "pack_flow.log"
    "Scenario: $($Scenario.Name)" | Out-File -FilePath $logPath
    "Options: $($Scenario.Options)" | Out-File -FilePath $logPath -Append

    $cliLiteral = Convert-ToBashLiteral $script:LinuxCLIWsl
    $binLiteral = Convert-ToBashLiteral $workBinWsl
    $cdPrefix = "cd $(Convert-ToBashLiteral $scenarioDirWsl) && "

    Invoke-LoggedCommand -LogPath $logPath -Command "wsl.exe" -Arguments @("bash", "-lc", "$cdPrefix$cliLiteral -a=mode=deep $binLiteral")
    Invoke-LoggedCommand -LogPath $logPath -Command "wsl.exe" -Arguments @("bash", "-lc", "$cdPrefix$cliLiteral -p=$($Scenario.Options) $binLiteral")
    Invoke-LoggedCommand -LogPath $logPath -Command "wsl.exe" -Arguments @("bash", "-lc", "$cdPrefix$cliLiteral -a=mode=deep $binLiteral")
    Invoke-LoggedCommand -LogPath $logPath -Command "wsl.exe" -Arguments @("bash", "-lc", "$cdPrefix$binLiteral")
}

function Main {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $script:RepoRootWsl = Convert-ToWslPath $script:RepoRoot
    $logRoot = Join-Path $PSScriptRoot "logs"
    [void][System.IO.Directory]::CreateDirectory($logRoot)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:RunRoot = Join-Path $logRoot "pack_matrix_$timestamp"
    [void][System.IO.Directory]::CreateDirectory($script:RunRoot)
    $script:RunRootWsl = Convert-ToWslPath $script:RunRoot
    $script:WindowsCLI = Join-Path $script:RunRoot "gosstrip.exe"
    $linuxCliPath = Join-Path $script:RunRoot "gosstrip-linux"
    $script:LinuxCLIWsl = Convert-ToWslPath $linuxCliPath
    $script:PEFixture = Join-Path $script:RunRoot "simple_pe.exe"
    $script:ELFFixture = Join-Path $script:RunRoot "simple_elf"
    $script:ELFFixtureWsl = Convert-ToWslPath $script:ELFFixture

    Write-Host "Building CLI binaries..."
    Build-WindowsCLI

    $hasWsl = (Get-Command wsl.exe -ErrorAction SilentlyContinue) -ne $null
    if (-not $hasWsl) {
        throw "WSL is required to exercise ELF packing scenarios but was not found."
    }
    Ensure-WslTool -Tool "go"
    Ensure-WslTool -Tool "gcc"
    Build-LinuxCLI

    if (-not (Get-Command x86_64-w64-mingw32-gcc -ErrorAction SilentlyContinue)) {
        throw "x86_64-w64-mingw32-gcc is required to build PE fixtures."
    }

    Write-Host "Building test fixtures..."
    Build-PeFixture
    Build-ElfFixture

    $compressions = @("xz", "lzma", "none")
    $encryptions = @("aes-256-gcm", "chacha20", "none")
    $peModes = @("off", "auto", "process_hollowing", "atomic_bombing")
    $elfModes = @("off", "auto", "memfd")

    $index = 0
    foreach ($comp in $compressions) {
        foreach ($enc in $encryptions) {
            foreach ($mode in $peModes) {
                $index++
                $scenario = New-PackScenario -Compression $comp -Encryption $enc -Mode $mode -Index $index
                Run-PEScenario -Scenario $scenario
            }
        }
    }

    $index = 0
    foreach ($comp in $compressions) {
        foreach ($enc in $encryptions) {
            foreach ($mode in $elfModes) {
                $index++
                $scenario = New-PackScenario -Compression $comp -Encryption $enc -Mode $mode -Index $index
                Run-ELFScenario -Scenario $scenario
            }
        }
    }

    Write-Host "Pack matrix logs available at $script:RunRoot"
}

Main
