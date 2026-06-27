# Build script for Windows (PowerShell)
# PhantomLDAP — PowerShell Build Script
# 
# This script cross-compiles PhantomLDAP BOF modules on Windows using
# either a locally installed MinGW-w64 toolchain or Windows Subsystem
# for Linux (WSL).
#
# Usage:
#   .\scripts\build.ps1
#   .\scripts\build.ps1 -Clean
#   .\scripts\build.ps1 -Module enum_spn
#   .\scripts\build.ps1 -UseWSL
#

param(
    [switch]$Clean,
    [string]$Module = "all",
    [switch]$UseWSL,
    [switch]$Verbose,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$BANNER = @"
================================================================
 PhantomLDAP Build Script (Windows/PowerShell)
 Version: 1.0.0
================================================================
"@

$MODULES = @(
    "enum_admins",
    "enum_spn",
    "enum_asrep",
    "enum_computers",
    "enum_trusts",
    "enum_gpo",
    "enum_acl",
    "ldap_query"
)

$CFLAGS = @(
    "-Wall",
    "-Wextra",
    "-Wno-unused-parameter",
    "-Wno-implicit-function-declaration",
    "-nostdlib",
    "-masm=intel",
    "-fno-builtin",
    "-fno-stack-protector",
    "-ffunction-sections",
    "-fdata-sections",
    "-O2",
    "-Iinclude",
    "-D_WIN64",
    "-DUNICODE",
    "-D_UNICODE"
)

function Write-PhantomLog {
    param([string]$Level, [string]$Message, [ConsoleColor]$Color = [ConsoleColor]::White)
    Write-Host "[$Level] $Message" -ForegroundColor $Color
}

function Write-OK   { Write-PhantomLog "OK" $args[0] Green }
function Write-Info { Write-PhantomLog "*"  $args[0] Cyan  }
function Write-Fail { Write-PhantomLog "!"  $args[0] Red   }
function Write-Warn { Write-PhantomLog "~"  $args[0] Yellow }

function Show-Help {
    Write-Host $BANNER
    Write-Host ""
    Write-Host "Usage: .\scripts\build.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Clean          Remove build directory and exit"
    Write-Host "  -Module NAME    Build a specific module (e.g., -Module enum_spn)"
    Write-Host "  -UseWSL         Use WSL (make all) instead of native MinGW"
    Write-Host "  -Verbose        Show verbose compiler output"
    Write-Host "  -Help           Show this message"
    Write-Host ""
    Write-Host "Available modules:"
    foreach ($m in $MODULES) {
        Write-Host "  $m"
    }
    exit 0
}

function Find-MinGW {
    # Search common installation paths for MinGW-w64
    $paths = @(
        "C:\mingw64\bin\x86_64-w64-mingw32-gcc.exe",
        "C:\Program Files\mingw-w64\x86_64-*\mingw64\bin\x86_64-w64-mingw32-gcc.exe",
        "C:\msys64\mingw64\bin\x86_64-w64-mingw32-gcc.exe",
        "C:\msys64\usr\bin\x86_64-w64-mingw32-gcc.exe",
        "C:\ProgramData\chocolatey\bin\x86_64-w64-mingw32-gcc.exe"
    )
    
    foreach ($p in $paths) {
        $resolved = Resolve-Path $p -ErrorAction SilentlyContinue
        if ($resolved) {
            return $resolved.Path
        }
    }
    
    # Try PATH
    $gcc = Get-Command "x86_64-w64-mingw32-gcc" -ErrorAction SilentlyContinue
    if ($gcc) { return $gcc.Path }
    
    return $null
}

function Invoke-Build-WSL {
    Write-Info "Using WSL to invoke make..."
    
    $wsl = Get-Command wsl -ErrorAction SilentlyContinue
    if (-not $wsl) {
        Write-Fail "WSL not found. Install WSL or use native MinGW."
        exit 1
    }
    
    # Get WSL path to project
    $wslPath = (wsl wslpath -a "$PWD").Trim().Replace("\", "/")
    
    if ($Clean) {
        wsl -e bash -c "cd '$wslPath' && make clean"
    } else {
        $target = if ($Module -eq "all") { "all" } else { $Module }
        wsl -e bash -c "cd '$wslPath' && make $target"
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "WSL build failed with exit code $LASTEXITCODE"
        exit 1
    }
    
    Write-OK "WSL build completed."
}

function Invoke-Build-Native {
    param([string]$GCC, [string]$LD)
    
    # Create build directory
    New-Item -ItemType Directory -Path "build\core" -Force | Out-Null
    
    $cflagsStr = $CFLAGS -join " "
    
    # Compile core objects
    Write-Info "Compiling core objects..."
    $coreFiles = @{
        "build\core\dynamic_resolve.o" = "src\core\dynamic_resolve.c"
        "build\core\ldap_ops.o"        = "src\core\ldap_ops.c"
        "build\core\output.o"          = "src\core\output.c"
    }
    
    foreach ($out in $coreFiles.Keys) {
        $src = $coreFiles[$out]
        Write-Host "  [CC] $src" -ForegroundColor Gray
        $proc = Start-Process -FilePath $GCC -ArgumentList "$cflagsStr -c `"$src`" -o `"$out`"" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-Fail "Failed to compile $src"
            exit 1
        }
    }
    Write-OK "Core objects compiled."
    
    # Build modules
    $targetModules = if ($Module -eq "all") { $MODULES } else { @($Module) }
    
    foreach ($mod in $targetModules) {
        $src = "src\modules\$mod.c"
        $modObj = "build\${mod}_mod.o"
        $finalObj = "build\$mod.o"
        
        Write-Host "  [CC] $src" -ForegroundColor Gray
        $proc = Start-Process -FilePath $GCC -ArgumentList "$cflagsStr -c `"$src`" -o `"$modObj`"" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-Fail "Failed to compile $src"
            exit 1
        }
        
        Write-Host "  [LD] Partial link -> $finalObj" -ForegroundColor Gray
        $ldArgs = "-r -o `"$finalObj`" `"$modObj`" build\core\dynamic_resolve.o build\core\ldap_ops.o build\core\output.o"
        $proc = Start-Process -FilePath $LD -ArgumentList $ldArgs -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) {
            Write-Fail "Partial link failed for $mod"
            exit 1
        }
        
        Remove-Item $modObj -ErrorAction SilentlyContinue
        
        $size = (Get-Item $finalObj).Length
        Write-OK "$finalObj ($size bytes)"
    }
}

# Main entry point
Write-Host $BANNER -ForegroundColor Cyan

if ($Help) { Show-Help }

# Clean
if ($Clean) {
    if (Test-Path "build") {
        Remove-Item "build" -Recurse -Force
        Write-OK "Build directory removed."
    } else {
        Write-Info "Nothing to clean."
    }
    exit 0
}

Write-Info "Target: $Module"

# Route to WSL or native
if ($UseWSL) {
    Invoke-Build-WSL
} else {
    $gcc = Find-MinGW
    if (-not $gcc) {
        Write-Warn "MinGW-w64 not found in PATH or standard locations."
        Write-Warn "Falling back to WSL. Use -UseWSL to skip auto-detection."
        Invoke-Build-WSL
    } else {
        $ld = $gcc -replace "gcc\.exe$", "ld.exe"
        Write-Info "Compiler: $gcc"
        Invoke-Build-Native -GCC $gcc -LD $ld
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Build Complete — BOF files in .\build\" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Info "Load .\cna\phantom_ldap.cna in Cobalt Strike to use."
