<#
.SYNOPSIS
    Builds (and optionally runs) the C and C++ examples against the NeoHook C ABI.

.DESCRIPTION
    Builds the neohook cdylib with cargo, then compiles every example in
    examples/c and examples/cpp with MSVC, linking against the generated import
    library. The DLL is copied next to the executables so they can be run in
    place.

    Must be run from an MSVC developer prompt (cl.exe on PATH), or with
    -VcVarsAll pointing at vcvarsall.bat.

.EXAMPLE
    .\examples\build.ps1 -Run

.EXAMPLE
    .\examples\build.ps1 -Target i686-pc-windows-msvc -Run
#>
[CmdletBinding()]
param(
    # Rust target triple; also selects the MSVC host architecture.
    [ValidateSet('x86_64-pc-windows-msvc', 'i686-pc-windows-msvc')]
    [string]$Target = 'x86_64-pc-windows-msvc',

    [ValidateSet('debug', 'release')]
    [string]$Config = 'release',

    # Run each example after building and fail on a non-zero exit code.
    [switch]$Run,

    # Path to vcvarsall.bat; only needed when cl.exe is not already on PATH.
    [string]$VcVarsAll
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$includeDir = Join-Path $repoRoot 'include'
$outDir = Join-Path $repoRoot "target\examples-native\$Target"
$arch = if ($Target -eq 'i686-pc-windows-msvc') { 'x86' } else { 'x64' }

# cargo and cl report progress on stderr, which Windows PowerShell turns into a
# terminating error under $ErrorActionPreference = 'Stop'. Run native tools with
# that relaxed and judge them by their exit code instead.
function Invoke-Native
{
    param(
        [Parameter(Mandatory)][string]$Exe,
        [string[]]$Arguments = @()
    )

    # No return value: the tool's own output must flow straight to the console.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Exe @Arguments } finally { $ErrorActionPreference = $previous }

    if ($LASTEXITCODE -ne 0) {
        throw "$(Split-Path -Leaf $Exe) failed with exit code $LASTEXITCODE"
    }
}

# --- MSVC environment ---------------------------------------------------------

if ($VcVarsAll) {
    if (-not (Test-Path $VcVarsAll)) { throw "vcvarsall.bat not found at $VcVarsAll" }
    Write-Host "Importing MSVC environment for $arch" -ForegroundColor Cyan
    # vcvarsall's own diagnostics go to nul; only the resulting `set` dump matters.
    cmd /c "`"$VcVarsAll`" $arch >nul 2>&1 && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
    }
}

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw 'cl.exe not found. Run from an MSVC developer prompt or pass -VcVarsAll.'
}

# --- Build the library --------------------------------------------------------

Write-Host "Building neohook ($Config, $Target)" -ForegroundColor Cyan
$cargoArgs = @('build', '--target', $Target)
if ($Config -eq 'release') { $cargoArgs += '--release' }
Invoke-Native -Exe 'cargo' -Arguments $cargoArgs | Out-Null

$libDir = Join-Path $repoRoot "target\$Target\$Config"
$importLib = Join-Path $libDir 'neohook.dll.lib'
$dll = Join-Path $libDir 'neohook.dll'
foreach ($artifact in @($importLib, $dll)) {
    if (-not (Test-Path $artifact)) { throw "Missing build artifact: $artifact" }
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Copy-Item $dll $outDir -Force

# --- Compile the examples -----------------------------------------------------

$sources = @()
$sources += Get-ChildItem (Join-Path $PSScriptRoot 'c\*.c')
$sources += Get-ChildItem (Join-Path $PSScriptRoot 'cpp\*.cpp')

$built = @()
foreach ($src in $sources) {
    # c/watchdog.c and cpp/watchdog.cpp deliberately share a name, so the
    # language has to be part of the artifact name.
    $isCpp = $src.Extension -eq '.cpp'
    $stem = "$(if ($isCpp) { 'cpp' } else { 'c' })_$($src.BaseName)"
    $exe = Join-Path $outDir "$stem.exe"
    Write-Host "Compiling $($src.Name)" -ForegroundColor Cyan

    # /W4 /WX so a header that only *almost* works still fails the build.
    $clArgs = @(
        '/nologo', '/W4', '/WX', '/O2', '/MD',
        "/I$includeDir",
        $src.FullName,
        "/Fo:$(Join-Path $outDir "$stem.obj")",
        "/Fe:$exe"
    )
    if ($isCpp) { $clArgs += @('/EHsc', '/std:c++17') }
    $clArgs += @('/link', '/INCREMENTAL:NO', $importLib)

    Invoke-Native -Exe 'cl.exe' -Arguments $clArgs
    $built += $exe
}

Write-Host "`nBuilt $($built.Count) example(s) in $outDir" -ForegroundColor Green

# --- Run ----------------------------------------------------------------------

if (-not $Run) { return }

$failed = @()
foreach ($exe in $built) {
    $name = Split-Path -Leaf $exe
    Write-Host "`n=== $name ===" -ForegroundColor Yellow

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $exe } finally { $ErrorActionPreference = $previous }
    $code = $LASTEXITCODE

    if ($code -ne 0) {
        Write-Host "$name exited with $code" -ForegroundColor Red
        $failed += $name
    }
}

if ($failed.Count -gt 0) {
    throw "Failing examples: $($failed -join ', ')"
}
Write-Host "`nAll $($built.Count) example(s) passed." -ForegroundColor Green
