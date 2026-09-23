<#
.SYNOPSIS
  Install Home SOC for the current user (no admin): venv, dependencies, init, Startup-folder autostart.
.PARAMETER NoAutostart
  Skip creating the Startup-folder shortcut.
.PARAMETER NoFeeds
  Skip the first feed download during init (offline install).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#>
[CmdletBinding()]
param(
    [switch]$NoAutostart,
    [switch]$NoFeeds
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$MinPython = [version]"3.12"

function Get-PythonVersion {
    <#
      Probe one interpreter candidate and return its [version], or $null.

      Two traps this has to avoid, both of which used to crash the installer on any PC that
      simply has `python` on PATH:
        * `$c[1..($c.Count - 1)]` on a ONE-element array evaluates `[1..0]`, which PowerShell
          helpfully reverses into `@($c[0])` - so the probe ran `python python -c ...`.
        * a native command writing to stderr under `$ErrorActionPreference = "Stop"` becomes a
          TERMINATING NativeCommandError in Windows PowerShell 5.1, even with `2>$null`.
      So: build the argument list explicitly, and probe with the preference relaxed.
    #>
    param([string]$Exe, [string[]]$PreArgs = @())

    if (-not (Get-Command $Exe -ErrorAction SilentlyContinue)) { return $null }
    $probe = @("-c", "import sys; sys.stdout.write('%d.%d.%d' % sys.version_info[:3])")
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $global:LASTEXITCODE = 0
    try {
        $output = & $Exe @PreArgs @probe 2>$null
    } catch {
        return $null
    } finally {
        $ErrorActionPreference = $previous
    }
    # 9009 = "not recognized"; also what the Microsoft-Store python.exe stub leaves behind.
    if ($LASTEXITCODE -ne 0) { return $null }
    $text = ([string]($output | Select-Object -First 1)).Trim()
    if (-not $text) { return $null }
    try { return [version]$text } catch { return $null }
}

function Find-Python {
    <# Returns @{ Exe = "py"; Args = @("-3"); Version = [version] } for the first usable
       interpreter, or $null. Callers splat .Args - never slice the candidate again. #>
    $candidates = @(
        @{ Exe = "python";  Args = @() },
        @{ Exe = "py";      Args = @("-3") },
        @{ Exe = "python3"; Args = @() }
    )
    foreach ($candidate in $candidates) {
        $version = Get-PythonVersion -Exe $candidate.Exe -PreArgs $candidate.Args
        if ($null -eq $version) { continue }
        if ($version -ge $MinPython) {
            return @{ Exe = $candidate.Exe; Args = $candidate.Args; Version = $version }
        }
        Write-Host ("[Home SOC] {0} is Python {1}, too old (need {2}+); looking further ..." -f `
            ((@($candidate.Exe) + @($candidate.Args)) -join " "), $version, $MinPython)
    }
    return $null
}

Write-Host "[Home SOC] installing into $root"
$py = Find-Python
if (-not $py) {
    Write-Host "Python $MinPython or newer was not found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and re-run." -ForegroundColor Red
    Write-Host "If Windows opens the Microsoft Store when you type 'python', turn off the app-execution alias:" -ForegroundColor Yellow
    Write-Host "  Settings -> Apps -> Advanced app settings -> App execution aliases -> switch off python.exe / python3.exe" -ForegroundColor Yellow
    exit 1
}
$pyExe = [string]$py.Exe
$pyArgs = @($py.Args)          # splatted with @pyArgs; an empty array splats to nothing
Write-Host ("[Home SOC] using Python {0} ({1})" -f $py.Version, ((@($pyExe) + $pyArgs) -join " "))

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "[Home SOC] creating virtual environment ..."
    & $pyExe @pyArgs -m venv (Join-Path $root ".venv")
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
}
if (-not (Test-Path $venvPython)) { throw "virtual environment is missing $venvPython" }

Write-Host "[Home SOC] installing dependencies ..."
# requirements.txt is the hash-locked lock file (every transitive package, pip included):
# --require-hashes makes pip refuse anything unpinned, unlisted or whose bytes differ from it.
& $venvPython -m pip install --require-hashes -r (Join-Path $root "requirements.txt") -q --disable-pip-version-check
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

Write-Host "[Home SOC] initialising data directory, config and database ..."
$initArgs = @("-m", "homesoc", "init")
if ($NoFeeds) { $initArgs += "--no-feeds" }
& $venvPython @initArgs
if ($LASTEXITCODE -ne 0) { throw "homesoc init failed" }

if (-not $NoAutostart) {
    & (Join-Path $PSScriptRoot "make-autostart.ps1") -Mode startup
}

Write-Host ""
Write-Host "Done. Next steps:" -ForegroundColor Green
Write-Host "  1. Start now:            run.bat        (or double-click it)"
Write-Host "  2. Open the dashboard:   http://127.0.0.1:8787/"
Write-Host "  3. Tune settings:        config.toml    (or the dashboard's Settings page)"
Write-Host "  4. LAN-wide DNS filter:  set dns.enabled = true, then run scripts\enable-lan-dns.ps1 as Administrator"
Write-Host "  5. Notifications:        set notify.ntfy_url / discord_webhook in config.toml"
