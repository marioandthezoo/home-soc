<#
.SYNOPSIS
  Make Home SOC start automatically at logon.
.DESCRIPTION
  Two mechanisms, neither of which runs user-writable code with administrator rights:

    startup : a shortcut in the user's Startup folder (default, no admin needed).
    task    : a Scheduled Task "Home SOC" at logon, running as the current user with
              NORMAL rights (-RunLevel Limited). Registering a task needs an elevated
              PowerShell, but the task itself is not elevated.

  -Elevated additionally asks for -RunLevel Highest. That is only accepted when the whole
  install tree is writable by administrators alone: an elevated logon task that executes
  files a standard user can rewrite is a local privilege escalation, not a convenience.
  On a normal install (Home SOC living under C:\Users\<you>\...) the check fails by design
  and the script tells you what to do instead.
.PARAMETER Mode
  startup (default) or task.
.PARAMETER Elevated
  Only with -Mode task: request highest privileges. Refused unless the tree is admin-only.
.PARAMETER Remove
  Remove the autostart entry for the chosen mode instead of creating it.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\make-autostart.ps1 -Mode startup
#>
[CmdletBinding()]
param(
    [ValidateSet("startup", "task")]
    [string]$Mode = "startup",
    [switch]$Elevated,
    [switch]$Remove
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$runBat = Join-Path $root "run.bat"
$venvPythonw = Join-Path $root ".venv\Scripts\pythonw.exe"
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
$taskName = "Home SOC"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeWriterNames {
    <# Account names (localised) that may legitimately hold write access to an admin-only tree. #>
    $sids = @(
        "S-1-5-18",                                                                            # NT AUTHORITY\SYSTEM
        "S-1-5-32-544",                                                                        # BUILTIN\Administrators
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"                       # NT SERVICE\TrustedInstaller
    )
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($sid in $sids) {
        try {
            $names.Add((New-Object System.Security.Principal.SecurityIdentifier $sid).Translate([System.Security.Principal.NTAccount]).Value)
        } catch {
            # An untranslatable SID just means we will treat its ACEs as unsafe: fail closed.
        }
    }
    return $names
}

# icacls right tokens on the tree itself that let a principal tamper with the executed code.
$script:DangerousRights = @("F", "M", "W", "D", "WD", "AD", "WA", "WEA", "DC", "WDAC", "WO", "GA", "GW")
# On an ANCESTOR directory only these matter: they are what lets someone delete or re-permission
# the install directory and swap in their own. Being able to create *siblings* (AD/W) does not.
$script:DangerousParentRights = @("F", "D", "DC", "WDAC", "WO", "GA")

function Get-UnsafeWriteAces {
    <#
      Return the icacls lines of $Path (and, with -Recurse, everything under it) that grant
      write-ish access to anyone outside SYSTEM / Administrators / TrustedInstaller.

      icacls is used rather than Get-Acl because a .venv holds tens of thousands of files and
      Get-Acl per file takes minutes. Identity names are matched by suffix, which sidesteps the
      "path may contain spaces" ambiguity in icacls output entirely.

      Inherit-only ACEs (the (IO) flag) are skipped: they do not apply to the object they are
      listed on, and every object they DO apply to is listed separately with its own effective
      rights. Without this, C:\ - which carries an inherit-only Authenticated Users:(M) - would
      make every path on the machine look unsafe.
    #>
    param([string]$Path, [switch]$Recurse, [switch]$AncestorRule)

    $safe = Get-SafeWriterNames
    $dangerous = if ($AncestorRule) { $script:DangerousParentRights } else { $script:DangerousRights }
    $arguments = @($Path)
    if ($Recurse) { $arguments += @("/T", "/C", "/Q") }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & icacls.exe @arguments 2>$null
    } finally {
        $ErrorActionPreference = $previous
    }
    if (-not $lines) { return @("<could not read the ACL of $Path>") }

    $bad = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        $text = [string]$line
        if ($text -notmatch '(?<rights>(\([A-Za-z_,]+\))+)\s*$') { continue }
        $rights = $Matches['rights']
        $prefix = $text.Substring(0, $text.Length - $rights.Length).TrimEnd().TrimEnd(':')
        if (-not $prefix) { continue }

        $tokens = @($rights.Trim('(', ')') -split '\)\(' | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToUpperInvariant() })
        if ($tokens -contains "IO") { continue }
        $writes = @($tokens | Where-Object { $dangerous -contains $_ })
        if ($writes.Count -eq 0) { continue }

        $isSafe = $false
        foreach ($name in $safe) {
            if ($prefix.EndsWith($name, [System.StringComparison]::OrdinalIgnoreCase)) { $isSafe = $true; break }
        }
        if (-not $isSafe) { $bad.Add($text.Trim()) }
    }
    return $bad
}

function Test-TreeIsAdminOnly {
    <# The tree AND every ancestor directory must be admin-only: a writable parent lets a
       standard user rename the folder away and drop a replacement in its place. #>
    param([string]$Path)

    $offenders = New-Object System.Collections.Generic.List[string]
    $ancestor = Split-Path -Parent $Path
    while ($ancestor) {
        foreach ($ace in (Get-UnsafeWriteAces -Path $ancestor -AncestorRule)) { $offenders.Add("$ancestor  ->  $ace") }
        $next = Split-Path -Parent $ancestor
        if ($next -eq $ancestor) { break }
        $ancestor = $next
    }
    foreach ($ace in (Get-UnsafeWriteAces -Path $Path -Recurse)) { $offenders.Add($ace) }
    return $offenders
}

# ------------------------------------------------------------------- startup mode

if ($Mode -eq "startup") {
    $startupDir = [Environment]::GetFolderPath("Startup")
    $lnk = Join-Path $startupDir "Home SOC.lnk"
    if ($Remove) {
        if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Host "[Home SOC] removed $lnk" }
        else { Write-Host "[Home SOC] no Startup shortcut found" }
        exit 0
    }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($lnk)
    $shortcut.TargetPath = $runBat
    # --autostart: run.bat then never waits on `pause`, so a failed logon start cannot sit
    # forever as an invisible minimised console. It logs to data\logs\launcher.log instead.
    $shortcut.Arguments = "--autostart"
    $shortcut.WorkingDirectory = $root
    $shortcut.WindowStyle = 7   # minimized console
    $shortcut.Description = "Home SOC - home network security monitor"
    $shortcut.Save()
    Write-Host "[Home SOC] autostart shortcut created: $lnk"
    Write-Host "           It runs run.bat --autostart; failures are logged to data\logs\launcher.log."
    exit 0
}

# ---------------------------------------------------------------------- task mode

if (-not (Test-IsAdmin)) {
    Write-Host "[Home SOC] -Mode task needs an elevated PowerShell to register the task (Run as Administrator)." -ForegroundColor Red
    Write-Host "           The task itself runs with your normal rights. Use -Mode startup for the no-admin path." -ForegroundColor Yellow
    exit 1
}
if ($Remove) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "[Home SOC] removed scheduled task '$taskName'"
    } else {
        Write-Host "[Home SOC] no scheduled task '$taskName' found"
    }
    exit 0
}

# The task executes a fixed command, never run.bat: run.bat installs from requirements.txt at
# every start, and a logon task must not run pip.
if (Test-Path $venvPythonw) {
    $execute = $venvPythonw
} elseif (Test-Path $venvPython) {
    $execute = $venvPython
} else {
    Write-Host "[Home SOC] .venv is missing. Run scripts\install.ps1 (or run.bat once) first, then re-run this script." -ForegroundColor Red
    exit 1
}
$argument = "-m homesoc run"

$runLevel = "Limited"
if ($Elevated) {
    Write-Host "[Home SOC] checking whether $root can be modified by non-administrators ..."
    $offenders = @(Test-TreeIsAdminOnly -Path $root)   # @() so .Count is reliable for 0 and 1
    if ($offenders.Count -gt 0) {
        Write-Host ""
        Write-Host "[Home SOC] refusing to register an ELEVATED logon task." -ForegroundColor Red
        Write-Host "  An elevated task runs $execute and the Python code under $root at every logon."
        Write-Host "  These entries let a standard user (i.e. any malware running as you, without a UAC prompt)"
        Write-Host "  rewrite that code and have Windows execute it as full Administrator:"
        foreach ($ace in ($offenders | Select-Object -Unique -First 8)) { Write-Host "    $ace" -ForegroundColor Yellow }
        if ($offenders.Count -gt 8) { Write-Host ("    ... and {0} more" -f ($offenders.Count - 8)) -ForegroundColor Yellow }
        Write-Host ""
        Write-Host "  Do one of these instead:" -ForegroundColor Green
        Write-Host "    * Drop -Elevated. A normal-rights logon task covers everything except the handful of"
        Write-Host "      posture checks that need admin; Home SOC reports those as 'needs administrator'"
        Write-Host "      (SOC-SYS-002) rather than as failures."
        Write-Host "    * When you do want those checks, run them on demand from an elevated prompt:"
        Write-Host "      .venv\Scripts\python.exe -m homesoc scan --only host"
        Write-Host "    * Or reinstall Home SOC somewhere only administrators can write, e.g."
        Write-Host "      C:\Program Files\HomeSOC (copy the tree there and let it inherit that folder's ACL),"
        Write-Host "      and keep the data under your own profile: set HOMESOC_DATA to"
        Write-Host "      %LOCALAPPDATA%\HomeSOC\data. Do not use a folder such as C:\HomeSOC-data: folders"
        Write-Host "      under C:\ let every local account modify them. (Home SOC resets a data folder"
        Write-Host "      outside your profile to owner + SYSTEM + Administrators on first start, but the"
        Write-Host "      profile is the safe place.) Then re-run this script with -Elevated."
        exit 1
    }
    Write-Host "[Home SOC] tree is admin-only; an elevated task is safe here."
    $runLevel = "Highest"
}

$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute $execute -Argument $argument -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel $runLevel -User $user -Force | Out-Null
Write-Host "[Home SOC] scheduled task '$taskName' registered (at logon, run level: $runLevel)."
Write-Host "           Command: $execute $argument"
Write-Host "           Remove the Startup-folder shortcut if you created one: make-autostart.ps1 -Mode startup -Remove"
