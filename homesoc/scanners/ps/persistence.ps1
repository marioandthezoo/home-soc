# persistence.ps1 -- Home SOC autostart / persistence probe (SPEC 6.9).
#
# Invoked as: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File persistence.ps1
# Emits exactly ONE compact JSON object on stdout:
#   run_keys : HKCU/HKLM Run + RunOnce (+ WOW6432Node) values
#   startup  : shortcuts/files in the user and common Startup folders (with resolved .lnk targets)
#   tasks    : scheduled tasks outside the \Microsoft\ task folder
#   services : every Auto-start service, with the parsed executable and, for executables inside the
#              Windows folder, the Authenticode signer when the signature is valid. persistence.py
#              decides which services are part of Windows (is_windows_service); this probe does not.
#              (fallback: System log event 7045 "new service installed" in the last 7 days)
#   windir   : $env:SystemRoot, for that decision
#   errors   : per-section 'ACCESS_DENIED' / 'ERROR: ...'
# Non-admin readers see their own tasks plus world-readable ones; that is what we baseline.
#
# Security (second security round): nothing here filters on a field an attacker writes. A task's
# Author is free text chosen by whoever registers it (a standard user can register a task in "\"
# with <Author>Microsoft Corporation</Author>), so tasks are filtered only by the \Microsoft\ folder,
# which standard users cannot write to. Services are no longer dropped by a string prefix test.

param([int]$ServiceEventDays = 7)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$script:Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Invoke-Probe {
    param([scriptblock]$Block)
    try {
        $r = & $Block
        return $r
    } catch {
        $m = [string]$_.Exception.Message
        if ($_.Exception -is [System.UnauthorizedAccessException] -or
            $_.Exception -is [System.Security.SecurityException] -or
            $m -match 'denied|elevat|privilege|administrator|not permitted|requires.*admin') {
            return 'ACCESS_DENIED'
        }
        return "ERROR: $m"
    }
}

$errors = @{}

# --- Run / RunOnce keys ----------------------------------------------------------------------
$runKeys = @()
$keyPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
)
foreach ($kp in $keyPaths) {
    if ($kp -like '*User Shell Folders') { continue }   # reserved for future Startup-folder redirection checks
    if (-not (Test-Path $kp)) { continue }
    $props = Invoke-Probe { Get-ItemProperty -Path $kp -ErrorAction Stop }
    if ($props -is [string]) { $errors[$kp] = $props; continue }
    if ($null -eq $props) { continue }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
        $runKeys += @{
            hive = $kp.Substring(0, 4)
            key = $kp
            name = [string]$p.Name
            command = [string]$p.Value
        }
    }
}

# --- Startup folders -------------------------------------------------------------------------
$startup = @()
$shell = $null
try { $shell = New-Object -ComObject WScript.Shell } catch {}
$folders = @(
    @{ scope = 'user'; path = [Environment]::GetFolderPath('Startup') },
    @{ scope = 'common'; path = [Environment]::GetFolderPath('CommonStartup') }
)
foreach ($f in $folders) {
    if (-not $f.path -or -not (Test-Path $f.path)) { continue }
    $files = Invoke-Probe { Get-ChildItem -Path $f.path -File -Force -ErrorAction Stop }
    if ($files -is [string]) { $errors["startup_$($f.scope)"] = $files; continue }
    foreach ($fi in @($files)) {
        if ($null -eq $fi -or $fi.Name -eq 'desktop.ini') { continue }
        $target = $null; $args_ = $null
        if ($shell -and $fi.Extension -ieq '.lnk') {
            try { $lnk = $shell.CreateShortcut($fi.FullName); $target = [string]$lnk.TargetPath; $args_ = [string]$lnk.Arguments } catch {}
        }
        $startup += @{
            scope = $f.scope
            folder = [string]$f.path
            name = [string]$fi.Name
            target = $target
            arguments = $args_
            modified = $fi.LastWriteTimeUtc.ToString('o')
        }
    }
}

# --- Scheduled tasks (non-Microsoft) ---------------------------------------------------------
$tasks = @()
$tl = Invoke-Probe { Get-ScheduledTask -ErrorAction Stop }
if ($tl -is [string]) {
    $errors['tasks'] = $tl
} else {
    foreach ($t in @($tl)) {
        if ($null -eq $t) { continue }
        # Only the \Microsoft\ folder is skipped (standard users have read-only access to it).
        # Author is NOT a filter: it is attacker-chosen text.
        if ([string]$t.TaskPath -like '\Microsoft\*') { continue }
        $actions = @()
        foreach ($a in @($t.Actions)) {
            if ($null -eq $a) { continue }
            $exe = [string]$a.Execute
            if ($exe) { $actions += ("$exe $([string]$a.Arguments)").Trim() }
        }
        if ($actions.Count -eq 0) { continue }   # COM-handler-only tasks carry no command line worth baselining
        $tasks += @{
            name = [string]$t.TaskName
            path = [string]$t.TaskPath
            author = [string]$t.Author
            state = [string]$t.State
            command = ($actions -join ' && ')
            run_level = [string]$t.Principal.RunLevel
            user = [string]$t.Principal.UserId
        }
    }
}

# --- Services: Auto start, non-Windows binaries ----------------------------------------------
$services = @()
$sl = Invoke-Probe { Get-CimInstance -ClassName Win32_Service -ErrorAction Stop }
if ($sl -is [string]) {
    $errors['services'] = $sl
    # Fallback: recently installed services from the System log (readable without elevation).
    $ev = Invoke-Probe {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = (Get-Date).AddDays(-$ServiceEventDays) } -MaxEvents 100 -ErrorAction Stop
    }
    if ($ev -is [string]) {
        if ($ev -notmatch 'No events were found') { $errors['services_eventlog'] = $ev }
    } else {
        foreach ($e in @($ev)) {
            if ($null -eq $e) { continue }
            $p = $e.Properties
            $services += @{
                name = [string]$p[0].Value
                display = [string]$p[0].Value
                path = [string]$p[1].Value
                start_mode = [string]$p[3].Value
                state = $null
                account = [string]$p[4].Value
                source = 'eventlog7045'
                installed_at = $e.TimeCreated.ToUniversalTime().ToString('o')
            }
        }
    }
} else {
    $winDir = [string]$env:SystemRoot
    $winPrefix = if ($winDir) { $winDir.TrimEnd('\') + '\' } else { $null }
    $signers = @{}
    foreach ($s in @($sl)) {
        if ($null -eq $s) { continue }
        if ([string]$s.StartMode -ne 'Auto') { continue }
        $path = [string]$s.PathName
        # Executable = the quoted part, or everything up to the first space (same rule as
        # persistence.split_command, which compares the two).
        $trimmed = $path.Trim()
        $exe = $null
        if ($trimmed.StartsWith('"')) {
            $end = $trimmed.IndexOf('"', 1)
            $exe = if ($end -gt 0) { $trimmed.Substring(1, $end - 1) } else { $trimmed.Substring(1) }
        } else {
            $exe = ($trimmed -split ' ', 2)[0]
        }
        $signer = $null
        if ($exe -and $winPrefix -and $exe.StartsWith($winPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $k = $exe.ToLowerInvariant()
            if (-not $signers.ContainsKey($k)) {
                $subject = $null
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
                    if ($sig -and [string]$sig.Status -eq 'Valid' -and $sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject }
                } catch {}
                $signers[$k] = $subject
            }
            $signer = $signers[$k]
        }
        $services += @{
            name = [string]$s.Name
            display = [string]$s.DisplayName
            path = $path
            exe = $exe
            signer = $signer
            start_mode = [string]$s.StartMode
            state = [string]$s.State
            account = [string]$s.StartName
            source = 'wmi'
        }
    }
}

$result = @{
    run_keys = @($runKeys)
    startup = @($startup)
    tasks = @($tasks)
    services = @($services)
    windir = [string]$env:SystemRoot
    errors = $errors
    elapsed_sec = [math]::Round($script:Stopwatch.Elapsed.TotalSeconds, 2)
}
Write-Output ($result | ConvertTo-Json -Depth 6 -Compress)
