# updates.ps1 -- Home SOC Windows Update probe (SPEC 6.7).
#
# Invoked as: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File updates.ps1
# Emits exactly ONE compact JSON object on stdout:
#   pending      : updates from the Windows Update COM search "IsInstalled=0 and IsHidden=0"
#   pending_error: null | 'ACCESS_DENIED' | 'ERROR: ...'
#   hotfix       : last installed hotfix (Get-HotFix)
#   history      : last successful cumulative update from the WU history (more accurate than Get-HotFix)
# The COM search is the slow part (~25 s on the reference machine); winget is run from Python.

param()

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

function ConvertTo-IsoDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
        return [string]$Value
    } catch { return $null }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

$result = @{ pending = @(); pending_error = $null; hotfix = $null; history = $null }

# --- Hotfixes (fast) -------------------------------------------------------------------------
$hf = Invoke-Probe { Get-HotFix -ErrorAction Stop }
if ($hf -is [string]) {
    $result['hotfix'] = @{ error = $hf }
} else {
    $items = @($hf | Where-Object { $null -ne $_ -and $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    $last = $null
    if ($items.Count -gt 0) { $last = $items[0] }
    $result['hotfix'] = @{
        count = @($hf).Count
        last_id = $(if ($last) { [string]$last.HotFixID } else { $null })
        last_description = $(if ($last) { [string]$last.Description } else { $null })
        last_installed = $(if ($last) { $last.InstalledOn.ToString('yyyy-MM-dd') } else { $null })
        recent = @($items | Select-Object -First 10 | ForEach-Object {
            @{ id = [string]$_.HotFixID; description = [string]$_.Description; installed = $_.InstalledOn.ToString('yyyy-MM-dd') }
        })
    }
}

$result['os'] = @{
    build = [string](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuild')
    ubr = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
    display_version = [string](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion')
}

# --- Windows Update COM: history + pending search -------------------------------------------
$session = Invoke-Probe { New-Object -ComObject 'Microsoft.Update.Session' }
if ($session -is [string] -or $null -eq $session) {
    $result['pending_error'] = $(if ($session -is [string]) { $session } else { 'ERROR: cannot create Microsoft.Update.Session' })
} else {
    $searcher = $session.CreateUpdateSearcher()

    $hist = Invoke-Probe {
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 60) { $count = 60 }
        if ($count -le 0) { return @() }
        return @($searcher.QueryHistory(0, $count))
    }
    if ($hist -is [string]) {
        $result['history'] = @{ error = $hist }
    } else {
        $lastCum = $null; $lastOk = $null
        foreach ($h in @($hist)) {
            if ($null -eq $h) { continue }
            # ResultCode 2 = Succeeded, 3 = SucceededWithErrors; Operation 1 = Installation
            if ($h.Operation -ne 1 -or ($h.ResultCode -ne 2 -and $h.ResultCode -ne 3)) { continue }
            if ($null -eq $lastOk -or $h.Date -gt $lastOk.Date) { $lastOk = $h }
            if ([string]$h.Title -match 'Cumulative Update') {
                if ($null -eq $lastCum -or $h.Date -gt $lastCum.Date) { $lastCum = $h }
            }
        }
        $result['history'] = @{
            entries = @($hist).Count
            last_cumulative_title = $(if ($lastCum) { [string]$lastCum.Title } else { $null })
            last_cumulative_date = $(if ($lastCum) { ConvertTo-IsoDate $lastCum.Date } else { $null })
            last_success_title = $(if ($lastOk) { [string]$lastOk.Title } else { $null })
            last_success_date = $(if ($lastOk) { ConvertTo-IsoDate $lastOk.Date } else { $null })
        }
    }

    $search = Invoke-Probe { $searcher.Search('IsInstalled=0 and IsHidden=0') }
    if ($search -is [string]) {
        $result['pending_error'] = $search
    } elseif ($null -eq $search) {
        $result['pending_error'] = 'ERROR: search returned nothing'
    } else {
        $list = @()
        for ($i = 0; $i -lt $search.Updates.Count; $i++) {
            $u = $search.Updates.Item($i)
            if ($null -eq $u) { continue }
            $kbs = @()
            try { foreach ($k in $u.KBArticleIDs) { $kbs += "KB$k" } } catch {}
            $cats = @()
            try { foreach ($c in $u.Categories) { $cats += [string]$c.Name } } catch {}
            $list += @{
                title = [string]$u.Title
                kb = ($kbs -join ',')
                severity = [string]$u.MsrcSeverity
                categories = @($cats)
                mandatory = [bool]$u.IsMandatory
                downloaded = [bool]$u.IsDownloaded
                size_mb = [math]::Round(([double]$u.MaxDownloadSize) / 1MB, 1)
                last_deployment = ConvertTo-IsoDate $u.LastDeploymentChangeTime
            }
        }
        $result['pending'] = @($list)
        $result['search_result_code'] = [int]$search.ResultCode
    }
}

$result['elapsed_sec'] = [math]::Round($script:Stopwatch.Elapsed.TotalSeconds, 2)
Write-Output ($result | ConvertTo-Json -Depth 6 -Compress)
