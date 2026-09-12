# defender.ps1 -- Home SOC Microsoft Defender probe (SPEC 6.6).
#
# Invoked as: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File defender.ps1 -Action <status|threats> [-Days N]
# Emits exactly ONE compact JSON object on stdout.
#   -Action status  -> Get-MpComputerStatus + Get-MpPreference subset (same shape as posture.ps1 "defender").
#   -Action threats -> {"detections":[...], "events":[...], "activity":{...}, "errors":{...}} where events
#                      come from the Microsoft-Windows-Windows Defender/Operational log (IDs 1006,1007,1116,
#                      1117,1118,1119,5001,5010,5012), newest first, capped at 200, and "activity" summarises
#                      scan / signature-update events (1000,1001,1002,2000,2001,2003,2004,5007) from the same log.
# Privileged failures are reported as the literal string 'ACCESS_DENIED'.

param(
    [string]$Action = 'status',
    [int]$Days = 30
)

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

function Get-DefenderStatus {
    $out = @{}
    $st = Invoke-Probe { Get-MpComputerStatus -ErrorAction Stop }
    if ($st -is [string]) { return @{ error = $st } }
    if ($null -eq $st) { return @{ error = 'ERROR: Get-MpComputerStatus returned nothing' } }
    foreach ($p in @('AMServiceEnabled','AntivirusEnabled','AntispywareEnabled','RealTimeProtectionEnabled',
                     'IsTamperProtected','NISEnabled','BehaviorMonitorEnabled','OnAccessProtectionEnabled',
                     'IoavProtectionEnabled','AntivirusSignatureAge','AntispywareSignatureAge','NISSignatureAge',
                     'QuickScanAge','FullScanAge','AMRunningMode','AMProductVersion','AMEngineVersion',
                     'AntivirusSignatureVersion','AntispywareSignatureVersion','NISSignatureVersion',
                     'IsVirtualMachine','ComputerState','DeviceControlState')) {
        $out[$p] = $st.$p
    }
    foreach ($p in @('AntivirusSignatureLastUpdated','AntispywareSignatureLastUpdated','QuickScanEndTime',
                     'FullScanEndTime','QuickScanStartTime','FullScanStartTime')) {
        $out[$p] = ConvertTo-IsoDate $st.$p
    }
    $pref = Invoke-Probe { Get-MpPreference -ErrorAction Stop }
    if ($pref -is [string]) {
        $out['preference_error'] = $pref
    } elseif ($null -ne $pref) {
        foreach ($p in @('MAPSReporting','PUAProtection','CloudBlockLevel','CloudExtendedTimeout','SubmitSamplesConsent',
                         'EnableControlledFolderAccess','EnableNetworkProtection','DisableRealtimeMonitoring',
                         'DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning',
                         'DisableArchiveScanning','DisableRemovableDriveScanning','ScanScheduleDay',
                         'ScanParameters','SignatureUpdateInterval','CheckForSignaturesBeforeRunningScan')) {
            $out[$p] = $pref.$p
        }
        $out['AttackSurfaceReductionRules_Ids'] = @($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $out['AttackSurfaceReductionRules_Actions'] = @($pref.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
        $out['ExclusionPath_count'] = @($pref.ExclusionPath).Count
        $out['ExclusionProcess_count'] = @($pref.ExclusionProcess).Count
        $out['ExclusionExtension_count'] = @($pref.ExclusionExtension).Count
    }
    # Platform folder holding MpCmdRun.exe when the Program Files copy is a stub.
    $platform = $null
    try {
        $base = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
        if (Test-Path $base) {
            $dirs = Get-ChildItem -Path $base -Directory -ErrorAction Stop | Sort-Object Name -Descending
            foreach ($d in @($dirs)) {
                if (Test-Path (Join-Path $d.FullName 'MpCmdRun.exe')) { $platform = $d.FullName; break }
            }
        }
    } catch {}
    $out['platform_dir'] = $platform
    $out['smart_app_control'] = $null
    try {
        $sac = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop
        $out['smart_app_control'] = $sac.VerifiedAndReputablePolicyState
    } catch {}
    return $out
}

function Get-DefenderThreats {
    param([int]$SinceDays)
    $errors = @{}
    $since = (Get-Date).AddDays(-$SinceDays)

    # 1. Detections known to the AV engine.
    $names = @{}
    $tl = Invoke-Probe { Get-MpThreat -ErrorAction Stop }
    if ($tl -is [string]) { $errors['get_mpthreat'] = $tl }
    else { foreach ($t in @($tl)) { if ($null -ne $t) { $names[[string]$t.ThreatID] = @{ name = [string]$t.ThreatName; severity = [int]$t.SeverityID; category = [int]$t.CategoryID } } } }

    $detections = @()
    $dl = Invoke-Probe { Get-MpThreatDetection -ErrorAction Stop }
    if ($dl -is [string]) { $errors['get_mpthreatdetection'] = $dl }
    else {
        foreach ($d in @($dl)) {
            if ($null -eq $d) { continue }
            if ($d.InitialDetectionTime -and $d.InitialDetectionTime -lt $since) { continue }
            $meta = $names[[string]$d.ThreatID]
            $detections += @{
                source = 'detection'
                threat_id = [string]$d.ThreatID
                threat_name = $(if ($meta) { $meta.name } else { $null })
                severity = $(if ($meta) { $meta.severity } else { $null })
                detected_at = ConvertTo-IsoDate $d.InitialDetectionTime
                last_action_at = ConvertTo-IsoDate $d.LastThreatStatusChangeTime
                process = [string]$d.ProcessName
                path = [string](@($d.Resources) -join '; ')
                action_success = $d.ActionSuccess
                status = [int]$d.ThreatStatusID
                user = [string]$d.DomainUser
            }
        }
    }

    # 2. Operational event log (readable without elevation; Security log is not).
    $events = @()
    $ev = Invoke-Probe {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            Id = @(1006, 1007, 1116, 1117, 1118, 1119, 5001, 5010, 5012)
            StartTime = $since
        } -MaxEvents 200 -ErrorAction Stop
    }
    if ($ev -is [string]) {
        # "No events were found" is not an error worth surfacing.
        if ($ev -notmatch 'No events were found') { $errors['get_winevent'] = $ev }
    } else {
        foreach ($e in @($ev)) {
            if ($null -eq $e) { continue }
            $data = @{}
            try {
                $x = [xml]$e.ToXml()
                foreach ($n in @($x.Event.EventData.Data)) {
                    if ($null -ne $n -and $n.Name) { $data[[string]$n.Name] = [string]$n.'#text' }
                }
            } catch {}
            $msg = [string]$e.Message
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
            $events += @{
                source = 'event'
                event_id = [int]$e.Id
                time = ConvertTo-IsoDate $e.TimeCreated
                threat_name = $data['Threat Name']
                path = $data['Path']
                severity = $data['Severity Name']
                action = $data['Action Name']
                user = $data['Detection User']
                process = $data['Process Name']
                status = $data['Status Description']
                message = $msg
            }
        }
    }
    # 3. Scan / signature-update history. On a clean machine none of the malware IDs above ever
    #    fire, so these are the only proof in the log that Defender is actually working. Reduced to
    #    a summary here rather than returned as rows: 5007 alone can be hundreds of events.
    $activity = @{
        last_scan_started = $null; last_scan_finished = $null; last_scan_type = $null
        last_scan_cancelled = $null; last_signature_update = $null; last_signature_version = $null
        last_signature_failure = $null; last_signature_failure_reason = $null
        config_changes = 0; scans = 0; signature_updates = 0
    }
    $av = Invoke-Probe {
        Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Windows Defender/Operational'
            Id = @(1000, 1001, 1002, 2000, 2001, 2003, 2004, 5007)
            StartTime = $since
        } -MaxEvents 500 -ErrorAction Stop
    }
    if ($av -is [string]) {
        if ($av -notmatch 'No events were found') { $errors['get_winevent_activity'] = $av }
    } else {
        # Newest first, so the first event of each kind is the latest one.
        foreach ($e in @($av)) {
            if ($null -eq $e) { continue }
            $d = @{}
            try {
                $x = [xml]$e.ToXml()
                foreach ($n in @($x.Event.EventData.Data)) {
                    if ($null -ne $n -and $n.Name) { $d[[string]$n.Name] = [string]$n.'#text' }
                }
            } catch {}
            $when = ConvertTo-IsoDate $e.TimeCreated
            switch ([int]$e.Id) {
                1000 {
                    $activity['scans'] = $activity['scans'] + 1
                    if (-not $activity['last_scan_started']) {
                        $activity['last_scan_started'] = $when
                        $activity['last_scan_type'] = $d['Scan Type']
                    }
                }
                1001 { if (-not $activity['last_scan_finished']) { $activity['last_scan_finished'] = $when } }
                1002 { if (-not $activity['last_scan_cancelled']) { $activity['last_scan_cancelled'] = $when } }
                2000 {
                    $activity['signature_updates'] = $activity['signature_updates'] + 1
                    if (-not $activity['last_signature_update']) {
                        $activity['last_signature_update'] = $when
                        $activity['last_signature_version'] = $d['Current security intelligence Version']
                    }
                }
                2001 {
                    if (-not $activity['last_signature_failure']) {
                        $activity['last_signature_failure'] = $when
                        $activity['last_signature_failure_reason'] = $d['Error Description']
                    }
                }
                2003 {
                    if (-not $activity['last_signature_failure']) {
                        $activity['last_signature_failure'] = $when
                        $activity['last_signature_failure_reason'] = $d['Error Description']
                    }
                }
                2004 {
                    if (-not $activity['last_signature_failure']) {
                        $activity['last_signature_failure'] = $when
                        $activity['last_signature_failure_reason'] = $d['Error Description']
                    }
                }
                5007 { $activity['config_changes'] = $activity['config_changes'] + 1 }
            }
        }
    }

    return @{ detections = @($detections); events = @($events); activity = $activity; errors = $errors; days = $SinceDays }
}

switch ($Action.ToLowerInvariant()) {
    'threats' { $result = Get-DefenderThreats -SinceDays $Days }
    default { $result = Get-DefenderStatus }
}
$result['elapsed_sec'] = [math]::Round($script:Stopwatch.Elapsed.TotalSeconds, 2)
Write-Output ($result | ConvertTo-Json -Depth 6 -Compress)
