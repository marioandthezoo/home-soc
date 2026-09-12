# posture.ps1 -- Home SOC Windows posture probe (SPEC 6.5).
#
# Invoked as: powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File posture.ps1
# Emits exactly ONE compact JSON object on stdout. Anything privileged that fails with an
# access-denied error is reported as the literal string 'ACCESS_DENIED' so the Python side
# can map the check to status "needs_admin" instead of "fail".
#
# Design notes:
#   * $ErrorActionPreference is SilentlyContinue globally; cmdlets that must surface an
#     access-denied condition are called with -ErrorAction Stop inside Invoke-Probe.
#   * No function is named 'Try' (reserved). Invoke-Probe is the try/catch wrapper.
#   * Dates are converted to ISO-8601 strings explicitly because ConvertTo-Json on
#     Windows PowerShell 5.1 serialises DateTime as "\/Date(...)\/".
#   * Never emit secrets (e.g. Winlogon DefaultPassword is reported as a boolean only).

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

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function ConvertTo-IsoDate {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
        return [string]$Value
    } catch { return $null }
}

function Get-DefenderSection {
    $out = @{}
    $st = Invoke-Probe { Get-MpComputerStatus -ErrorAction Stop }
    if ($st -is [string]) { return $st }
    if ($null -eq $st) { return 'ERROR: Get-MpComputerStatus returned nothing' }
    foreach ($p in @('AMServiceEnabled','AntivirusEnabled','AntispywareEnabled','RealTimeProtectionEnabled',
                     'IsTamperProtected','NISEnabled','BehaviorMonitorEnabled','OnAccessProtectionEnabled',
                     'IoavProtectionEnabled','AntivirusSignatureAge','AntispywareSignatureAge','NISSignatureAge',
                     'QuickScanAge','FullScanAge','AMRunningMode','AMProductVersion','AMEngineVersion',
                     'AntivirusSignatureVersion','IsVirtualMachine')) {
        $out[$p] = $st.$p
    }
    foreach ($p in @('AntivirusSignatureLastUpdated','QuickScanEndTime','FullScanEndTime')) {
        $out[$p] = ConvertTo-IsoDate $st.$p
    }
    $pref = Invoke-Probe { Get-MpPreference -ErrorAction Stop }
    if ($pref -is [string]) {
        $out['preference_error'] = $pref
    } elseif ($null -ne $pref) {
        foreach ($p in @('MAPSReporting','PUAProtection','CloudBlockLevel','SubmitSamplesConsent',
                         'EnableControlledFolderAccess','EnableNetworkProtection','DisableRealtimeMonitoring',
                         'DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning',
                         'ScanScheduleDay','ScanParameters','SignatureUpdateInterval')) {
            $out[$p] = $pref.$p
        }
        $out['AttackSurfaceReductionRules_Ids'] = @($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $out['AttackSurfaceReductionRules_Actions'] = @($pref.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
    }
    # Recent detections (30 days) so the posture pass alone can raise WIN-DEF-011.
    $threats = @()
    $names = @{}
    $tl = Invoke-Probe { Get-MpThreat -ErrorAction Stop }
    if ($tl -isnot [string]) {
        foreach ($t in @($tl)) { if ($null -ne $t) { $names[[string]$t.ThreatID] = [string]$t.ThreatName } }
    }
    $dl = Invoke-Probe { Get-MpThreatDetection -ErrorAction Stop }
    if ($dl -isnot [string]) {
        $since = (Get-Date).AddDays(-30)
        foreach ($d in @($dl)) {
            if ($null -eq $d) { continue }
            if ($d.InitialDetectionTime -and $d.InitialDetectionTime -lt $since) { continue }
            $threats += @{
                source = 'detection'
                threat_id = [string]$d.ThreatID
                threat_name = $names[[string]$d.ThreatID]
                detected_at = ConvertTo-IsoDate $d.InitialDetectionTime
                process = [string]$d.ProcessName
                path = [string](@($d.Resources) -join '; ')
                action_success = $d.ActionSuccess
                user = [string]$d.DomainUser
            }
        }
    }
    $out['threats'] = @($threats)
    return $out
}

function Get-FirewallSection {
    $r = Invoke-Probe { Get-NetFirewallProfile -ErrorAction Stop }
    if ($r -is [string]) { return $r }
    $list = @()
    foreach ($p in @($r)) {
        if ($null -eq $p) { continue }
        $list += @{
            name = [string]$p.Name
            enabled = ([string]$p.Enabled -eq 'True')
            default_inbound = [string]$p.DefaultInboundAction
            default_outbound = [string]$p.DefaultOutboundAction
            notify_on_listen = ([string]$p.NotifyOnListen -eq 'True')
        }
    }
    return ,@($list)   # unary comma keeps a single-element list from unrolling into a scalar
}

function Get-SmbSection {
    $r = Invoke-Probe { Get-SmbServerConfiguration -ErrorAction Stop }
    if ($r -is [string]) { return $r }
    if ($null -eq $r) { return 'ERROR: Get-SmbServerConfiguration returned nothing' }
    return @{
        EnableSMB1Protocol = [bool]$r.EnableSMB1Protocol
        RequireSecuritySignature = [bool]$r.RequireSecuritySignature
        EnableSecuritySignature = [bool]$r.EnableSecuritySignature
        EncryptData = [bool]$r.EncryptData
    }
}

function Get-ListenerSection {
    $conns = Invoke-Probe { Get-NetTCPConnection -State Listen -ErrorAction Stop }
    if ($conns -is [string]) { return $conns }
    $procs = @{}
    foreach ($p in @(Get-Process)) { if ($null -ne $p) { $procs[[int]$p.Id] = [string]$p.ProcessName } }
    $seen = @{}
    $list = @()
    foreach ($c in @($conns)) {
        if ($null -eq $c) { continue }
        $k = "$($c.LocalAddress):$($c.LocalPort)"
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $pid_ = [int]$c.OwningProcess
        $list += @{
            port = [int]$c.LocalPort
            address = [string]$c.LocalAddress
            pid = $pid_
            process = $procs[$pid_]
        }
    }
    return ,@($list | Sort-Object { $_.port })
}

function Get-AdminSection {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $mySid = [string]$id.User.Value
    $members = @()
    $err = $null
    $isMember = $false
    try {
        $m = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop
        foreach ($x in @($m)) {
            if ($null -eq $x) { continue }
            $sid = [string]$x.SID.Value
            if ($sid -and $sid -eq $mySid) { $isMember = $true }
            $members += @{ name = [string]$x.Name; sid = $sid; kind = [string]$x.ObjectClass; source = [string]$x.PrincipalSource }
        }
    } catch {
        # Get-LocalGroupMember is known to throw on Home editions with orphaned Microsoft-account SIDs.
        $err = [string]$_.Exception.Message
        $lines = & net localgroup administrators 2>$null
        $inList = $false
        foreach ($ln in @($lines)) {
            if ($ln -match '^-{5,}') { $inList = $true; continue }
            if ($ln -match 'completed successfully') { break }
            if ($inList -and $ln.Trim()) { $members += @{ name = $ln.Trim(); kind = 'unknown'; source = 'net' } }
        }
    }
    # Fallbacks for the UAC-filtered token (the deny-only Administrators SID is not always
    # surfaced by .NET): name match, token groups, then `whoami /groups`.
    $myName = [string]$id.Name
    foreach ($mm in $members) { if ($mm.name -and $mm.name -ieq $myName) { $isMember = $true } }
    foreach ($g in @($id.Groups)) { if ([string]$g.Value -eq 'S-1-5-32-544') { $isMember = $true } }
    if (-not $isMember) {
        $wg = & whoami /groups 2>$null
        foreach ($ln in @($wg)) { if ($ln -match 'S-1-5-32-544') { $isMember = $true } }
    }
    return @{
        current_user = $myName
        current_is_admin_member = $isMember
        members = @($members)
        error = $err
    }
}

function Get-LocalAccountBySidSuffix {
    param([string]$Suffix)
    $r = Invoke-Probe { Get-LocalUser -ErrorAction Stop }
    if ($r -is [string]) { return $r }
    foreach ($u in @($r)) {
        if ($null -ne $u -and [string]$u.SID.Value -like "S-1-5-21-*-$Suffix") {
            return @{ name = [string]$u.Name; enabled = [bool]$u.Enabled; last_logon = ConvertTo-IsoDate $u.LastLogon }
        }
    }
    return $null
}

function Get-HotfixSection {
    $r = Invoke-Probe { Get-HotFix -ErrorAction Stop }
    if ($r -is [string]) { return $r }
    $items = @($r | Where-Object { $null -ne $_ -and $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    $last = $null
    if ($items.Count -gt 0) { $last = $items[0] }
    return @{
        count = @($r).Count
        last_id = $(if ($last) { [string]$last.HotFixID } else { $null })
        last_description = $(if ($last) { [string]$last.Description } else { $null })
        last_installed = $(if ($last) { $last.InstalledOn.ToString('yyyy-MM-dd') } else { $null })
    }
}

function Get-WifiSection {
    $lines = & netsh wlan show interfaces 2>$null
    if (-not $lines) { return $null }
    $o = @{ connected = $false }
    foreach ($ln in @($lines)) {
        if ($ln -match '^\s*State\s*:\s*(.+)$') { $o['state'] = $Matches[1].Trim(); $o['connected'] = ($Matches[1].Trim() -eq 'connected') }
        elseif ($ln -match '^\s*SSID\s*:\s*(.+)$') { $o['ssid'] = $Matches[1].Trim() }
        elseif ($ln -match '^\s*Authentication\s*:\s*(.+)$') { $o['auth'] = $Matches[1].Trim() }
        elseif ($ln -match '^\s*Cipher\s*:\s*(.+)$') { $o['cipher'] = $Matches[1].Trim() }
        elseif ($ln -match '^\s*Band\s*:\s*(.+)$') { $o['band'] = $Matches[1].Trim() }
        elseif ($ln -match '^\s*Radio type\s*:\s*(.+)$') { $o['radio'] = $Matches[1].Trim() }
    }
    return $o
}

function Get-DnsSection {
    $r = Invoke-Probe { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop }
    if ($r -is [string]) { return $r }
    $list = @()
    foreach ($i in @($r)) {
        if ($null -eq $i -or -not $i.ServerAddresses) { continue }
        $list += @{ interface = [string]$i.InterfaceAlias; servers = @($i.ServerAddresses | ForEach-Object { [string]$_ }) }
    }
    return ,@($list)
}

function Get-PsV2Section {
    $state = Invoke-Probe { (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).State.ToString() }
    return @{
        state = $state
        # Heuristic usable without elevation: the v2 engine registers this key only when installed.
        registry_v2_engine = (Test-Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine')
    }
}

function Get-ScreenLockSection {
    $acIdle = $null
    $lines = & powercfg /q SCHEME_CURRENT SUB_VIDEO VIDEOIDLE 2>$null
    foreach ($ln in @($lines)) {
        if ($ln -match 'Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)') { $acIdle = [Convert]::ToInt32($Matches[1], 16) }
    }
    return @{
        ScreenSaveActive = Get-RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'
        ScreenSaveTimeOut = Get-RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'
        ScreenSaverIsSecure = Get-RegValue 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'
        InactivityTimeoutSecs = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
        display_off_ac_sec = $acIdle
    }
}

function Get-ServiceState {
    param([string]$Name)
    $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $s) { return $null }
    return @{ status = [string]$s.Status; start_type = [string]$s.StartType }
}

# ---------------------------------------------------------------------------------------------
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($id)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

$result = @{
    probe_version = 1
    is_admin = [bool]$isAdmin
    hostname = [string]$env:COMPUTERNAME
    os = @{
        caption = $(if ($os) { [string]$os.Caption } else { $null })
        version = $(if ($os) { [string]$os.Version } else { $null })
        build = [string](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuild')
        display_version = [string](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion')
        last_boot = $(if ($os) { ConvertTo-IsoDate $os.LastBootUpTime } else { $null })
    }
    defender = Get-DefenderSection
    firewall = Get-FirewallSection
    smb = Get-SmbSection
    rdp = @{
        fDenyTSConnections = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        UserAuthentication = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        service = Get-ServiceState 'TermService'
    }
    uac = @{
        EnableLUA = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
        ConsentPromptBehaviorAdmin = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin'
        PromptOnSecureDesktop = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop'
    }
    lsa = @{
        RunAsPPL = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
        LsaCfgFlags = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags'
    }
    secure_boot = Invoke-Probe { [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
    secure_boot_registry = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled'
    # Get-Tpm silently returns all-false fields without elevation; the WMI class raises a proper
    # access-denied error instead, so it is the one we trust for the ACCESS_DENIED mapping.
    tpm = Invoke-Probe {
        $t = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
        if ($null -eq $t) { throw 'Access denied (no Win32_Tpm instance visible)' }
        @{ present = $true; enabled = [bool]$t.IsEnabled_InitialValue; activated = [bool]$t.IsActivated_InitialValue; owned = [bool]$t.IsOwned_InitialValue; spec = [string]$t.SpecVersion }
    }
    tpm_pnp = @(Get-PnpDevice -Class SecurityDevices -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match 'Trusted Platform' } | ForEach-Object { @{ name = [string]$_.FriendlyName; status = [string]$_.Status } })
    device_guard = Invoke-Probe {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
        @{
            VirtualizationBasedSecurityStatus = [int]$dg.VirtualizationBasedSecurityStatus
            SecurityServicesRunning = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ })
            SecurityServicesConfigured = @($dg.SecurityServicesConfigured | ForEach-Object { [int]$_ })
            CodeIntegrityPolicyEnforcementStatus = [int]$dg.CodeIntegrityPolicyEnforcementStatus
        }
    }
    bitlocker = Invoke-Probe {
        $vols = Get-BitLockerVolume -ErrorAction Stop
        ,@(@($vols) | Where-Object { $null -ne $_ } | ForEach-Object {
            @{ mount = [string]$_.MountPoint; protection = [string]$_.ProtectionStatus; status = [string]$_.VolumeStatus; type = [string]$_.VolumeType; percent = $_.EncryptionPercentage }
        })
    }
    admins = Get-AdminSection
    guest = Get-LocalAccountBySidSuffix '501'
    builtin_admin = Get-LocalAccountBySidSuffix '500'
    listeners = Get-ListenerSection
    hotfix = Get-HotfixSection
    wifi = Get-WifiSection
    dns = Get-DnsSection
    llmnr = @{ EnableMulticast = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' }
    ps_v2 = Get-PsV2Section
    autologon = @{
        AutoAdminLogon = [string](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')
        DefaultUserName = [string](Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName')
        has_default_password = ($null -ne (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword'))
    }
    smartscreen = @{
        SmartScreenEnabled = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
        policy_EnableSmartScreen = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
        apps_EnableWebContentEvaluation = Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' 'EnableWebContentEvaluation'
    }
    smart_app_control = @{
        VerifiedAndReputablePolicyState = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
    }
    screen_lock = Get-ScreenLockSection
    winrm = Get-ServiceState 'WinRM'
    remote_registry = Get-ServiceState 'RemoteRegistry'
}

$result['elapsed_sec'] = [math]::Round($script:Stopwatch.Elapsed.TotalSeconds, 2)
Write-Output ($result | ConvertTo-Json -Depth 6 -Compress)
