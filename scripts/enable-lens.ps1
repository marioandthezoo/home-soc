<#
.SYNOPSIS
  Let phones on your own Wi-Fi reach Home SOC Lens (requires Administrator).
  Adds an inbound Windows Firewall rule for the Lens HTTPS port on the Private profile,
  then prints the remaining steps.
.DESCRIPTION
  Only the firewall rule needs Administrator. Everything else - the certificate, the
  pairing code, the QR - is done by 'python -m homesoc lens ...' as your normal user.

  The rule is limited to the Private profile on purpose: on a public network (a cafe,
  an airport) Windows uses the Public profile and Lens stays unreachable, which is the
  behaviour you want from something that shows your whole network inventory.
.PARAMETER Port
  TCP port Lens is served on (default 8443; match web.port in config.toml).
.PARAMETER Remove
  Remove the rule instead of creating it.
.EXAMPLE
  .\scripts\enable-lens.ps1 -Port 8443
.EXAMPLE
  .\scripts\enable-lens.ps1 -Remove
#>
[CmdletBinding()]
param(
    [int]$Port = 8443,
    [switch]$Remove
)
$ErrorActionPreference = "Stop"
$displayName = "Home SOC Lens"

if ($Port -lt 1 -or $Port -gt 65535) {
    Write-Host "[Home SOC] -Port must be between 1 and 65535 (got $Port)." -ForegroundColor Red
    exit 2
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script needs an elevated PowerShell: right-click PowerShell -> Run as Administrator, then re-run it." -ForegroundColor Red
    Write-Host "It only adds one inbound firewall rule; nothing else about Lens needs Administrator." -ForegroundColor Red
    exit 1
}

# Idempotent: drop any previous rule with our name before (re)creating it, so changing
# the port does not leave the old one open.
Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) {
    Write-Host "[Home SOC] firewall rule '$displayName' removed. Phones can no longer reach Lens."
    exit 0
}

New-NetFirewallRule -DisplayName $displayName -Name "HomeSOC-Lens-TCP" -Direction Inbound `
    -Protocol TCP -LocalPort $Port -Action Allow -Profile Private | Out-Null
Write-Host "[Home SOC] inbound firewall rule added for TCP $Port (Private profile)."

$ipConfig = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | Select-Object -First 1
$myIp = if ($ipConfig) { $ipConfig.IPv4Address[0].IPAddress } else { "<this PC's IP>" }
$netProfile = (Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  1. In config.toml set:"
Write-Host "       [web]   host = `"0.0.0.0`"   port = $Port   token = `"<keep the random one>`""
Write-Host "       [lens]  enabled = true"
Write-Host "  2. Create the certificate:   python -m homesoc lens cert --regenerate"
Write-Host "  3. Start Home SOC over HTTPS: python -m homesoc run --tls"
Write-Host "  4. Pair the phone:            python -m homesoc lens pair"
Write-Host "     Scan the QR with the phone's camera. The browser warns that the certificate"
Write-Host "     is not trusted - compare the fingerprint it shows with the one printed by"
Write-Host "     'lens pair', then continue."
Write-Host "  5. Check from the phone:      https://${myIp}:$Port/lens"
Write-Host ""
Write-Host "To undo: .\scripts\enable-lens.ps1 -Port $Port -Remove"
Write-Host ""
if ($netProfile -ne "Private") {
    Write-Host "Note: the active network profile is '$netProfile'. This rule applies to the Private profile only;" -ForegroundColor Yellow
    Write-Host "      set your home Wi-Fi to Private (Settings -> Network -> Wi-Fi -> your network -> Private)," -ForegroundColor Yellow
    Write-Host "      or the phone cannot reach port $Port." -ForegroundColor Yellow
    Write-Host ""
}
Write-Host "Lens shows everything Home SOC knows about a device, so keep web.token set and revoke"
Write-Host "phones you no longer use: python -m homesoc lens tokens / lens revoke <id>"
