<#
.SYNOPSIS
  Allow LAN devices to reach the Home SOC DNS filter (requires Administrator).
  Adds inbound Windows Firewall rules for UDP and TCP port 53 on the Private profile,
  then prints the router-side instructions.
.PARAMETER Remove
  Remove the rules instead of creating them.
.PARAMETER Port
  DNS port (default 53; match dns.port in config.toml).
#>
[CmdletBinding()]
param(
    [switch]$Remove,
    [int]$Port = 53
)
$ErrorActionPreference = "Stop"
$displayName = "Home SOC DNS"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script needs an elevated PowerShell: right-click PowerShell -> Run as Administrator, then re-run it." -ForegroundColor Red
    exit 1
}

# Idempotent: drop any previous rules with our name before (re)creating them.
Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($Remove) {
    Write-Host "[Home SOC] firewall rules '$displayName' removed."
    exit 0
}

New-NetFirewallRule -DisplayName $displayName -Name "HomeSOC-DNS-UDP" -Direction Inbound -Protocol UDP -LocalPort $Port -Action Allow -Profile Private | Out-Null
New-NetFirewallRule -DisplayName $displayName -Name "HomeSOC-DNS-TCP" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Private | Out-Null
Write-Host "[Home SOC] inbound firewall rules added for UDP/TCP $Port (Private profile)."

$ipConfig = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address } | Select-Object -First 1
$myIp = if ($ipConfig) { $ipConfig.IPv4Address[0].IPAddress } else { "<this PC's IP>" }
$gateway = if ($ipConfig) { $ipConfig.IPv4DefaultGateway[0].NextHop } else { "<router IP>" }
$profile = (Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory

Write-Host ""
Write-Host "Next steps on the router ($gateway):" -ForegroundColor Green
Write-Host "  1. Give this PC a fixed address: DHCP reservation for $myIp (LAN -> DHCP -> reservations / static leases)."
Write-Host "  2. Set the DHCP DNS server handed to clients to $myIp (some routers call it 'Primary DNS' under LAN/DHCP settings)."
Write-Host "     If the router cannot change the DHCP DNS (AT&T gateways often cannot), set DNS = $myIp on each device instead,"
Write-Host "     or use the router's 'DNS relay/override' if present."
Write-Host "  3. In config.toml set dns.enabled = true (dns.listen = 0.0.0.0, dns.port = $Port) and restart Home SOC."
Write-Host "  4. Verify from another device:  nslookup example.com $myIp"
Write-Host ""
if ($profile -ne "Private") {
    Write-Host "Note: the active network profile is '$profile'. The rules apply to the Private profile only;" -ForegroundColor Yellow
    Write-Host "      set the Wi-Fi network to Private (Settings -> Network -> Wi-Fi -> your network -> Private) or LAN clients cannot reach port $Port." -ForegroundColor Yellow
}
Write-Host "Keep Home SOC running (scripts\make-autostart.ps1) - if it stops, devices lose DNS until they fall back."
