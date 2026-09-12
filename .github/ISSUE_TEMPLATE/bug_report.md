---
name: Bug report
about: Something in Home SOC does not work the way it should
title: ''
labels: bug
assignees: ''
---

> ### ⚠️ Before you paste anything: redact your network
>
> Home SOC looks at your home network, so its output contains things you should not publish.
> **Please do not paste real MAC addresses, your public IP address, your Wi-Fi SSID, or hostnames
> from your own network** — those identify your house and your hardware to anyone reading this issue.
>
> Replace them consistently, keeping the shape of the value so the bug still makes sense:
>
> - MAC address → `aa:bb:cc:dd:ee:ff` (keep a distinct placeholder per device: `...:01`, `...:02`)
> - Public IP → `203.0.113.10` (the RFC 5737 documentation range)
> - Hostname → `my-printer`, `my-router`, `my-laptop`
> - Wi-Fi SSID → `MY-SSID`
> - Local paths → `C:\Users\you\Home_SOC` or `/home/you/Home_SOC`
>
> Private LAN addresses (`192.168.x.x`, `10.x.x.x`) are fine to leave as they are.
> If you would rather not redact by hand, describe the problem in words and say so — a maintainer
> will tell you exactly which line is needed.

## What happened

<!-- What you expected, and what you got instead. -->

## Steps to reproduce

1.
2.
3.

## Environment

- **Operating system and version:** <!-- e.g. Windows 11 23H2, Ubuntu 24.04, macOS 15.2 -->
- **Python version:** <!-- output of: python -V -->
- **Home SOC version:** <!-- output of: python -m homesoc --version -->
- **Running as administrator / root?** <!-- yes / no -->
- **Is nmap installed?** <!-- yes / no -->
- **Installed how?** <!-- run.bat, run.sh, pip install, from source -->

## Relevant log excerpt

<!--
From data/logs/homesoc.log, or the console output. A dozen lines around the problem is usually
enough — please do not attach the whole file, and re-read the redaction note above first.
-->

```text

```

## Anything else

<!-- Screenshots (with the network details blurred or redacted), config snippets with secrets removed, etc. -->
