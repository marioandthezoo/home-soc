<!--
Thanks for contributing to Home SOC. CONTRIBUTING.md has the dev-environment setup
and what a good pull request looks like.

⚠️ Before you commit: make sure nothing from your own network got in — real MAC
addresses, your public IP, your Wi-Fi SSID, hostnames from your LAN, or absolute
paths containing your username. Test fixtures should use aa:bb:cc:dd:ee:ff,
203.0.113.x / 198.51.100.x (RFC 5737) and names like "my-router".
-->

## What this changes

<!-- One or two sentences, and the issue it closes: "Closes #123". -->

## Why

<!-- The problem this solves. -->

## Type of change

- [ ] Bug fix
- [ ] New finding rule
- [ ] New or improved scanner / posture check
- [ ] Notification channel or integration
- [ ] Dashboard / reporting
- [ ] Documentation only
- [ ] Refactor or maintenance

## Checklist

- [ ] `python -m pytest -q` passes locally
- [ ] New or changed behaviour is covered by a test
- [ ] Tests stay offline — no real network calls, no nmap required, no administrator/root rights
- [ ] No personal or device-identifying data in the diff (MACs, public IPs, SSIDs, LAN hostnames, local paths)
- [ ] Docs updated if behaviour or configuration changed (`README.md`, `docs/`, `config.example.toml`)
- [ ] `CHANGELOG.md` updated under **Unreleased** if this is user-visible

## How you tested it

<!-- Which platform and Python version, and what you actually ran. -->

- OS:
- Python version:
