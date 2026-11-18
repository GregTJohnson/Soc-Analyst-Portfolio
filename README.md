# SOC Analyst Portfolio — Home Lab Case Write-Ups

A set of alert triage playbooks and case write-ups built from my home SOC lab (Wazuh SIEM + Sysmon on an Apple Silicon Mac mini, Ubuntu `wazuh-server` + Windows 11 `win-victim01` in UTM) and from public phishing samples. Each case pairs a reusable triage playbook with a real investigation, written the way a Tier 1/Tier 2 SOC analyst documents an alert: findings cited to specific log lines and dashboard evidence, defanged indicators, and a verdict with what would change it.

## Cases

### Phishing

Four case write-ups built from public phishing samples ([phishing_pot](https://github.com/rf-peixoto/phishing_pot)), covering header analysis (SPF/DKIM/DMARC), redirect-chain tracing, and attachment decoding.

- [`phishing-action-required-capital-one/`](./phishing-action-required-capital-one) — Capital One "Action Required: New Payment Temporary on Hold" (credential phishing via HTML attachment)
- [`phishing-wallet-access-restricted/`](./phishing-wallet-access-restricted) — "Wallet Access Will Be Restricted" (compromised NHS.net sender, redirect chain to a non-affiliated domain)
- [`phishing-your-reward-is-available/`](./phishing-your-reward-is-available) — "Your reward is available" (bulk casino promotion, SPF failure, tracking pixel)
- [`phishing-your-turn-to-play/`](./phishing-your-turn-to-play) — "Your turn to play"

### SSH Brute Force

[`ssh-brute-force/`](./ssh-brute-force) — Real brute-force attempts generated against `wazuh-server`, triaged through `auth.log` and Wazuh correlation rules (rule 2502, T1110 Brute Force; rule 5501, T1078 Valid Accounts). Includes a generic triage playbook plus the case write-up, with supporting screenshots.

### Malware / Suspicious Process

[`malware-powershell-execution/`](./malware-powershell-execution) — An obfuscated PowerShell command executed on `win-victim01` and detected via Sysmon + Wazuh (rule 92027). The case documents two real findings beyond the detection itself: a PowerShell Script Block Logging coverage gap (event 4104 didn't capture this command) and a VM clock-drift issue caught by cross-referencing UTC timestamps. Includes a generic triage playbook plus the case write-up, with supporting screenshots.

## Lab environment

- **Host:** Apple Silicon Mac mini, UTM (Apple Virtualization)
- **SIEM:** Wazuh 4.x all-in-one on Ubuntu Server (`wazuh-server`, 192.168.64.2)
- **Endpoint:** Windows 11 ARM64 (`win-victim01`) with Wazuh agent + Sysmon (SwiftOnSecurity config)

## About

Built while transitioning into a Cyber Threat Intelligence / SOC Tier 1-2 analyst role. Each write-up follows the same structure: Case Details, Findings (cited to evidence), Indicators (defanged), Response, and a Verdict section that states what would change the call.
