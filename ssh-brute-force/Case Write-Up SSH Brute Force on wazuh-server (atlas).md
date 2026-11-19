# Case Write-Up: SSH Brute Force on wazuh-server (atlas)

Nov 14, 2026 · @Greg

## Summary

A controlled SSH brute-force test against `wazuh-server` (192.168.64.2) from a Mac at 192.168.64.1, targeting the `atlas` account. Four wrong passwords were entered across two connections before a correct login; `sshd` closed the first connection after three failures (`MaxAuthTries`). Wazuh's own correlation rule caught the pattern, raising a level-10 alert mapped to MITRE ATT&CK T1110 (Brute Force), and the eventual successful login was logged separately as T1078 (Valid Accounts). Both the raw `auth.log` and the Wazuh alerts agree on the sequence and timing.

## Case Details

| Field | Value |
| --- | --- |
| Playbook used | SSH Brute Force Triage |
| Source | Self-generated test in home SOC lab (Wazuh + Sysmon, Apple Silicon Mac mini, UTM) |
| Target host | `wazuh-server`, Ubuntu 26.04 LTS, 192.168.64.2 (Wazuh manager, agent.id 000) |
| Attacking host | Mac mini, 192.168.64.1 (same UTM shared network) |
| Target account | `atlas` |
| Window | 2026-11-14 18:22:53 UTC – 18:24:04 UTC (13:22:53 – 13:24:04 local) |
| SIEM | Wazuh 4.x |
| Tools used | UTM console, Mac Terminal (manual SSH attempts), Wazuh dashboard (Threat Hunting / Events) |

## Findings

| Check | Result | Evidence |
| --- | --- | --- |
| First connection, failures | 3 failed passwords for `atlas` from 192.168.64.1:55305, at 18:22:54.736, 18:23:04.735, 18:23:09.997 UTC | `auth.log`: "Failed password for atlas from 192.168.64.1 port 55305" (x3) |
| sshd self-defense | After the 3rd failure, sshd closed the connection itself before a 4th try on that connection (`MaxAuthTries` reached) | `auth.log`, 18:23:11.986: "Connection closed by authenticating user atlas 192.168.64.1 port 55305 \[preauth\]" |
| PAM summary line | PAM logged a summary of repeated failures on the same connection | `auth.log`, 18:23:11.992: "PAM 2 more authentication failures; ... user=atlas" |
| Wazuh correlation alert | Rule 2502, level 10, fired at 18:23:12.339 UTC, quoting the same PAM summary line. Mapped to MITRE ATT&CK T1110 (Brute Force), tactic Credential Access | Wazuh alert detail: `rule.id 2502`, `rule.level 10`, `rule.mitre.id T1110`, `data.srcip 192.168.64.1`, `data.dstuser atlas` |
| Second connection, failure and success | A second connection (port 55307) opened; 1 more failed password at 18:23:42.611–18:23:44.337, then a successful login at 18:24:04.093 UTC | `auth.log`: "Failed password for atlas ... port 55307" then "Accepted password for atlas from 192.168.64.1 port 55307" |
| Wazuh success event | Rule 5501, level 3, group `authentication_success`, logged the session opening at 18:24:04.366 UTC. Mapped to MITRE ATT&CK T1078 (Valid Accounts) | Wazuh alert detail: `rule.id 5501`, `rule.mitre.id T1078`, `full_log`: "pam_unix(sshd:session): session opened for user atlas" |
| Total pattern | 4 failed attempts across 2 connections in about 71 seconds, then 1 success, all from the same source IP against the same account | Combined timeline above |
| Account validity | `atlas` is a real, privileged (sudo-capable) local account on the target host, not a decoy or nonexistent user | Confirmed on the host |

## Indicators

| Type | Value | Use |
| --- | --- | --- |
| Source IP | 192.168.64.1 | Lab-internal (Mac host); in a real case, check reputation in AbuseIPDB/VirusTotal and WHOIS before any block |
| Target account | `atlas` | Watch for further attempts; candidate for password rotation after a real incident |
| Target host | `wazuh-server`, 192.168.64.2 | Host to monitor and, if compromised, to isolate |
| MITRE ATT&CK | T1110 (Brute Force), T1078 (Valid Accounts) | Reference for the report and for correlating with other alerts |
| Wazuh rule IDs | 2502 (correlation, level 10), 5760 (individual failure, level 5), 5501 (success, level 3) | Reference for building a detection dashboard or alert tuning |

Note: 192.168.64.1 and .2 are private, lab-internal addresses and are not real-world indicators; they are recorded here only because this is a self-generated lab case.

## Response

This was a self-generated test, so no real response was required. In a real case matching this pattern (failures followed by a success from the same source), the playbook's response table calls for:

- Treat the `atlas` account as compromised: reset its password and revoke any active SSH sessions and keys.
- Check what the successful session did: command history, new users, new SSH keys, outbound connections.
- Block the source IP at the firewall once its reputation is confirmed as malicious.
- Escalate to Tier 2, since a login succeeded after failures and the account has sudo privileges.
- If this host's `sshd` config did not already enforce `MaxAuthTries`, recommend setting it; it is what limited this test to 3 tries per connection.

## Verdict

1. Alert: Wazuh rule 2502 (level 10), SSH brute-force pattern against `atlas` on `wazuh-server`, 14 Nov 2026, from 192.168.64.1.
2. What I checked: raw `auth.log` lines on the target host, the correlation alert's full detail, and the follow-on login event.
3. Findings: 4 failed password attempts across 2 connections in about 71 seconds, with `sshd` closing the first connection after 3 tries, followed by 1 successful login from the same source against the same account.
4. Verdict: confirmed successful brute force (lab test). Reason: a login succeeded immediately after repeated failures from the same source against the same account — the defining pattern, not just an attempt.
5. What would change it: this was a controlled, self-generated test, so there is no real adversary; in a live case, the source IP's reputation and the post-login activity would decide whether to treat it as a confirmed compromise versus a benign retry (e.g. the account owner forgetting their own password).

Not verified: source IP reputation (not applicable; lab-internal address), whether any other host in a real environment received the same pattern.
