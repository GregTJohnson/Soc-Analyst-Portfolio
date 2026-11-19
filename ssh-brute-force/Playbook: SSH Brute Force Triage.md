# Playbook: SSH Brute Force Triage

Nov 14, 2026 · @Greg

## Purpose and Scope

This playbook covers triage of a suspected SSH brute-force or password-guessing attempt against a Linux host: repeated failed logins from one source, aimed at one or more accounts, over a short window. It applies whether the source is external or internal, and whether the attempt succeeds or fails. It does not cover post-compromise activity after a successful intrusion; that moves to an incident response process once an account is confirmed compromised.

## Trigger / Inputs

This playbook starts from any of:

- A SIEM alert correlating multiple authentication failures from one source in a short window (e.g. a Wazuh rule in the `authentication_failed` group, or one mapped to MITRE ATT&CK T1110, Brute Force).
- A spike of `Failed password` or `authentication failure` lines in `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS).
- A fail2ban or firewall alert for a banned IP.
- A report from a user or admin of unexpected lockouts or login notifications.

## Triage Steps

| # | Step | Where | Why |
| --- | --- | --- | --- |
| 1 | Identify the source IP and targeted account(s) from the alert | SIEM alert fields (e.g. `data.srcip`, `data.dstuser`) | Scopes the investigation before reading raw logs |
| 2 | Pull the raw authentication log lines for that source and account | `/var/log/auth.log` or `/var/log/secure` on the target host | Confirms the alert against the primary evidence; the SIEM may summarize or miss entries |
| 3 | Count failed attempts and measure the time window | Timestamps in the log lines | A handful of failures over hours is different from dozens in seconds; the pattern decides urgency |
| 4 | Check whether the account exists and is valid | `/etc/passwd`, or ask the account owner | An attempt against a real admin account is more serious than one against a nonexistent user |
| 5 | Check whether any attempt succeeded | `Accepted password` / `Accepted publickey` lines after the failures | This is the single most important fact: failed-only is an attempt, a success after failures is a likely compromise |
| 6 | If the host has a correlation rule (e.g. Wazuh rule firing on repeated failures), read its full alert details | SIEM alert detail view | Confirms the SIEM's own pattern-matching, and gives MITRE ATT&CK mapping for the report |
| 7 | Check the source IP's reputation and ownership | VirusTotal, AbuseIPDB, WHOIS | Distinguishes a known scanner/botnet IP from an internal or unexpected source |
| 8 | Check for the same source IP against other hosts or accounts | SIEM search across all agents | A brute force against one host is often part of a wider sweep |
| 9 | If an attempt succeeded, check what that session did | Command history, new processes, new users, outbound connections, `last` command | Determines whether this is an active compromise, not just an attempt |
| 10 | Check for existing defenses that fired | `sshd` `MaxAuthTries` disconnects, fail2ban, firewall blocks | Shows whether controls already limited the attack, and whether they need tightening |

## Verdict Categories

- **Failed brute force / scan:** repeated failures, no success, source IP is a known scanner or shows no targeted intent. Low priority once blocked.
- **Targeted brute force, not confirmed successful:** repeated failures against a specific real account, no success found, but worth watching, especially if the source IP is not a known benign scanner.
- **Successful brute force (likely compromise):** one or more failures followed by a successful login from the same source. Treat the account as compromised until proven otherwise.
- **Not malicious:** failures explained by a legitimate user mistyping a password, an expired credential, or a misconfigured script/service account. Confirm with the account owner before closing this way.

## Escalation Criteria

Escalate to Tier 2 / IR if any of the following are true:

- A login succeeded after one or more failures from the same source.
- The targeted account has elevated privileges (root, admin, service account with broad access).
- The same source IP is hitting multiple hosts or accounts across the environment.
- Evidence of post-login activity that doesn't match the account owner's normal behavior (new users created, new SSH keys added, outbound connections to unfamiliar hosts).
- The account owner denies logging in at the time of a successful, matching login.

## Response Actions

| Scenario | Action |
| --- | --- |
| Failed-only, source is a known scanner | Block the source IP at the firewall if not already blocked; no further action |
| Failed-only, targeted, unclear source | Block the source IP; notify the account owner; monitor for repeat attempts |
| Successful login after failures | Disable or reset the account immediately; force a password reset; revoke active sessions and SSH keys; escalate to Tier 2 |
| Service account involved | Reset its credential through the owning team; check for hardcoded credentials that need rotating elsewhere |
| Pattern across multiple hosts | Report to the network/firewall team for a broader block; check if a WAF or bastion host can absorb future attempts |

All actions depend on company policy; a Tier 1 analyst typically requests account resets and isolation rather than performing them directly.

## Documentation

Record in the case write-up:

- Source IP, targeted account(s), host, and the time window of the activity (with timezone noted).
- The raw log lines that show each failure and any success, oited by timestamp.
- The SIEM alert ID/rule, its level, and any MITRE ATT&CK mapping it provides.
- Whether a login succeeded, and if so, what was found when checking post-login activity.
- The response actions taken and by whom (if requested from another team).

## Tools and References

- SIEM (Wazuh or equivalent) for correlation alerts and MITRE ATT&CK mapping
- `/var/log/auth.log` or `/var/log/secure`, read directly on the host when SIEM data is incomplete
- VirusTotal, AbuseIPDB, WHOIS for source IP reputation and ownership
- MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)
- fail2ban / firewall logs, where in use
