# Incident Response Report: Simulated SSH Brute-Force Attack

Report Type: Home Lab Detection Exercise
Classification: Internal / Portfolio Use
Framework Reference: NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
Analyst: Zachary Coomber
Date of Incident: August 2026
Report Date: August 2026

## Executive Summary

A simulated brute-force authentication attack was launched against a Windows 11 endpoint within an isolated home lab environment. The attack was detected via a custom Wazuh SIEM correlation rule built specifically for this exercise. This report documents the incident using the four-phase NIST SP 800-61 incident handling lifecycle: Preparation, Detection & Analysis, Containment/Eradication/Recovery, and Post-Incident Activity.

This was a controlled, self-generated exercise conducted for skills development purposes, not a real-world compromise. All systems involved were isolated virtual machines with no connection to production systems or the internet-facing host network.

## 1. Preparation

Prior to the incident, the following environment and controls were in place:

| Component | Detail |
|---|---|
| SIEM | Wazuh 4.14 (manager, indexer, dashboard) — Ubuntu Server 26.04 |
| Target/Victim | Windows 11 Enterprise (evaluation), hostname `victim-pc`, IP `192.168.56.20` |
| Attack Source | Kali Linux, IP `192.168.56.30` |
| Network Segmentation | All three hosts isolated on a VirtualBox internal network (`soclab`), with no bridged access to the host's real network |
| Log Source | Windows Security Event Log, forwarded via Wazuh agent (Event Channel decoder) |
| Detection Logic | Custom Wazuh local rule (ID `100010`), built specifically to detect repeated authentication failures |

Custom detection rule deployed:
```xml
<group name="local,syslog,sshd,">
  <rule id="100010" level="10" frequency="5" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>SSH brute force attempt: multiple failed logins against same account</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

This rule triggers when the base Wazuh rule for Windows logon failure (SID `60122`) fires 5 or more times within a 120-second window against the same target username, indicating a likely credential brute-force attempt rather than isolated, incidental failed logins.

## 2. Detection & Analysis

### 2.1 Initial Detection

The attack was carried out using Hydra, a password-auditing tool, targeting the SSH service running on the Windows victim host (via Windows' built-in OpenSSH Server feature). Multiple rapid authentication attempts were made against the account `victimuser`.

Wazuh's base rule 60122 ("Logon Failure — Unknown user or bad password") fired on each individual failed attempt, corresponding to Windows Event ID 4625. Once five such failures against the same account occurred within the 120-second window, custom correlation rule 100010 fired at severity level 10, generating a high-priority alert.

### 2.2 Evidence Gathered

| Field | Value |
|---|---|
| Event ID | 4625 (An account failed to log on) |
| Target Account | `victimuser` |
| Target Host | `VICTIM-PC` (192.168.56.20) |
| Logon Type | 8 (NetworkCleartext — consistent with password-based SSH auth) |
| Failure Sub-Status | `0xc000006a` (bad password) |
| Process | `C:\Windows\System32\OpenSSH\sshd.exe` |
| Number of Failures Observed | 10 events within ~48 seconds during one test window |
| Correlation Rule Fired | `100010`, level 10 |
| MITRE ATT&CK Mapping | T1110 – Brute Force |

### 2.3 Analysis Notes

A notable finding during analysis: Windows did not populate the "Source Network Address" field on the 4625 events, even though the login attempts originated from a known, real network source (the Kali attacker host). This is a real-world limitation of certain Windows logon paths (in this case, the `Advapi`/`Negotiate` authentication package used by Windows' OpenSSH implementation), and it meant that a source-IP-based correlation approach (`same_source_ip`) was not viable with this specific log source.

Analyst response: the detection logic was redesigned to correlate on repeated failures against the *same target account* instead of the *same source IP*. This is a legitimate and commonly-used alternative correlation strategy in real SOC environments, particularly useful when:
- Source IP data is unreliable, spoofed, or unavailable (e.g., behind NAT, proxies, or certain auth mechanisms)
- The primary risk of concern is account compromise rather than attacker infrastructure tracking

This also surfaced a secondary technical finding: Wazuh's rule engine references dynamic fields internally without the `data.` prefix used in the indexed/display layer (e.g., `win.eventdata.targetUserName` rather than `data.win.eventdata.targetUserName`), which was the root cause of an initial non-firing rule during testing.

[Screenshot: Wazuh Discover view showing rule.id:100010 firing at level 10]

## 3. Containment, Eradication & Recovery

*(Note: as this was a controlled, self-generated exercise rather than a genuine compromise, containment actions below reflect what would be the appropriate real-world response given this alert, for demonstration purposes.)*

Containment (recommended actions):
- Temporarily block the source IP (`192.168.56.30`) at the host firewall or network perimeter
- Enforce account lockout policy on `victimuser` after N failed attempts (Windows supports this natively via Account Lockout Policy in Local Security Policy / Group Policy)
- Rotate the password for the targeted account if there is any indication of a successful subsequent login

Eradication:
- No unauthorized access occurred in this exercise (all password attempts failed by design). In a real incident, eradication would involve verifying no persistence mechanisms, scheduled tasks, or new accounts were created by an attacker who succeeded.

Recovery:
- Confirm the account remains accessible to its legitimate owner
- Verify no configuration changes occurred on the host
- Resume normal monitoring

## 4. Post-Incident Activity / Lessons Learned

- Detection logic validated: the custom rule successfully detected the simulated attack pattern in a live test, confirming the SIEM pipeline (endpoint → agent → manager → correlation rule → indexed alert) functions end-to-end.
- Gap identified and resolved: initial detection design assumed source-IP data would be available and reliable; testing revealed this assumption was incorrect for this log source, requiring a redesign of the correlation logic. This reinforces the importance of validating detection assumptions against real log data rather than documentation alone.
- Recommended follow-up improvements:
  - Add a secondary detection rule that also correlates on workstation name or process, to catch brute-force attempts even in edge cases where the target account varies (e.g., username enumeration attacks)
  - Enable and test Windows Account Lockout Policy as a compensating control alongside detection
  - Extend log collection to capture successful post-brute-force logins (Event ID 4624 immediately following a cluster of 4625s) as an additional high-priority correlation, since a successful login after multiple failures is a stronger compromise indicator than failures alone

## Appendix: Framework Mapping

| Framework | Reference | Relevance |
|---|---|---|
| NIST SP 800-61 Rev. 2 | Full incident lifecycle | Structure of this report |
| NIST CSF 2.0 | Detect (DE), Respond (RS) | Functions exercised in this scenario |
| MITRE ATT&CK | T1110 (Brute Force) | Technique detected |
| NIST SP 800-53 | AU-14 (Session Audit), AC-7 (Unsuccessful Logon Attempts) | Controls related to the underlying detection (per Wazuh rule tagging) |
