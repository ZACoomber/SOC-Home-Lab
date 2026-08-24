# SOC Home Lab: SIEM Detection Engineering (On-Prem & Cloud)

A self-built Security Operations Center home lab demonstrating end-to-end detection engineering: deploying a SIEM, generating real attack traffic, building custom correlation rules, and documenting findings using industry-standard incident response frameworks.

## What this lab demonstrates

- Deploying and configuring **Wazuh** (SIEM/XDR) from scratch on Ubuntu Server
- Onboarding an endpoint (Windows 11) and ingesting **Windows Security Event Log** data
- Extending the SIEM into **AWS cloud monitoring** via CloudTrail and Wazuh's native AWS integration
- Writing **custom detection rules** from the ground up (not just using defaults), including debugging real data-availability and field-mapping issues
- Simulating realistic attacker behavior (Kali Linux, Hydra, manual credential attacks) in an isolated network
- Mapping detections to **MITRE ATT&CK**
- Writing formal **incident response reports** structured around **NIST SP 800-61**
- Working knowledge of related compliance frameworks encountered throughout (NIST CSF 2.0, NIST 800-53, PCI-DSS, HIPAA, GDPR, SOC 2) via Wazuh's automatic rule tagging

## Architecture

**On-prem detection lab:**
```
Kali Linux (attacker) → Windows 11 (victim, Wazuh agent) → Wazuh Manager (SIEM)
```
All three hosts isolated on a private VirtualBox internal network, with no bridged access to the host machine's real network.

**Cloud detection lab:**
```
AWS Account (IAM user, CloudTrail) → S3 → Wazuh Manager (AWS S3 module) → Correlation Rule → Alert
```
Extends the same Wazuh manager used in the on-prem lab, rather than standing up a separate cloud-only environment — one SIEM, two log sources.

## Detections built

| # | Scenario | Technique | Rule ID | Report |
|---|---|---|---|---|
| 1 | SSH brute-force against a Windows endpoint | MITRE T1110 – Brute Force | Custom rule 100010 | [SSH Brute-Force Incident Report](reports/ssh-bruteforce-incident-report.md) |
| 2 | AWS Console login brute-force against an IAM user | MITRE T1110 – Brute Force | Custom rule 100011 | [AWS Console Brute-Force Incident Report](reports/aws-console-bruteforce-incident-report.md) |

Both detections were built as **correlation rules** — not simple single-event alerts — triggering only when repeated authentication failures occur against the same account within a defined time window, reducing false positives compared to alerting on every individual failed login.

## Real problems solved along the way

This lab wasn't a straight-line tutorial follow-along. A few of the genuine technical issues diagnosed and resolved during the build:

- **Windows source-IP logging gap:** discovered that Windows' `Advapi`/`Negotiate`-based SSH authentication doesn't populate the Source Network Address field on failed-logon events, which broke an initial `same_source_ip` correlation approach. Redesigned the rule to correlate on target account instead.
- **Wazuh field-reference mismatch:** found that Wazuh's rule engine references dynamic fields internally without the `data.` prefix used in the indexed/display layer — the root cause of a rule that loaded successfully but never fired.
- **AWS region quirk:** confirmed that AWS CloudTrail records all Console sign-in events exclusively in `us-east-1`, regardless of which region the account's resources otherwise run in.
- **CLI vs. Console authentication failures:** an initial detection attempt using invalid AWS CLI access keys didn't generate account-attributable CloudTrail data, since a wholly-unrecognized Access Key ID can't be tied to a specific account. Pivoted to Console login failures, which is also the better-documented, industry-standard pattern for this detection.

## Tech stack

- **SIEM:** Wazuh 4.14 (manager, indexer, dashboard)
- **Virtualization:** VirtualBox
- **Endpoint OS:** Windows 11 Enterprise (evaluation)
- **Attacker tooling:** Kali Linux, Hydra
- **Cloud:** AWS (IAM, CloudTrail, S3)
- **Frameworks referenced:** NIST SP 800-61, NIST CSF 2.0, NIST SP 800-53, MITRE ATT&CK

## Repository structure

```
├── README.md
├── reports/
│   ├── ssh-bruteforce-incident-report.md
│   └── aws-console-bruteforce-incident-report.md
├── detection-rules/
│   └── local_rules.xml
└── screenshots/
    └── (supporting evidence referenced in the reports above)
```

## Notes

All internal IP addresses shown (`192.168.56.x`) are private lab-only addresses with no external significance. AWS account identifiers and public IP addresses have been redacted throughout.

---
*Built as part of a hands-on transition into SOC/detection engineering work. Feedback welcome.*
