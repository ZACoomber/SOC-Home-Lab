# Incident Response Report: Simulated AWS Console Brute-Force Attack

Report Type: Home Lab Detection Exercise
Classification: Internal / Portfolio Use
Framework Reference: NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
Analyst: Zachary Coomber
Date of Incident: August 2026
Report Date: August 2026

## Executive Summary

A simulated brute-force authentication attack was launched against an AWS IAM user account's Management Console login, extending an existing home-lab SIEM deployment into cloud infrastructure monitoring. The attack was detected via a custom Wazuh correlation rule built specifically for this exercise, ingesting AWS CloudTrail logs through Wazuh's native AWS S3 module. This report documents the incident using the four-phase NIST SP 800-61 incident handling lifecycle: Preparation, Detection & Analysis, Containment/Eradication/Recovery, and Post-Incident Activity.

This was a controlled, self-generated exercise conducted for skills development purposes, not a real-world compromise, performed against a personal AWS free-tier account created solely for this lab.

## 1. Preparation

Prior to the incident, the following environment and controls were in place:

| Component | Detail |
|---|---|
| SIEM | Wazuh 4.14 (manager, indexer, dashboard) — Ubuntu Server 26.04, same deployment used for prior on-prem detection work |
| Cloud Environment | AWS Free Tier account, region us-west-1 (N. California) |
| Audit Log Source | AWS CloudTrail (trail: soclab-trail), delivering logs to a dedicated S3 bucket |
| IAM Configuration | Dedicated IAM user (soclab-admin) created for lab use; root account credentials not used for daily operations |
| Log Ingestion | Wazuh AWS S3 module (wodle), polling the CloudTrail S3 bucket every 5 minutes |
| Detection Logic | Custom Wazuh local rule (ID 100011), built to detect repeated Console login failures against the same IAM user |

Custom detection rule deployed:
```xml
<group name="local,amazon,aws,">
  <rule id="100011" level="10" frequency="5" timeframe="120">
    <if_matched_sid>80254</if_matched_sid>
    <same_field>aws.userIdentity.userName</same_field>
    <description>AWS Console brute force attempt: multiple failed logins against same IAM user</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

This rule triggers when the base Wazuh AWS CloudTrail rule for a failed Console login (SID 80254) fires 5 or more times within a 120-second window against the same IAM user name, indicating a likely credential brute-force attempt against that account.

## 2. Detection & Analysis

### 2.1 Initial Detection

The attack was simulated by repeatedly signing out of the AWS Management Console and re-attempting login against the soclab-admin IAM user with an intentionally incorrect password, six times in quick succession.

Wazuh's base rule 80254 ("AWS Cloudtrail: signin.amazonaws.com - ConsoleLogin - User login failed.") fired on each individual failed attempt, corresponding to a CloudTrail ConsoleLogin event with responseElements.ConsoleLogin: "Failure". Once five such failures against the same IAM user occurred within the 120-second window, custom correlation rule 100011 fired at severity level 10, generating a high-priority alert with MITRE ATT&CK technique T1110 (Brute Force) automatically tagged.

[Screenshot: Wazuh Discover view showing rule.id:100011 firing at level 10]

### 2.2 Evidence Gathered

| Field | Value |
|---|---|
| Event Name | ConsoleLogin |
| Event Source | signin.amazonaws.com |
| Target IAM User | soclab-admin |
| AWS Account ID | REDACTED |
| Error Message | Failed authentication |
| Response Element | ConsoleLogin: Failure |
| Source IP Address | REDACTED |
| Geolocation (Wazuh-enriched) | Roseville, California, United States |
| MFA Used | No |
| Number of Failures Observed | 6 events within approximately 30 seconds |
| Correlation Rule Fired | 100011, level 10 |
| MITRE ATT&CK Mapping | T1110 — Brute Force (Tactic: Credential Access) |
| Base Rule Compliance Tags | NIST 800-53 AC.7 / AU.14, PCI-DSS 10.2.4 / 10.2.5, HIPAA 164.312.b, GDPR IV_32.2 / IV_35.7.d |

### 2.3 Analysis Notes

Wazuh's built-in geolocation enrichment identified the source IP of the failed login attempts as originating from Roseville, California — consistent with the analyst's actual location. In a real investigation, this is a meaningful data point: a cluster of failed logins from a geolocation consistent with the legitimate account owner substantially lowers the likelihood of external compromise and instead points toward a locked-out or mistyped-password scenario, versus a cluster of failures from an unexpected country or ASN, which would warrant immediate escalation and containment.

The event also confirmed MFA was not enabled on the targeted account (MFAUsed: No). This is a real, actionable finding: MFA is one of the single most effective controls against credential-based attacks, including successful brute-force and credential-stuffing attempts, and its absence here represents a genuine gap identified through this exercise.

A notable technical finding during rule development: AWS CloudTrail records ConsoleLogin and other sign-in-related events exclusively in the us-east-1 region, regardless of which region the account or its resources are otherwise operating in. Initial verification attempts in the AWS Console's Event History (viewed under us-west-1) returned no results for this reason; switching the console's region to us-east-1 resolved this and confirmed the events had in fact been logged. This is a documented but easy-to-miss AWS behavior worth accounting for in any cloud log analysis workflow.

[Screenshot: AWS CloudTrail Event History (us-east-1) showing the ConsoleLogin failure entries]

An initial detection attempt also used CLI-based authentication failures (invalid AWS access key/secret pairs via the aws s3 ls command) rather than Console login failures. This approach did not generate usable CloudTrail entries tied to the account, because a wholly invalid/unrecognized Access Key ID does not allow AWS to attribute the failed request to a specific account in the first place. The detection strategy was revised to target Console sign-in failures specifically, which is also the better-documented and more realistic pattern for this type of detection in real-world SOC tooling.

## 3. Containment, Eradication & Recovery

*(Note: as this was a controlled, self-generated exercise rather than a genuine compromise, containment actions below reflect what would be the appropriate real-world response given this alert, for demonstration purposes.)*

Containment (recommended actions):
- Temporarily restrict console access for the targeted IAM user, or require password reset before further login attempts
- Review CloudTrail for any subsequent successful ConsoleLogin from the same or related source IPs following the failure cluster
- Apply an IP-based conditional access restriction (via IAM policy conditions) if the account does not require login from varied locations

Eradication:
- No unauthorized access occurred in this exercise (all login attempts failed by design). In a real incident, eradication would involve reviewing CloudTrail for any resource creation, permission changes, or new access key generation that may have occurred if the attacker had succeeded.

Recovery:
- Confirm the account remains accessible to its legitimate owner
- Reset the IAM user's password
- Enable MFA on the account going forward
- Resume normal monitoring

## 4. Post-Incident Activity / Lessons Learned

- Detection logic validated: the custom rule successfully detected the simulated attack pattern in a live test, confirming the cloud log pipeline (CloudTrail → S3 → Wazuh AWS module → correlation rule → indexed alert) functions end-to-end.
- Gap identified and resolved: the initial detection strategy (CLI signature-mismatch failures) did not produce account-attributable log data; the strategy was revised to target Console login failures, which is both the technically correct approach and the industry-standard detection pattern for this scenario.
- Real security gap identified: MFA was not enabled on the tested IAM user at the time of the exercise. This is a genuine, actionable finding, and MFA enforcement is recommended as a compensating control alongside detection.
- Operational lesson: AWS CloudTrail log delivery to S3, combined with Wazuh's polling interval, introduces a realistic 15–20 minute delay between an event occurring and it becoming visible in the SIEM. This is a meaningful difference from the near-real-time visibility available from the on-prem Windows endpoint in the earlier exercise, and is a genuine operational consideration for cloud-based detection and response timing.
- Recommended follow-up improvements:
  - Enable MFA on the soclab-admin IAM user and validate that MFA-related CloudTrail fields are captured correctly
  - Enable AWS GuardDuty (pending account verification at time of this report) to layer AWS's native threat detection alongside custom Wazuh correlation rules
  - Extend the correlation rule to also alert on a successful ConsoleLogin immediately following a failure cluster, since a successful login after multiple failures is a stronger compromise indicator than failures alone
  - Add IP/geolocation-based anomaly logic to flag failed login clusters originating from locations inconsistent with the account owner's typical location

## Appendix: Framework Mapping

| Framework | Reference | Relevance |
|---|---|---|
| NIST SP 800-61 Rev. 2 | Full incident lifecycle | Structure of this report |
| NIST CSF 2.0 | Detect (DE), Respond (RS), Protect (PR) — MFA gap | Functions exercised in this scenario |
| MITRE ATT&CK | T1110 (Brute Force), Tactic: Credential Access | Technique detected |
| NIST SP 800-53 | AC-7 (Unsuccessful Logon Attempts), AU-14 (Session Audit) | Controls related to the underlying detection (per Wazuh rule tagging) |
| CIS AWS Foundations Benchmark | Related to CIS control area on MFA and console login monitoring | Referenced given the MFA gap identified |
