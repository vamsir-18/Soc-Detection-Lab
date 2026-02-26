# Phishing Detection & Response (IBM QRadar)

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|--------------|----------------|--------|
| **T1566.001** | Phishing: Spearphishing Attachment | Initial Access |
| **T1566.002** | Phishing: Spearphishing Link | Initial Access |
| **T1204.002** | User Execution: Malicious File | Execution |
| **T1539** | Steal Web Session Cookie | Credential Access |
| **T1078** | Valid Accounts (Post-Compromise) | Defense Evasion |

**Detection Coverage:**
- Detects spoofed emails via SPF/DKIM failure correlation
- Catches phishing link clicks via proxy logs
- Identifies credential submission to external phishing pages
- Detects malicious macro execution from Office applications
- Does NOT detect: Encrypted email channels, image-only phishing

---

## What This Project Is About

Detect **real-world phishing attacks** across the full kill chain using **QRadar's Rule Wizard, Log Activity filters, Offense Manager, and Reference Sets.**

- **Email auth failures** - Spoofed senders failing SPF, DKIM, DMARC
- **Malicious link clicks** - Users navigating to phishing pages via proxy
- **Credential harvesting** - HTTP POST sent to suspicious external domains
- **Macro execution** - Office apps spawning shells after attachment opens
- **Account takeover** - Impossible travel login after credential theft

---

## Detection Rules

### Rule 1: Suspicious Inbound Email — Auth Failures

**QRadar Log Activity Filter:**
```
Log Source  : Proofpoint OR Mimecast
SPF_Result  : fail OR softfail
DKIM_Result : fail
Source IP   : NOT in Reference Set 'Trusted_Mail_Servers'
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-001 | Suspicious Email - Auth Failures

Conditions:
  - Log Source is: Proofpoint OR Mimecast
  - SPF_Result is: fail OR softfail
  - DKIM_Result is: fail
  - Source IP NOT in Reference Set: Trusted_Mail_Servers

Actions:
  - Contribute to Offense | Severity: 7
  - Add Username to Reference Set: Active_Phishing_Recipients (TTL: 2hrs)
```

**False Positives:** Misconfigured legitimate servers, forwarded emails breaking DKIM.

---

### Rule 2: Phishing Link Click via Proxy

**QRadar Log Activity Filter:**
```
Log Source       : Zscaler OR Bluecoat OR Squid
URL_Category     : Phishing OR Malicious OR Newly Registered Domain
HTTP_Status_Code : 200
Username         : IN Reference Set 'Active_Phishing_Recipients'
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-002 | Phishing Link Click

Conditions:
  - Log Source is: Zscaler OR Bluecoat OR Squid
  - URL_Category is: Phishing OR Malicious OR Newly Registered
  - HTTP_Response_Code is: 200
  - Username IN Reference Set: Active_Phishing_Recipients

Actions:
  - Contribute to existing Offense | Severity: 9
  - Add Username to Reference Set: Users_Who_Clicked_Phishing (TTL: 4hrs)
```

**False Positives:** Newly registered legitimate domains, proxy categorization lag.

---

### Rule 3: Credential Submission to External Site

**QRadar Log Activity Filter:**
```
Log Source   : Zscaler OR Bluecoat
HTTP_Method  : POST
Bytes_Sent   : > 100
Destination  : NOT in Reference Set 'Approved_SaaS_Domains'
URL_Category : Phishing OR Uncategorized OR Newly Registered
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-003 | Credential Submission

Conditions:
  - HTTP_Method is: POST
  - Bytes_Sent greater than: 100
  - Destination NOT in Reference Set: Approved_SaaS_Domains
  - URL_Category is: Phishing OR Uncategorized OR Newly Registered

Actions:
  - Contribute to Offense | Severity: 10 (CRITICAL)
  - Add Username to Reference Set: Credential_Compromise_Suspected (TTL: 24hrs)
  - Trigger SOAR: Force password reset workflow
```

**False Positives:** Web forms on new legitimate sites, new SaaS tools not yet whitelisted.

---

### Rule 4: Malicious Attachment — Macro Execution

**QRadar Log Activity Filter:**
```
Log Source     : Windows Security Event Log
Event ID       : 4688
Parent_Process : WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE
Child_Process  : powershell.exe OR cmd.exe OR wscript.exe OR mshta.exe
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-004 | Macro Execution from Office App

Conditions:
  - Event ID is: 4688
  - Parent_Process is: WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE, ACRORD32.EXE
  - Child_Process is: cmd.exe, powershell.exe, wscript.exe, mshta.exe
  - Username IN Reference Set: Active_Phishing_Recipients (within 2hrs)

Actions:
  - Create CRITICAL Offense | Severity: 10
  - Trigger SOAR: Endpoint isolation
  - Notify: IR Team immediately
```

**False Positives:** Legitimate finance/HR macros, IT admin scripts via Office automation.

---

### Rule 5: Post-Phish Impossible Travel

**QRadar Log Activity Filter:**
```
Log Source    : Azure AD OR Okta
Event ID      : 4624 OR SuccessfulSignIn
Username      : IN Reference Set 'Credential_Compromise_Suspected'
Login_Country : NOT EQUAL TO 'IN'
```

**QRadar Rule Wizard:**
```
Rule Name : PHI-005 | Impossible Travel Post-Phish

Sequence Rule:
  Event A: Username IN Reference Set: Credential_Compromise_Suspected
  THEN Event B within 60 minutes:
    - Log Source is: Azure AD OR Okta
    - Login_Country is NOT: IN

Actions:
  - Create P1 Offense | Severity: 10 (CRITICAL)
  - Add Username to Reference Set: Confirmed_Compromise
  - Trigger SOAR: Session revocation + MFA re-enrollment
```

**False Positives:** Employees traveling internationally, VPN with foreign exit nodes.

---

## Example Detection Scenario
```
09:14 AM - Phishing email arrives — SPF: fail | DKIM: fail
           → PHI-001 FIRES | User added to Active_Phishing_Recipients

09:17 AM - User clicks link → HTTP 200 on phishing domain
           → PHI-002 FIRES | Severity elevated to HIGH

09:18 AM - User submits credentials → POST 847 bytes
           → PHI-003 FIRES | CRITICAL | Password reset triggered

09:51 AM - Login from Moscow (user is based in India)
           → PHI-005 FIRES | Session revoked | P1 Incident created

Result: Attack fully detected and contained in 37 minutes.
```

---

## SOC Investigation Checklist

**Triage**
- [ ] Open Offense in QRadar Offense Manager — review contributing events
- [ ] Check how many users are in `Active_Phishing_Recipients`
- [ ] Any users in `Credential_Compromise_Suspected`?

**Containment**
- [ ] Add phishing domain to `Known_Phishing_Domains`
- [ ] Retract phishing email from all mailboxes
- [ ] Force password reset for users in `Credential_Compromise_Suspected`
- [ ] Isolate endpoint if macro execution confirmed

**Escalate to IR immediately if:**
- Impossible travel login detected — PHI-005 fired
- Lateral movement detected post-compromise
- Executive or VIP account compromised

---

## QRadar Reference Sets

| Reference Set | Type | Purpose |
|---------------|------|---------|
| **Trusted_Mail_Servers** | IP Set | Whitelist for known SMTP relays |
| **Known_Phishing_Domains** | ALN Set | Confirmed phishing domains — auto-block |
| **Approved_SaaS_Domains** | ALN Set | Legitimate external POST destinations |
| **Active_Phishing_Recipients** | ALN Set | Users who received suspicious email |
| **Users_Who_Clicked_Phishing** | ALN Set | Users with proxy hit on phishing URL |
| **Credential_Compromise_Suspected** | ALN Set | Users who POSTed to suspicious site |
| **Confirmed_Compromise** | ALN Set | Confirmed takeover — full IR triggered |

---

## References

- **MITRE ATT&CK**: https://attack.mitre.org/techniques/T1566/
- **IBM QRadar Rule Wizard**: https://www.ibm.com/docs/en/qsip/7.5?topic=rules-qradar
- **CISA Phishing Guidance**: https://www.cisa.gov/topics/cyber-threats-and-advisories/phishing

---

*Built using QRadar Rule Wizard, Log Activity filters, and Reference Sets — tested against real-world phishing campaigns.*
