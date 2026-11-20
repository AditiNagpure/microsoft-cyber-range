# Security Incident Report — AiTM Credential-Phishing Compromise

**Report ID:** IR-2026-001
**Analyst:** Aditi Nagpure
**Date of report:** 9 November 2026
**Environment:** Aditi Security Lab (`AditiSecurityLab.onmicrosoft.com`) — Microsoft Entra ID / Defender XDR / Sentinel
**Classification:** Lab exercise (controlled simulation) — no production impact

---

## 1. Summary

On 9 November 2026 a simulated adversary-in-the-middle (AiTM) credential-harvesting attack was executed against a single test user, **Geetansh Chawla** (`geet@AditiSecurityLab.onmicrosoft.com`). The user received a phishing email impersonating an Office 365 password-expiry notice, clicked the embedded link **within 1 minute 38 seconds**, and submitted valid credentials on an attacker-controlled page at `shareholds.com`. The account reached a **100% compromise** state under the pre-existing control set (password + push MFA).

Following detection and investigation in Microsoft Sentinel, a phishing-resistant **FIDO2 passkey** control was enforced via Conditional Access. The **same attack was re-run and blocked** — sign-in could not complete without the passkey, which the attacker did not possess.

| Field | Value |
|---|---|
| Incident type | Phishing → credential compromise |
| MITRE ATT&CK | T1566 (Phishing), T1566.002 (Spearphishing Link) |
| Severity | High (credential theft, account takeover potential) |
| Affected identity | geet@AditiSecurityLab.onmicrosoft.com |
| Lure domain | shareholds.com |
| Outcome | Contained — phishing-resistant MFA enforced, re-attack failed |

---

## 2. Timeline of events (9 November 2026, IST)

| Time | Event | Evidence |
|---|---|---|
| 14:08–14:14 | Legitimate baseline sign-ins by the user (ResultType 0) | SigninLogs |
| 14:34 | Sign-in interrupt (ResultType 50140) | SigninLogs |
| ~14:48 | Phishing email delivered to user's mailbox | Attack Simulation report |
| +1m 38s | User clicked the phishing link | Simulation report (First Link Clicked) |
| ~14:49 | User submitted credentials on `shareholds.com` landing page | Simulation report (Supplied credentials 1/1) |
| 14:36 / 14:47 | Sign-in interrupts observed (ResultType 50203) | SigninLogs |
| Post-incident | Passkey registered; Conditional Access CA002 enforced | Entra config |
| Post-incident | Same attack re-run → **blocked, passkey required** | Windows Security prompt |

---

## 3. Investigation

Detection and hunting were performed in Microsoft Sentinel using KQL against Entra ID sign-in logs.

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where UserPrincipalName startswith "geet"
| extend Outcome = case(
    ResultType == 0,     "Success",
    ResultType == 50203, "Interrupt - MFA/other",
    ResultType == 50126, "Invalid credentials",
    strcat("Other: ", tostring(ResultType)))
| project TimeGenerated, IPAddress, AppDisplayName, ResultType, Outcome, Location
| order by TimeGenerated asc
```

**Findings**

- **Credential compromise confirmed.** The Attack Simulation report recorded 1/1 users compromised: message delivered, link clicked (1m 38s), credentials supplied.
- **Sign-in anomalies.** Result codes 50126 (invalid credentials), 50140 and 50203 (interaction/MFA interrupts) clustered around the attack window, consistent with credential replay and MFA interruption against the `Office365 Shell WCSS-Client` app.
- **Single source IP.** All sign-in events originated from `202.148.61.204`. In a live AiTM attack the attacker's proxy would appear as a distinct geography (impossible-travel signal); here the simulation runs from the operator's own session, so no separate attacker IP or Entra ID Protection risk event was generated. This is a known limitation of Attack Simulation Training and is documented rather than inferred.
- **Simulation scope.** Attack Simulation Training's credential-harvest technique captures credentials on a simulated landing page; it does not operate a live reverse proxy that relays MFA or steals a session token. Findings and remediation are scoped accordingly: the re-test verifies that harvested credentials plus push MFA no longer satisfy Conditional Access.
- **Email table gap.** `EmailEvents` returned no records for the lure. Simulation messages are injected directly into the mailbox and bypass Exchange Online Protection, so the email evidence is carried by the simulation report rather than the mail-flow telemetry.

---

## 4. Root cause

The pre-existing control set required a password plus **push-based MFA** (Microsoft Authenticator). Push and OTP MFA are **not phishing-resistant**: an AiTM proxy relays both the password and the live MFA approval, so the second factor provides no protection once the user interacts with the attacker page. The user's rapid interaction (under two minutes) left no time for human detection.

---

## 5. Remediation

| Action | Control |
|---|---|
| Registered a FIDO2 passkey for the user (Microsoft Authenticator + platform) | Entra authentication methods |
| Enforced phishing-resistant authentication strength | Conditional Access policy **CA002** (Require authentication strength → Phishing-resistant MFA) |
| Retained baseline MFA for all users | Conditional Access policy **CA001** |
| Break-glass admin excluded from all policies | Lockout prevention |

**Verification.** A fresh sign-in was attempted with the harvested credentials. The password was accepted but the flow halted at **"Sign in with a passkey"** — there was no password-only or push-only path forward. An attacker holding the stolen password cannot complete sign-in, and because a FIDO2 assertion is bound to the legitimate origin, a live relay proxy would also fail (see `passkeys-vs-aitm.md`).

---

## 6. Why passkeys defeat AiTM (one line)

FIDO2 authentication is cryptographically bound to the real site's origin: the authenticator signs a challenge tied to `login.microsoftonline.com`, so a credential presented to `shareholds.com` is invalid by construction. There is no shared secret for a proxy to steal or replay.

---

## 7. Recommendations

1. Make phishing-resistant MFA the default for all privileged and high-value accounts, not a per-user exception.
2. Retire push/OTP MFA as a sole second factor where account value justifies it.
3. Add a risk-based Conditional Access policy to block or step-up on risky sign-ins once Entra ID Protection signal is available.
4. Run periodic Attack Simulation campaigns to measure click/compromise rates over time.

---

*Prepared as part of the Microsoft Cyber Range portfolio project. All activity was performed against an isolated lab tenant with test accounts; no production systems or real user data were involved.*
