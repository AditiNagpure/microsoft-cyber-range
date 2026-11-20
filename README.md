# Microsoft Cyber Range — AiTM Phishing: Attack → Detect → Defend

A full attack-to-defence loop on the Microsoft enterprise security stack. An adversary-in-the-middle (AiTM) credential-phishing attack is executed against a test user, detected and investigated in Microsoft Sentinel with KQL, then **blocked with FIDO2 passkeys** — and the identical attack is re-run to prove it now fails.

Built on a single E5 lab tenant covering identity, endpoint and detection in one coherent story.

---

## Stack

| Layer | Technology |
|---|---|
| Identity | Microsoft Entra ID, Conditional Access, Entra ID Protection |
| Endpoint | Microsoft Defender for Endpoint (Azure-hosted Windows 11 VM) |
| Detection | Microsoft Sentinel (Log Analytics) + Defender XDR, unified portal |
| Attack | Attack Simulation Training (Credential Harvest / AiTM) |
| Defence | FIDO2 passkeys enforced via Conditional Access authentication strength |

---

## The story

1. **Baseline.** Test user `geet@` is protected by password + push MFA (Microsoft Authenticator) — the control most organisations rely on.
2. **Attack.** A phishing email (Office 365 password-expiry lure) is delivered. The user clicks the link in **1 minute 38 seconds**, submits credentials on the attacker page `shareholds.com`, and the account reaches **100% compromise** (MITRE ATT&CK T1566).
3. **Detect.** The sign-in activity is hunted in Sentinel with KQL — a decoded attack timeline, result-code analysis, and two honest telemetry gaps documented.
4. **Defend.** A FIDO2 passkey is registered and Conditional Access policy **CA002** enforces phishing-resistant authentication strength.
5. **Prove it.** A fresh sign-in with the same stolen credentials halts at **"Sign in with a passkey"** — no password-only or push-only path exists. The harvested credentials are now useless.

---

## Key artefacts

- [`incident-report.md`](./incident-report.md) — one-page SOC incident report
- [`passkeys-vs-aitm.md`](./passkeys-vs-aitm.md) — why FIDO2 origin-binding defeats AiTM
- [`/evidence`](./evidence) — 17 screenshots documenting every stage
- KQL queries used in the hunt (below)

---

## Detection (KQL)

Decoded attack timeline from Entra sign-in logs:

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

Sign-in summary by user and result:

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize SignInCount = count() by UserPrincipalName, ResultType
| order by SignInCount desc
```

---

## Before / after

| | Before (push MFA) | After (FIDO2 passkey) |
|---|---|---|
| Same AiTM attack | **100% compromised** | **Blocked** — passkey required |
| Control | Password + Authenticator push | Phishing-resistant MFA (CA002) |

---

## Honest limitations

- The attack used Attack Simulation Training's **credential harvest**, which captures the password on a simulated phishing page. It does not run a live reverse proxy that relays MFA and steals a session cookie (as evilginx does). The re-test therefore proves that stolen credentials + push MFA can no longer satisfy Conditional Access; passkey origin binding — explained in `passkeys-vs-aitm.md` — is why a full live-proxy AiTM would also fail. Demonstrating that end to end is the planned next extension.
- Attack Simulation Training runs from the operator's own session, so all sign-ins share one source IP (`202.148.61.204`) and **no impossible-travel / Entra ID Protection risk event is generated** — a live AiTM proxy would surface a distinct geography. Documented rather than claimed.
- Simulation emails are injected directly into the mailbox and bypass Exchange Online Protection, so `EmailEvents` holds no record of the lure; the email evidence lives in the simulation report instead.
- Built on time-limited E5/Sentinel trials in an isolated lab tenant. No production systems or real user data were involved.

---

*Part of a Japan-ready cybersecurity portfolio. All activity was performed against a controlled lab tenant with synthetic test accounts.*
