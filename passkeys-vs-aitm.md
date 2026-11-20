# Why Passkeys Beat Adversary-in-the-Middle Phishing

> A technical note from the Microsoft Cyber Range project. In my lab, a credential-harvesting phish compromised a test user protected by password + push MFA (**100% compromise**). After enforcing a FIDO2 passkey through Conditional Access, the same stolen credentials could no longer complete a sign-in. This note explains why phishing-resistant MFA works — and is precise about what my lab did and did not demonstrate.

## The weakness in push and OTP MFA

Password-plus-push MFA rests on factors an attacker can capture or relay. The password is a shared secret, and a push approval or one-time code is confirmed by the user in real time. A full adversary-in-the-middle (AiTM) attack, using tools such as evilginx, places a reverse proxy between the victim and the real login page. The victim's password is forwarded to Microsoft, Microsoft's MFA challenge is relayed back to the victim, the victim approves it, and the attacker walks away with the authenticated session cookie.

The second factor never helps in that flow, because both the password and the live approval pass *through* the attacker. Number matching does not fix it either: the proxy simply shows the victim the real number. In my lab the victim clicked the phishing link in 1 minute 38 seconds — too fast for any human to notice something was wrong.

## What FIDO2 does differently

FIDO2 passkeys replace the shared secret with public-key cryptography. At registration the authenticator generates a **key pair** scoped to one relying party — here, Microsoft's sign-in service. The public key goes to Microsoft; the private key is **never sent to the server or to any website**. (A device-bound passkey stays on one device; a synced passkey, like the iCloud Keychain one I registered, moves only between the user's own devices, end-to-end encrypted.) There is nothing for the victim to type and nothing on the server for an attacker to steal.

## The part that actually stops the attack: origin binding

A passkey is bound to the **relying party ID** it was created for, and the browser enforces that binding:

1. A page on `shareholds.com` cannot request a credential scoped to Microsoft's relying party ID — the browser refuses, so the authenticator is never even asked to sign for the attacker's domain.
2. Every assertion includes **client data built by the browser**, containing the real origin of the page and a single-use challenge. The authenticator signs over a hash of that data.
3. Microsoft's server checks the origin and challenge inside the signature. An assertion produced on any other origin fails verification.

The attack therefore fails by construction — not because a detection rule fired, but because the browser and the cryptography refuse to produce a usable credential for the wrong site.

## Why a relay can't rescue the attacker

Could the proxy forward the FIDO2 exchange the way it forwards a password? No. The proxy's origin is `shareholds.com`, so either no credential is offered at all, or any signature carries the attacker's origin and is rejected by Microsoft. The challenge is single-use, so nothing captured can be replayed later. There is no secret crossing the wire for the proxy to steal.

## What my lab demonstrated — and what it didn't

My attack used Microsoft's Attack Simulation Training credential harvest. That technique captures the password on a simulated phishing page; it does not run a live reverse proxy that relays the MFA step and steals a session cookie. So my re-test proves a specific, important point:

- **Before:** password + push MFA satisfied sign-in, so the harvested password was enough for compromise.
- **After:** Conditional Access policy CA002 requires phishing-resistant authentication strength. A fresh sign-in with the same password stopped at **"Sign in with a passkey"** — no password-only or push-only path remained.

The origin-binding argument above is why that requirement would also defeat a full live-proxy AiTM attack. Demonstrating that end to end with a tool such as evilginx is the natural next extension of this project.
