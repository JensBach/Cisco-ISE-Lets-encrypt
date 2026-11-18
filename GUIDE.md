# CiscoIseLetsEncrypt guide

The program renews system certificates on Cisco ISE with Let's Encrypt certificates. The domain is validated with DNS-01 through the ACME DNS Proxy.
**The private key is generated on ISE.** ISE creates the CSR (Certificate Signing Request) itself. The program only makes sure
that Let's Encrypt signs it, and that the signed certificate is installed and put into use on ISE again.
Only if ISE refuses the CSR because the name does not point to the node in DNS does the program generate the key itself. This is logged as a warning (see step 3).

```
 ┌──────────────┐  OpenAPI       ┌──────────┐
 │ CiscoIse-    │◄──────────────►│ ISE PAN  │  (CSR, bind, roles)
 │ LetsEncrypt  │                └──────────┘
 │              │  ACME          ┌──────────────┐
 │              │◄──────────────►│ Let's Encrypt│
 │              │  REST          ┌──────────────┐
 │              │◄──────────────►│ DNS proxy    │──► Cloudflare TXT _acme-challenge
 │              │  RADIUS/HTTPS  ┌──────────┐
 │              │───────────────►│ ISE node │  (verification)
 └──────────────┘                └──────────┘
```

---

## 1. Prerequisites

### ISE
| Requirement | Where |
|---|---|
| OpenAPI enabled (on all nodes that get an imported certificate) | Administration > System > Settings > API Settings > *Open API (Read/Write)* |
| API user in the *ERS Admin* or *Super Admin* group | Administration > System > Admin Access > Administrators |
| The Let's Encrypt CA certificates installed as trusted, with only *Trust for authentication within ISE* (see step 0c) | Administration > System > Certificates > Trusted Certificates > Import |
| Network Device for the machine running the program (required when EAP is updated: steps 0a and 9) | Administration > Network Resources > Network Devices: IP = the source IP as seen by ISE (mind VPN/NAT), RADIUS shared secret = `-RadiusSecret` |
| PEAP allowed in the Allowed Protocols list that matches the test NAD | Policy > Policy Elements > Results > Allowed Protocols |

### DNS
- The DNS proxy token must be allowed to create `_acme-challenge.<name>` for all names in `-CertificateDNS`.
- The names **should** resolve to the ISE node's IP through the DNS servers ISE itself uses (e.g. an internal A record). Otherwise ISE refuses the CSR,
  and the program generates the key itself instead (see step 3).

### The machine running the program
- .NET 10 runtime (or a self-contained build).
- Access to ISE on HTTPS (443) and RADIUS (UDP 1812), to Let's Encrypt (443), to the DNS proxy (443) and to the public DNS resolvers
  (default 1.1.1.1 and 8.8.8.8, UDP 53).

---

## 2. Secrets

Secrets are best stored in **.NET user secrets**. They live in the user's profile, outside the program folder
(Windows: `%APPDATA%\Microsoft\UserSecrets\<id>\secrets.json`, macOS/Linux: `~/.microsoft/usersecrets/<id>/secrets.json`),
and only apply to the user who stored them.

```
CiscoIseLetsEncrypt -SetSecret Ise:Username
CiscoIseLetsEncrypt -SetSecret Ise:Password
CiscoIseLetsEncrypt -SetSecret DnsProxy:Token
CiscoIseLetsEncrypt -SetSecret Radius:Secret
CiscoIseLetsEncrypt -SetSecret Backup:Password     # only for -Backup
```

The program prompts for the value without echoing it (or reads it from stdin, e.g. `echo … | CiscoIseLetsEncrypt -SetSecret …`).
From the source code, `dotnet user-secrets set Ise:Password … --project src/CiscoIseLetsEncrypt` also works.
On Windows there is the script `Set-CiscoIseLetsEncryptSecrets.ps1` (see [WINDOWS-TASK-SCHEDULER.md](WINDOWS-TASK-SCHEDULER.md)).

Files, environment variables and parameters still work. The precedence is: **parameter > file > environment variable > user secret**.

| Secret | User secret | File | Environment variable | Parameter |
|---|---|---|---|---|
| ISE username/password | `Ise:Username`, `Ise:Password` | `-IseCredentialFile` with `username : …` and `password : …` | `ISE_USERNAME`, `ISE_PASSWORD` | `-IseUsername`, `-IsePassword` |
| DNS proxy token | `DnsProxy:Token` | `-DnsTokenFile` with `token : …` | `ACMEDNSPROXY_TOKEN` | `-DnsChallengeToken` |
| RADIUS shared secret | `Radius:Secret` | – | `RADIUS_SECRET` | `-RadiusSecret` |
| Backup password (encrypts the keys) | `Backup:Password` | – | `BACKUP_PASSWORD` | `-BackupPassword` |

The RADIUS secret is **required** when EAP is among the roles (the program starts by testing RADIUS), unless `-SkipVerification` is used.
Protect any files with `chmod 600`.

---

## 3. Running

### Dry run (changes nothing)
```
CiscoIseLetsEncrypt \
  -AdmNode ise-17-a.example.com -Node ise-17-a.example.com \
  -Roles EAP,DTLS -CertificateDNS eap.example.net \
  -DnsChallengeUrl https://dnsproxy.example.com \
  -AcmeTest -SkipIseTlsValidation -DryRun
```
In PowerShell, use a backtick (`` ` ``) instead of `\` for line continuation.

`-DryRun` (or `-WhatIf`) runs all checks (RADIUS, permissions, cluster overview, steps 2a/2b) and logs exactly what
*would* be done: CSR, ACME order, TXT records, roles, export/import and cleanup. Nothing is changed on ISE, in DNS or at
Let's Encrypt (not even an ACME order is created). The exit code is 0.

### Test against Let's Encrypt staging (recommended first)
The same command without `-DryRun`. The secrets are read from user secrets (section 2).
`-AcmeTest` gives an **untrusted** test certificate (issuer "(STAGING) …"), and there is no risk of hitting the production rate limits.

### Production
The same command without `-AcmeTest`. The program can run daily from cron or Task Scheduler
(see [WINDOWS-TASK-SCHEDULER.md](WINDOWS-TASK-SCHEDULER.md)). It does nothing
(exit 0) until the certificate expires within `-RenewBeforeDays` (default 30 days).

### Important parameters
| Parameter | Meaning |
|---|---|
| `-AdmNode` | Primary Admin Node (PAN) that the API calls are sent to |
| `-Node` | Node(s) to update (comma separated). Without `-Node`, all nodes running services for the selected roles are chosen. With several nodes, all get the **same** certificate (see step 6) |
| `-Roles` | `Admin, EAP, DTLS, Portal, pxGrid, IMS, SAML` |
| `-CertificateDNS` | Names in the certificate. The first one becomes the CN |
| `-DnsChallengeUrl` | The DNS proxy address. Without a path, `/api/txt` is added automatically. TXT records are created with POST and deleted with DELETE on the same URL |
| `-Force` | Replace the certificate even if the current one is still valid |
| `-DryRun` / `-WhatIf` | Run the checks and show the plan without changing anything |
| `-NoLocalKey` | Fail instead of generating the key in the program if ISE refuses the CSR (see step 3) |
| `-DeleteOldCertificates` | Delete the old certificates when nothing uses them any more. The default (`-KeepOldCertificates`) is to keep them |
| `-RenewBeforeDays` | Renew when fewer than N days are left (default 30) |
| `-RadiusSecret` | RADIUS shared secret for the EAP-PEAP tests in steps 0a and 9. Required for EAP |
| `-SkipVerification` | Skip the live tests (steps 0a and 9) |
| `-SkipIseTlsValidation` | Do not validate ISE's HTTPS certificate (use it if the machine does not trust ISE's CA) |
| `-VerifyTimeoutMinutes` | How long to wait for ISE to start using the new certificate (default 20) |
| `-Verbose` | Debug logging |

Run `CiscoIseLetsEncrypt -Help` to see all parameters.

### Backup of all system certificates
```powershell
.\CiscoIseLetsEncrypt.exe -Backup -AdmNode ise-pan.example.com -BackupDirectory D:\Backup\ISE
```
- Exports **all** system certificates on **all** nodes in the deployment with their private key. Nothing is changed on ISE.
- Only needs `-AdmNode`, the ISE username/password and a backup password (min. 8 characters, see section 2). Roles, names and DNS parameters are not used.
- ISE encrypts the key (PKCS#8) with the backup password, so the key is never stored unencrypted. **Without the password the keys cannot be used.**
- Result: `<BackupDirectory>\<yyyyMMdd-HHmmss>\<node>\<name>_<sha256>.crt` and `.key`, plus `manifest.json` with node, name, CN,
  issuer, expiry, roles (`usedBy`), portal group tag, fingerprint and status (`Exported`, `Skipped`, `Failed`).
- The program checks every export: the key must decrypt with the password and match the certificate.
- ISE cannot export **Data Grid** certificates. They are marked `Skipped` and do not count as errors.
- For the *Default self-signed* certificates, ISE 3.5 shows a different SHA-256 in the API than that of the certificate it exports.
  This is logged as a warning, and both fingerprints are in the manifest.
- Restore: *Administration > System > Certificates > System Certificates > Import* on the node, with the `.crt`, the `.key` and the backup password.
- Exit code `1` if at least one certificate could not be exported. Protect the backup folder with NTFS permissions.

### Exit codes
`0` = OK, nothing to do or dry run, `1` = at least one node failed (with `-Backup`: at least one certificate failed), `2` = invalid parameters.

---

## 4. Step by step

Each step is logged as `===== Step N: …` both on the console and in `logs/CiscoIseLetsEncrypt-yyyyMMdd.log`.
The log file also contains the full error responses from ISE.

Before anything is changed, the program runs four checks (steps 0a, 0b, 0c and 1). If 0a, 0b or 0c fails, the program stops without changes.
The checks also run with `-DryRun`. The program only uses the ISE OpenAPI – no admin GUI.

### Step 0a – Test RADIUS access (only when EAP is updated)
The **first** thing the program does when EAP is among the roles is an EAP-PEAP handshake against each selected node
(the same test as in step 9), logging the current EAP certificate. If a node does not answer, the program stops with
"RADIUS check failed – nothing has been changed". Without this check the program could switch the certificate without being able to verify it afterwards.
Typical causes are that the machine's source IP (mind VPN/NAT) is not a Network Device in ISE, or that the shared secret is wrong.
`-SkipVerification` skips the test.

### Step 0b – Test API access and permissions
- Login and reading of the node list and the trusted certificates through OpenAPI.
- **Write access**: the program sends a deliberately invalid import of a trusted certificate. ISE rejects it with 400 (validation error)
  if the user may write, or with 401/403 if not. Nothing is changed. Without write access the program stops
  (the user must be *ERS Admin* or *Super Admin*).

### Step 0c – Does ISE trust Let's Encrypt?
The program has the Let's Encrypt CA certificates built in and checks that ISE's trusted store contains the ones matching the environment
(`-AcmeTest` or production) and `-KeyType`:

| Environment / key type | Must be trusted | Warning only |
|---|---|---|
| Production RSA | ISRG Root X1, ISRG Root YR, YR1, YR2 | YR3 (backup) |
| Production ECDSA | ISRG Root X1, ISRG Root X2, ISRG Root YE, YE1, YE2 | YE3 (backup) |
| Staging RSA | (STAGING) Pretend Pear X1, (STAGING) Yonder Yam Root YR | – |
| Staging ECDSA | (STAGING) Pretend Pear X1, (STAGING) Bogus Broccoli X2, (STAGING) Yearning Yucca Root YE | – |

- A root counts as installed in both its self-signed and its cross-signed version (same subject and key).
- Staging does not publish its intermediates, so they are only checked after issuance (step 6).
- If anything is missing, the program stops and logs for each certificate: name, subject, issuer, validity, SHA-256, download URL and
  the certificate in PEM format. Copy the PEM text (from `-----BEGIN` to `END-----`) into a `.cer` file, or download the URL, and import it in
  *Administration > System > Certificates > Trusted Certificates > Import* with only **Trust for authentication within ISE**.
  Use the self-signed root when both versions exist.
- The program does **not** import CAs itself: the ISE API rejects certificates with `'` in the subject ("Security Check Failed"), and that applies to
  all Let's Encrypt intermediates (`O=Let's Encrypt`).

### Step 1 – Cluster overview
The program reads the node list (`GET /api/v1/deployment/node`) and logs each node with FQDN, IP, roles, services and status.
Under each node, all system certificates are logged: what they are used for (`usedBy`), name, CN, issuer and expiry date.
This documents the state *before* the change.

### Step 2 – Select nodes
- With `-Node`, the given nodes are used. If a node does not run the services the roles require, a warning is logged, but it is updated anyway.
- Without `-Node`, all nodes with the relevant personas are selected. EAP, DTLS and Portal require PSN (Policy Service), and Admin applies to all nodes.
- The node with the Admin role is processed **last**, because a role change on the Admin certificate restarts the application server.
- **Several nodes get the same certificate.** The certificate is issued on the first node and then exported to the others (see step 6).
  If the nodes currently have different certificates for the roles, they are replaced even if each one is valid.

### Step 2a – Read the certificates and their usage
The program reads `GET /api/v1/certs/system-certificate/{node}` and logs each certificate with CN, issuer, expiry date and
`usedBy` (the roles). For the portal role it also logs which portals use the certificate's portal group tag.
This documents the state *before* the change.

### Step 2b – Must the certificate be replaced?
The certificate is skipped (with `nothing to do`) when **all** of these conditions are met:
- One certificate covers all the `-CertificateDNS` names and has all the requested roles.
- It has not expired and does not expire within `-RenewBeforeDays`.

Otherwise the program continues. `-Force` always replaces. With `-DryRun` the plan is logged here, and the program stops.

### Step 3 – Create the CSR on ISE (the key stays on ISE)
- The program asks ISE to generate a CSR with `POST /api/v1/certs/certificate-signing-request`
  (RSA 2048 / SHA-256 by default, CN and SAN = `-CertificateDNS`).
  - The usage type is chosen from the roles. EAP+DTLS gives an EAP CSR, because a Multi-Use CSR requires the node's FQDN in the SAN.
- The CSR is exported and checked: it may only contain the expected names, otherwise the program stops.
- The ISE API requires every name to resolve to the node's IP through ISE's own DNS. Otherwise the API answers
  "bad Comman Name & SAN Values" or "non resolvable". In the GUI you can choose to continue, but the API cannot.

**Fallback: the key is generated by the program (warning).** When ISE refuses the CSR for that reason, the program does the following:
1. A `[WRN]` is logged: ISE refused the CSR, and the key is now generated in the program.
2. The program generates the key and CSR itself, with the same `-KeyType`/`-KeyLength`/`-DigestType` and the same CN/SAN.
   The key exists **only in memory** and is never written to disk.
3. Steps 4–5 and 7 run as normal.
4. In step 6 the certificate is imported with the key, encrypted (PKCS#8, AES-256) with a random 40-character password
   (`POST /api/v1/certs/system-certificate/import`). The roles are set directly by the import, so step 8 is skipped.
5. Steps 9–11 run as normal.

With `-NoLocalKey` the program fails instead, so the key is always generated on ISE.
To avoid the fallback, create an internal A record for the name pointing to the node.

### Step 4 – Create the DNS-01 challenge
The program creates an ACME order at Let's Encrypt (staging with `-AcmeTest`). The account and its key are stored in
`~/.ciscoiseletsencrypt/acme-account-{staging|production}.pem`.
For each name that is not yet validated, the TXT record `_acme-challenge.<name>` is created through the DNS proxy:
```
POST {DnsChallengeUrl}   Authorization: ******
{"recordName":"_acme-challenge.eap.example.net","value":"<digest>"}
```
Let's Encrypt reuses validations for a period. The log may therefore say "0 DNS-01 challenge record(s)", and steps 4, 5 and 7 are then effectively skipped.

### Step 5 – Validate the challenge and issue the certificate
- The program waits until the TXT record is visible on the public resolvers (`-DnsResolvers`, max. `-DnsPropagationTimeoutSeconds`).
- It then asks Let's Encrypt to validate, and when the validation is approved, the order is finalized with **ISE's CSR** (or the local CSR on fallback).
- The certificate is downloaded, and its subject, issuer, expiry and SHA-256 fingerprint are logged.
- Temporary errors ("rateLimited", "Service busy", network errors) are retried automatically with increasing delays.

### Step 6 – Install the certificate on ISE
1. The program checks that ISE trusts the whole issued chain (intermediate and root). If an issuer is missing from the chain, it is
   downloaded from the AIA URL. If a CA is not trusted (e.g. a new intermediate the program does not know), the program stops **before** binding,
   deletes the CSR and the TXT record and logs the certificate in PEM format – just like in step 0c.
2. The certificate is bound to the CSR (`POST /api/v1/certs/signed-certificate/bind`) **without roles**. It gets the name
   `<CN> LetsEncrypt[-STAGING] <date time>`. ISE matches it with the private key from step 3.

**Several nodes (same certificate):** when the first node is done (steps 3–11), the certificate is installed on the others:
1. The certificate is exported from the first node with its private key (`POST /api/v1/certs/system-certificate/export`).
   ISE encrypts the key with a random 40-character password generated by the program. The ZIP file, the key and the password are kept
   **in memory only** and are never written to disk. An unencrypted key is rejected.
2. The certificate is imported on each of the other nodes (`POST /api/v1/certs/system-certificate/import` against the node's own API)
   with the roles set directly. Steps 9–11 then run for that node.
3. If the import fails on one node, only that node fails. If the issuance fails on the first node, none of the others are changed.

The key therefore only leaves ISE encrypted, and only to be placed on another ISE node in the same cluster.

### Step 7 – Remove the DNS challenge
The TXT record is deleted with `DELETE {DnsChallengeUrl}`. This **always** happens, even if an earlier step failed.
If the run fails before binding, the CSR is also deleted on ISE, so no orphaned keys are left behind.

### Step 8 – Move the roles to the new certificate
- `PUT /api/v1/certs/system-certificate/{node}/{id}` sets the selected roles on the new certificate. ISE automatically moves them
  from the old certificate.
- Roles the program does not manage (TACACS, Native IPsec) are kept as they are.
- The Portal role gets the portal group tag from `-PortalGroupTag`.
- The Admin role restarts the application server on the node. The program then waits for the API to come back (`-VerifyTimeoutMinutes`).
- The old certificate loses the roles. What happens to it after that is handled in step 11.

### Step 9 – Verify that the services use the new certificate
The program connects to each service and compares the fingerprint with the new certificate. It retries until
`-VerifyTimeoutMinutes` has passed, because ISE may take a moment to switch.

| Role | How it is tested |
|---|---|
| Admin | HTTPS handshake against the node on port 443 |
| Portal | HTTPS handshake on `-PortalPort` (8443) |
| EAP | **EAP-PEAP over RADIUS** (see below) |
| DTLS, pxGrid, IMS, SAML | No live test. Checked through the API in step 10 |

**How the EAP test works:**
1. The program sends a RADIUS Access-Request with EAP-Identity (`-RadiusIdentity`, default `anonymous`) to the node's IP on
   UDP 1812. The packet is signed with `-RadiusSecret` (Message-Authenticator).
2. ISE answers with a PEAP start, and the program starts the TLS handshake inside the EAP/RADIUS packets.
3. ISE sends its EAP server certificate. The program stores it and **aborts the handshake**.
   No username or password is ever sent.
4. ISE therefore logs a **rejected/failed authentication** in Operations > RADIUS > Live Logs. This is expected and correct.

The RADIUS secret is required for EAP (the program stops at startup without it). Only with `-SkipVerification` is the test skipped.
"No RADIUS response" typically means that the source IP is not configured as a Network Device, or that the shared secret is wrong.
ISE ignores packets with a wrong secret instead of answering.

### Step 10 – Verify the installation through the ISE API
The program reads the system certificates again and checks that:
- the new certificate (same fingerprint) exists on the node,
- it has all the requested roles,
- it has not expired,
- no other certificate still has any of the roles.

### Step 11 – The old certificates
The program looks at the certificates that had the roles before the run:
- If a certificate is still used for something (e.g. TACACS, Portal, a portal group tag or another role), it is always **kept**.
- If it is no longer used, it is kept by default. With `-DeleteOldCertificates` it is deleted
  (`DELETE /api/v1/certs/system-certificate/{node}/{id}`). If the deletion fails, only a warning is logged.
- If ISE has already removed it, this is logged. ISE typically replaces a certificate with the **same subject** when the roles are moved.
  The old Let's Encrypt certificate therefore often disappears on renewal, even without `-DeleteOldCertificates`.

Finally `Result <node>: Renewed …` is logged, and the exit code is set.

---

## 5. Troubleshooting

| Symptom | Cause / solution |
|---|---|
| `UntrustedRoot` / TLS error against ISE | The machine does not trust ISE's admin certificate. Install the CA or use `-SkipIseTlsValidation` |
| 401 from ISE | Wrong username or password, or the user is not in ERS Admin |
| "ISE does not trust … Let's Encrypt CA certificate(s)" | Install the logged certificates as trusted (step 0c) and run again |
| `[WRN]` "ISE refused to generate the CSR" in step 3 | The name does not resolve to the node in ISE's DNS. The key is generated in the program. Create an internal A record to keep the key on ISE |
| "Certificate must contain the FQDN … in the SAN" | Multi-Use CSR. Use `-IncludeNodeFqdn` or a single role/EAP+DTLS |
| DNS proxy 401/403 | Wrong token, or the token is not allowed to change the name |
| TXT not visible on the resolvers | Increase `-DnsPropagationTimeoutSeconds`. The program asks Let's Encrypt to validate anyway |
| `rateLimited` in production | Let's Encrypt limits. Use `-AcmeTest` for testing, and do not run `-Force` repeatedly |
| "No RADIUS response" / "RADIUS check failed" | Add the source IP (VPN/NAT!) as a Network Device with the correct shared secret |
| "can read but not change certificates" | The API user must be in the ERS Admin or Super Admin group |
| "The EAP role requires a RADIUS shared secret" | Store `Radius:Secret` (section 2) or use `-SkipVerification` |
| "ISE username missing" from Task Scheduler | The user secrets are stored for a different user than the task's. See [WINDOWS-TASK-SCHEDULER.md](WINDOWS-TASK-SCHEDULER.md) |
| Import on another node fails | That node must have OpenAPI enabled, and the API user must be able to log in to it |
| "ISE did not offer EAP-PEAP" | PEAP is not allowed in the Allowed Protocols list that matches the test NAD |
| "Failed due to Server Exception" on role change | Should be fixed (ISE 3.5 requires all fields in the PUT). See the log file |

---

## 6. Warnings

- **The Admin role:** a change restarts the application server. Let's Encrypt removes the *clientAuth* EKU (2026), and ISE uses
  the Admin certificate for communication between the nodes. Test thoroughly before using Let's Encrypt for Admin.
- The list of Let's Encrypt CAs is built in (`Certificates/LetsEncryptCertificates.Data.cs`). If Let's Encrypt changes its hierarchy,
  the program must be updated – step 6 does, however, catch an unknown intermediate before anything is installed.
- Old certificates are kept by default (use `-DeleteOldCertificates`). Staging CAs in the trusted store must be cleaned up manually.
- Export/import between several nodes is unit tested, but only tested live with one node. Test with `-AcmeTest` on your cluster first.
