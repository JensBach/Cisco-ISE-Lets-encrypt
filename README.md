# CiscoIseLetsEncrypt

Renews Cisco ISE system certificates with Let's Encrypt (DNS-01 through the ACME DNS Proxy).
The CSR and private key are **generated on the ISE node**. The program exports the CSR, has it signed by Let's Encrypt,
and binds the signed certificate back to the same CSR on ISE.
If ISE refuses the CSR because a name does not resolve to the node, the program falls back to generating the key and CSR
itself (memory only, logged as a **warning**) and imports the certificate with its encrypted key. `-NoLocalKey` disables this.

See **[GUIDE.md](GUIDE.md)** for a step-by-step guide, and **[WINDOWS-TASK-SCHEDULER.md](WINDOWS-TASK-SCHEDULER.md)**
for running it daily from Windows Task Scheduler with the PowerShell scripts in [`scripts/windows`](scripts/windows).

## Usage

```
CiscoIseLetsEncrypt -AdmNode ise-pan.example.com -Node ise-17-a.example.com -Roles EAP,DTLS \
  -CertificateDNS eap.example.com \
  -DnsChallengeUrl https://dnsproxy.example \
  -AcmeTest -DryRun
```

Run `CiscoIseLetsEncrypt -Help` to see all options.

- `-AcmeTest` uses Let's Encrypt **staging**, which issues untrusted test certificates.
- `-DryRun` (`-WhatIf`) runs all checks and logs what would be done, without changing anything on ISE, DNS or Let's Encrypt.
- `-DeleteOldCertificates` deletes the previous certificates once nothing uses them. The default is to keep them.
- `-DnsScript <script.ps1>` replaces the ACME DNS Proxy (`-DnsChallengeUrl`) for other DNS providers. The script is run with
  `-Action Create -RecordName <name> -Value <txt>` and `-Action Delete -RecordName <name>` (exit code 0 = success, timeout
  `-DnsScriptTimeoutSeconds`, default 120). Template: [`scripts/windows/Invoke-DnsChallenge.example.ps1`](scripts/windows/Invoke-DnsChallenge.example.ps1).
  No DNS token is needed with `-DnsScript`. Requires PowerShell (`powershell.exe` on Windows, `pwsh` elsewhere).
- With several nodes in `-Node` (or none, meaning all relevant nodes), **one** certificate is issued on the first node.
  It is exported with its encrypted private key (in memory only) and imported with the roles on the other nodes.

### Backup

```
CiscoIseLetsEncrypt -Backup -AdmNode ise-pan.example.com [-BackupDirectory backups] [-BackupPassword …]
```

Exports every system certificate of every node with its private key, encrypted by ISE with the backup password
(`-BackupPassword`, env `BACKUP_PASSWORD` or user secret `Backup:Password`, min. 8 characters). Output:
`<dir>/<yyyyMMdd-HHmmss>/<node>/<name>_<sha256>.crt|.key` and `manifest.json`. Each key is checked against its certificate.
Data Grid certificates cannot be exported (ISE refuses) and are reported as `Skipped`. Nothing is changed on ISE.
Exit code 1 if any certificate failed.

### Secrets

Store secrets in **.NET user secrets** (per OS user, outside the program folder):

```
CiscoIseLetsEncrypt -SetSecret Ise:Username     # prompts without echo, or reads stdin
CiscoIseLetsEncrypt -SetSecret Ise:Password
CiscoIseLetsEncrypt -SetSecret DnsProxy:Token
CiscoIseLetsEncrypt -SetSecret Radius:Secret
CiscoIseLetsEncrypt -SetSecret Backup:Password   # only for -Backup
```

Files (`-IseCredentialFile`, `-DnsTokenFile`), environment variables (`ISE_USERNAME`, `ISE_PASSWORD`, `ACMEDNSPROXY_TOKEN`,
`RADIUS_SECRET`) and parameters still work. Precedence: parameter > file > environment > user secrets.
A RADIUS secret is required when EAP is among the roles, unless `-SkipVerification` is used.

Exit codes: `0` means success, nothing to do or dry run, `1` means one or more nodes failed, and `2` means invalid arguments.

## Steps (logged to the console and to `logs/CiscoIseLetsEncrypt-<date>.log`)

0. Pre-checks. If a pre-check fails, nothing is changed.
   - 0a. Only when EAP is among the roles: an EAP-PEAP handshake over RADIUS against every selected node. Fails if a node does not answer.
   - 0b. API access and permissions: read nodes and trusted certificates; write access, probed with an invalid import that ISE rejects.
   - 0c. ISE must trust the Let's Encrypt CA certificates (embedded in the program) for the environment and `-KeyType`:
     production RSA = ISRG Root X1, Root YR, YR1, YR2; ECDSA = ISRG Root X1, X2, Root YE, YE1, YE2;
     staging = (STAGING) Pretend Pear X1 + Yonder Yam Root YR (RSA) or Bogus Broccoli X2 + Yearning Yucca Root YE (ECDSA).
     A self-signed or cross-signed variant counts (match on fingerprint or subject). Backup intermediates (YR3/YE3) only give a warning.
     If any is missing, the run fails and logs name, subject, SHA-256, download URL and PEM of each certificate to install.
1. Log a cluster overview: every node (IP, roles, services, status) and all its system certificates (usage, CN, issuer, expiry).
2. Select nodes by `-Node`, or by the services required for the roles. The admin node is processed last.
   - 2a. Read the system certificates, their roles and the portals that use the portal group tag.
   - 2b. Skip if the certificate is valid, correctly named, assigned to all roles, does not expire within `-RenewBeforeDays`,
     and (with several nodes) is the same on all nodes. `-Force` replaces it anyway. `-DryRun` logs the plan here and stops.
3. Generate the CSR on ISE, export it and validate its names.
4. Create an ACME order and the `_acme-challenge` TXT record via the DNS proxy.
5. Wait for DNS propagation, validate the challenge and finalize the order with the ISE CSR.
6. Check that ISE trusts every CA in the issued chain (fetched via AIA if needed). If not, the run fails before bind,
   deletes the CSR and the TXT record, and logs the missing certificates (PEM). Then bind the certificate.
   For the other nodes: export from the first node and import with the roles (after the first node has finished step 11).
7. Delete the TXT record. This always happens, even on failure. If the run fails before bind, the CSR is also deleted.
8. Assign the roles to the new certificate.
9. Verify the services live:
   - Admin: checked over HTTPS.
   - Portal: checked over HTTPS on port 8443.
   - EAP: checked with an EAP-PEAP handshake over RADIUS.
   - DTLS, pxGrid, IMS and SAML: checked via the API only.
10. Verify the installation: the certificate is present, has all roles, has not expired, and no other certificate holds the roles.
11. Old certificates: those still used for anything (TACACS, portal tag, other roles) are always kept. Unused ones are kept
    unless `-DeleteOldCertificates` is set. ISE itself usually removes a previous certificate with the same subject when the roles move.

## ISE prerequisites

- OpenAPI is enabled (Administration > System > Settings > API Settings).
- The API user is in the *ERS Admin* or *Super Admin* group.
- The OpenAPI CSR call requires every name in `-CertificateDNS` to resolve to the node IP through ISE's own DNS.
  Otherwise ISE returns "bad Common Name & SAN Values" or "non resolvable" and the API cannot override this. The program then
  generates the key locally (see above), or fails with `-NoLocalKey`. Create internal A records to keep the key on ISE.
- The Let's Encrypt CA certificates must be installed manually as trusted certificates (Administration > System > Certificates >
  Trusted Certificates > Import, "Trust for authentication within ISE" only). The program uses only the OpenAPI (no admin GUI)
  and does not import CAs: the OpenAPI import fails with "Security Check Failed" for subjects with `'` (`O=Let's Encrypt`).
  Run with `-DryRun` to get the list of missing certificates.
- The DNS proxy token must be allowed to manage `_acme-challenge.<name>` for each name.
- The EAP checks (step 0a and 9) need the RADIUS secret, the host running the program configured as a Network Device in ISE,
  and PEAP allowed.
  The probe aborts the TLS handshake after receiving the certificate, so ISE logs a failed authentication. This is expected.
- Multi-node import calls the OpenAPI of each target node, so OpenAPI must be enabled there as well.
  Export/import is unit-tested but has only been tested live with a single node.
- If the ISE admin certificate is not trusted by the host, trust the CA or use `-SkipIseTlsValidation`.

## Notes and warnings

- **Admin role:** Changing the Admin certificate restarts the application server on the node.
  Let's Encrypt is removing the *clientAuth* EKU from its certificates (2026), and ISE uses the Admin certificate for
  node-to-node communication. Test carefully before you use Let's Encrypt for the Admin role.
- Trust the Let's Encrypt CAs only for "Trust for authentication within ISE", **not** for client/EAP-TLS authentication.
- The embedded CA list (`Certificates/LetsEncryptCertificates.Data.cs`) must be updated when Let's Encrypt changes its hierarchy.
  Step 6 still catches an unknown intermediate after issuance.
- Old certificates are kept by default (see step 11). Staging CAs in the trusted store are not removed.
- For roles EAP+DTLS, the CSR uses the EAP usage type. A Multi-Use CSR requires the node FQDN in the SAN.
  The roles are assigned afterwards with PUT, and ISE keeps the existing TACACS/Native IPsec roles unchanged.
- ACME calls are retried automatically on `rateLimited`/"Service busy" and network errors.
- The ACME account key is stored in `~/.ciscoiseletsencrypt/acme-account-{staging|production}.pem`.

## Tests

```
dotnet test
```
