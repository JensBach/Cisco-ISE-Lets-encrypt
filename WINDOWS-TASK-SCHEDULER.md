# Windows Task Scheduler setup

This guide sets up CiscoIseLetsEncrypt to run automatically once a day on a Windows server.
The program only does something when a certificate expires within `-RenewBeforeDays` (default 30 days). Otherwise it exits with 0.

The scripts are in [`scripts/windows`](scripts/windows):

| Script | Purpose |
|---|---|
| `Publish-CiscoIseLetsEncrypt.ps1` | Builds a self-contained `CiscoIseLetsEncrypt.exe` (no .NET needed on the server) and copies the scripts along |
| `jobs.example.psd1` | Example configuration: common parameters and one job per certificate |
| `Set-CiscoIseLetsEncryptSecrets.ps1` | Stores the ISE username, password, DNS token and RADIUS secret in .NET user secrets for the user running it |
| `Invoke-CiscoIseLetsEncrypt.ps1` | Runs all jobs, logs (transcript) and cleans up old logs. This is the script the task starts |
| `Register-CiscoIseLetsEncryptTask.ps1` | Creates (or removes) the scheduled task |

---

## 1. Prerequisites

- A Windows server with access to ISE (HTTPS 443, RADIUS UDP 1812), Let's Encrypt (443), the DNS proxy (443) and
  the DNS resolvers (UDP 53). See [GUIDE.md](GUIDE.md#1-prerequisites).
- The server's IP address must be configured as a **Network Device** in ISE with a RADIUS shared secret if the EAP role is updated.
- A **dedicated service account**, e.g. `EXAMPLE\svc-iseacme`, which:
  - has the *Log on as a batch job* right (GPO or `secpol.msc` > Local Policies > User Rights Assignment),
  - has write access to the log folder (e.g. `C:\ProgramData\CiscoIseLetsEncrypt\logs`),
  - does not need to be an administrator.

> The secrets are stored in the service account's profile (`%APPDATA%\Microsoft\UserSecrets\…\secrets.json`).
> The task must therefore run as **the same account** the secrets were stored with.
> Alternatively the task can run as **Local System**, see [section 8](#8-alternative-run-as-local-system). A gMSA is not recommended,
> because you cannot log on as it to store the user secrets.

---

## 2. Build and install

### 2a. Compile directly on Windows Server

1. Install the .NET 10 SDK (only on the build machine – the finished exe does not need .NET):
   ```powershell
   winget install Microsoft.DotNet.SDK.10
   ```
   Without winget (e.g. Server 2019/2022 without App Installer): download the *.NET 10 SDK x64 Installer* from
   https://dotnet.microsoft.com/download/dotnet/10.0, or use the script:
   ```powershell
   Invoke-WebRequest https://dot.net/v1/dotnet-install.ps1 -OutFile $env:TEMP\dotnet-install.ps1
   & $env:TEMP\dotnet-install.ps1 -Channel 10.0 -InstallDir 'C:\Program Files\dotnet'
   ```
   Open a new PowerShell afterwards and check with `dotnet --version` (it must start with `10.`).
2. Copy the source code to the server (e.g. `git clone` or a zip of the folder *without* `bin`, `obj`, `logs`, `testIse.txt` and `dnsToken.txt`),
   e.g. to `C:\Build\CiscoIseLetsEncrypt`.
3. Build and (optionally) run the tests. The server must be able to reach `api.nuget.org` (443) to download the NuGet packages:
   ```powershell
   cd C:\Build\CiscoIseLetsEncrypt
   dotnet test
   powershell -ExecutionPolicy Bypass -File .\scripts\windows\Publish-CiscoIseLetsEncrypt.ps1 -Output 'C:\Program Files\CiscoIseLetsEncrypt'
   ```
   Or without the script:
   ```powershell
   dotnet publish src\CiscoIseLetsEncrypt -c Release -r win-x64 --self-contained true `
       -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o 'C:\Program Files\CiscoIseLetsEncrypt'
   Copy-Item scripts\windows\*.ps1, scripts\windows\jobs.example.psd1 'C:\Program Files\CiscoIseLetsEncrypt' -Exclude Publish-*.ps1
   ```
4. Check: `& 'C:\Program Files\CiscoIseLetsEncrypt\CiscoIseLetsEncrypt.exe' -Help`.

To update: stop/disable the task, get the new code and run step 3 again (the exe is overwritten).

### 2b. Build on another machine

On a machine with the .NET 10 SDK (it can be a Mac/Linux machine):

```powershell
.\scripts\windows\Publish-CiscoIseLetsEncrypt.ps1 -Output .\publish\win-x64
```

Copy the contents of `publish\win-x64` to the server, e.g. to `C:\Program Files\CiscoIseLetsEncrypt`.
The folder contains `CiscoIseLetsEncrypt.exe`, the four scripts and `jobs.example.psd1`.

If the scripts were downloaded from the network, remove the "downloaded" mark:

```powershell
Get-ChildItem 'C:\Program Files\CiscoIseLetsEncrypt' | Unblock-File
```

---

## 3. Configuration (jobs.psd1)

```powershell
cd 'C:\Program Files\CiscoIseLetsEncrypt'
Copy-Item jobs.example.psd1 jobs.psd1
notepad jobs.psd1
```

- `CommonArguments` apply to all jobs (admin node, DNS proxy URL, optionally `-AcmeTest`, `-DeleteOldCertificates`).
- `Jobs` contains one job per certificate, e.g. one for EAP/DTLS and one for Portal. The jobs run one after the other,
  and a failed job does not stop the next one.
- With several nodes in `-Node`, one certificate is issued on the first node. It is exported with its (encrypted) key and imported
  on the others, so all nodes present the **same** EAP certificate.
- **Secrets must not be in the file.**

Start with `-AcmeTest` in `CommonArguments` until everything works. Then remove it to get real certificates.

---

## 4. Store the secrets as the service account

Start a PowerShell **as the service account** and run the secrets script:

```powershell
runas /user:EXAMPLE\svc-iseacme "powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File \"C:\Program Files\CiscoIseLetsEncrypt\Set-CiscoIseLetsEncryptSecrets.ps1\""
```

The script asks for `Ise:Username`, `Ise:Password`, `DnsProxy:Token`, `Radius:Secret` and `Backup:Password` (empty = unchanged; only needed for `-Backup`).
Passwords are typed hidden and sent to the program through stdin, so they never appear on a command line. Press Enter to keep an existing value.
Only one value, e.g. after a DNS token change:

```powershell
.\Set-CiscoIseLetsEncryptSecrets.ps1 -Keys 'DnsProxy:Token'
```

In the same window (still as the service account), test the configuration with a **dry run**, which changes nothing:

```powershell
cd 'C:\Program Files\CiscoIseLetsEncrypt'
.\Invoke-CiscoIseLetsEncrypt.ps1 -DryRun
```

Check in the output that:
- *Step 0a* (RADIUS), *Step 0b* (permissions) and *Step 0c* (Let's Encrypt CAs trusted in ISE) are ✔,
- the cluster overview (*Step 1*) shows the expected nodes and certificates,
- the plan shows the right nodes, roles and names.

---

## 5. Create the scheduled task

As **administrator**:

```powershell
cd 'C:\Program Files\CiscoIseLetsEncrypt'
.\Register-CiscoIseLetsEncryptTask.ps1 -User 'EXAMPLE\svc-iseacme' -At 03:15
```

The script asks for the service account's password and creates the task `\CiscoIseLetsEncrypt`:

| Setting | Value |
|---|---|
| Trigger | Daily at `-At` plus a random delay of 0–30 min (recommended for ACME clients) |
| Runs as | The service account, *Run whether user is logged on or not*, not elevated |
| Action | `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Invoke-CiscoIseLetsEncrypt.ps1 -ConfigFile jobs.psd1` |
| Start when available | Yes (a missed run is done when the server is up again) |
| Max run time | 2 hours |
| Parallel runs | No (IgnoreNew) |

Test the task right away:

```powershell
Start-ScheduledTask -TaskName CiscoIseLetsEncrypt
Get-ScheduledTaskInfo -TaskName CiscoIseLetsEncrypt   # LastTaskResult: 0 = OK, 1 = error, 2 = configuration error
```

Remove the task again:

```powershell
.\Register-CiscoIseLetsEncryptTask.ps1 -Unregister
```

> When the service account's password changes, the task must be registered again (or the password updated in Task Scheduler).

---

## 6. Logs and monitoring

| What | Where |
|---|---|
| The program's log (all steps) | `<LogDirectory>\CiscoIseLetsEncrypt-yyyyMMdd.log` |
| Transcript of the whole run (all jobs and exit codes) | `<LogDirectory>\task-yyyyMMdd-HHmmss.log` |
| Task history | Task Scheduler > CiscoIseLetsEncrypt > History (enable *Enable All Tasks History*) |

The exit code of `Invoke-CiscoIseLetsEncrypt.ps1` is the highest one from the jobs and is shown as *Last Run Result*:
`0` = OK or nothing to do, `1` = at least one node failed, `2` = invalid parameters or configuration.
Monitor it with your monitoring tool, or create an alert on *Last Run Result ≠ 0*.

Transcripts older than `LogRetentionDays` (default 90) are deleted automatically. The program itself keeps 90 daily log files.

---

## 7. Troubleshooting

| Symptom | Cause / solution |
|---|---|
| `LastTaskResult` 0x1 and "ISE username missing" in the log | The secrets are stored for a different user than the one the task runs as. Run step 4 again as the service account |
| The task does not start ("logon failure") | The service account lacks *Log on as a batch job*, or the password has changed |
| "RADIUS check failed" | The server's IP is not a Network Device in ISE, or `Radius:Secret` is wrong |
| "running scripts is disabled" | The task uses `-ExecutionPolicy Bypass`. When running manually: `powershell -ExecutionPolicy Bypass -File …` or `Unblock-File` |
| "ISE does not trust … Let's Encrypt CA certificate(s)" | Install the logged CA certificates in ISE (see [GUIDE.md step 0c](GUIDE.md#step-0c--does-ise-trust-lets-encrypt)) |
| TLS error against ISE | The server does not trust ISE's admin certificate. Import the CA into *Trusted Root* or add `-SkipIseTlsValidation` |
| No log files | The service account has no write access to `LogDirectory` |
| As SYSTEM: "ISE username missing" | The secrets are stored for your own user. Store them again through `psexec -s -i` (section 8) |

---

## 8. Alternative: run as Local System

The task can run as `SYSTEM` instead of a service account. The program logs in to ISE and the DNS proxy with the stored
secrets, not with the Windows account, so it works the same way.

| | Service account | Local System |
|---|---|---|
| Password that must be changed | Yes (and the task must be updated afterwards) | No |
| *Log on as a batch job* | Must be granted | Not needed |
| Permissions on the server | Only what is needed | **Full** – a bug or compromise affects the whole server |
| Who can read the secrets | The account itself and local administrators | SYSTEM and local administrators |
| Proxy settings | The user's | None (see below) |

**File locations as SYSTEM**

| What | Path |
|---|---|
| User secrets | `C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\UserSecrets\<id>\secrets.json` |
| ACME account key | `C:\Windows\System32\config\systemprofile\.ciscoiseletsencrypt\` |
| Logs | `LogDirectory` from `jobs.psd1`, e.g. `C:\ProgramData\CiscoIseLetsEncrypt\logs` |

**Setup**

1. **Store the secrets as SYSTEM.** `runas` cannot start a process as SYSTEM, so use
   [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec) from Sysinternals in an administrator prompt:
   ```powershell
   psexec -s -i powershell.exe -NoProfile -ExecutionPolicy Bypass
   ```
   In the new window (check with `whoami`, which must show `nt authority\system`):
   ```powershell
   cd 'C:\Program Files\CiscoIseLetsEncrypt'
   .\Set-CiscoIseLetsEncryptSecrets.ps1
   .\Invoke-CiscoIseLetsEncrypt.ps1 -DryRun
   ```
2. **Create the task** as administrator (no password is asked for):
   ```powershell
   .\Register-CiscoIseLetsEncryptTask.ps1 -User SYSTEM -At 03:15
   ```
   The task gets *Run with highest privileges* and *Run whether user is logged on or not*.

**Proxy:** SYSTEM normally has no proxy settings. If the server must use a proxy to reach Let's Encrypt or the DNS proxy,
set it at machine level (remember `NO_PROXY` for the ISE nodes, and RADIUS does not go through an HTTP proxy):
```powershell
[Environment]::SetEnvironmentVariable('HTTPS_PROXY', 'http://proxy.example.com:8080', 'Machine')
[Environment]::SetEnvironmentVariable('NO_PROXY', '.example.com', 'Machine')
```

**Switching from a service account to SYSTEM:** store the secrets as SYSTEM (step 1) and register the task again with `-User SYSTEM`.
The ACME account key is created again automatically for SYSTEM. Then delete `%APPDATA%\Microsoft\UserSecrets\<id>` in the service account's profile.
