using System.Globalization;
using CiscoIseLetsEncrypt.Ise;

namespace CiscoIseLetsEncrypt.Cli;

public sealed class CliArgumentException(string message) : Exception(message);

/// <summary>
/// Parses PowerShell style arguments: <c>-Name value</c> (case-insensitive, "-", "--" or "/" prefix).
/// Lists are comma separated. Secrets can come from files or environment variables.
/// </summary>
public static class ArgumentParser
{
    private static readonly HashSet<string> Switches = new(StringComparer.OrdinalIgnoreCase)
    {
        "Force", "AcmeTest", "Staging", "SkipIseTlsValidation", "Insecure", "SkipVerification",
        "IncludeNodeFqdn", "Verbose", "Help", "?", "h", "DryRun", "WhatIf", "DeleteOldCertificates", "KeepOldCertificates", "Backup", "NoLocalKey",
    };

    /// <summary>Keys used in .NET user secrets (dotnet user-secrets set &lt;key&gt; &lt;value&gt;).</summary>
    public static class SecretKeys
    {
        public const string IseUsername = "Ise:Username";
        public const string IsePassword = "Ise:Password";
        public const string DnsToken = "DnsProxy:Token";
        public const string RadiusSecret = "Radius:Secret";
        public const string BackupPassword = "Backup:Password";
        public static readonly string[] All = [IseUsername, IsePassword, DnsToken, RadiusSecret, BackupPassword];
    }

    public const string HelpText = """
        CiscoIseLetsEncrypt - renew Cisco ISE system certificates with Let's Encrypt (DNS-01).
        The CSR and private key are generated on the ISE node; the key never leaves ISE.

        Usage:
          CiscoIseLetsEncrypt -AdmNode <pan-fqdn> [-Node <fqdn>[,<fqdn>...]] -Roles EAP,DTLS
                              -CertificateDNS <name>[,<name>...]
                              -DnsChallengeUrl <url> | -DnsScript <script.ps1> [options]
          CiscoIseLetsEncrypt -Backup -AdmNode <pan-fqdn> [-BackupDirectory <dir>] [-BackupPassword <pw>]

        Required:
          -AdmNode                 ISE Primary Admin Node (OpenAPI endpoint).
          -Roles                   Admin, EAP, DTLS, Portal, pxGrid, IMS, SAML (comma separated).
          -CertificateDNS          DNS names for the certificate. First name is the CN.
          -DnsChallengeUrl         ACME DNS proxy, e.g. https://dnsproxy.example.com (/api/txt is added when no
                                   path is given). TXT records are created with POST and removed with DELETE.
          -DnsScript               Alternative for other DNS providers (instead of -DnsChallengeUrl): a PowerShell
                                   script called as  -Action Create -RecordName <name> -Value <txt>  and
                                   -Action Delete -RecordName <name>. Exit code 0 = ok. See scripts/windows/Invoke-DnsChallenge.example.ps1.
          -DnsScriptTimeoutSeconds Max run time per script call (default 120).

        Optional:
          -Node                    Node(s) to update. Default: all nodes running services for the roles.
                                   With several nodes, one certificate is issued on the first node and the
                                   same certificate (with key) is exported/imported to the others.
          -DnsChallengeToken       Bearer token (or env ACMEDNSPROXY_TOKEN, or -DnsTokenFile).
          -DnsTokenFile            File with "token : <value>".
          -IseUsername/-IsePassword  (or env ISE_USERNAME/ISE_PASSWORD, or -IseCredentialFile).
          -IseCredentialFile       File with "username : <value>" and "password : <value>".
          -AcmeTest                Use Let's Encrypt STAGING (test certificates, not trusted).
          -AcmeEmail               Contact e-mail for the ACME account.
          -AcmeAccountKey          Path of the ACME account key (created if missing).
          -DryRun (-WhatIf)        Run all checks and show what would be done, without changing anything.
          -DeleteOldCertificates   Delete previous certificates that are no longer used by anything.
          -NoLocalKey              Fail if ISE refuses the CSR because a name does not resolve to the node.
                                   Default: generate the key and CSR in this program (memory only, logged as a
                                   warning) and import the certificate with its encrypted key into ISE.
                                   Default (-KeepOldCertificates): keep them.
          -Force                   Replace the certificate even if the current one is still valid.
          -RenewBeforeDays         Renew when the certificate expires within N days (default 30).
          -IncludeNodeFqdn         Add the node FQDN as an extra SAN.
          -KeyType / -KeyLength / -DigestType   CSR parameters (default RSA / 2048 / SHA-256).
          -PortalGroupTag          Portal group tag (default "Default Portal Certificate Group").
          -RadiusSecret            Shared secret for the RADIUS/EAP-PEAP checks (or env RADIUS_SECRET, user secret
                                   Radius:Secret). Required for the EAP role unless -SkipVerification.
                                   This host must be a Network Device in ISE.
          -RadiusPort              Default 1812.   -RadiusIdentity  Default "anonymous".
          -PortalPort              Default 8443.
          -VerifyTimeoutMinutes    Wait for services/role changes (default 20).
          -DnsPropagationTimeoutSeconds   Default 300.
          -DnsResolvers            Resolvers used to check TXT propagation (default 1.1.1.1,8.8.8.8).
          -SkipVerification        Skip the live (HTTPS/RADIUS) verification.
          -SkipIseTlsValidation    Do not validate the TLS certificate of the ISE API.
          -LogDirectory            Default ./logs.   -Verbose  Debug logging.

        Backup (-Backup): exports every system certificate of every node in the deployment, with its private key
        encrypted by ISE with the backup password, to <BackupDirectory>/<yyyyMMdd-HHmmss>/<node>/ (.crt + .key)
        plus manifest.json. Nothing is changed and no other options are needed.
          -BackupDirectory         Default ./backups.
          -BackupPassword          Password for the private keys, min. 8 characters (or env BACKUP_PASSWORD,
                                   user secret Backup:Password). Needed to import the keys again.

        Secrets (.NET user secrets, stored per Windows/macOS user outside the program folder):
          CiscoIseLetsEncrypt -SetSecret <key>   Prompts for the value (or reads it from stdin).
          Keys: Ise:Username, Ise:Password, DnsProxy:Token, Radius:Secret, Backup:Password
          Precedence: command line > file > environment > user secrets.

        Exit codes: 0 = success / nothing to do, 1 = failure, 2 = invalid arguments.
        """;

    public static bool IsHelp(string[] args) =>
        args.Length == 0 || args.Any(a => a.TrimStart('-', '/') is "help" or "Help" or "?" or "h");

    public static AppOptions Parse(string[] args, Func<string, string?> env, Func<string, string?>? secrets = null)
    {
        secrets ??= _ => null;
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (!(arg.StartsWith('-') || arg.StartsWith('/')))
                throw new CliArgumentException($"Unexpected argument '{arg}'.");

            var name = arg.TrimStart('-', '/');
            string? inline = null;
            var colon = name.IndexOfAny([':', '=']);
            if (colon > 0)
            {
                inline = name[(colon + 1)..];
                name = name[..colon];
            }

            if (Switches.Contains(name))
            {
                if (inline is null || bool.Parse(inline))
                    flags.Add(name);
                continue;
            }

            var value = inline ?? (i + 1 < args.Length ? args[++i] : throw new CliArgumentException($"Missing value for -{name}."));
            values[name] = value;
        }

        string? Get(params string[] names) =>
            names.Select(n => values.TryGetValue(n, out var v) ? v : null).FirstOrDefault(v => v is not null);

        var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "AdmNode", "Node", "Nodes", "Roles", "Role", "CertificateDNS", "DnsChallengeUrl", "DnsChallengeCreateURL", "DnsChallengeDeleteURL",
            "DnsChallengeToken", "DnsTokenFile", "IseUsername", "IsePassword", "IseCredentialFile", "AcmeEmail",
            "AcmeAccountKey", "RenewBeforeDays", "KeyType", "KeyLength", "DigestType", "PortalGroupTag", "RadiusSecret",
            "RadiusPort", "RadiusIdentity", "PortalPort", "VerifyTimeoutMinutes", "DnsPropagationTimeoutSeconds",
            "DnsResolvers", "LogDirectory", "BackupDirectory", "BackupPassword", "DnsScript", "DnsScriptTimeoutSeconds",
        };
        var unknown = values.Keys.Where(k => !known.Contains(k)).ToList();
        if (unknown.Count > 0)
            throw new CliArgumentException($"Unknown option(s): {string.Join(", ", unknown.Select(u => "-" + u))}");

        var o = new AppOptions
        {
            AdmNode = Get("AdmNode") ?? throw new CliArgumentException("-AdmNode is required."),
            Nodes = SplitList(Get("Node", "Nodes")),
            CertificateDns = SplitList(Get("CertificateDNS")).Select(n => n.ToLowerInvariant()).Distinct().ToList(),
            Force = flags.Contains("Force"),
            AcmeTest = flags.Contains("AcmeTest") || flags.Contains("Staging"),
            SkipIseTlsValidation = flags.Contains("SkipIseTlsValidation") || flags.Contains("Insecure"),
            SkipVerification = flags.Contains("SkipVerification"),
            NoLocalKey = flags.Contains("NoLocalKey"),
            IncludeNodeFqdn = flags.Contains("IncludeNodeFqdn"),
            DryRun = flags.Contains("DryRun") || flags.Contains("WhatIf"),
            KeepOldCertificates = !flags.Contains("DeleteOldCertificates"),
            Verbose = flags.Contains("Verbose"),
            Backup = flags.Contains("Backup"),
            AcmeEmail = Get("AcmeEmail"),
            AcmeAccountKeyPath = Get("AcmeAccountKey"),
        };
        o.AdmNode = StripScheme(o.AdmNode);
        o.Nodes = o.Nodes.Select(StripScheme).ToList();
        if (Get("LogDirectory") is { } logDir) o.LogDirectory = logDir;
        ReadIseCredentials(o, Get, env, secrets);

        if (o.Backup)
        {
            if (Get("BackupDirectory") is { } bd) o.BackupDirectory = bd;
            o.BackupPassword = Get("BackupPassword") ?? env("BACKUP_PASSWORD") ?? secrets(SecretKeys.BackupPassword)
                ?? throw new CliArgumentException($"Backup password missing (-BackupPassword, env BACKUP_PASSWORD or user secret {SecretKeys.BackupPassword}).");
            if (o.BackupPassword.Length < 8)
                throw new CliArgumentException("The backup password must be at least 8 characters.");
            return o;
        }

        foreach (var r in SplitList(Get("Roles", "Role")))
        {
            if (!IseRoles.TryParse(r, out var role))
                throw new CliArgumentException($"Unknown role '{r}'. Valid: Admin, EAP, DTLS, Portal, pxGrid, IMS, SAML.");
            if (!o.Roles.Contains(role))
                o.Roles.Add(role);
        }
        if (o.Roles.Count == 0)
            throw new CliArgumentException("-Roles is required.");
        if (o.Roles.Contains(IseRole.Saml) && o.Roles.Count > 1)
            throw new CliArgumentException("SAML cannot be combined with other roles.");
        if (o.CertificateDns.Count == 0)
            throw new CliArgumentException("-CertificateDNS is required.");
        if (o.CertificateDns.Any(n => n.Contains('*')))
            throw new CliArgumentException("Wildcard names are not supported.");

        if (Get("DnsScript") is { } script)
        {
            if (new[] { "DnsChallengeUrl", "DnsChallengeCreateURL", "DnsChallengeDeleteURL", "DnsChallengeToken", "DnsTokenFile" }.Any(values.ContainsKey))
                throw new CliArgumentException("-DnsScript cannot be combined with -DnsChallengeUrl/-DnsChallengeToken/-DnsTokenFile.");
            if (!File.Exists(script))
                throw new CliArgumentException($"DNS script not found: {script}");
            o.DnsScript = Path.GetFullPath(script);
            if (Get("DnsScriptTimeoutSeconds") is { } st)
                o.DnsScriptTimeout = TimeSpan.FromSeconds(ParseInt(st, "DnsScriptTimeoutSeconds", 1, 3600));
        }
        else
        {
            // -DnsChallengeCreateURL/-DnsChallengeDeleteURL are accepted as aliases from earlier versions.
            var dnsUrls = new[] { "DnsChallengeUrl", "DnsChallengeCreateURL", "DnsChallengeDeleteURL" }
                .Where(values.ContainsKey).Select(n => ParseDnsProxyUrl(values[n], n)).Distinct().ToList();
            o.DnsChallengeUrl = dnsUrls.Count switch
            {
                0 => throw new CliArgumentException("-DnsChallengeUrl (ACME DNS proxy) or -DnsScript (other DNS providers) is required."),
                1 => dnsUrls[0],
                _ => throw new CliArgumentException("Only one DNS proxy URL is supported (-DnsChallengeUrl)."),
            };

            var dnsFile = Get("DnsTokenFile") is { } df ? ReadKeyValueFile(df) : null;
            o.DnsChallengeToken = Get("DnsChallengeToken") ?? dnsFile?.GetValueOrDefault("token") ?? env("ACMEDNSPROXY_TOKEN")
                ?? secrets(SecretKeys.DnsToken)
                ?? throw new CliArgumentException($"DNS proxy token missing (-DnsChallengeToken, -DnsTokenFile, env ACMEDNSPROXY_TOKEN or user secret {SecretKeys.DnsToken}).");
        }
        o.RadiusSecret = Get("RadiusSecret") ?? env("RADIUS_SECRET") ?? secrets(SecretKeys.RadiusSecret);
        if (flags.Contains("DeleteOldCertificates") && flags.Contains("KeepOldCertificates"))
            throw new CliArgumentException("-DeleteOldCertificates and -KeepOldCertificates cannot be combined.");
        if (o.Roles.Contains(IseRole.Eap) && !o.SkipVerification && string.IsNullOrEmpty(o.RadiusSecret))
            throw new CliArgumentException(
                $"The EAP role requires a RADIUS shared secret for the RADIUS check (-RadiusSecret, env RADIUS_SECRET or user secret {SecretKeys.RadiusSecret}), " +
                "or -SkipVerification.");
        if (Get("RenewBeforeDays") is { } rbd) o.RenewBeforeDays = ParseInt(rbd, "RenewBeforeDays", 0, 3650);
        if (Get("RadiusPort") is { } rp) o.RadiusPort = ParseInt(rp, "RadiusPort", 1, 65535);
        if (Get("PortalPort") is { } pp) o.PortalPort = ParseInt(pp, "PortalPort", 1, 65535);
        if (Get("RadiusIdentity") is { } ri) o.RadiusIdentity = ri;
        if (Get("VerifyTimeoutMinutes") is { } vt) o.VerifyTimeout = TimeSpan.FromMinutes(ParseInt(vt, "VerifyTimeoutMinutes", 1, 240));
        if (Get("DnsPropagationTimeoutSeconds") is { } dt)
            o.DnsPropagationTimeout = TimeSpan.FromSeconds(ParseInt(dt, "DnsPropagationTimeoutSeconds", 0, 3600));
        if (Get("DnsResolvers") is { } dr) o.DnsResolvers = SplitList(dr);
        if (Get("KeyType") is { } kt) o.KeyType = kt.ToUpperInvariant();
        if (Get("KeyLength") is { } kl) o.KeyLength = kl;
        if (Get("DigestType") is { } dg) o.DigestType = dg.ToUpperInvariant();
        if (Get("PortalGroupTag") is { } pg) o.PortalGroupTag = pg;

        if (o.KeyType is not ("RSA" or "ECDSA"))
            throw new CliArgumentException("-KeyType must be RSA or ECDSA.");
        foreach (var r in o.DnsResolvers)
            if (!System.Net.IPAddress.TryParse(r, out _))
                throw new CliArgumentException($"Invalid DNS resolver '{r}'.");

        return o;
    }

    private static void ReadIseCredentials(AppOptions o, Func<string[], string?> get, Func<string, string?> env, Func<string, string?> secrets)
    {
        var credFile = get(["IseCredentialFile"]) is { } cf ? ReadKeyValueFile(cf) : null;
        o.IseUsername = get(["IseUsername"]) ?? credFile?.GetValueOrDefault("username") ?? env("ISE_USERNAME")
            ?? secrets(SecretKeys.IseUsername)
            ?? throw new CliArgumentException($"ISE username missing (-IseUsername, -IseCredentialFile, env ISE_USERNAME or user secret {SecretKeys.IseUsername}).");
        o.IsePassword = get(["IsePassword"]) ?? credFile?.GetValueOrDefault("password") ?? env("ISE_PASSWORD")
            ?? secrets(SecretKeys.IsePassword)
            ?? throw new CliArgumentException($"ISE password missing (-IsePassword, -IseCredentialFile, env ISE_PASSWORD or user secret {SecretKeys.IsePassword}).");
    }

    /// <summary>Reads files in the format "key : value" (one per line).</summary>
    public static Dictionary<string, string> ReadKeyValueFile(string path)
    {
        if (!File.Exists(path))
            throw new CliArgumentException($"File not found: {path}");
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in File.ReadAllLines(path))
        {
            var idx = line.IndexOf(':');
            if (idx <= 0)
                continue;
            var key = line[..idx].Trim();
            var value = line[(idx + 1)..].Trim();
            if (key.Length > 0)
                result[key] = value;
        }
        return result;
    }

    private static List<string> SplitList(string? value) =>
        (value ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static string StripScheme(string host) =>
        Uri.TryCreate(host, UriKind.Absolute, out var u) && u.Scheme.StartsWith("http") ? u.Host : host.TrimEnd('/');

    private static Uri ParseUrl(string value, string name) =>
        Uri.TryCreate(value, UriKind.Absolute, out var u) && u.Scheme is "https" or "http"
            ? u
            : throw new CliArgumentException($"-{name} must be an absolute http(s) URL.");

    /// <summary>Like the acme.sh hook: a base URL without a path gets "/api/txt" appended.</summary>
    private static Uri ParseDnsProxyUrl(string value, string name)
    {
        var u = ParseUrl(value, name);
        return u.AbsolutePath is "/" or "" ? new Uri(u, "/api/txt") : u;
    }

    private static int ParseInt(string value, string name, int min, int max) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) && v >= min && v <= max
            ? v
            : throw new CliArgumentException($"-{name} must be an integer between {min} and {max}.");
}
