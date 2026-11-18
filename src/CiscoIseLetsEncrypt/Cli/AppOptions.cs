using CiscoIseLetsEncrypt.Ise;

namespace CiscoIseLetsEncrypt.Cli;

public sealed class AppOptions
{
    public string AdmNode { get; set; } = "";
    public List<string> Nodes { get; set; } = [];
    public List<IseRole> Roles { get; set; } = [];
    public List<string> CertificateDns { get; set; } = [];
    public bool IncludeNodeFqdn { get; set; }

    public string IseUsername { get; set; } = "";
    public string IsePassword { get; set; } = "";
    public bool SkipIseTlsValidation { get; set; }

    /// <summary>ACME DNS Proxy URL. Null when <see cref="DnsScript"/> is used instead.</summary>
    public Uri? DnsChallengeUrl { get; set; }
    public string DnsChallengeToken { get; set; } = "";

    /// <summary>PowerShell script that creates/deletes the TXT record (other DNS providers). Replaces the proxy.</summary>
    public string? DnsScript { get; set; }
    public TimeSpan DnsScriptTimeout { get; set; } = TimeSpan.FromMinutes(2);

    public string DnsDescription => DnsScript is not null ? $"script {DnsScript}" : DnsChallengeUrl?.ToString() ?? "";
    public List<string> DnsResolvers { get; set; } = ["1.1.1.1", "8.8.8.8"];
    public TimeSpan DnsPropagationTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Use the Let's Encrypt staging environment (test certificates).</summary>
    public bool AcmeTest { get; set; }
    public string? AcmeEmail { get; set; }
    public string? AcmeAccountKeyPath { get; set; }

    public bool Force { get; set; }

    /// <summary>Only inspect and report what would be changed – no changes on ISE, ACME or DNS.</summary>
    public bool DryRun { get; set; }

    /// <summary>Keep certificates that lost all roles (default). -DeleteOldCertificates turns this off.</summary>
    public bool KeepOldCertificates { get; set; } = true;
    public int RenewBeforeDays { get; set; } = 30;

    public string KeyType { get; set; } = "RSA";
    public string KeyLength { get; set; } = "2048";
    public string DigestType { get; set; } = "SHA-256";
    public string PortalGroupTag { get; set; } = "Default Portal Certificate Group";

    public string? RadiusSecret { get; set; }
    public int RadiusPort { get; set; } = 1812;
    public string RadiusIdentity { get; set; } = "anonymous";
    public int PortalPort { get; set; } = 8443;
    public TimeSpan VerifyTimeout { get; set; } = TimeSpan.FromMinutes(20);
    public bool SkipVerification { get; set; }

    /// <summary>
    /// When ISE refuses the CSR because a name does not resolve to the node, fail instead of generating the key
    /// locally and importing it (-NoLocalKey).
    /// </summary>
    public bool NoLocalKey { get; set; }

    /// <summary>Only export all system certificates (with encrypted private keys) of all nodes – no renewal.</summary>
    public bool Backup { get; set; }
    public string BackupDirectory { get; set; } = "backups";
    public string BackupPassword { get; set; } = "";

    public string LogDirectory { get; set; } = "logs";
    public bool Verbose { get; set; }

    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(10);

    public string ResolveAcmeAccountKeyPath() =>
        AcmeAccountKeyPath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ciscoiseletsencrypt",
            AcmeTest ? "acme-account-staging.pem" : "acme-account-production.pem");
}
