using System.Text.Json.Serialization;

namespace CiscoIseLetsEncrypt.Ise;

public sealed class IseNode
{
    [JsonPropertyName("hostname")] public string Hostname { get; set; } = "";
    [JsonPropertyName("fqdn")] public string Fqdn { get; set; } = "";
    [JsonPropertyName("ipAddress")] public string? IpAddress { get; set; }
    [JsonPropertyName("roles")] public List<string> Roles { get; set; } = [];
    [JsonPropertyName("services")] public List<string> Services { get; set; } = [];
    [JsonPropertyName("nodeStatus")] public string? NodeStatus { get; set; }

    public bool Matches(string name) =>
        string.Equals(Hostname, name, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(Fqdn, name, StringComparison.OrdinalIgnoreCase);

    /// <summary>Address used for TLS/RADIUS probes.</summary>
    public string ProbeAddress => !string.IsNullOrEmpty(Fqdn) ? Fqdn : Hostname;

    public override string ToString() => string.IsNullOrEmpty(Fqdn) ? Hostname : Fqdn;
}

public sealed class SystemCertificate
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("friendlyName")] public string? FriendlyName { get; set; }
    [JsonPropertyName("issuedTo")] public string? IssuedTo { get; set; }
    [JsonPropertyName("issuedBy")] public string? IssuedBy { get; set; }
    [JsonPropertyName("validFrom")] public string? ValidFrom { get; set; }
    [JsonPropertyName("expirationDate")] public string? ExpirationDate { get; set; }
    [JsonPropertyName("usedBy")] public string? UsedBy { get; set; }
    [JsonPropertyName("groupTag")] public string? GroupTag { get; set; }
    [JsonPropertyName("portalsUsingTheTag")] public string? PortalsUsingTheTag { get; set; }
    [JsonPropertyName("sha256Fingerprint")] public string? Sha256Fingerprint { get; set; }
    [JsonPropertyName("selfSigned")] public bool? SelfSigned { get; set; }

    [JsonIgnore] public IReadOnlySet<IseRole> Roles => IseRoles.ParseUsedBy(UsedBy);

    /// <summary>True when ISE reports no service/role and no portal using the certificate.</summary>
    [JsonIgnore] public bool IsUnused =>
        (string.IsNullOrWhiteSpace(UsedBy) || UsedBy.Trim().Equals("Not in use", StringComparison.OrdinalIgnoreCase)) &&
        string.IsNullOrWhiteSpace(PortalsUsingTheTag);
    [JsonIgnore] public DateTimeOffset? ExpiresUtc => IseDateParser.TryParse(ExpirationDate);

    public override string ToString() =>
        $"'{FriendlyName}' (CN={IssuedTo}, issuer={IssuedBy}, expires={ExpirationDate}, usedBy={UsedBy}, id={Id})";
}

public sealed class TrustedCertificate
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("friendlyName")] public string? FriendlyName { get; set; }
    [JsonPropertyName("subject")] public string? Subject { get; set; }
    [JsonPropertyName("sha256Fingerprint")] public string? Sha256Fingerprint { get; set; }
}

public sealed record CsrRequest(
    string Hostname,
    IReadOnlyCollection<IseRole> Roles,
    string CommonName,
    IReadOnlyList<string> SanDns,
    string KeyType,
    string KeyLength,
    string DigestType,
    string? PortalGroupTag);

public sealed record BindRequest(string Hostname, string CsrId, string CertificatePem, string FriendlyName);

/// <summary>System certificate exported from ISE. The private key is PKCS#8 encrypted with <see cref="Password"/>.</summary>
public sealed record ExportedCertificate(string CertificatePem, string EncryptedPrivateKeyPem, string Password);

public sealed record SystemCertificateImport(
    string FriendlyName,
    ExportedCertificate Certificate,
    IReadOnlyCollection<IseRole> Roles,
    string? PortalGroupTag);
