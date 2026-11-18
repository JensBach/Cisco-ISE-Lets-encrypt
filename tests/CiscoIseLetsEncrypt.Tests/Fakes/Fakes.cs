using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CiscoIseLetsEncrypt.Acme;
using CiscoIseLetsEncrypt.Certificates;
using CiscoIseLetsEncrypt.Dns;
using CiscoIseLetsEncrypt.Ise;
using CiscoIseLetsEncrypt.Verification;

namespace CiscoIseLetsEncrypt.Tests.Fakes;

public static class TestCa
{
    public static readonly RSA Key = RSA.Create(2048);
    public static readonly X509Certificate2 Certificate = CreateCa();

    private static X509Certificate2 CreateCa()
    {
        var req = new CertificateRequest("CN=Test ACME Root", Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    }

    public static TrustedCertificate Trusted() => new()
    {
        Id = Guid.NewGuid().ToString(), FriendlyName = "Test ACME Root", Subject = Certificate.Subject, Sha256Fingerprint = CertificateUtil.Sha256(Certificate),
    };

    public static KnownCa Known() => new(AcmeEnvironment.Production, CaKeyType.RSA, CaKind.Root, "Test ACME Root", "Test ACME Root",
        "https://ca.test/root.der", Convert.ToBase64String(Certificate.RawData));

    public static X509Certificate2 Sign(byte[] csrDer, int validDays = 90)
    {
        var csr = CertificateRequest.LoadSigningRequest(csrDer, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var generator = X509SignatureGenerator.CreateForRSA(Key, RSASignaturePadding.Pkcs1);
        return csr.Create(Certificate.SubjectName, generator, DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(validDays), RandomNumberGenerator.GetBytes(16));
    }

    public static X509Certificate2 SelfSigned(string cn, int validDays)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(validDays));
    }
}

/// <summary>In-memory ISE. Keys for CSRs are generated "on ISE" (here) and never exposed.</summary>
public sealed class FakeIse : IIseClient
{
    private readonly Dictionary<string, (string Host, RSA Key, string Pem)> _csrs = new();

    public List<IseNode> Nodes { get; } = [];
    public Dictionary<string, List<SystemCertificate>> Certificates { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<TrustedCertificate> Trusted { get; } = [];
    public List<CsrRequest> GeneratedCsrs { get; } = [];
    public List<string> DeletedCsrs { get; } = [];
    public List<BindRequest> Bound { get; } = [];
    public List<(string Host, string Id, IReadOnlyCollection<IseRole> Roles)> RoleUpdates { get; } = [];
    public List<string> ExtraSanInCsr { get; } = [];

    /// <summary>Simulates ISE refusing the CSR because the names do not resolve to the node.</summary>
    public bool CsrNameResolutionFails { get; set; }
    public Dictionary<string, X509Certificate2> InstalledByFingerprint { get; } = new();

    public IseNode AddNode(string hostname, string domain = "example.net", params string[] services)
    {
        var node = new IseNode
        {
            Hostname = hostname, Fqdn = $"{hostname}.{domain}", IpAddress = "10.0.0." + (Nodes.Count + 10),
            Roles = ["Standalone"], Services = services.Length > 0 ? services.ToList() : ["Session", "Profiler"],
            NodeStatus = "Connected",
        };
        Nodes.Add(node);
        Certificates[hostname] = [];
        return node;
    }

    public SystemCertificate AddCertificate(string hostname, X509Certificate2 cert, string usedBy, string? issuedBy = null)
    {
        var sc = new SystemCertificate
        {
            Id = Guid.NewGuid().ToString(), FriendlyName = cert.Subject, IssuedTo = CertificateUtil.CommonName(cert),
            IssuedBy = issuedBy ?? cert.GetNameInfo(X509NameType.SimpleName, true),
            ExpirationDate = cert.NotAfter.ToUniversalTime().ToString("ddd MMM dd HH:mm:ss 'UTC' yyyy", System.Globalization.CultureInfo.InvariantCulture),
            UsedBy = usedBy, SelfSigned = CertificateUtil.IsSelfSigned(cert), Sha256Fingerprint = CertificateUtil.Sha256(cert),
        };
        Certificates[hostname].Add(sc);
        InstalledByFingerprint[sc.Sha256Fingerprint] = cert;
        return sc;
    }

    public Task<IReadOnlyList<IseNode>> GetNodesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<IseNode>>(Nodes);

    public Task<IReadOnlyList<SystemCertificate>> GetSystemCertificatesAsync(string hostname, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<SystemCertificate>>(Certificates[hostname].ToList());

    public Task<string> GenerateCsrAsync(CsrRequest request, CancellationToken ct)
    {
        if (CsrNameResolutionFails)
            throw new IseCsrNameResolutionException("Certificate contains bad Comman Name & SAN Values", System.Net.HttpStatusCode.BadRequest);
        GeneratedCsrs.Add(request);
        var key = RSA.Create(2048);
        var req = new CertificateRequest($"CN={request.CommonName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in request.SanDns.Concat(ExtraSanInCsr))
            san.AddDnsName(n);
        req.CertificateExtensions.Add(san.Build());
        var id = Guid.NewGuid().ToString();
        _csrs[id] = (request.Hostname, key, req.CreateSigningRequestPem());
        return Task.FromResult(id);
    }

    public Task<string> ExportCsrAsync(string hostname, string csrId, CancellationToken ct) => Task.FromResult(_csrs[csrId].Pem);

    public Task DeleteCsrAsync(string hostname, string csrId, CancellationToken ct)
    {
        DeletedCsrs.Add(csrId);
        _csrs.Remove(csrId);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<TrustedCertificate>> GetTrustedCertificatesAsync(CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<TrustedCertificate>>(Trusted.ToList());

    public Task BindCertificateAsync(BindRequest request, CancellationToken ct)
    {
        if (!_csrs.Remove(request.CsrId))
            throw new IseApiException("CSR not found");
        var cert = X509Certificate2.CreateFromPem(request.CertificatePem);
        if (!Trusted.Any(t => t.Sha256Fingerprint == CertificateUtil.Sha256(TestCa.Certificate)))
            throw new IseApiException("Issuer is not trusted");
        Bound.Add(request);
        var sc = AddCertificate(request.Hostname, cert, "Not in use", TestCa.Certificate.GetNameInfo(X509NameType.SimpleName, false));
        sc.FriendlyName = request.FriendlyName;
        return Task.CompletedTask;
    }

    public Task UpdateSystemCertificateRolesAsync(string hostname, SystemCertificate certificate, IReadOnlyCollection<IseRole> roles,
        string? portalGroupTag, CancellationToken ct)
    {
        RoleUpdates.Add((hostname, certificate.Id, roles));
        var names = new Dictionary<IseRole, string>
        {
            [IseRole.Admin] = "Admin", [IseRole.Eap] = "EAP Authentication", [IseRole.Dtls] = "RADIUS DTLS",
            [IseRole.Portal] = "Portal", [IseRole.PxGrid] = "pxGrid", [IseRole.Ims] = "ISE Messaging Service", [IseRole.Saml] = "SAML",
        };
        foreach (var other in Certificates[hostname].Where(c => c.Id != certificate.Id))
        {
            var remaining = (other.UsedBy ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Where(u => !roles.Any(r => names[r] == u));
            other.UsedBy = string.Join(", ", remaining);
        }
        Certificates[hostname].Single(c => c.Id == certificate.Id).UsedBy = string.Join(", ", roles.Select(r => names[r]));
        return Task.CompletedTask;
    }

    public Task<bool> IsApiAvailableAsync(CancellationToken ct) => Task.FromResult(true);

    public bool WriteAccess { get; set; } = true;
    public List<(string Host, string Id)> DeletedCertificates { get; } = [];
    public List<(string Host, string Id)> Exports { get; } = [];
    public HashSet<string> NotExportable { get; } = [];
    public List<(string Host, SystemCertificateImport Import)> Imports { get; } = [];

    public Task DeleteSystemCertificateAsync(string hostname, string id, CancellationToken ct)
    {
        DeletedCertificates.Add((hostname, id));
        Certificates[hostname].RemoveAll(c => c.Id == id);
        return Task.CompletedTask;
    }

    public Task<ExportedCertificate> ExportSystemCertificateAsync(string hostname, string id, string password, CancellationToken ct)
    {
        Exports.Add((hostname, id));
        if (NotExportable.Contains(id))
            throw new IseApiException("ISE POST export failed: 400 BadRequest. The export operation is not allowed for Data Grid Certificates.");
        var sc = Certificates[hostname].Single(c => c.Id == id);
        var cert = InstalledByFingerprint[sc.Sha256Fingerprint!];
        var key = cert.GetRSAPrivateKey()?.ExportEncryptedPkcs8PrivateKeyPem(password,
                      new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10000))
                  ?? "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZmFrZQ==\n-----END ENCRYPTED PRIVATE KEY-----";
        return Task.FromResult(new ExportedCertificate(CertificateUtil.ToPem(cert), key + "\n", password));
    }

    public async Task ImportSystemCertificateAsync(IseNode node, SystemCertificateImport import, CancellationToken ct)
    {
        Imports.Add((node.Hostname, import));
        var cert = X509Certificate2.CreateFromPem(import.Certificate.CertificatePem);
        var sc = AddCertificate(node.Hostname, cert, "Not in use", TestCa.Certificate.GetNameInfo(X509NameType.SimpleName, false));
        sc.FriendlyName = import.FriendlyName;
        await UpdateSystemCertificateRolesAsync(node.Hostname, sc, import.Roles, import.PortalGroupTag, ct);
        RoleUpdates.RemoveAt(RoleUpdates.Count - 1);
    }

    public Task<bool> HasWriteAccessAsync(CancellationToken ct) => Task.FromResult(WriteAccess);

    /// <summary>Certificate currently holding a role on a node (what a client would see).</summary>
    public X509Certificate2? CertificateForRole(string hostname, IseRole role)
    {
        var sc = Certificates[hostname].FirstOrDefault(c => c.Roles.Contains(role));
        return sc is null ? null : InstalledByFingerprint[sc.Sha256Fingerprint!];
    }
}

public sealed class FakeAcme : IAcmeService
{
    public bool FailValidation { get; set; }
    public List<IReadOnlyList<string>> Orders { get; } = [];
    public string ServerDescription => "fake-acme";

    public Task<IAcmeOrder> NewOrderAsync(IReadOnlyList<string> dnsNames, CancellationToken ct)
    {
        Orders.Add(dnsNames);
        return Task.FromResult<IAcmeOrder>(new Order(this, dnsNames));
    }

    private sealed class Order(FakeAcme owner, IReadOnlyList<string> names) : IAcmeOrder
    {
        private bool _validated;

        public Task<IReadOnlyList<DnsChallenge>> GetPendingDnsChallengesAsync(CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<DnsChallenge>>(names.Select(n => new DnsChallenge(n, $"_acme-challenge.{n}", "txt-" + n)).ToList());

        public Task ValidateAsync(CancellationToken ct)
        {
            if (owner.FailValidation)
                throw new AcmeException("ACME validation failed: urn:ietf:params:acme:error:unauthorized");
            _validated = true;
            return Task.CompletedTask;
        }

        public Task<IssuedCertificate> FinalizeAsync(byte[] csrDer, CancellationToken ct)
        {
            if (!_validated)
                throw new AcmeException("Order not ready");
            var cert = TestCa.Sign(csrDer);
            return Task.FromResult(new IssuedCertificate(CertificateUtil.ToPem(cert), []));
        }
    }
}

public sealed class FakeDns : IDnsChallengeClient, IDnsPropagationChecker
{
    public Dictionary<string, string> Records { get; } = new();
    public List<string> Created { get; } = [];
    public List<string> Deleted { get; } = [];

    public Task CreateTxtRecordAsync(string recordName, string value, CancellationToken ct)
    {
        Records[recordName] = value;
        Created.Add(recordName);
        return Task.CompletedTask;
    }

    public Task DeleteTxtRecordAsync(string recordName, CancellationToken ct)
    {
        Records.Remove(recordName);
        Deleted.Add(recordName);
        return Task.CompletedTask;
    }

    public Task<bool> WaitForTxtRecordAsync(string recordName, string expectedValue, TimeSpan timeout, CancellationToken ct) =>
        Task.FromResult(Records.TryGetValue(recordName, out var v) && v == expectedValue);
}

public sealed class FakeChainResolver : IIssuerChainResolver
{
    public Task<IReadOnlyList<X509Certificate2>> ResolveAsync(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> knownIssuers, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<X509Certificate2>>([TestCa.Certificate]);
}

/// <summary>Probe that reports the certificate the fake ISE has assigned to the role (or a stale one).</summary>
public sealed class FakeProbe(FakeIse ise) : ICertificateProbe
{
    private readonly Dictionary<string, X509Certificate2> _initial = new();

    public bool StaleServices { get; set; }
    public bool FailRadius { get; set; }
    public List<string> Probed { get; } = [];

    public void Snapshot(string hostname)
    {
        foreach (var role in new[] { IseRole.Admin, IseRole.Eap, IseRole.Portal })
            if (ise.CertificateForRole(hostname, role) is { } c)
                _initial[$"{hostname}/{role}"] = c;
    }

    public Task<X509Certificate2> GetTlsCertificateAsync(string host, int port, string? sni, CancellationToken ct) =>
        Task.FromResult(Get(host, port == 443 ? IseRole.Admin : IseRole.Portal));

    public Task<X509Certificate2> GetEapCertificateAsync(string host, int port, string sharedSecret, string identity, CancellationToken ct) =>
        FailRadius ? throw new TimeoutException("No RADIUS response") : Task.FromResult(Get(host, IseRole.Eap));

    private X509Certificate2 Get(string host, IseRole role)
    {
        Probed.Add($"{role}@{host}");
        var node = ise.Nodes.First(n => n.Fqdn == host || n.IpAddress == host);
        if (StaleServices)
            return _initial[$"{node.Hostname}/{role}"];
        return ise.CertificateForRole(node.Hostname, role) ?? throw new IOException("no certificate");
    }
}
