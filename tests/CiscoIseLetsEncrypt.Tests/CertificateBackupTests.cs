using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using CiscoIseLetsEncrypt.Tests.Fakes;
using CiscoIseLetsEncrypt.Workflow;
using Microsoft.Extensions.Logging.Abstractions;

namespace CiscoIseLetsEncrypt.Tests;

public sealed class CertificateBackupTests : IDisposable
{
    private const string Password = "Backup12345";
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "isebackup-" + Guid.NewGuid().ToString("N"));
    private readonly FakeIse _ise = new();

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    private static X509Certificate2 WithKey(string cn)
    {
        var key = RSA.Create(2048);
        return new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    [Fact]
    public async Task Exports_all_certificates_of_all_nodes_with_encrypted_keys_and_manifest()
    {
        _ise.AddNode("ise-17-a");
        _ise.AddNode("ise-17-b");
        var a = _ise.AddCertificate("ise-17-a", WithKey("a.example.net"), "EAP Authentication");
        _ise.AddCertificate("ise-17-a", WithKey("admin.example.net"), "Admin");
        _ise.AddCertificate("ise-17-b", WithKey("b.example.net"), "Not in use");
        var grid = _ise.AddCertificate("ise-17-b", WithKey("grid"), "Data Grid");
        _ise.NotExportable.Add(grid.Id);

        var result = await new CertificateBackup(_ise, TimeProvider.System, NullLogger<CertificateBackup>.Instance)
            .RunAsync(_dir, Password, CancellationToken.None);

        Assert.Equal((3, 1, 0), (result.Exported, result.Skipped, result.Failed));
        Assert.Equal(4, _ise.Exports.Count);
        var entry = result.Entries.Single(e => e.Id == a.Id);
        var cert = await File.ReadAllTextAsync(Path.Combine(result.Directory, entry.CertificateFile!));
        var key = await File.ReadAllTextAsync(Path.Combine(result.Directory, entry.KeyFile!));
        Assert.StartsWith("ise-17-a", entry.CertificateFile);
        Assert.Contains("ENCRYPTED PRIVATE KEY", key);
        using var restored = X509Certificate2.CreateFromEncryptedPem(cert, key, Password);
        Assert.True(restored.HasPrivateKey);

        var manifest = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(result.Directory, "manifest.json")))!;
        Assert.Equal(4, manifest["certificates"]!.AsArray().Count);
        Assert.Contains(manifest["certificates"]!.AsArray(), c => c!["status"]!.GetValue<string>() == "Skipped");
    }

    [Fact]
    public async Task Key_that_does_not_belong_to_the_certificate_is_a_failure()
    {
        _ise.AddNode("ise-17-a");
        _ise.AddCertificate("ise-17-a", TestCa.Certificate, "Admin"); // TestCa key is not exported by the fake -> invalid key

        var result = await new CertificateBackup(new KeylessIse(_ise), TimeProvider.System, NullLogger<CertificateBackup>.Instance)
            .RunAsync(_dir, Password, CancellationToken.None);

        Assert.Equal(1, result.Failed);
        Assert.Empty(Directory.GetFiles(result.Directory, "*.key", SearchOption.AllDirectories));
    }

    private sealed class KeylessIse(FakeIse inner) : CiscoIseLetsEncrypt.Ise.IIseClient
    {
        public async Task<CiscoIseLetsEncrypt.Ise.ExportedCertificate> ExportSystemCertificateAsync(string h, string id, string p, CancellationToken ct) =>
            (await inner.ExportSystemCertificateAsync(h, id, p, ct)) with
            {
                EncryptedPrivateKeyPem = RSA.Create(2048).ExportEncryptedPkcs8PrivateKeyPem(p,
                    new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000)),
            };

        public Task<IReadOnlyList<CiscoIseLetsEncrypt.Ise.IseNode>> GetNodesAsync(CancellationToken ct) => inner.GetNodesAsync(ct);
        public Task<IReadOnlyList<CiscoIseLetsEncrypt.Ise.SystemCertificate>> GetSystemCertificatesAsync(string h, CancellationToken ct) => inner.GetSystemCertificatesAsync(h, ct);
        public Task<IReadOnlyList<CiscoIseLetsEncrypt.Ise.TrustedCertificate>> GetTrustedCertificatesAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<string> GenerateCsrAsync(CiscoIseLetsEncrypt.Ise.CsrRequest r, CancellationToken ct) => throw new NotSupportedException();
        public Task<string> ExportCsrAsync(string h, string id, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteCsrAsync(string h, string id, CancellationToken ct) => throw new NotSupportedException();
        public Task BindCertificateAsync(CiscoIseLetsEncrypt.Ise.BindRequest r, CancellationToken ct) => throw new NotSupportedException();
        public Task UpdateSystemCertificateRolesAsync(string h, CiscoIseLetsEncrypt.Ise.SystemCertificate c, IReadOnlyCollection<CiscoIseLetsEncrypt.Ise.IseRole> r, string? t, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteSystemCertificateAsync(string h, string id, CancellationToken ct) => throw new NotSupportedException();
        public Task ImportSystemCertificateAsync(CiscoIseLetsEncrypt.Ise.IseNode n, CiscoIseLetsEncrypt.Ise.SystemCertificateImport r, CancellationToken ct) => throw new NotSupportedException();
        public Task<bool> HasWriteAccessAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<bool> IsApiAvailableAsync(CancellationToken ct) => throw new NotSupportedException();
    }
}
