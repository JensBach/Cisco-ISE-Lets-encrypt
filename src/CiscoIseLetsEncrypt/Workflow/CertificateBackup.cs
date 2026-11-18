using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CiscoIseLetsEncrypt.Certificates;
using CiscoIseLetsEncrypt.Ise;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Workflow;

public enum BackupStatus { Exported, Skipped, Failed }

public sealed record BackupEntry(
    string Node, string Id, string? FriendlyName, string? IssuedTo, string? IssuedBy, string? ExpirationDate, string? UsedBy,
    string? PortalGroupTag, string? Sha256Fingerprint, string? ExportedSha256, string? CertificateFile, string? KeyFile,
    [property: System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter))] BackupStatus Status,
    string? Message);

public sealed record BackupResult(string Directory, IReadOnlyList<BackupEntry> Entries)
{
    public int Exported => Entries.Count(e => e.Status == BackupStatus.Exported);
    public int Skipped => Entries.Count(e => e.Status == BackupStatus.Skipped);
    public int Failed => Entries.Count(e => e.Status == BackupStatus.Failed);
}

/// <summary>
/// Exports every system certificate of every node with its private key. ISE encrypts the key (PKCS#8) with the
/// backup password, so the key is never written unencrypted. Nothing is changed on ISE.
/// </summary>
public sealed class CertificateBackup(IIseClient ise, TimeProvider time, ILogger<CertificateBackup> log)
{
    public async Task<BackupResult> RunAsync(string baseDirectory, string password, CancellationToken ct)
    {
        var directory = Path.GetFullPath(Path.Combine(baseDirectory, time.GetLocalNow().ToString("yyyyMMdd-HHmmss")));
        Directory.CreateDirectory(directory);
        log.LogInformation("Backing up all system certificates to {Directory}", directory);

        var entries = new List<BackupEntry>();
        foreach (var node in await ise.GetNodesAsync(ct))
        {
            IReadOnlyList<SystemCertificate> certificates;
            try
            {
                certificates = await ise.GetSystemCertificatesAsync(node.Hostname, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                log.LogError("[{Node}] Could not read system certificates: {Error}", node, ex.Message);
                entries.Add(new BackupEntry(node.Hostname, "", null, null, null, null, null, null, null, null, null, null, BackupStatus.Failed, ex.Message));
                continue;
            }

            var nodeDir = Path.Combine(directory, SafeName(node.Hostname));
            Directory.CreateDirectory(nodeDir);
            log.LogInformation("[{Node}] {Count} system certificate(s)", node, certificates.Count);
            foreach (var c in certificates)
                entries.Add(await BackupOneAsync(node, c, nodeDir, directory, password, ct));
        }

        var manifest = Path.Combine(directory, "manifest.json");
        await File.WriteAllTextAsync(manifest, JsonSerializer.Serialize(new
        {
            created = time.GetUtcNow(),
            note = "Private keys (.key) are PKCS#8 encrypted with the backup password. Import in ISE: Administration > System > " +
                   "Certificates > System Certificates > Import (certificate file + private key file + password).",
            certificates = entries,
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }), ct);

        var result = new BackupResult(directory, entries);
        log.LogInformation("Backup finished: {Ok} exported, {Skipped} skipped (not exportable), {Failed} failed. Manifest: {Manifest}",
            result.Exported, result.Skipped, result.Failed, manifest);
        return result;
    }

    private async Task<BackupEntry> BackupOneAsync(IseNode node, SystemCertificate c, string nodeDir, string root, string password,
        CancellationToken ct)
    {
        var fp = CertificateUtil.NormalizeFingerprint(c.Sha256Fingerprint);
        var baseName = $"{SafeName(c.FriendlyName ?? c.IssuedTo ?? c.Id)}_{(fp.Length >= 12 ? fp[..12] : SafeName(c.Id))}";
        string? certFile = null, keyFile = null, exportedFp = null, message = null;
        var status = BackupStatus.Exported;
        try
        {
            var exported = await ise.ExportSystemCertificateAsync(node.Hostname, c.Id, password, ct);
            using var cert = X509Certificate2.CreateFromPem(exported.CertificatePem);
            exportedFp = CertificateUtil.Sha256(cert);
            // Throws if the key cannot be decrypted with the password or does not belong to the certificate.
            using (X509Certificate2.CreateFromEncryptedPem(exported.CertificatePem, exported.EncryptedPrivateKeyPem, password))
            {
            }
            if (fp.Length > 0 && exportedFp != fp)
            {
                // Seen on ISE 3.5 for the default self-signed certificates: the API lists another fingerprint than the certificate it exports.
                message = $"ISE lists sha256 {fp}, but the exported certificate ({cert.Subject}) has {exportedFp}";
                log.LogWarning("[{Node}]   '{Name}': {Message}", node, c.FriendlyName, message);
            }

            certFile = Path.Combine(nodeDir, baseName + ".crt");
            keyFile = Path.Combine(nodeDir, baseName + ".key");
            await File.WriteAllTextAsync(certFile, exported.CertificatePem, Encoding.ASCII, ct);
            await File.WriteAllTextAsync(keyFile, exported.EncryptedPrivateKeyPem, Encoding.ASCII, ct);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            log.LogInformation("[{Node}]   ✔ '{Name}' [{UsedBy}] → {File}", node, c.FriendlyName,
                c.IsUnused ? "Not in use" : c.UsedBy, Path.GetRelativePath(root, certFile));
        }
        catch (IseApiException ex) when (ex.Message.Contains("export operation is not allowed", StringComparison.OrdinalIgnoreCase))
        {
            status = BackupStatus.Skipped;
            message = "ISE does not allow exporting this certificate (e.g. Data Grid certificates, which ISE manages itself)";
            log.LogInformation("[{Node}]   – '{Name}' skipped: {Message}", node, c.FriendlyName, message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            status = BackupStatus.Failed;
            message = ex.Message;
            certFile = keyFile = null;
            log.LogError("[{Node}]   ✖ '{Name}' could not be exported: {Error}", node, c.FriendlyName, ex.Message);
        }

        return new BackupEntry(node.Hostname, c.Id, c.FriendlyName, c.IssuedTo, c.IssuedBy, c.ExpirationDate, c.UsedBy, c.GroupTag,
            fp, exportedFp, certFile is null ? null : Path.GetRelativePath(root, certFile),
            keyFile is null ? null : Path.GetRelativePath(root, keyFile), status, message);
    }

    internal static string SafeName(string name)
    {
        var invalid = Path.GetInvalidFileNameChars().Concat([' ', '\'', '"', '*', '?', ':', '/', '\\', '<', '>', '|']).ToHashSet();
        var safe = new string(name.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray()).Trim('_', '.');
        return safe.Length == 0 ? "certificate" : safe.Length > 80 ? safe[..80] : safe;
    }
}
