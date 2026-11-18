namespace CiscoIseLetsEncrypt.Ise;

public interface IIseClient
{
    Task<IReadOnlyList<IseNode>> GetNodesAsync(CancellationToken ct);

    Task<IReadOnlyList<SystemCertificate>> GetSystemCertificatesAsync(string hostname, CancellationToken ct);

    /// <summary>Generates a CSR on the ISE node (the private key never leaves ISE). Returns the CSR id.</summary>
    Task<string> GenerateCsrAsync(CsrRequest request, CancellationToken ct);

    Task<string> ExportCsrAsync(string hostname, string csrId, CancellationToken ct);

    Task DeleteCsrAsync(string hostname, string csrId, CancellationToken ct);

    Task<IReadOnlyList<TrustedCertificate>> GetTrustedCertificatesAsync(CancellationToken ct);

    /// <summary>Binds a CA signed certificate to an existing CSR (no roles assigned).</summary>
    Task BindCertificateAsync(BindRequest request, CancellationToken ct);

    Task UpdateSystemCertificateRolesAsync(string hostname, SystemCertificate certificate, IReadOnlyCollection<IseRole> roles,
        string? portalGroupTag, CancellationToken ct);

    Task DeleteSystemCertificateAsync(string hostname, string id, CancellationToken ct);

    /// <summary>Exports a system certificate with its private key (encrypted with <paramref name="password"/>).</summary>
    Task<ExportedCertificate> ExportSystemCertificateAsync(string hostname, string id, string password, CancellationToken ct);

    /// <summary>Imports a system certificate with private key on <paramref name="node"/> (runs against that node's API).</summary>
    Task ImportSystemCertificateAsync(IseNode node, SystemCertificateImport request, CancellationToken ct);

    /// <summary>
    /// Checks that the API user may change certificates, using a deliberately invalid request that ISE rejects
    /// with 400 after the authorization check (no change is made). Returns false on 401/403.
    /// </summary>
    Task<bool> HasWriteAccessAsync(CancellationToken ct);

    /// <summary>Returns true when the ISE OpenAPI answers (used while the application server restarts).</summary>
    Task<bool> IsApiAvailableAsync(CancellationToken ct);
}
