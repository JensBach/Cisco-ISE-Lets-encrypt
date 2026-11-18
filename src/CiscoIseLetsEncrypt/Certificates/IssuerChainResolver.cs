using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Certificates;

public interface IIssuerChainResolver
{
    /// <summary>
    /// Returns all CA certificates (intermediates and root) above <paramref name="leaf"/>,
    /// downloading missing issuers via the AIA "caIssuers" URL.
    /// </summary>
    Task<IReadOnlyList<X509Certificate2>> ResolveAsync(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> knownIssuers, CancellationToken ct);
}

public sealed class IssuerChainResolver(HttpClient http, ILogger<IssuerChainResolver> log) : IIssuerChainResolver
{
    private const int MaxDepth = 6;

    public async Task<IReadOnlyList<X509Certificate2>> ResolveAsync(X509Certificate2 leaf,
        IReadOnlyList<X509Certificate2> knownIssuers, CancellationToken ct)
    {
        var chain = new List<X509Certificate2>();
        var current = leaf;
        for (var depth = 0; depth < MaxDepth && !CertificateUtil.IsSelfSigned(current); depth++)
        {
            var issuer = knownIssuers.FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData))
                         ?? await DownloadIssuerAsync(current, ct);
            if (issuer is null)
            {
                log.LogWarning("Could not find issuer '{Issuer}' of '{Subject}' (no AIA caIssuers URL).", current.Issuer, current.Subject);
                break;
            }
            chain.Add(issuer);
            current = issuer;
        }
        return chain;
    }

    private async Task<X509Certificate2?> DownloadIssuerAsync(X509Certificate2 cert, CancellationToken ct)
    {
        var aia = cert.Extensions.OfType<X509AuthorityInformationAccessExtension>().FirstOrDefault();
        foreach (var uri in aia?.EnumerateCAIssuersUris() ?? [])
        {
            if (!uri.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                log.LogInformation("Downloading issuer certificate from {Url}", uri);
                var bytes = await http.GetByteArrayAsync(uri, ct);
                var match = CertificateUtil.LoadCertificates(bytes)
                    .FirstOrDefault(c => c.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData));
                if (match is not null)
                    return match;
            }
            catch (Exception ex) when (ex is HttpRequestException or System.Security.Cryptography.CryptographicException)
            {
                log.LogWarning("Failed to download issuer from {Url}: {Error}", uri, ex.Message);
            }
        }
        return null;
    }
}
