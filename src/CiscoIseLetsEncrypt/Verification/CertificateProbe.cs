using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace CiscoIseLetsEncrypt.Verification;

public interface ICertificateProbe
{
    /// <summary>Returns the TLS server certificate presented on host:port (no validation).</summary>
    Task<X509Certificate2> GetTlsCertificateAsync(string host, int port, string? sni, CancellationToken ct);

    /// <summary>Returns the server certificate ISE presents inside EAP-PEAP over RADIUS.</summary>
    Task<X509Certificate2> GetEapCertificateAsync(string host, int port, string sharedSecret, string identity, CancellationToken ct);
}

public sealed class CertificateProbe(TimeSpan timeout) : ICertificateProbe
{
    public async Task<X509Certificate2> GetTlsCertificateAsync(string host, int port, string? sni, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port, cts.Token);
        X509Certificate2? captured = null;
        await using var ssl = new SslStream(tcp.GetStream(), false);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = sni ?? host,
            RemoteCertificateValidationCallback = (_, cert, _, _) =>
            {
                if (cert is not null)
                    captured = new X509Certificate2(cert);
                return true;
            },
        }, cts.Token);
        return captured ?? throw new InvalidOperationException($"No certificate received from {host}:{port}");
    }

    public Task<X509Certificate2> GetEapCertificateAsync(string host, int port, string sharedSecret, string identity, CancellationToken ct) =>
        new Radius.PeapCertificateProbe(host, port, sharedSecret, identity, timeout).GetServerCertificateAsync(ct);
}
