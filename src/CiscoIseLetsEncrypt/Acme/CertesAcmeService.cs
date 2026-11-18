using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Acme;

/// <summary>ACME (Let's Encrypt) implementation using Certes. Only the ACME account key is local.</summary>
public sealed class CertesAcmeService : IAcmeService
{
    private readonly Uri _server;
    private readonly string _accountKeyPath;
    private readonly string? _email;
    private readonly TimeSpan _pollInterval;
    private readonly TimeSpan _timeout;
    private readonly ILogger _log;
    private AcmeContext? _context;

    public CertesAcmeService(bool staging, string accountKeyPath, string? email, TimeSpan pollInterval, TimeSpan timeout,
        ILogger<CertesAcmeService> log)
    {
        _server = staging ? WellKnownServers.LetsEncryptStagingV2 : WellKnownServers.LetsEncryptV2;
        _accountKeyPath = accountKeyPath;
        _email = email;
        _pollInterval = pollInterval;
        _timeout = timeout;
        _log = log;
    }

    public string ServerDescription => _server.ToString();

    public async Task<IAcmeOrder> NewOrderAsync(IReadOnlyList<string> dnsNames, CancellationToken ct)
    {
        var ctx = await GetContextAsync();
        _log.LogInformation("Creating ACME order on {Server} for {Names}", _server, string.Join(", ", dnsNames));
        var order = await AcmeRetry.RunAsync(() => ctx.NewOrder(dnsNames.ToList()), _log, ct);
        return new CertesOrder(ctx, order, _pollInterval, _timeout, _log);
    }

    private async Task<AcmeContext> GetContextAsync()
    {
        if (_context is not null)
            return _context;

        IKey key;
        if (File.Exists(_accountKeyPath))
        {
            key = KeyFactory.FromPem(await File.ReadAllTextAsync(_accountKeyPath));
            _log.LogInformation("Using ACME account key {Path}", _accountKeyPath);
        }
        else
        {
            key = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var dir = Path.GetDirectoryName(Path.GetFullPath(_accountKeyPath));
            if (!string.IsNullOrEmpty(dir))
                System.IO.Directory.CreateDirectory(dir);
            await File.WriteAllTextAsync(_accountKeyPath, key.ToPem());
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(_accountKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            _log.LogInformation("Created new ACME account key {Path}", _accountKeyPath);
        }

        var ctx = new AcmeContext(_server, key);
        var contacts = string.IsNullOrWhiteSpace(_email) ? new List<string>() : new List<string> { $"mailto:{_email}" };
        await AcmeRetry.RunAsync(() => ctx.NewAccount(contacts, true, null!, null!, null!), _log, CancellationToken.None);
        _context = ctx;
        return ctx;
    }

    private sealed class CertesOrder(AcmeContext ctx, IOrderContext order, TimeSpan pollInterval, TimeSpan timeout, ILogger log)
        : IAcmeOrder
    {
        private readonly List<(IAuthorizationContext Authz, IChallengeContext Challenge, string Domain)> _pending = [];

        public async Task<IReadOnlyList<DnsChallenge>> GetPendingDnsChallengesAsync(CancellationToken ct)
        {
            _pending.Clear();
            var result = new List<DnsChallenge>();
            foreach (var authz in await AcmeRetry.RunAsync(order.Authorizations, log, ct))
            {
                var resource = await AcmeRetry.RunAsync(authz.Resource, log, ct);
                var domain = resource.Identifier.Value;
                if (resource.Status == AuthorizationStatus.Valid)
                {
                    log.LogInformation("ACME authorization for {Domain} is already valid", domain);
                    continue;
                }
                var challenge = await AcmeRetry.RunAsync(authz.Dns, log, ct) ?? throw new AcmeException($"No dns-01 challenge offered for {domain}");
                _pending.Add((authz, challenge, domain));
                result.Add(new DnsChallenge(domain, $"_acme-challenge.{domain.TrimStart('*', '.')}", ctx.AccountKey.DnsTxt(challenge.Token)));
            }
            return result;
        }

        public async Task ValidateAsync(CancellationToken ct)
        {
            foreach (var (_, challenge, domain) in _pending)
            {
                log.LogInformation("Requesting ACME validation of dns-01 for {Domain}", domain);
                await AcmeRetry.RunAsync(challenge.Validate, log, ct);
            }

            foreach (var (authz, challenge, domain) in _pending)
            {
                var deadline = DateTimeOffset.UtcNow + timeout;
                while (true)
                {
                    var res = await AcmeRetry.RunAsync(authz.Resource, log, ct);
                    if (res.Status == AuthorizationStatus.Valid)
                    {
                        log.LogInformation("ACME authorization for {Domain} is valid", domain);
                        break;
                    }
                    if (res.Status is AuthorizationStatus.Invalid or AuthorizationStatus.Revoked
                        or AuthorizationStatus.Deactivated or AuthorizationStatus.Expired)
                    {
                        var chRes = await AcmeRetry.RunAsync(challenge.Resource, log, ct);
                        throw new AcmeException($"ACME validation for {domain} failed: {res.Status} {chRes.Error?.Type} {chRes.Error?.Detail}");
                    }
                    if (DateTimeOffset.UtcNow > deadline)
                        throw new AcmeException($"Timed out waiting for ACME validation of {domain} (status {res.Status})");
                    await Task.Delay(pollInterval, ct);
                }
            }
        }

        public async Task<IssuedCertificate> FinalizeAsync(byte[] csrDer, CancellationToken ct)
        {
            log.LogInformation("Finalizing ACME order with the CSR");
            var res = await AcmeRetry.RunAsync(() => order.Finalize(csrDer), log, ct);
            var deadline = DateTimeOffset.UtcNow + timeout;
            while (res.Status is OrderStatus.Pending or OrderStatus.Ready or OrderStatus.Processing)
            {
                if (DateTimeOffset.UtcNow > deadline)
                    throw new AcmeException($"Timed out waiting for ACME order (status {res.Status})");
                await Task.Delay(pollInterval, ct);
                res = await AcmeRetry.RunAsync(order.Resource, log, ct);
            }
            if (res.Status != OrderStatus.Valid)
                throw new AcmeException($"ACME order failed: {res.Status} {res.Error}");

            var chain = await AcmeRetry.RunAsync(() => order.Download(null!), log, ct);
            return new IssuedCertificate(chain.Certificate.ToPem(), chain.Issuers.Select(i => i.ToPem()).ToList());
        }
    }
}
