using System.Net;
using DnsClient;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Dns;

public interface IDnsPropagationChecker
{
    /// <summary>Waits until all resolvers return the TXT value. Returns false on timeout.</summary>
    Task<bool> WaitForTxtRecordAsync(string recordName, string expectedValue, TimeSpan timeout, CancellationToken ct);
}

public sealed class DnsPropagationChecker(IReadOnlyList<IPAddress> resolvers, TimeSpan pollInterval, ILogger<DnsPropagationChecker> log)
    : IDnsPropagationChecker
{
    public async Task<bool> WaitForTxtRecordAsync(string recordName, string expectedValue, TimeSpan timeout, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        var pending = resolvers.ToList();
        while (true)
        {
            foreach (var resolver in pending.ToList())
            {
                if (await HasValueAsync(resolver, recordName, expectedValue, ct))
                {
                    log.LogInformation("TXT {Record} visible on resolver {Resolver}", recordName, resolver);
                    pending.Remove(resolver);
                }
            }
            if (pending.Count == 0)
                return true;
            if (DateTimeOffset.UtcNow >= deadline)
            {
                log.LogWarning("TXT {Record} not visible on {Resolvers} after {Timeout}", recordName, string.Join(", ", pending), timeout);
                return false;
            }
            log.LogInformation("Waiting for TXT {Record} on {Resolvers}...", recordName, string.Join(", ", pending));
            await Task.Delay(pollInterval, ct);
        }
    }

    private async Task<bool> HasValueAsync(IPAddress resolver, string recordName, string expected, CancellationToken ct)
    {
        try
        {
            var client = new LookupClient(new LookupClientOptions(resolver)
            {
                UseCache = false,
                Timeout = TimeSpan.FromSeconds(5),
                Retries = 1,
            });
            var result = await client.QueryAsync(recordName, QueryType.TXT, cancellationToken: ct);
            return result.Answers.TxtRecords().Any(r => r.Text.Any(t => t == expected));
        }
        catch (DnsResponseException ex)
        {
            log.LogDebug("DNS query {Record} on {Resolver} failed: {Error}", recordName, resolver, ex.Message);
            return false;
        }
    }
}
