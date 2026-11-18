using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Acme;

/// <summary>Retries ACME requests that fail transiently ("rateLimited: Service busy; retry later", server errors, network).</summary>
public static class AcmeRetry
{
    private static readonly TimeSpan[] DefaultDelays =
        [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30)];

    public static async Task<T> RunAsync<T>(Func<Task<T>> action, ILogger log, CancellationToken ct, IReadOnlyList<TimeSpan>? delays = null)
    {
        delays ??= DefaultDelays;
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return await action();
            }
            catch (Exception ex) when (attempt < delays.Count && IsTransient(ex))
            {
                log.LogWarning("ACME request failed transiently ({Error}); retrying in {Delay}s (attempt {Attempt}/{Max})",
                    ex.Message.ReplaceLineEndings(" "), delays[attempt].TotalSeconds, attempt + 1, delays.Count);
                await Task.Delay(delays[attempt], ct);
            }
        }
    }

    public static bool IsTransient(Exception ex) => ex switch
    {
        Certes.AcmeRequestException are => are.Error?.Type is { } type
            ? type.EndsWith(":rateLimited", StringComparison.Ordinal) || type.EndsWith(":serverInternal", StringComparison.Ordinal)
            : are.Message.Contains("retry later", StringComparison.OrdinalIgnoreCase),
        HttpRequestException => true,
        TaskCanceledException tce => tce.InnerException is TimeoutException,
        _ => false,
    };
}
