using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Dns;

public interface IDnsChallengeClient
{
    Task CreateTxtRecordAsync(string recordName, string value, CancellationToken ct);
    Task DeleteTxtRecordAsync(string recordName, CancellationToken ct);
}

public sealed class DnsProxyException(string message) : Exception(message);

/// <summary>
/// Client for the "ACME DNS Proxy" (CloudflareDNSupdateProxy) REST API – same contract as the acme.sh
/// dns_acmednsproxy hook: POST {recordName,value} to create, DELETE {recordName} to remove,
/// Bearer token auth, empty body on success and {"error":"..."} on failure.
/// </summary>
public sealed class AcmeDnsProxyClient(HttpClient http, Uri url, string token, ILogger<AcmeDnsProxyClient> log)
    : IDnsChallengeClient
{
    public Task CreateTxtRecordAsync(string recordName, string value, CancellationToken ct) =>
        SendAsync(HttpMethod.Post, url, new JsonObject { ["recordName"] = recordName, ["value"] = value }, recordName, ct);

    public Task DeleteTxtRecordAsync(string recordName, CancellationToken ct) =>
        SendAsync(HttpMethod.Delete, url, new JsonObject { ["recordName"] = recordName }, recordName, ct);

    private async Task SendAsync(HttpMethod method, Uri url, JsonObject body, string recordName, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, url) { Content = JsonContent.Create(body) };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        log.LogDebug("DNS proxy {Method} {Url} {Body}", method, url, body.ToJsonString());
        HttpResponseMessage resp;
        try
        {
            resp = await http.SendAsync(req, ct);
        }
        catch (HttpRequestException ex)
        {
            throw new DnsProxyException($"ACME DNS Proxy request failed (network error): {ex.Message}");
        }

        using (resp)
        {
            var text = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode || text.Contains("\"error\"", StringComparison.Ordinal))
                throw new DnsProxyException($"ACME DNS Proxy {method} for {recordName} failed: {(int)resp.StatusCode} {resp.StatusCode} {text}");
        }
        log.LogInformation("ACME DNS Proxy: {Method} ok for {Record}", method, recordName);
    }
}
