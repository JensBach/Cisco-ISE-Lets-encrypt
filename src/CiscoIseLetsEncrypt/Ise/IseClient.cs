using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Ise;

public class IseApiException(string message, HttpStatusCode? status = null) : Exception(message)
{
    public HttpStatusCode? Status { get; } = status;
}

/// <summary>ISE refused the CSR because a name does not resolve (in ISE's DNS) to the node's IP address.</summary>
public sealed class IseCsrNameResolutionException(string message, HttpStatusCode? status) : IseApiException(message, status);

/// <summary>Client for the Cisco ISE OpenAPI (https://{PAN}/api/v1/...).</summary>
public sealed class IseClient : IIseClient
{
    private const int PageSize = 100;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        NumberHandling = System.Text.Json.Serialization.JsonNumberHandling.AllowReadingFromString,
    };

    private readonly HttpClient _http;
    private readonly ILogger _log;
    private readonly Func<string, HttpClient>? _nodeHttpFactory;

    /// <param name="nodeHttpFactory">Creates an authenticated client for another node (system certificate import
    /// must run against the target node's own API). Defaults to <paramref name="http"/>.</param>
    public IseClient(HttpClient http, ILogger<IseClient> log, Func<string, HttpClient>? nodeHttpFactory = null)
    {
        _http = http;
        _log = log;
        _nodeHttpFactory = nodeHttpFactory;
    }

    public static HttpClient CreateHttpClient(string adminNode, string username, string password, bool skipTlsValidation)
    {
        var handler = new HttpClientHandler();
        if (skipTlsValidation)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        var http = new HttpClient(handler)
        {
            BaseAddress = new Uri($"https://{adminNode}/"),
            Timeout = TimeSpan.FromMinutes(3),
        };
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basic);
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return http;
    }

    public async Task<IReadOnlyList<IseNode>> GetNodesAsync(CancellationToken ct)
    {
        var root = await SendJsonAsync(HttpMethod.Get, "api/v1/deployment/node", null, ct);
        return Deserialize<List<IseNode>>(root?["response"]) ?? [];
    }

    public Task<IReadOnlyList<SystemCertificate>> GetSystemCertificatesAsync(string hostname, CancellationToken ct) =>
        GetAllPagesAsync<SystemCertificate>($"api/v1/certs/system-certificate/{Uri.EscapeDataString(hostname)}", ct);

    public Task<IReadOnlyList<TrustedCertificate>> GetTrustedCertificatesAsync(CancellationToken ct) =>
        GetAllPagesAsync<TrustedCertificate>("api/v1/certs/trusted-certificate", ct);

    public async Task<string> GenerateCsrAsync(CsrRequest request, CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["hostnames"] = new JsonArray(request.Hostname),
            ["allowWildCardCert"] = false,
            ["keyType"] = request.KeyType,
            ["keyLength"] = request.KeyLength,
            ["digestType"] = request.DigestType,
            ["usedFor"] = IseRoles.ToCsrUsedFor(request.Roles),
            ["subjectCommonName"] = request.CommonName,
            ["sanDNS"] = new JsonArray(request.SanDns.Select(s => (JsonNode)JsonValue.Create(s)!).ToArray()),
        };
        if (request.Roles.Contains(IseRole.Portal))
            body["portalGroupTag"] = request.PortalGroupTag;

        var root = await SendJsonAsync(HttpMethod.Post, "api/v1/certs/certificate-signing-request", body, ct);
        var response = root?["response"];
        var first = response is JsonArray arr ? arr.FirstOrDefault() : response;
        var id = first?["id"]?.GetValue<string>();
        if (string.IsNullOrEmpty(id))
            throw new IseApiException($"ISE did not return a CSR id. Response: {root?.ToJsonString()}");

        _log.LogDebug("ISE CSR response: {Response}", root?.ToJsonString());
        return id;
    }

    public async Task<string> ExportCsrAsync(string hostname, string csrId, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get,
            $"api/v1/certs/certificate-signing-request/export/{Uri.EscapeDataString(hostname)}/{Uri.EscapeDataString(csrId)}");
        req.Headers.Accept.Clear();
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        EnsureSuccess(resp, text);

        const string begin = "-----BEGIN CERTIFICATE REQUEST-----";
        const string end = "-----END CERTIFICATE REQUEST-----";
        var b = text.IndexOf(begin, StringComparison.Ordinal);
        var e = text.IndexOf(end, StringComparison.Ordinal);
        if (b < 0 || e < b)
            throw new IseApiException("Exported CSR is not a PEM certificate request.");
        return text[b..(e + end.Length)] + "\n";
    }

    public async Task DeleteCsrAsync(string hostname, string csrId, CancellationToken ct) =>
        await SendJsonAsync(HttpMethod.Delete,
            $"api/v1/certs/certificate-signing-request/{Uri.EscapeDataString(hostname)}/{Uri.EscapeDataString(csrId)}", null, ct);

    public async Task BindCertificateAsync(BindRequest request, CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["hostName"] = request.Hostname,
            ["id"] = request.CsrId,
            ["name"] = request.FriendlyName,
            ["data"] = NormalizePem(request.CertificatePem),
            ["allowExtendedValidity"] = false,
            ["allowOutOfDateCert"] = false,
            ["allowReplacementOfCertificates"] = true,
            ["allowReplacementOfPortalGroupTag"] = true,
            ["validateCertificateExtensions"] = false,
            ["admin"] = false,
            ["eap"] = false,
            ["radius"] = false,
            ["pxgrid"] = false,
            ["ims"] = false,
            ["saml"] = false,
            ["portal"] = false,
        };
        var root = await SendJsonAsync(HttpMethod.Post, "api/v1/certs/signed-certificate/bind", body, ct);
        _log.LogDebug("ISE bind response: {Response}", root?.ToJsonString());
    }

    public async Task UpdateSystemCertificateRolesAsync(string hostname, SystemCertificate certificate,
        IReadOnlyCollection<IseRole> roles, string? portalGroupTag, CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["name"] = certificate.FriendlyName,
            ["admin"] = roles.Contains(IseRole.Admin),
            ["eap"] = roles.Contains(IseRole.Eap),
            ["radius"] = roles.Contains(IseRole.Dtls),
            ["pxgrid"] = roles.Contains(IseRole.PxGrid),
            ["ims"] = roles.Contains(IseRole.Ims),
            ["saml"] = roles.Contains(IseRole.Saml),
            ["portal"] = roles.Contains(IseRole.Portal),
            // Roles this program does not manage keep their current state. ISE 3.5 fails with
            // "Failed due to Server Exception" unless all fields are present.
            ["tacacs"] = HasUsage(certificate, "TACACS"),
            ["NativeIPsec"] = HasUsage(certificate, "IPsec"),
            ["description"] = "",
            ["renewSelfSignedCertificate"] = false,
            ["expirationTTLPeriod"] = 365,
            ["expirationTTLUnits"] = "days",
            ["allowReplacementOfPortalGroupTag"] = true,
            ["allowRoleTransferForSameSubject"] = true,
            ["allowPortalTagTransferForSameSubject"] = true,
        };
        if (roles.Contains(IseRole.Portal))
            body["portalGroupTag"] = portalGroupTag;

        var root = await SendJsonAsync(HttpMethod.Put,
            $"api/v1/certs/system-certificate/{Uri.EscapeDataString(hostname)}/{Uri.EscapeDataString(certificate.Id)}", body, ct);
        _log.LogDebug("ISE role update response: {Response}", root?.ToJsonString());
    }

    public async Task DeleteSystemCertificateAsync(string hostname, string id, CancellationToken ct) =>
        await SendJsonAsync(HttpMethod.Delete,
            $"api/v1/certs/system-certificate/{Uri.EscapeDataString(hostname)}/{Uri.EscapeDataString(id)}", null, ct);

    public async Task<ExportedCertificate> ExportSystemCertificateAsync(string hostname, string id, string password, CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["id"] = id,
            ["hostName"] = hostname,
            ["export"] = "CERTIFICATE_WITH_PRIVATE_KEY",
            ["password"] = password,
        };
        using var req = new HttpRequestMessage(HttpMethod.Post, "api/v1/certs/system-certificate/export")
        {
            Content = JsonContent.Create(body, options: Json),
        };
        req.Headers.Accept.Clear();
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _log.LogDebug("ISE POST api/v1/certs/system-certificate/export (id {Id} on {Host})", id, hostname);
        using var resp = await _http.SendAsync(req, ct);
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        EnsureSuccess(resp, resp.IsSuccessStatusCode ? "" : Encoding.UTF8.GetString(bytes));
        return ParseExportZip(bytes, password);
    }

    /// <summary>The export is a ZIP with the certificate (.pem) and the encrypted PKCS#8 key (.pvk). Read in memory only.</summary>
    internal static ExportedCertificate ParseExportZip(byte[] zip, string password)
    {
        string? cert = null, key = null;
        try
        {
            using var archive = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read);
            foreach (var entry in archive.Entries)
            {
                using var reader = new StreamReader(entry.Open());
                var text = reader.ReadToEnd();
                if (text.Contains("PRIVATE KEY-----", StringComparison.Ordinal))
                    key = text;
                else if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                    cert = text;
            }
        }
        catch (InvalidDataException ex)
        {
            throw new IseApiException($"ISE certificate export is not a ZIP file: {ex.Message}");
        }
        if (cert is null || key is null)
            throw new IseApiException("ISE certificate export did not contain both the certificate and the private key.");
        if (!key.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal))
            throw new IseApiException("ISE exported an unencrypted private key – refusing to continue.");
        return new ExportedCertificate(cert, key, password);
    }

    public async Task ImportSystemCertificateAsync(IseNode node, SystemCertificateImport request, CancellationToken ct)
    {
        var roles = request.Roles;
        var body = new JsonObject
        {
            ["name"] = request.FriendlyName,
            ["data"] = NormalizePem(request.Certificate.CertificatePem),
            ["privateKeyData"] = NormalizePem(request.Certificate.EncryptedPrivateKeyPem),
            ["password"] = request.Certificate.Password,
            ["admin"] = roles.Contains(IseRole.Admin),
            ["eap"] = roles.Contains(IseRole.Eap),
            ["radius"] = roles.Contains(IseRole.Dtls),
            ["pxgrid"] = roles.Contains(IseRole.PxGrid),
            ["ims"] = roles.Contains(IseRole.Ims),
            ["saml"] = roles.Contains(IseRole.Saml),
            ["portal"] = roles.Contains(IseRole.Portal),
            ["allowExtendedValidity"] = false,
            ["allowOutOfDateCert"] = false,
            ["allowSHA1Certificates"] = false,
            ["allowWildCardCertificates"] = false,
            ["validateCertificateExtensions"] = false,
            ["allowReplacementOfCertificates"] = true,
            ["allowReplacementOfPortalGroupTag"] = true,
            ["allowRoleTransferForSameSubject"] = true,
            ["allowPortalTagTransferForSameSubject"] = true,
        };
        if (roles.Contains(IseRole.Portal))
            body["portalGroupTag"] = request.PortalGroupTag;

        var http = _nodeHttpFactory?.Invoke(node.ProbeAddress) ?? _http;
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "api/v1/certs/system-certificate/import")
            {
                Content = JsonContent.Create(body, options: Json),
            };
            _log.LogDebug("ISE POST {Base}api/v1/certs/system-certificate/import", http.BaseAddress);
            using var resp = await http.SendAsync(req, ct);
            var text = await resp.Content.ReadAsStringAsync(ct);
            EnsureSuccess(resp, text);
            _log.LogDebug("ISE import response: {Response}", text);
        }
        finally
        {
            if (!ReferenceEquals(http, _http))
                http.Dispose();
        }
    }

    public async Task<bool> HasWriteAccessAsync(CancellationToken ct)
    {
        try
        {
            await SendJsonAsync(HttpMethod.Post, "api/v1/certs/trusted-certificate/import",
                new JsonObject { ["name"] = "permission-check", ["data"] = "invalid" }, ct);
            throw new IseApiException("ISE accepted an invalid trusted certificate import during the permission check.");
        }
        catch (IseApiException ex) when (ex.Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            return false;
        }
        catch (IseApiException ex) when (ex.Status is HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity)
        {
            return true;
        }
    }

    public async Task<bool> IsApiAvailableAsync(CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(20));
            using var resp = await _http.GetAsync("api/v1/deployment/node", cts.Token);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return false;
        }
    }

    /// <summary>ISE wants the PEM as a single string with "\n" line separators.</summary>
    public static string NormalizePem(string pem) =>
        string.Join("\n", pem.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) + "\n";

    private async Task<IReadOnlyList<T>> GetAllPagesAsync<T>(string path, CancellationToken ct)
    {
        var result = new List<T>();
        for (var page = 1; page < 1000; page++)
        {
            var root = await SendJsonAsync(HttpMethod.Get, $"{path}?page={page}&size={PageSize}", null, ct);
            var items = Deserialize<List<T>>(root?["response"]) ?? [];
            result.AddRange(items);
            if (items.Count < PageSize || root?["nextPage"] is null)
                break;
        }
        return result;
    }

    private async Task<JsonNode?> SendJsonAsync(HttpMethod method, string path, JsonNode? body, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, path);
        if (body is not null)
            req.Content = JsonContent.Create(body, options: Json);

        _log.LogDebug("ISE {Method} {Path}", method, path);
        using var resp = await _http.SendAsync(req, ct);
        var text = await resp.Content.ReadAsStringAsync(ct);
        EnsureSuccess(resp, text);
        if (string.IsNullOrWhiteSpace(text))
            return null;
        try
        {
            return JsonNode.Parse(text);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void EnsureSuccess(HttpResponseMessage resp, string body)
    {
        if (resp.IsSuccessStatusCode)
            return;
        var reason = resp.StatusCode == HttpStatusCode.Unauthorized
            ? " (check ISE credentials and that the user is in the ERS Admin / Super Admin group)"
            : resp.StatusCode == HttpStatusCode.Forbidden
            ? " (the ISE user lacks permission – it must be in the ERS Admin / Super Admin group)"
            : IsCsrNameResolutionError(body)
                ? " (ISE requires every certificate name (-CertificateDNS) to resolve, using the DNS servers configured on ISE, " +
                  "to the IP address of the node the CSR is generated on. Create an internal A record for the name pointing to the node)"
                : "";
        var message = $"ISE {resp.RequestMessage?.Method} {resp.RequestMessage?.RequestUri?.AbsolutePath} failed: {(int)resp.StatusCode} {resp.StatusCode}{reason}. {Truncate(body)}";
        throw IsCsrNameResolutionError(body)
            ? new IseCsrNameResolutionException(message, resp.StatusCode)
            : new IseApiException(message, resp.StatusCode);
    }

    private static bool HasUsage(SystemCertificate certificate, string usage) =>
        (certificate.UsedBy ?? "").Split(',', StringSplitOptions.TrimEntries)
            .Any(u => u.Contains(usage, StringComparison.OrdinalIgnoreCase));

    internal static bool IsCsrNameResolutionError(string body) =>
        body.Contains("bad Comman Name", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("bad Common Name", StringComparison.OrdinalIgnoreCase) ||
        body.Contains("non resolvable", StringComparison.OrdinalIgnoreCase);

    private static T? Deserialize<T>(JsonNode? node) => node is null ? default : node.Deserialize<T>(Json);

    private static string Truncate(string s) => s.Length > 1000 ? s[..1000] + "..." : s;
}
