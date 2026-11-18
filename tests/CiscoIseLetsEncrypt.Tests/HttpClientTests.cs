using System.Net;
using System.Text.Json.Nodes;
using CiscoIseLetsEncrypt.Dns;
using CiscoIseLetsEncrypt.Ise;
using CiscoIseLetsEncrypt.Tests.Fakes;
using Microsoft.Extensions.Logging.Abstractions;

namespace CiscoIseLetsEncrypt.Tests;

public class IseClientTests
{
    private static (IseClient Client, FakeHttpHandler Handler) Create(Func<RecordedRequest, HttpResponseMessage> responder)
    {
        var handler = new FakeHttpHandler(responder);
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://ise/") };
        return (new IseClient(http, NullLogger<IseClient>.Instance), handler);
    }

    private static byte[] Zip(params (string Name, string Text)[] entries)
    {
        using var ms = new MemoryStream();
        using (var zip = new System.IO.Compression.ZipArchive(ms, System.IO.Compression.ZipArchiveMode.Create, true))
            foreach (var (name, text) in entries)
            {
                using var w = new StreamWriter(zip.CreateEntry(name).Open());
                w.Write(text);
            }
        return ms.ToArray();
    }

    [Fact]
    public async Task Exports_certificate_with_encrypted_key_in_memory()
    {
        var certPem = CiscoIseLetsEncrypt.Certificates.CertificateUtil.ToPem(TestCa.SelfSigned("eap.example.net", 90));
        const string keyPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZmFrZQ==\n-----END ENCRYPTED PRIVATE KEY-----\n";
        var (client, handler) = Create(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Zip(("eap.pem", certPem), ("eap.pvk", keyPem))),
        });

        var exported = await client.ExportSystemCertificateAsync("ise-17-a", "id-1", "Passw0rd123", CancellationToken.None);

        Assert.Equal((certPem, keyPem, "Passw0rd123"), (exported.CertificatePem, exported.EncryptedPrivateKeyPem, exported.Password));
        var body = JsonNode.Parse(handler.Requests.Single().Body!)!;
        Assert.Equal("CERTIFICATE_WITH_PRIVATE_KEY", (string?)body["export"]);
        Assert.Equal("ise-17-a", (string?)body["hostName"]);
    }

    [Fact]
    public async Task Export_with_unencrypted_key_is_refused()
    {
        var certPem = CiscoIseLetsEncrypt.Certificates.CertificateUtil.ToPem(TestCa.SelfSigned("eap.example.net", 90));
        var (client, _) = Create(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Zip(("eap.pem", certPem), ("eap.pvk", "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"))),
        });

        await Assert.ThrowsAsync<IseApiException>(() => client.ExportSystemCertificateAsync("ise-17-a", "id-1", "Passw0rd123", CancellationToken.None));
    }

    [Fact]
    public async Task Imports_system_certificate_through_the_target_node_api()
    {
        var adminHandler = new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var nodeHandler = new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        string? factoryHost = null;
        var client = new IseClient(new HttpClient(adminHandler) { BaseAddress = new Uri("https://pan/") }, NullLogger<IseClient>.Instance,
            nodeHttpFactory: h => { factoryHost = h; return new HttpClient(nodeHandler) { BaseAddress = new Uri($"https://{h}/") }; });
        var node = new IseNode { Hostname = "ise-17-b", Fqdn = "ise-17-b.example.net", IpAddress = "10.0.0.11" };

        await client.ImportSystemCertificateAsync(node, new SystemCertificateImport("eap LetsEncrypt",
            new ExportedCertificate("CERT", "KEY", "Passw0rd123"), [IseRole.Eap, IseRole.Dtls], "Default Portal Certificate Group"), CancellationToken.None);

        Assert.Empty(adminHandler.Requests);
        Assert.Equal(node.ProbeAddress, factoryHost);
        var req = Assert.Single(nodeHandler.Requests);
        Assert.EndsWith("api/v1/certs/system-certificate/import", req.Uri.AbsolutePath);
        var body = JsonNode.Parse(req.Body!)!;
        Assert.Equal(("CERT", "KEY", "Passw0rd123"), (((string?)body["data"])?.Trim(), ((string?)body["privateKeyData"])?.Trim(), (string?)body["password"]));
        Assert.True((bool)body["eap"]!);
        Assert.True((bool)body["radius"]!);
        Assert.False((bool)body["admin"]!);
    }

    [Fact]
    public async Task Reads_system_certificates_across_pages()
    {
        var (client, handler) = Create(r =>
        {
            var page = r.Uri.Query.Contains("page=1") ? 1 : 2;
            var count = page == 1 ? 100 : 3;
            var items = new JsonArray(Enumerable.Range(0, count).Select(i => (JsonNode)new JsonObject
            {
                ["id"] = $"{page}-{i}", ["usedBy"] = "EAP Authentication", ["keySize"] = 4096,
                ["expirationDate"] = "Wed Oct 08 13:48:22 CEST 2031",
            }).ToArray());
            var root = new JsonObject { ["response"] = items };
            if (page == 1) root["nextPage"] = new JsonObject { ["href"] = "x" };
            return FakeHttpHandler.Json(root.ToJsonString());
        });

        var certs = await client.GetSystemCertificatesAsync("ise-17-a", CancellationToken.None);

        Assert.Equal(103, certs.Count);
        Assert.Equal(2, handler.Requests.Count);
        Assert.StartsWith("/api/v1/certs/system-certificate/ise-17-a", handler.Requests[0].Uri.AbsolutePath);
        Assert.Contains(IseRole.Eap, certs[0].Roles);
    }

    [Fact]
    public async Task Generates_csr_on_ise_with_expected_body()
    {
        var (client, handler) = Create(_ => FakeHttpHandler.Json("""{"response":[{"id":"csr-1","message":"ok"}]}"""));

        var id = await client.GenerateCsrAsync(new CsrRequest("ise-17-a", [IseRole.Eap, IseRole.Dtls], "eap.example.com",
            ["eap.example.com"], "RSA", "2048", "SHA-256", null), CancellationToken.None);

        Assert.Equal("csr-1", id);
        var body = JsonNode.Parse(handler.Requests.Single().Body!)!;
        Assert.Equal("EAP-AUTH", body["usedFor"]!.GetValue<string>());
        Assert.Equal("ise-17-a", body["hostnames"]![0]!.GetValue<string>());
        Assert.Equal("eap.example.com", body["sanDNS"]![0]!.GetValue<string>());
        Assert.Null(body["portalGroupTag"]);
    }

    [Fact]
    public async Task Bind_sends_certificate_without_roles_and_role_update_sets_roles()
    {
        var (client, handler) = Create(_ => FakeHttpHandler.Json("""{"response":{"status":"success"}}"""));

        await client.BindCertificateAsync(new BindRequest("ise-17-a", "csr-1", "-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n", "n"), CancellationToken.None);
        await client.UpdateSystemCertificateRolesAsync("ise-17-a", new SystemCertificate { Id = "c1", FriendlyName = "n", UsedBy = "TACACS" },
            [IseRole.Eap, IseRole.Dtls], "tag", CancellationToken.None);

        var bind = JsonNode.Parse(handler.Requests[0].Body!)!;
        Assert.Equal("/api/v1/certs/signed-certificate/bind", handler.Requests[0].Uri.AbsolutePath);
        Assert.Equal("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", bind["data"]!.GetValue<string>());
        Assert.False(bind["eap"]!.GetValue<bool>());
        Assert.False(bind["allowOutOfDateCert"]!.GetValue<bool>());

        var put = JsonNode.Parse(handler.Requests[1].Body!)!;
        Assert.Equal(HttpMethod.Put, handler.Requests[1].Method);
        Assert.Equal("/api/v1/certs/system-certificate/ise-17-a/c1", handler.Requests[1].Uri.AbsolutePath);
        Assert.True(put["eap"]!.GetValue<bool>());
        Assert.True(put["radius"]!.GetValue<bool>());
        Assert.False(put["admin"]!.GetValue<bool>());
        Assert.True(put["tacacs"]!.GetValue<bool>());
        Assert.False(put["NativeIPsec"]!.GetValue<bool>());
        Assert.Equal("days", put["expirationTTLUnits"]!.GetValue<string>());
        Assert.Null(put["portalGroupTag"]);
    }

    [Fact]
    public async Task Export_extracts_pem_and_errors_are_reported()
    {
        var (client, _) = Create(r => r.Uri.AbsolutePath.Contains("export")
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("junk\n-----BEGIN CERTIFICATE REQUEST-----\nAB\n-----END CERTIFICATE REQUEST-----\n") }
            : FakeHttpHandler.Json("""{"message":"denied"}""", HttpStatusCode.Unauthorized));

        var pem = await client.ExportCsrAsync("h", "1", CancellationToken.None);
        Assert.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", pem);

        var ex = await Assert.ThrowsAsync<IseApiException>(() => client.GetNodesAsync(CancellationToken.None));
        Assert.Equal(HttpStatusCode.Unauthorized, ex.Status);
        Assert.Contains("credentials", ex.Message);
    }

    [Fact]
    public async Task Csr_name_resolution_error_explains_dns_requirement()
    {
        var (client, _) = Create(_ => FakeHttpHandler.Json(
            """{"response":[{"message":"Certificate contains bad Comman Name & SAN Values 'eap.example.com'. Please confirm still you want to proceed.","id":null}]}""",
            HttpStatusCode.BadRequest));

        var ex = await Assert.ThrowsAsync<IseCsrNameResolutionException>(() => client.GenerateCsrAsync(new CsrRequest("ise-17-a", [IseRole.Eap],
            "eap.example.com", ["eap.example.com"], "RSA", "2048", "SHA-256", null), CancellationToken.None));
        Assert.Contains("A record", ex.Message);
    }
}

public class ScriptDnsChallengeClientTests
{
    private static ScriptDnsChallengeClient Client(string shellScript, TimeSpan? timeout = null) =>
        new("/bin/sh", timeout ?? TimeSpan.FromSeconds(10), NullLogger<ScriptDnsChallengeClient>.Instance,
            executable: "/bin/sh", leadingArguments: ["-c", shellScript, "sh"]);

    [Fact]
    public async Task Passes_action_record_and_value_to_the_script()
    {
        if (OperatingSystem.IsWindows()) return;
        var file = Path.GetTempFileName();
        try
        {
            var client = Client($"echo \"$@\" >> '{file}'");
            await client.CreateTxtRecordAsync("_acme-challenge.x", "v1", CancellationToken.None);
            await client.DeleteTxtRecordAsync("_acme-challenge.x", CancellationToken.None);

            Assert.Equal(["/bin/sh -Action Create -RecordName _acme-challenge.x -Value v1", "/bin/sh -Action Delete -RecordName _acme-challenge.x"],
                File.ReadAllLines(file));
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task Values_with_spaces_and_quotes_are_passed_unchanged()
    {
        if (OperatingSystem.IsWindows()) return;
        var file = Path.GetTempFileName();
        try
        {
            await Client($"printf '%s' \"$7\" > '{file}'").CreateTxtRecordAsync("r", "a b\"c'd", CancellationToken.None);
            Assert.Equal("a b\"c'd", File.ReadAllText(file));
        }
        finally { File.Delete(file); }
    }

    [Fact]
    public async Task Missing_executable_gives_dns_error()
    {
        var client = new ScriptDnsChallengeClient("x.ps1", TimeSpan.FromSeconds(5), NullLogger<ScriptDnsChallengeClient>.Instance,
            executable: "/nonexistent/powershell");
        await Assert.ThrowsAsync<DnsProxyException>(() => client.CreateTxtRecordAsync("r", "v", CancellationToken.None));
    }

    [Fact]
    public async Task Cancellation_is_propagated_not_wrapped()
    {
        if (OperatingSystem.IsWindows()) return;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Client("sleep 5").CreateTxtRecordAsync("r", "v", cts.Token));
    }

    [Fact]
    public async Task Non_zero_exit_code_and_timeout_fail()
    {
        if (OperatingSystem.IsWindows()) return;
        var ex = await Assert.ThrowsAsync<DnsProxyException>(() =>
            Client("echo boom >&2; exit 3").CreateTxtRecordAsync("r", "v", CancellationToken.None));
        Assert.Contains("exit code 3", ex.Message);
        Assert.Contains("boom", ex.Message);

        await Assert.ThrowsAsync<DnsProxyException>(() =>
            Client("sleep 5", TimeSpan.FromMilliseconds(300)).DeleteTxtRecordAsync("r", CancellationToken.None));
    }
}

public class AcmeDnsProxyClientTests
{
    [Fact]
    public async Task Create_and_delete_follow_the_acme_sh_contract()
    {
        var handler = new FakeHttpHandler(r => FakeHttpHandler.Empty(r.Method == HttpMethod.Post ? HttpStatusCode.Created : HttpStatusCode.NoContent));
        var client = new AcmeDnsProxyClient(new HttpClient(handler), new Uri("https://dns/api/txt"), "tok",
            NullLogger<AcmeDnsProxyClient>.Instance);

        await client.CreateTxtRecordAsync("_acme-challenge.eap.example.com", "v1", CancellationToken.None);
        await client.DeleteTxtRecordAsync("_acme-challenge.eap.example.com", CancellationToken.None);

        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("Bearer tok", handler.Requests[0].Authorization);
        Assert.Equal("""{"recordName":"_acme-challenge.eap.example.com","value":"v1"}""", handler.Requests[0].Body);
        Assert.Equal(HttpMethod.Delete, handler.Requests[1].Method);
        Assert.Equal("/api/txt", handler.Requests[1].Uri.AbsolutePath);
        Assert.Equal("""{"recordName":"_acme-challenge.eap.example.com"}""", handler.Requests[1].Body);
    }

    [Fact]
    public async Task Network_errors_become_dns_proxy_exceptions()
    {
        var handler = new FakeHttpHandler(_ => throw new HttpRequestException("down"));
        var client = new AcmeDnsProxyClient(new HttpClient(handler), new Uri("https://dns/api/txt"), "tok",
            NullLogger<AcmeDnsProxyClient>.Instance);

        var ex = await Assert.ThrowsAsync<DnsProxyException>(() => client.DeleteTxtRecordAsync("r", CancellationToken.None));
        Assert.Contains("network error", ex.Message);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, """{"error":"forbidden zone"}""")]
    [InlineData(HttpStatusCode.OK, """{"error":"upstream"}""")]
    public async Task Errors_are_raised(HttpStatusCode status, string body)
    {
        var handler = new FakeHttpHandler(_ => FakeHttpHandler.Json(body, status));
        var client = new AcmeDnsProxyClient(new HttpClient(handler), new Uri("https://dns/api/txt"), "tok",
            NullLogger<AcmeDnsProxyClient>.Instance);

        var ex = await Assert.ThrowsAsync<DnsProxyException>(() => client.CreateTxtRecordAsync("r", "v", CancellationToken.None));
        Assert.Contains("error", ex.Message);
    }
}
