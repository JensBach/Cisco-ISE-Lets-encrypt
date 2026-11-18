using System.Net;
using System.Text;

namespace CiscoIseLetsEncrypt.Tests.Fakes;

public sealed record RecordedRequest(HttpMethod Method, Uri Uri, string? Body, string? Authorization);

/// <summary>HttpMessageHandler that records requests and answers with a responder function.</summary>
public sealed class FakeHttpHandler(Func<RecordedRequest, HttpResponseMessage> responder) : HttpMessageHandler
{
    public List<RecordedRequest> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        var rec = new RecordedRequest(request.Method, request.RequestUri!, body, request.Headers.Authorization?.ToString());
        Requests.Add(rec);
        var resp = responder(rec);
        resp.RequestMessage = request;
        return resp;
    }

    public static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Empty(HttpStatusCode status) => new(status) { Content = new StringContent("") };
}
