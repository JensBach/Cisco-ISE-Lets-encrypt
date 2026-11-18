using System.Security.Cryptography;
using System.Text;
using CiscoIseLetsEncrypt.Certificates;
using CiscoIseLetsEncrypt.Tests.Fakes;
using CiscoIseLetsEncrypt.Verification.Radius;

namespace CiscoIseLetsEncrypt.Tests;

public class RadiusTests
{
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("s3cret");

    [Fact]
    public void Access_request_has_valid_message_authenticator_and_round_trips()
    {
        var p = new RadiusPacket { Code = RadiusCode.AccessRequest, Identifier = 7, Authenticator = RandomNumberGenerator.GetBytes(16) };
        p.Attributes.Add((RadiusAttribute.UserName, "anonymous"u8.ToArray()));
        p.AddEapMessage(new byte[600]);

        var raw = p.EncodeAccessRequest(Secret);
        var parsed = RadiusPacket.Parse(raw);

        Assert.Equal(3, parsed.Attributes.Count(a => a.Type == RadiusAttribute.EapMessage));
        Assert.Equal(600, parsed.GetEapMessage().Length);
        var ma = parsed.GetAttribute(RadiusAttribute.MessageAuthenticator)!;
        var zeroed = raw.ToArray();
        Array.Clear(zeroed, raw.Length - 16, 16);
        Assert.Equal(HMACMD5.HashData(Secret, zeroed), ma);
    }

    [Fact]
    public void Response_authenticator_is_verified_with_shared_secret()
    {
        var requestAuth = RandomNumberGenerator.GetBytes(16);
        var response = BuildChallenge(9, requestAuth, Secret, [1, 2, 3, 4, 5]);

        Assert.True(RadiusPacket.VerifyResponse(response, requestAuth, Secret));
        Assert.False(RadiusPacket.VerifyResponse(response, requestAuth, "wrong"u8.ToArray()));
        response[^1] ^= 0xff;
        Assert.False(RadiusPacket.VerifyResponse(response, requestAuth, Secret));
    }

    [Fact]
    public void Peap_packets_encode_flags_and_length()
    {
        var eap = EapPacket.PeapResponse(5, PeapFlags.LengthIncluded | PeapFlags.MoreFragments, new byte[] { 9, 9 }, 3000);
        var parsed = EapPacket.Parse(eap);

        Assert.Equal((EapCode.Response, (byte)5, EapType.Peap), (parsed.Code, parsed.Identifier, parsed.Type));
        Assert.Equal(PeapFlags.LengthIncluded | PeapFlags.MoreFragments, parsed.Flags);
        Assert.Equal(new byte[] { 9, 9 }, parsed.Data);
        Assert.Equal(new byte[] { 2, 3, 0, 6, EapType.Nak, EapType.Peap }, EapPacket.Nak(3, EapType.Peap));
    }

    [Fact]
    public async Task Tunnel_stream_fragments_outgoing_and_reassembles_incoming_tls_data()
    {
        var clientData = RandomNumberGenerator.GetBytes(2500);
        var serverData = RandomNumberGenerator.GetBytes(2200);
        var received = new MemoryStream();
        var sentFlags = new List<byte>();
        byte id = 10;
        var serverOffset = 0;

        Task<EapPacket> Exchange(byte[] eap, CancellationToken ct)
        {
            var r = EapPacket.Parse(eap);
            Assert.Equal(id, r.Identifier);
            sentFlags.Add(r.Flags);
            received.Write(r.Data);
            id++;
            if ((r.Flags & PeapFlags.MoreFragments) != 0)
                return Task.FromResult(new EapPacket(EapCode.Request, id, EapType.Peap, 0, []));

            var len = Math.Min(1000, serverData.Length - serverOffset);
            var more = serverOffset + len < serverData.Length;
            var chunk = serverData[serverOffset..(serverOffset + len)];
            serverOffset += len;
            return Task.FromResult(new EapPacket(EapCode.Request, id, EapType.Peap, more ? PeapFlags.MoreFragments : (byte)0, chunk));
        }

        var stream = new PeapTunnelStream(Exchange, 10, maxFragment: 1000);
        await stream.WriteAsync(clientData);
        var buffer = new byte[4096];
        var read = await stream.ReadAsync(buffer);

        Assert.Equal(clientData, received.ToArray());
        Assert.Equal([PeapFlags.LengthIncluded | PeapFlags.MoreFragments, PeapFlags.MoreFragments, 0, 0, 0], sentFlags);
        Assert.Equal(serverData, buffer[..read]);
    }

    [Fact]
    public async Task Tunnel_stream_fails_on_eap_failure()
    {
        var stream = new PeapTunnelStream((_, _) => Task.FromResult(new EapPacket(EapCode.Failure, 1, 0, 0, [])), 1);
        await stream.WriteAsync(new byte[10]);

        await Assert.ThrowsAsync<IOException>(async () => await stream.ReadAsync(new byte[10]));
    }

    private static byte[] BuildChallenge(byte id, byte[] requestAuth, byte[] secret, byte[] eap)
    {
        var p = new RadiusPacket { Code = RadiusCode.AccessChallenge, Identifier = id, Authenticator = requestAuth };
        p.AddEapMessage(eap);
        p.Attributes.Add((RadiusAttribute.MessageAuthenticator, new byte[16]));
        var raw = p.Encode();
        HMACMD5.HashData(secret, raw).CopyTo(raw, raw.Length - 16);
        MD5.HashData([.. raw, .. secret]).CopyTo(raw, 4);
        return raw;
    }
}

public class CertificateUtilTests
{
    [Fact]
    public async Task Parses_csr_names_and_der()
    {
        var ise = new FakeIse();
        ise.AddNode("n");
        var id = await ise.GenerateCsrAsync(new("n", [], "eap.example.com", ["eap.example.com", "radius.example.com"], "RSA", "2048", "SHA-256", null), default);
        var pem = await ise.ExportCsrAsync("n", id, default);

        var csr = CertificateUtil.ParseCsr(pem);

        Assert.Equal("eap.example.com", csr.CommonName);
        Assert.Equal(["eap.example.com", "radius.example.com"], csr.AllNames);
        Assert.Equal(0x30, csr.Der[0]);
    }

    [Fact]
    public void Normalizes_fingerprints()
    {
        Assert.Equal("aabb01", CertificateUtil.NormalizeFingerprint("AA:BB:01"));
    }
}
