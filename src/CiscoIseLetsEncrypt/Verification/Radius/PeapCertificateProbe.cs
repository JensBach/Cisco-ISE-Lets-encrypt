using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CiscoIseLetsEncrypt.Verification.Radius;

/// <summary>
/// Starts an EAP-PEAP authentication against ISE over RADIUS and captures the server certificate
/// from the TLS handshake. The handshake is aborted once the certificate is received (no credentials are sent).
/// Requires the machine running this tool to be configured as a Network Device in ISE with the shared secret.
/// </summary>
public sealed class PeapCertificateProbe(string host, int port, string sharedSecret, string identity, TimeSpan timeout)
{
    private const int MaxRetransmits = 3;
    private static readonly TimeSpan ReceiveTimeout = TimeSpan.FromSeconds(5);

    private readonly byte[] _secret = Encoding.UTF8.GetBytes(sharedSecret);
    private readonly string _callingStationId = "02-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(5)).Insert(8, "-").Insert(6, "-").Insert(4, "-").Insert(2, "-");
    private byte _radiusId = (byte)RandomNumberGenerator.GetInt32(256);
    private byte[]? _state;
    private UdpClient? _udp;

    public async Task<X509Certificate2> GetServerCertificateAsync(CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var udp = new UdpClient();
        _udp = udp;
        udp.Connect(host, port);

        var request = await ExchangeAsync(EapPacket.Identity(0, identity), cts.Token);
        for (var i = 0; i < 5 && !(request.Type == EapType.Peap && (request.Flags & PeapFlags.Start) != 0); i++)
        {
            if (request.Code != EapCode.Request)
                throw new IOException($"ISE ended EAP conversation (EAP code {request.Code}).");
            // ISE proposed another EAP method – ask for PEAP instead.
            request = await ExchangeAsync(EapPacket.Nak(request.Identifier, EapType.Peap), cts.Token);
        }
        if (request.Type != EapType.Peap)
            throw new IOException("ISE did not offer EAP-PEAP (check the allowed protocols of the authentication policy).");

        X509Certificate2? captured = null;
        await using var tunnel = new PeapTunnelStream(ExchangeAsync, request.Identifier);
        await using var ssl = new SslStream(tunnel, leaveInnerStreamOpen: true);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                RemoteCertificateValidationCallback = (_, cert, _, _) =>
                {
                    if (cert is not null)
                        captured = new X509Certificate2(cert);
                    return false; // abort the handshake – we only need the certificate
                },
            }, cts.Token);
        }
        catch (Exception ex) when (captured is not null && ex is AuthenticationException or IOException)
        {
        }
        catch (AuthenticationException ex)
        {
            throw new IOException(
                $"PEAP TLS handshake failed before a certificate was received: {ex.InnerException?.Message ?? ex.Message}", ex);
        }
        return captured ?? throw new IOException("No server certificate received in the PEAP handshake.");
    }

    private async Task<EapPacket> ExchangeAsync(byte[] eapMessage, CancellationToken ct)
    {
        var packet = new RadiusPacket
        {
            Code = RadiusCode.AccessRequest,
            Identifier = unchecked(_radiusId++),
            Authenticator = RandomNumberGenerator.GetBytes(16),
        };
        packet.Attributes.Add((RadiusAttribute.UserName, Encoding.UTF8.GetBytes(identity)));
        packet.Attributes.Add((RadiusAttribute.NasIdentifier, "CiscoIseLetsEncrypt"u8.ToArray()));
        packet.Attributes.Add((RadiusAttribute.CallingStationId, Encoding.ASCII.GetBytes(_callingStationId)));
        packet.Attributes.Add((RadiusAttribute.ServiceType, UInt32(2))); // Framed
        packet.Attributes.Add((RadiusAttribute.NasPortType, UInt32(15))); // Ethernet
        packet.Attributes.Add((RadiusAttribute.FramedMtu, UInt32(1300)));
        if (_state is not null)
            packet.Attributes.Add((RadiusAttribute.State, _state));
        packet.AddEapMessage(eapMessage);
        var raw = packet.EncodeAccessRequest(_secret);

        for (var attempt = 0; attempt < MaxRetransmits; attempt++)
        {
            await _udp!.SendAsync(raw, ct);
            using var rcts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            rcts.CancelAfter(ReceiveTimeout);
            try
            {
                while (true)
                {
                    var result = await _udp.ReceiveAsync(rcts.Token);
                    if (result.Buffer.Length < 20 || result.Buffer[1] != packet.Identifier)
                        continue;
                    return HandleResponse(result.Buffer, packet.Authenticator);
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
            }
        }
        throw new TimeoutException($"No RADIUS response from {host}:{port} (is this host a Network Device in ISE with the correct shared secret?).");
    }

    private EapPacket HandleResponse(byte[] buffer, byte[] requestAuthenticator)
    {
        if (!RadiusPacket.VerifyResponse(buffer, requestAuthenticator, _secret))
            throw new IOException("Invalid RADIUS response authenticator – wrong shared secret?");

        var response = RadiusPacket.Parse(buffer);
        switch (response.Code)
        {
            case RadiusCode.AccessChallenge:
                _state = response.GetAttribute(RadiusAttribute.State);
                return EapPacket.Parse(response.GetEapMessage());
            case RadiusCode.AccessReject:
                throw new IOException("ISE sent Access-Reject (check Network Device, allowed protocols (PEAP) and policy).");
            default:
                throw new IOException($"Unexpected RADIUS response code {response.Code}.");
        }
    }

    private static byte[] UInt32(uint v)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return b;
    }
}
