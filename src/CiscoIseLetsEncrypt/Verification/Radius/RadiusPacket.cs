using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CiscoIseLetsEncrypt.Verification.Radius;

public static class RadiusCode
{
    public const byte AccessRequest = 1;
    public const byte AccessAccept = 2;
    public const byte AccessReject = 3;
    public const byte AccessChallenge = 11;
}

public static class RadiusAttribute
{
    public const byte UserName = 1;
    public const byte ServiceType = 6;
    public const byte FramedMtu = 12;
    public const byte State = 24;
    public const byte CallingStationId = 31;
    public const byte NasIdentifier = 32;
    public const byte NasPortType = 61;
    public const byte EapMessage = 79;
    public const byte MessageAuthenticator = 80;
}

/// <summary>Minimal RFC 2865/3579 RADIUS packet with Message-Authenticator support.</summary>
public sealed class RadiusPacket
{
    public byte Code { get; init; }
    public byte Identifier { get; init; }
    public byte[] Authenticator { get; init; } = new byte[16];
    public List<(byte Type, byte[] Value)> Attributes { get; } = [];

    public byte[]? GetAttribute(byte type) => Attributes.FirstOrDefault(a => a.Type == type).Value;

    /// <summary>Concatenates all EAP-Message attributes.</summary>
    public byte[] GetEapMessage() => Attributes.Where(a => a.Type == RadiusAttribute.EapMessage).SelectMany(a => a.Value).ToArray();

    public void AddEapMessage(byte[] eap)
    {
        for (var offset = 0; offset < eap.Length; offset += 253)
            Attributes.Add((RadiusAttribute.EapMessage, eap[offset..Math.Min(eap.Length, offset + 253)]));
    }

    public byte[] Encode()
    {
        var length = 20 + Attributes.Sum(a => 2 + a.Value.Length);
        if (length > 4096)
            throw new InvalidOperationException("RADIUS packet too large");
        var buf = new byte[length];
        buf[0] = Code;
        buf[1] = Identifier;
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), (ushort)length);
        Authenticator.CopyTo(buf, 4);
        var pos = 20;
        foreach (var (type, value) in Attributes)
        {
            if (value.Length > 253)
                throw new InvalidOperationException($"RADIUS attribute {type} too long");
            buf[pos] = type;
            buf[pos + 1] = (byte)(value.Length + 2);
            value.CopyTo(buf, pos + 2);
            pos += value.Length + 2;
        }
        return buf;
    }

    /// <summary>Encodes an Access-Request with a valid Message-Authenticator (HMAC-MD5).</summary>
    public byte[] EncodeAccessRequest(byte[] secret)
    {
        Attributes.RemoveAll(a => a.Type == RadiusAttribute.MessageAuthenticator);
        Attributes.Add((RadiusAttribute.MessageAuthenticator, new byte[16]));
        var raw = Encode();
        var mac = HMACMD5.HashData(secret, raw);
        var offset = FindMessageAuthenticatorOffset(raw);
        mac.CopyTo(raw, offset);
        return raw;
    }

    public static RadiusPacket Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 20)
            throw new FormatException("RADIUS packet too short");
        var length = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        if (length < 20 || length > data.Length)
            throw new FormatException("Invalid RADIUS length");

        var packet = new RadiusPacket { Code = data[0], Identifier = data[1], Authenticator = data[4..20].ToArray() };
        var pos = 20;
        while (pos + 2 <= length)
        {
            var type = data[pos];
            var len = data[pos + 1];
            if (len < 2 || pos + len > length)
                throw new FormatException("Invalid RADIUS attribute");
            packet.Attributes.Add((type, data.Slice(pos + 2, len - 2).ToArray()));
            pos += len;
        }
        return packet;
    }

    /// <summary>
    /// Verifies the Response Authenticator (RFC 2865) and, if present, the Message-Authenticator (RFC 3579).
    /// </summary>
    public static bool VerifyResponse(byte[] response, byte[] requestAuthenticator, byte[] secret)
    {
        if (response.Length < 20)
            return false;
        var length = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2));
        var raw = response[..length];

        var check = raw.ToArray();
        requestAuthenticator.CopyTo(check, 4);
        var expected = MD5.HashData([.. check, .. secret]);
        if (!CryptographicOperations.FixedTimeEquals(expected, raw.AsSpan(4, 16)))
            return false;

        var maOffset = FindMessageAuthenticatorOffset(raw);
        if (maOffset < 0)
            return true;
        var received = raw.AsSpan(maOffset, 16).ToArray();
        Array.Clear(check, maOffset, 16);
        var mac = HMACMD5.HashData(secret, check);
        return CryptographicOperations.FixedTimeEquals(mac, received);
    }

    private static int FindMessageAuthenticatorOffset(byte[] raw)
    {
        var pos = 20;
        while (pos + 2 <= raw.Length)
        {
            if (raw[pos] == RadiusAttribute.MessageAuthenticator && raw[pos + 1] == 18)
                return pos + 2;
            if (raw[pos + 1] < 2)
                break;
            pos += raw[pos + 1];
        }
        return -1;
    }
}
