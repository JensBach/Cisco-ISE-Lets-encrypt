using System.Buffers.Binary;

namespace CiscoIseLetsEncrypt.Verification.Radius;

public static class EapCode
{
    public const byte Request = 1;
    public const byte Response = 2;
    public const byte Success = 3;
    public const byte Failure = 4;
}

public static class EapType
{
    public const byte Identity = 1;
    public const byte Nak = 3;
    public const byte Peap = 25;
}

public static class PeapFlags
{
    public const byte LengthIncluded = 0x80;
    public const byte MoreFragments = 0x40;
    public const byte Start = 0x20;
}

/// <summary>EAP packet (RFC 3748). For PEAP, <see cref="Flags"/> and <see cref="Data"/> hold the TLS payload.</summary>
public sealed record EapPacket(byte Code, byte Identifier, byte Type, byte Flags, byte[] Data)
{
    public static byte[] Identity(byte id, string identity) =>
        Build(EapCode.Response, id, EapType.Identity, System.Text.Encoding.UTF8.GetBytes(identity));

    public static byte[] Nak(byte id, byte desiredType) => Build(EapCode.Response, id, EapType.Nak, [desiredType]);

    public static byte[] PeapResponse(byte id, byte flags, ReadOnlySpan<byte> tlsData, int? totalLength = null)
    {
        var header = (flags & PeapFlags.LengthIncluded) != 0 ? 5 : 1;
        var payload = new byte[header + tlsData.Length];
        payload[0] = flags;
        if (header == 5)
            BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), (uint)(totalLength ?? tlsData.Length));
        tlsData.CopyTo(payload.AsSpan(header));
        return Build(EapCode.Response, id, EapType.Peap, payload);
    }

    private static byte[] Build(byte code, byte id, byte type, ReadOnlySpan<byte> typeData)
    {
        var buf = new byte[5 + typeData.Length];
        buf[0] = code;
        buf[1] = id;
        BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), (ushort)buf.Length);
        buf[4] = type;
        typeData.CopyTo(buf.AsSpan(5));
        return buf;
    }

    public static EapPacket Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
            throw new FormatException("EAP packet too short");
        var length = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        if (length > data.Length || length < 4)
            throw new FormatException("Invalid EAP length");
        if (length == 4)
            return new EapPacket(data[0], data[1], 0, 0, []);

        var type = data[4];
        if (type != EapType.Peap)
            return new EapPacket(data[0], data[1], type, 0, data[5..length].ToArray());
        if (length < 6)
            throw new FormatException("PEAP packet without flags");

        var flags = data[5];
        var start = (flags & PeapFlags.LengthIncluded) != 0 ? 10 : 6;
        if (start > length)
            throw new FormatException("Invalid PEAP length");
        return new EapPacket(data[0], data[1], type, flags, data[start..length].ToArray());
    }
}
