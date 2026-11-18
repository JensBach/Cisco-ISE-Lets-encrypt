namespace CiscoIseLetsEncrypt.Verification.Radius;

/// <summary>
/// Stream that tunnels TLS records through EAP-PEAP packets so <see cref="System.Net.Security.SslStream"/>
/// can perform the TLS handshake with ISE over RADIUS. Handles PEAP fragmentation in both directions.
/// </summary>
public sealed class PeapTunnelStream(Func<byte[], CancellationToken, Task<EapPacket>> exchange, byte initialEapId, int maxFragment = 1000)
    : Stream
{
    private readonly MemoryStream _outgoing = new();
    private byte[] _incoming = [];
    private int _incomingPos;
    private byte _eapId = initialEapId;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Write(byte[] buffer, int offset, int count) => _outgoing.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        _outgoing.Write(buffer, offset, count);
        return Task.CompletedTask;
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        _outgoing.Write(buffer.Span);
        return ValueTask.CompletedTask;
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_incomingPos >= _incoming.Length)
        {
            _incoming = await ExchangeAsync(ct);
            _incomingPos = 0;
        }
        var n = Math.Min(buffer.Length, _incoming.Length - _incomingPos);
        _incoming.AsMemory(_incomingPos, n).CopyTo(buffer);
        _incomingPos += n;
        return n;
    }

    private async Task<byte[]> ExchangeAsync(CancellationToken ct)
    {
        var data = _outgoing.ToArray();
        _outgoing.SetLength(0);

        EapPacket request;
        if (data.Length == 0)
        {
            request = await SendAsync(EapPacket.PeapResponse(_eapId, 0, []), ct);
        }
        else
        {
            var fragmented = data.Length > maxFragment;
            var offset = 0;
            while (true)
            {
                var len = Math.Min(maxFragment, data.Length - offset);
                var last = offset + len >= data.Length;
                byte flags = 0;
                if (fragmented && offset == 0) flags |= PeapFlags.LengthIncluded;
                if (!last) flags |= PeapFlags.MoreFragments;

                request = await SendAsync(EapPacket.PeapResponse(_eapId, flags, data.AsSpan(offset, len), data.Length), ct);
                offset += len;
                if (last)
                    break;
                if (request.Data.Length != 0)
                    throw new InvalidOperationException("Expected PEAP fragment acknowledgement from server.");
            }
        }

        using var received = new MemoryStream();
        received.Write(request.Data);
        while ((request.Flags & PeapFlags.MoreFragments) != 0)
        {
            request = await SendAsync(EapPacket.PeapResponse(_eapId, 0, []), ct);
            received.Write(request.Data);
        }
        return received.ToArray();
    }

    private async Task<EapPacket> SendAsync(byte[] eapResponse, CancellationToken ct)
    {
        var request = await exchange(eapResponse, ct);
        if (request.Code != EapCode.Request || request.Type != EapType.Peap)
            throw new IOException($"Unexpected EAP packet during PEAP handshake (code {request.Code}, type {request.Type}).");
        _eapId = request.Identifier;
        return request;
    }
}
