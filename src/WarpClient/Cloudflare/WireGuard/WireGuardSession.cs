using System.Buffers.Binary;

namespace Warp.Cloudflare.WireGuard;

/// <summary>
/// Transport keys from one completed handshake, with the counters and replay window that belong to them.
/// </summary>
internal sealed class WireGuardSession(TransportKeys keys, long createdAt) : IDisposable
{
    public const int DataHeaderLength = 16;
    public const byte DataType = 4;
    private const int PaddingMultiple = 16;

    private readonly ChaChaPolyCipher _sender = new(keys.SendingKey);
    private readonly ChaChaPolyCipher _receiver = new(keys.ReceivingKey);
    private readonly ReplayWindow _replayWindow = new();
    private long _sendCounter = -1;

    public long CreatedAt => createdAt;

    public uint LocalIndex => keys.LocalIndex;

    public void Dispose()
    {
        _sender.Dispose();
        _receiver.Dispose();
    }

    /// <summary>
    /// Decrypts a data message addressed to this session, or returns <see langword="null"/> when it fails authentication
    /// or is a replay. Padding is left in place; the IP header states the real length.
    /// </summary>
    public byte[]? Open(ReadOnlySpan<byte> message)
    {
        ulong counter = BinaryPrimitives.ReadUInt64LittleEndian(message[8..]);
        byte[]? plaintext = WireGuardCrypto.Open(_receiver, counter, message[DataHeaderLength..], []);

        return plaintext is not null && _replayWindow.TryAccept(counter) ? plaintext : null;
    }

    public byte[] Seal(ReadOnlySpan<byte> packet)
    {
        ulong counter = (ulong)Interlocked.Increment(ref _sendCounter);
        int paddedLength = (packet.Length + PaddingMultiple - 1) / PaddingMultiple * PaddingMultiple;
        byte[] plaintext = new byte[paddedLength];

        packet.CopyTo(plaintext);

        byte[] ciphertext = WireGuardCrypto.Seal(_sender, counter, plaintext, []);
        byte[] message = new byte[DataHeaderLength + ciphertext.Length];

        message[0] = DataType;
        BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(start: 4), keys.RemoteIndex);
        BinaryPrimitives.WriteUInt64LittleEndian(message.AsSpan(start: 8), counter);
        ciphertext.CopyTo(message, DataHeaderLength);

        return message;
    }
}
