using System.Security.Cryptography;

using Warp.Quic.Frames;
using Warp.Quic.Recovery;

namespace Warp.Quic.Packets;

/// <summary>
/// The connection IDs the server issued for this client to address it by, their retirement, and the stateless reset tokens
/// that come with them (RFC 9000 sections 5.1 and 10.3).
/// </summary>
internal sealed class ConnectionIdManager(byte[] initialDestination)
{
    public const int StatelessResetTokenLength = 16;
    private const int MaximumConnectionIdLength = 20;
    private const int MaximumPeerConnectionIds = 8;
    private const int MinimumStatelessResetLength = 21;

    private readonly SortedDictionary<long, byte[]> _available = [];
    private readonly List<byte[]> _resetTokens = [];
    private readonly Queue<long> _retirePending = new();
    private long _retiredBelow;
    private long _sequence;

    public byte[] Destination { get; set; } = initialDestination;

    public void AddResetToken(byte[] token)
    {
        _resetTokens.Add(token);
    }

    public bool IsStatelessReset(ReadOnlySpan<byte> datagram)
    {
        if (datagram.Length < MinimumStatelessResetLength)
            return false;

        ReadOnlySpan<byte> candidate = datagram[^StatelessResetTokenLength..];

        foreach (byte[] token in _resetTokens)
        {
            if (CryptographicOperations.FixedTimeEquals(token, candidate))
                return true;
        }

        return false;
    }

    public void OnNewConnectionId(long sequence, long retirePriorTo, byte[] connectionId, byte[] resetToken)
    {
        bool valid = connectionId.Length is > 0 and <= MaximumConnectionIdLength && retirePriorTo <= sequence && resetToken.Length == StatelessResetTokenLength;

        if (!valid)
            throw new QuicTransportException(QuicTransportException.FrameEncodingError, message: "The server sent a malformed NEW_CONNECTION_ID frame.");

        if (sequence < _retiredBelow)
        {
            _retirePending.Enqueue(sequence);

            return;
        }

        if (sequence != _sequence && _available.TryAdd(sequence, connectionId))
            _resetTokens.Add(resetToken);

        if (retirePriorTo > _retiredBelow)
            RetireBelow(retirePriorTo);

        if (_available.Count > MaximumPeerConnectionIds)
            throw new QuicTransportException(QuicTransportException.ConnectionIdLimitError, message: "The server issued more connection IDs than allowed.");
    }

    public void OnRetireLost(long sequence)
    {
        _retirePending.Enqueue(sequence);
    }

    public void WriteRetireFrames(QuicWriter payload, int limit, List<SentFrame> frames)
    {
        const int maximumFrameLength = 1 + 8;

        while (payload.Length + maximumFrameLength <= limit && _retirePending.TryDequeue(out long sequence))
        {
            FrameWriter.WriteInteger(payload, FrameType.RetireConnectionId, sequence);
            frames.Add(new SentFrame(SentFrameKind.RetireConnectionId, sequence, Offset: 0, Length: 0, Fin: false));
        }
    }

    private void RetireBelow(long retirePriorTo)
    {
        _retiredBelow = retirePriorTo;

        foreach (long retired in _available.Keys.Where(key => key < retirePriorTo).ToList())
        {
            if (_available.Remove(retired))
                _retirePending.Enqueue(retired);
        }

        if (_sequence >= retirePriorTo)
            return;

        // The ID in use was retired too, so the client moves to the oldest one still available.
        _retirePending.Enqueue(_sequence);

        KeyValuePair<long, byte[]> next = _available.FirstOrDefault();

        if (next.Value is null || !_available.Remove(next.Key))
            throw new QuicTransportException(QuicTransportException.ProtocolViolation, message: "The server retired every connection ID this client could use.");

        _sequence = next.Key;
        Destination = next.Value;
    }
}
