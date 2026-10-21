using Warp.Quic.Buffers;
using Warp.Quic.Crypto;
using Warp.Quic.Recovery;

namespace Warp.Quic;

/// <summary>
/// The per-encryption-level state of a connection (RFC 9000 section 12.3): keys, packet numbers, received packets to
/// acknowledge, packets awaiting acknowledgment and the CRYPTO stream.
/// </summary>
internal sealed class PacketNumberSpace(EncryptionLevel level)
{
    public long AckDeadline { get; set; } = long.MaxValue;

    public int AckElicitingSinceAck { get; set; }

    public bool AckPending { get; set; }

    public bool CanSend => SendKeys is not null && !IsDiscarded;

    public ReassemblyBuffer CryptoReceive { get; } = new();

    public SendBuffer CryptoSend { get; set; } = new();

    // Packet numbers below this are treated as duplicates once old acknowledgment ranges have been forgotten.
    public long DuplicateFloor { get; set; }

    public bool IsDiscarded { get; set; }

    public long LargestAcknowledged { get; set; } = -1;

    public long LargestReceived { get; set; } = -1;

    public long LargestReceivedAt { get; set; }

    public long LastAckElicitingSentAt { get; set; }

    public EncryptionLevel Level => level;

    public long LossTime { get; set; } = long.MaxValue;

    public long NextPacketNumber { get; set; }

    public bool PingPending { get; set; }

    public int ProbesPending { get; set; }

    public PacketKeys? ReceiveKeys { get; set; }

    public RangeSet Received { get; } = new();

    public PacketKeys? SendKeys { get; set; }

    public SortedDictionary<long, SentPacket> Sent { get; } = [];
}
