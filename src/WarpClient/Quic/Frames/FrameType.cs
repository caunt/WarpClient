namespace Warp.Quic.Frames;

/// <summary>
/// QUIC frame type codes (RFC 9000 section 19, RFC 9221 section 4).
/// </summary>
internal static class FrameType
{
    public const ulong Ack = 0x02;
    public const ulong AckWithCounts = 0x03;
    public const ulong ApplicationClose = 0x1D;
    public const ulong ConnectionClose = 0x1C;
    public const ulong Crypto = 0x06;
    public const ulong DataBlocked = 0x14;
    public const ulong Datagram = 0x30;
    public const ulong DatagramWithLength = 0x31;
    public const ulong HandshakeDone = 0x1E;
    public const ulong MaximumData = 0x10;
    public const ulong MaximumStreamData = 0x11;
    public const ulong MaximumStreamsBidirectional = 0x12;
    public const ulong MaximumStreamsUnidirectional = 0x13;
    public const ulong NewConnectionId = 0x18;
    public const ulong NewToken = 0x07;
    public const ulong Padding = 0x00;
    public const ulong PathChallenge = 0x1A;
    public const ulong PathResponse = 0x1B;
    public const ulong Ping = 0x01;
    public const ulong ResetStream = 0x04;
    public const ulong RetireConnectionId = 0x19;
    public const ulong StopSending = 0x05;
    public const ulong Stream = 0x08;
    public const ulong StreamDataBlocked = 0x15;
    public const ulong StreamFin = 0x01;
    public const ulong StreamLength = 0x02;
    public const ulong StreamOffset = 0x04;
    public const ulong StreamTypeLast = 0x0F;
    public const ulong StreamsBlockedBidirectional = 0x16;
    public const ulong StreamsBlockedUnidirectional = 0x17;
}
