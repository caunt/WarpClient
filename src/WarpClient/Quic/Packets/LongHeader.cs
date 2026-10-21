namespace Warp.Quic.Packets;

/// <summary>
/// The fields of a long-header packet that are readable before header protection is removed (RFC 9000 section 17.2).
/// </summary>
internal readonly record struct LongHeader(byte First, uint Version, byte[] Destination, byte[] Source, int TokenOffset, int PacketNumberOffset, int End)
{
    public const int HandshakeType = 0x02;
    public const int InitialType = 0x00;
    public const int RetryType = 0x03;
    public const uint Version1 = 1;
    private const int MaximumConnectionIdLength = 20;

    public int Type => (First >> 4) & 0x03;

    public static int GetLength(int type, int destinationLength, int sourceLength, int tokenLength, int packetNumberLength)
    {
        int token = type == InitialType ? VariableLengthInteger.GetLength((ulong)tokenLength) + tokenLength : 0;

        return 1 + 4 + 1 + destinationLength + 1 + sourceLength + token + 2 + packetNumberLength;
    }

    /// <summary>
    /// Reads the header at the start of <paramref name="data"/>; malformed headers throw <see cref="InvalidDataException"/>.
    /// Version negotiation, Retry and unknown versions have no packet number, and span the rest of the datagram.
    /// </summary>
    public static LongHeader Parse(ReadOnlySpan<byte> data)
    {
        QuicReader reader = new(data.ToArray());
        byte first = reader.ReadByte();
        uint version = reader.ReadUInt32();
        byte[] destination = reader.ReadVector8().ToArray();
        byte[] source = reader.ReadVector8().ToArray();
        int tokenOffset = reader.Offset;
        int type = (first >> 4) & 0x03;

        if (version != Version1 || type == RetryType)
            return new LongHeader(first, version, destination, source, tokenOffset, PacketNumberOffset: 0, data.Length);

        bool valid = (first & 0x40) != 0 && destination.Length <= MaximumConnectionIdLength && source.Length <= MaximumConnectionIdLength;

        if (!valid)
            throw new InvalidDataException(message: "The packet has a malformed long header.");

        if (type == InitialType)
            reader.Skip(reader.ReadLength());

        int length = reader.ReadLength();
        int packetNumberOffset = reader.Offset;

        return packetNumberOffset + length <= data.Length
            ? new LongHeader(first, version, destination, source, tokenOffset, packetNumberOffset, packetNumberOffset + length)
            : throw new InvalidDataException(message: "The packet is longer than its datagram.");
    }

    // The length field is always two bytes, so the header size is known before the payload is.
    public static void Write(QuicWriter writer, int type, byte[] destination, byte[] source, byte[] token, int remainingLength, int packetNumberLength)
    {
        writer.WriteByte((byte)(0xC0 | (type << 4) | (packetNumberLength - 1)));
        writer.WriteUInt32(Version1);
        writer.WriteVector8(destination);
        writer.WriteVector8(source);

        if (type == InitialType)
        {
            writer.WriteVariableLengthInteger((ulong)token.Length);
            writer.WriteBytes(token);
        }

        writer.WriteUInt16((ushort)(0x4000 | remainingLength));
    }
}
