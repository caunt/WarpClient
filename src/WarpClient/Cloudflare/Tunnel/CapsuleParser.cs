namespace Warp.Cloudflare.Tunnel;

/// <summary>
/// Reassembles HTTP capsules (RFC 9297) from a byte stream whose frame boundaries do not line up with capsule boundaries.
/// </summary>
/// <remarks>
/// Cloudflare's HTTP/2 tunnel puts raw IP packets in DATAGRAM capsules without the context identifier RFC 9484 requires,
/// so each DATAGRAM payload is returned as a packet as-is. Other capsule types are skipped.
/// </remarks>
internal sealed class CapsuleParser
{
    private const ulong DatagramType = 0;
    private const int MaximumCapsuleLength = ushort.MaxValue;

    private byte[] _buffer = new byte[8192];
    private int _count;

    public IReadOnlyList<byte[]> Append(ReadOnlySpan<byte> data)
    {
        if (_count + data.Length > _buffer.Length)
            Array.Resize(ref _buffer, Math.Max(_count + data.Length, _buffer.Length * 2));

        data.CopyTo(_buffer.AsSpan(_count));
        _count += data.Length;

        List<byte[]> packets = [];
        int offset = 0;
        int consumed = TryReadCapsule(_buffer.AsSpan(offset, _count - offset), packets);

        while (consumed > 0)
        {
            offset += consumed;
            consumed = TryReadCapsule(_buffer.AsSpan(offset, _count - offset), packets);
        }

        _buffer.AsSpan(offset, _count - offset).CopyTo(_buffer);
        _count -= offset;

        return packets;
    }

    private static int TryReadCapsule(ReadOnlySpan<byte> available, List<byte[]> packets)
    {
        if (!VariableLengthInteger.TryRead(available, out ulong type, out int typeLength))
            return 0;

        if (!VariableLengthInteger.TryRead(available[typeLength..], out ulong length, out int lengthLength))
            return 0;

        if (length > MaximumCapsuleLength)
            throw new InvalidDataException(message: "The tunnel sent an oversized capsule.");

        int headerLength = typeLength + lengthLength;
        int capsuleLength = headerLength + (int)length;

        if (available.Length < capsuleLength)
            return 0;

        if (type == DatagramType)
            packets.Add(available[headerLength..capsuleLength].ToArray());

        return capsuleLength;
    }
}
