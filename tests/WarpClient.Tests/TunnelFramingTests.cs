using Warp.Cloudflare.Tunnel;
using Warp.Quic;

namespace Warp.Tests;

/// <summary>
/// Covers the byte-level framing of the MASQUE tunnel: QUIC integers, DATAGRAM capsules and the HPACK status line.
/// </summary>
public sealed class TunnelFramingTests
{
    /// <summary>
    /// Gets values on both edges of every QUIC integer encoding width.
    /// </summary>
    public static TheoryData<ulong> WidthBoundaries { get; } =
    [
        0,
        63,
        64,
        16383,
        16384,
        1073741823,
        1073741824,
        4611686018427387903,
    ];

    /// <summary>
    /// Gets header blocks that encode a status as a static-table entry, after a table size update, as a plain literal and
    /// as a Huffman-coded literal.
    /// </summary>
    public static TheoryData<byte[], int> StatusEncodings { get; } = new()
    {
        { [0x88], 200 },
        { [0x8C, 0x40], 400 },
        { [0x3F, 0xE1, 0x1F, 0x88], 200 },
        { [0x08, 0x03, (byte)'5', (byte)'0', (byte)'3'], 503 },
        { [0x08, 0x83, 0x68, 0x0C, 0xFF], 403 },
    };

    /// <summary>
    /// Capsule types other than DATAGRAM carry no packets and must be skipped without disturbing the ones around them.
    /// </summary>
    [Fact]
    public void CapsuleParserSkipsNonDatagramCapsules()
    {
        CapsuleParser parser = new();
        byte[] stream = [0x01, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0x45];
        byte[] expected = [0x45];

        IReadOnlyList<byte[]> packets = parser.Append(stream);

        Assert.Equal(expected, Assert.Single(packets));
    }

    /// <summary>
    /// HTTP/2 DATA frames split capsules at arbitrary points, so a packet only appears once all of its bytes arrived.
    /// </summary>
    [Fact]
    public void CapsuleParserWaitsForCapsulesSplitAcrossFrames()
    {
        CapsuleParser parser = new();
        byte[] packet = [0x45, 0x00, 0x00, 0x14, 0x01, 0x02];
        byte[] capsule = [0x00, (byte)packet.Length, .. packet];

        IReadOnlyList<byte[]> early = parser.Append(capsule.AsSpan(start: 0, length: 3));
        IReadOnlyList<byte[]> completed = parser.Append(capsule.AsSpan(start: 3));

        Assert.Empty(early);
        Assert.Equal(packet, Assert.Single(completed));
    }

    /// <summary>
    /// Statuses arrive as static-table entries, plain literals or Huffman-coded literals depending on the server's encoder.
    /// </summary>
    /// <param name="block">HPACK header block whose first field is the status.</param>
    /// <param name="expected">Status the block encodes.</param>
    [Theory]
    [MemberData(nameof(StatusEncodings))]
    public void ResponseStatusDecoderReadsEveryStatusEncoding(byte[] block, int expected)
    {
        Assert.Equal(expected, ResponseStatusDecoder.Decode(block));
    }

    /// <summary>
    /// A block that starts with an ordinary header instead of the status pseudo-header is a protocol error.
    /// </summary>
    [Fact]
    public void ResponseStatusDecoderRejectsBlocksWithoutStatus()
    {
        byte[] block = [0x82];

        InvalidDataException failure = Assert.Throws<InvalidDataException>(
            () =>
            {
                int status = ResponseStatusDecoder.Decode(block);

                Assert.Fail($"Decoded unexpected status {status}.");
            }
        );

        Assert.Contains(expectedSubstring: "status", failure.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Every encoding width, including both edges of each width, must decode back to the value that was written.
    /// </summary>
    /// <param name="value">Value sitting on or next to an encoding-width boundary.</param>
    [Theory]
    [MemberData(nameof(WidthBoundaries))]
    public void VariableLengthIntegerRoundTripsAcrossWidths(ulong value)
    {
        byte[] buffer = new byte[8];
        int written = VariableLengthInteger.Write(value, buffer);
        bool read = VariableLengthInteger.TryRead(buffer, out ulong decoded, out int length);

        Assert.True(read);
        Assert.Equal(written, length);
        Assert.Equal(value, decoded);
        Assert.Equal(VariableLengthInteger.GetLength(value), written);
    }
}
