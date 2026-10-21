using System.Text;

using Warp.Cloudflare.Http3;

namespace Warp.Tests;

/// <summary>
/// Covers the HTTP/3 pieces of MASQUE proxy mode: QPACK field sections for <c>CONNECT</c> and frame headers.
/// </summary>
public sealed class Http3FramingTests
{
    /// <summary>
    /// Gets QPACK response sections whose status is a one-byte static index, a multi-byte static index, a literal value and
    /// a Huffman-coded literal value.
    /// </summary>
    public static TheoryData<byte[], int> StatusSections { get; } = new()
    {
        { [0x00, 0x00, 0xD9], 200 },
        { [0x00, 0x00, 0xFF, 0x05], 403 },
        { [0x00, 0x00, 0x5F, 0x09, 0x03, (byte)'4', (byte)'0', (byte)'7'], 407 },
        { [0x00, 0x00, 0x5F, 0x09, 0x83, 0x68, 0x0C, 0xFF], 403 },
    };

    /// <summary>
    /// A classic CONNECT carries only <c>:method</c> from the static table and <c>:authority</c> as a literal, with no
    /// dynamic table references.
    /// </summary>
    [Fact]
    public void ConnectRequestUsesStaticTableOnly()
    {
        byte[] section = QpackFieldSection.CreateConnectRequest(authority: "example.com:443");
        byte[] expected = [0x00, 0x00, 0xCF, 0x50, 0x0F, .. Encoding.ASCII.GetBytes(s: "example.com:443")];

        Assert.Equal(expected, section);
    }

    /// <summary>
    /// Frame headers written for DATA must read back with their type and length, and a stream that ends between frames
    /// reports a clean end rather than an error.
    /// </summary>
    /// <returns>A task that completes when the frames have been read back.</returns>
    [Fact]
    public async Task FrameHeadersRoundTripAndEndCleanly()
    {
        byte[] payload = new byte[300];
        byte[] frame = Http3Framing.CreateFrame(Http3Framing.DataFrame, payload);

        using MemoryStream stream = new([.. frame]);

        Http3FrameHeader? header = await Http3Framing.ReadHeaderAsync(stream, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: true);

        await Http3Framing.SkipAsync(stream, payload.Length, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: true);

        Http3FrameHeader? end = await Http3Framing.ReadHeaderAsync(stream, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: true);

        Assert.Equal(new Http3FrameHeader(Http3Framing.DataFrame, payload.Length), header);
        Assert.Null(end);
    }

    /// <summary>
    /// The status is read from whichever representation the server's QPACK encoder chose.
    /// </summary>
    /// <param name="section">Encoded response field section.</param>
    /// <param name="expected">Status the section encodes.</param>
    [Theory]
    [MemberData(nameof(StatusSections))]
    public void StatusDecodesFromEveryRepresentation(byte[] section, int expected)
    {
        Assert.Equal(expected, QpackFieldSection.DecodeStatus(section));
    }

    /// <summary>
    /// A response may not reference a dynamic table the client never allowed, so such a section is rejected.
    /// </summary>
    [Fact]
    public void StatusRejectsDynamicTableReferences()
    {
        byte[] section = [0x01, 0x00, 0xD9];

        InvalidDataException failure = Assert.Throws<InvalidDataException>(
            () =>
            {
                int status = QpackFieldSection.DecodeStatus(section);

                Assert.Fail($"Decoded unexpected status {status}.");
            }
        );

        Assert.Contains(expectedSubstring: "dynamic table", failure.Message, StringComparison.Ordinal);
    }
}
