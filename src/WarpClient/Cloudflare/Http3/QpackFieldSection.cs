using System.Globalization;
using System.Text;

using Warp.Cloudflare.Tunnel;

namespace Warp.Cloudflare.Http3;

/// <summary>
/// The two QPACK field sections proxy mode needs (RFC 9204): the request for a classic <c>CONNECT</c> and the status of its
/// response. The dynamic table is never used, which is what an advertised table capacity of zero promises the peer.
/// </summary>
internal static class QpackFieldSection
{
    private const int AuthorityIndex = 0;
    private const int MethodConnectIndex = 15;
    private const int StatusDigits = 3;

    public static byte[] CreateConnectRequest(string authority)
    {
        byte[] value = Encoding.ASCII.GetBytes(authority);
        List<byte> section = [0x00, 0x00];

        // ":method: CONNECT" is a static-table entry; ":authority" is a static name with a literal value.
        section.Add(0xC0 | MethodConnectIndex);
        AddInteger(section, prefix: 0x50, prefixBits: 4, AuthorityIndex);
        AddInteger(section, prefix: 0x00, prefixBits: 7, value.Length);
        section.AddRange(value);

        return [.. section];
    }

    public static int DecodeStatus(ReadOnlySpan<byte> section)
    {
        int offset = 0;
        int requiredInsertCount = ResponseStatusDecoder.ReadInteger(section, ref offset, prefixBits: 8);
        int deltaBase = ResponseStatusDecoder.ReadInteger(section, ref offset, prefixBits: 7);

        if (requiredInsertCount != 0 || deltaBase != 0 || offset >= section.Length)
            throw new InvalidDataException(message: "The response refers to a QPACK dynamic table that was never allowed.");

        byte first = section[offset];

        // Indexed field line from the static table: 11xxxxxx.
        if ((first & 0xC0) == 0xC0)
            return StatusFromStaticIndex(ResponseStatusDecoder.ReadInteger(section, ref offset, prefixBits: 6));

        // Literal with a static name reference: 01N1xxxx, followed by the value string.
        if ((first & 0xD0) != 0x50)
            throw new InvalidDataException(message: "The response does not start with a status.");

        int nameIndex = ResponseStatusDecoder.ReadInteger(section, ref offset, prefixBits: 4);

        if (!IsStatusIndex(nameIndex))
            throw new InvalidDataException(message: "The response does not start with a status.");

        bool huffmanCoded = offset < section.Length && (section[offset] & 0x80) != 0;
        int length = offset < section.Length ? ResponseStatusDecoder.ReadInteger(section, ref offset, prefixBits: 7) : 0;

        if (length == 0 || offset + length > section.Length)
            throw new InvalidDataException(message: "The response status is truncated.");

        ReadOnlySpan<byte> digits = section.Slice(offset, length);

        return huffmanCoded ? ResponseStatusDecoder.DecodeHuffmanDigits(digits) : ParseDigits(digits);
    }

    private static void AddInteger(List<byte> section, byte prefix, int prefixBits, int value)
    {
        int limit = (1 << prefixBits) - 1;

        if (value < limit)
        {
            section.Add((byte)(prefix | value));

            return;
        }

        section.Add((byte)(prefix | limit));
        value -= limit;

        while (value >= 0x80)
        {
            section.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        section.Add((byte)value);
    }

    private static bool IsStatusIndex(int index)
    {
        return index is (>= 24 and <= 28) or (>= 63 and <= 71);
    }

    private static int ParseDigits(ReadOnlySpan<byte> digits)
    {
        return digits.Length == StatusDigits
            ? int.Parse(digits, CultureInfo.InvariantCulture)
            : throw new InvalidDataException(message: "The response status is not three digits.");
    }

    private static int StatusFromStaticIndex(int index)
    {
        return index switch
        {
            24 => 103,
            25 => 200,
            26 => 304,
            27 => 404,
            28 => 503,
            63 => 100,
            64 => 204,
            65 => 206,
            66 => 302,
            67 => 400,
            68 => 403,
            69 => 421,
            70 => 425,
            71 => 500,
            _ => throw new InvalidDataException(message: "The response does not start with a status."),
        };
    }
}
