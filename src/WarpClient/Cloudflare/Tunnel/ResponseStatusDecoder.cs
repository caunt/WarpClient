using System.Globalization;

namespace Warp.Cloudflare.Tunnel;

/// <summary>
/// Reads the <c>:status</c> pseudo-header from the start of an HPACK header block without a full decoder.
/// </summary>
/// <remarks>
/// RFC 9113 puts pseudo-headers first, and the status is either a static table entry or a literal whose value is three
/// digits, plain or Huffman-coded. Only the Huffman codes for digits are needed, so only those are implemented.
/// </remarks>
internal static class ResponseStatusDecoder
{
    private const int FirstStatusIndex = 8;
    private const int LastStatusIndex = 14;
    private const int StatusDigits = 3;

    public static int Decode(ReadOnlySpan<byte> block)
    {
        int offset = 0;

        // Dynamic table size updates may precede the first header; they carry no header and are skipped.
        while (offset < block.Length && (block[offset] & 0xE0) == 0x20)
        {
            int ignoredSize = ReadInteger(block, ref offset, prefixBits: 5);

            if (ignoredSize < 0)
                throw new InvalidDataException(message: "The response header block is malformed.");
        }

        if (offset >= block.Length)
            throw new InvalidDataException(message: "The response header block is empty.");

        if ((block[offset] & 0x80) != 0)
            return StatusFromIndex(ReadInteger(block, ref offset, prefixBits: 7));

        int nameIndex = ReadInteger(block, ref offset, (block[offset] & 0x40) != 0 ? 6 : 4);

        if (nameIndex is < FirstStatusIndex or > LastStatusIndex || offset >= block.Length)
            throw new InvalidDataException(message: "The response does not start with a status.");

        bool huffmanCoded = (block[offset] & 0x80) != 0;
        int length = ReadInteger(block, ref offset, prefixBits: 7);

        if (offset + length > block.Length)
            throw new InvalidDataException(message: "The response status is truncated.");

        ReadOnlySpan<byte> value = block.Slice(offset, length);

        return huffmanCoded ? DecodeHuffmanDigits(value) : int.Parse(value, CultureInfo.InvariantCulture);
    }

    private static int DecodeHuffmanDigits(ReadOnlySpan<byte> value)
    {
        if (value.Length > sizeof(ulong))
            throw new InvalidDataException(message: "The response status is too long.");

        ulong bits = 0;
        int available = 0;
        int status = 0;
        int digits = 0;

        foreach (byte octet in value)
        {
            bits = (bits << 8) | octet;
            available += 8;
        }

        // Digits 0-2 have 5-bit codes 00000-00010 and digits 3-9 have 6-bit codes 011001-011111 (RFC 7541 appendix B).
        while (digits < StatusDigits && available >= 5)
        {
            int shortCode = (int)(bits >> (available - 5)) & 0x1F;

            if (shortCode <= 2)
            {
                status = (status * 10) + shortCode;
                available -= 5;
                digits++;

                continue;
            }

            int longCode = available >= 6 ? (int)(bits >> (available - 6)) & 0x3F : -1;

            if (longCode is < 25 or > 31)
                throw new InvalidDataException(message: "The response status is not numeric.");

            status = (status * 10) + longCode - 22;
            available -= 6;
            digits++;
        }

        return digits == StatusDigits ? status : throw new InvalidDataException(message: "The response status is truncated.");
    }

    private static int ReadInteger(ReadOnlySpan<byte> block, ref int offset, int prefixBits)
    {
        int limit = (1 << prefixBits) - 1;
        int value = block[offset] & limit;
        int shift = 0;

        offset++;

        if (value < limit)
            return value;

        while (offset < block.Length)
        {
            byte next = block[offset];

            offset++;
            value += (next & 0x7F) << shift;
            shift += 7;

            if ((next & 0x80) == 0)
                return value;
        }

        throw new InvalidDataException(message: "The response header block ends inside an integer.");
    }

    private static int StatusFromIndex(int index)
    {
        return index switch
        {
            8 => 200,
            9 => 204,
            10 => 206,
            11 => 304,
            12 => 400,
            13 => 404,
            14 => 500,
            _ => throw new InvalidDataException(message: "The response does not start with a status."),
        };
    }
}
