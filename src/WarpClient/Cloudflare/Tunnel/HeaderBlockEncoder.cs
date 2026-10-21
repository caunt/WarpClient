using System.Text;

namespace Warp.Cloudflare.Tunnel;

/// <summary>
/// Writes an HPACK header block (RFC 7541) using only literal representations without indexing, so neither side ever
/// needs a dynamic table.
/// </summary>
internal sealed class HeaderBlockEncoder
{
    private readonly List<byte> _block = [];

    public void AddIndexedName(int staticIndex, string value)
    {
        AddInteger(prefix: 0x00, prefixBits: 4, staticIndex);
        AddString(value);
    }

    public void AddLiteral(string name, string value)
    {
        _block.Add(item: 0x00);
        AddString(name);
        AddString(value);
    }

    public byte[] ToArray()
    {
        return [.. _block];
    }

    private void AddInteger(byte prefix, int prefixBits, int value)
    {
        int limit = (1 << prefixBits) - 1;

        if (value < limit)
        {
            _block.Add((byte)(prefix | value));

            return;
        }

        _block.Add((byte)(prefix | limit));
        value -= limit;

        while (value >= 0x80)
        {
            _block.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        _block.Add((byte)value);
    }

    private void AddString(string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value);

        AddInteger(prefix: 0x00, prefixBits: 7, bytes.Length);
        _block.AddRange(bytes);
    }
}
