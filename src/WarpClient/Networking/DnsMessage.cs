using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Text;

namespace Warp.Networking;

internal static class DnsMessage
{
    private const ushort AddressRecordType = 1;
    private const byte CompressionMarker = 0xC0;
    private const int HeaderLength = 12;
    private const ushort InternetClass = 1;
    private const int MaximumLabelLength = 63;
    private const ushort RecursionDesired = 0x0100;
    private const ushort ResponseCodeMask = 0x000F;
    private const ushort ResponseFlag = 0x8000;

    public static byte[] CreateQuery(ushort identifier, string hostName)
    {
        string[] labels = new IdnMapping().GetAscii(hostName.TrimEnd(trimChar: '.')).Split(separator: '.');
        int nameLength = labels.Sum(static label => label.Length + 1) + 1;
        byte[] message = new byte[HeaderLength + nameLength + 4];
        int offset = HeaderLength;

        BinaryPrimitives.WriteUInt16BigEndian(message, identifier);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(start: 2), RecursionDesired);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(start: 4), value: 1);

        foreach (string label in labels)
        {
            if (label.Length is 0 or > MaximumLabelLength)
                throw new ArgumentException(message: "The host name is not a valid DNS name.", nameof(hostName));

            message[offset] = (byte)label.Length;
            offset += Encoding.ASCII.GetBytes(label, message.AsSpan(offset + 1)) + 1;
        }

        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(offset + 1), AddressRecordType);
        BinaryPrimitives.WriteUInt16BigEndian(message.AsSpan(offset + 3), InternetClass);

        return message;
    }

    public static bool TryReadFirstAddress(ReadOnlySpan<byte> message, ushort identifier, [NotNullWhen(returnValue: true)] out IPAddress? address)
    {
        address = null;

        if (message.Length < HeaderLength || BinaryPrimitives.ReadUInt16BigEndian(message) != identifier)
            return false;

        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);

        if ((flags & ResponseFlag) == 0 || (flags & ResponseCodeMask) != 0)
            return false;

        int questions = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
        int answers = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
        int offset = HeaderLength;

        for (int index = 0; index < questions; index++)
        {
            int end = SkipName(message, offset);

            if (end < 0)
                return false;

            offset = end + 4;
        }

        for (int index = 0; index < answers; index++)
        {
            int end = SkipName(message, offset);

            if (end < 0 || end + 10 > message.Length)
                return false;

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(message[end..]);
            int dataLength = BinaryPrimitives.ReadUInt16BigEndian(message[(end + 8)..]);
            int dataOffset = end + 10;

            if (dataOffset + dataLength > message.Length)
                return false;

            if (type == AddressRecordType && dataLength == 4)
            {
                address = new IPAddress(message.Slice(dataOffset, length: 4));

                return true;
            }

            offset = dataOffset + dataLength;
        }

        return false;
    }

    private static int SkipName(ReadOnlySpan<byte> message, int offset)
    {
        while (offset < message.Length)
        {
            byte length = message[offset];

            if ((length & CompressionMarker) == CompressionMarker)
                return offset + 2 <= message.Length ? offset + 2 : -1;

            if (length == 0)
                return offset + 1;

            offset += length + 1;
        }

        return -1;
    }
}
