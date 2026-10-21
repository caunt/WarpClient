namespace Warp.Quic;

/// <summary>
/// QUIC transport parameters (RFC 9000 section 18), exchanged in the TLS handshake to set each side's limits.
/// </summary>
internal sealed class TransportParameters
{
    private const ulong AckDelayExponentId = 0x0A;
    private const ulong ActiveConnectionIdLimitId = 0x0E;
    private const ulong InitialMaximumDataId = 0x04;
    private const ulong InitialMaximumStreamDataBidirectionalLocalId = 0x05;
    private const ulong InitialMaximumStreamDataBidirectionalRemoteId = 0x06;
    private const ulong InitialMaximumStreamDataUnidirectionalId = 0x07;
    private const ulong InitialMaximumStreamsBidirectionalId = 0x08;
    private const ulong InitialMaximumStreamsUnidirectionalId = 0x09;
    private const ulong InitialSourceConnectionIdId = 0x0F;
    private const ulong MaximumAckDelayId = 0x0B;
    private const ulong MaximumDatagramFrameSizeId = 0x20;
    private const ulong MaximumIdleTimeoutId = 0x01;
    private const ulong MaximumStreamCount = 1UL << 60;
    private const ulong MaximumUdpPayloadSizeId = 0x03;
    private const ulong OriginalDestinationConnectionIdId = 0x00;
    private const ulong RetrySourceConnectionIdId = 0x10;
    private const ulong StatelessResetTokenId = 0x02;
    private const int StatelessResetTokenLength = 16;

    public int AckDelayExponent { get; set; } = 3;

    public long ActiveConnectionIdLimit { get; set; } = 2;

    public long InitialMaximumData { get; set; }

    public long InitialMaximumStreamDataBidirectionalLocal { get; set; }

    public long InitialMaximumStreamDataBidirectionalRemote { get; set; }

    public long InitialMaximumStreamDataUnidirectional { get; set; }

    public long InitialMaximumStreamsBidirectional { get; set; }

    public long InitialMaximumStreamsUnidirectional { get; set; }

    public byte[]? InitialSourceConnectionId { get; set; }

    public long MaximumAckDelay { get; set; } = 25;

    public long MaximumDatagramFrameSize { get; set; }

    public long MaximumIdleTimeout { get; set; }

    public long MaximumUdpPayloadSize { get; set; } = 65527;

    public byte[]? OriginalDestinationConnectionId { get; set; }

    public byte[]? RetrySourceConnectionId { get; set; }

    public byte[]? StatelessResetToken { get; set; }

    public static TransportParameters Decode(ReadOnlyMemory<byte> encoded)
    {
        TransportParameters parameters = new();
        HashSet<ulong> seen = [];
        QuicReader reader = new(encoded);

        while (!reader.IsEnd)
        {
            ulong id = reader.ReadVariableLengthInteger();
            QuicReader value = new(reader.ReadBytes(reader.ReadLength()));

            if (!seen.Add(id))
                throw new QuicTransportException(QuicTransportException.TransportParameterError, message: "The server repeated a transport parameter.");

            parameters.Read(id, value);
        }

        parameters.Validate();

        return parameters;
    }

    public byte[] Encode()
    {
        QuicWriter writer = new();

        WriteInteger(writer, MaximumIdleTimeoutId, MaximumIdleTimeout);
        WriteInteger(writer, InitialMaximumDataId, InitialMaximumData);
        WriteInteger(writer, InitialMaximumStreamDataBidirectionalLocalId, InitialMaximumStreamDataBidirectionalLocal);
        WriteInteger(writer, InitialMaximumStreamDataBidirectionalRemoteId, InitialMaximumStreamDataBidirectionalRemote);
        WriteInteger(writer, InitialMaximumStreamDataUnidirectionalId, InitialMaximumStreamDataUnidirectional);
        WriteInteger(writer, InitialMaximumStreamsBidirectionalId, InitialMaximumStreamsBidirectional);
        WriteInteger(writer, InitialMaximumStreamsUnidirectionalId, InitialMaximumStreamsUnidirectional);

        if (MaximumDatagramFrameSize > 0)
            WriteInteger(writer, MaximumDatagramFrameSizeId, MaximumDatagramFrameSize);

        if (InitialSourceConnectionId is not null)
        {
            writer.WriteVariableLengthInteger(InitialSourceConnectionIdId);
            writer.WriteVariableLengthInteger((ulong)InitialSourceConnectionId.Length);
            writer.WriteBytes(InitialSourceConnectionId);
        }

        return writer.ToArray();
    }

    // The connection IDs both sides saw must match what the server authenticated in the handshake (RFC 9000 section 7.3).
    public bool MatchesConnectionIds(byte[] originalDestination, byte[]? serverSource, byte[]? retrySource)
    {
        bool originalMatches = OriginalDestinationConnectionId is not null && OriginalDestinationConnectionId.AsSpan().SequenceEqual(originalDestination);
        bool sourceMatches = InitialSourceConnectionId is not null && serverSource is not null && InitialSourceConnectionId.AsSpan().SequenceEqual(serverSource);
        bool retryMatches = retrySource is null ? RetrySourceConnectionId is null : RetrySourceConnectionId.AsSpan().SequenceEqual(retrySource);

        return originalMatches && sourceMatches && retryMatches;
    }

    private static long ReadInteger(QuicReader value)
    {
        long result = value.ReadVariableLengthLong();

        return value.IsEnd ? result : throw new QuicTransportException(QuicTransportException.TransportParameterError, message: "A transport parameter has trailing data.");
    }

    private static void WriteInteger(QuicWriter writer, ulong id, long value)
    {
        writer.WriteVariableLengthInteger(id);
        writer.WriteVariableLengthInteger((ulong)VariableLengthInteger.GetLength((ulong)value));
        writer.WriteVariableLengthInteger((ulong)value);
    }

    private void Read(ulong id, QuicReader value)
    {
        switch (id)
        {
            case OriginalDestinationConnectionIdId:
                {
                    OriginalDestinationConnectionId = value.ReadRemaining().ToArray();

                    break;
                }
            case MaximumIdleTimeoutId:
                {
                    MaximumIdleTimeout = ReadInteger(value);

                    break;
                }
            case StatelessResetTokenId:
                {
                    StatelessResetToken = value.ReadRemaining().ToArray();

                    break;
                }
            case MaximumUdpPayloadSizeId:
                {
                    MaximumUdpPayloadSize = ReadInteger(value);

                    break;
                }
            case InitialMaximumDataId:
                {
                    InitialMaximumData = ReadInteger(value);

                    break;
                }
            case InitialMaximumStreamDataBidirectionalLocalId:
                {
                    InitialMaximumStreamDataBidirectionalLocal = ReadInteger(value);

                    break;
                }
            case InitialMaximumStreamDataBidirectionalRemoteId:
                {
                    InitialMaximumStreamDataBidirectionalRemote = ReadInteger(value);

                    break;
                }
            case InitialMaximumStreamDataUnidirectionalId:
                {
                    InitialMaximumStreamDataUnidirectional = ReadInteger(value);

                    break;
                }
            case InitialMaximumStreamsBidirectionalId:
                {
                    InitialMaximumStreamsBidirectional = ReadInteger(value);

                    break;
                }
            case InitialMaximumStreamsUnidirectionalId:
                {
                    InitialMaximumStreamsUnidirectional = ReadInteger(value);

                    break;
                }
            case AckDelayExponentId:
                {
                    AckDelayExponent = (int)Math.Min(ReadInteger(value), val2: 64);

                    break;
                }
            case MaximumAckDelayId:
                {
                    MaximumAckDelay = ReadInteger(value);

                    break;
                }
            case ActiveConnectionIdLimitId:
                {
                    ActiveConnectionIdLimit = ReadInteger(value);

                    break;
                }
            case InitialSourceConnectionIdId:
                {
                    InitialSourceConnectionId = value.ReadRemaining().ToArray();

                    break;
                }
            case RetrySourceConnectionIdId:
                {
                    RetrySourceConnectionId = value.ReadRemaining().ToArray();

                    break;
                }
            case MaximumDatagramFrameSizeId:
                {
                    MaximumDatagramFrameSize = ReadInteger(value);

                    break;
                }
            default:
                // Unknown parameters, including preferred_address and reserved ones, are ignored (RFC 9000 section 7.4.2).
                break;
        }
    }

    private void Validate()
    {
        bool streamsInRange = (ulong)InitialMaximumStreamsBidirectional <= MaximumStreamCount && (ulong)InitialMaximumStreamsUnidirectional <= MaximumStreamCount;
        bool delaysInRange = AckDelayExponent <= 20 && MaximumAckDelay < (1 << 14);
        bool sizesInRange = MaximumUdpPayloadSize >= 1200 && ActiveConnectionIdLimit >= 2;
        bool tokenValid = StatelessResetToken is null || StatelessResetToken.Length == StatelessResetTokenLength;

        if (!streamsInRange || !delaysInRange || !sizesInRange || !tokenValid)
            throw new QuicTransportException(QuicTransportException.TransportParameterError, message: "The server sent an out-of-range transport parameter.");
    }
}
