using Warp.Quic.Buffers;
using Warp.Quic.Frames;
using Warp.Quic.Recovery;

namespace Warp.Quic;

/// <summary>
/// The streams of one connection with stream-count and connection-level flow control (RFC 9000 sections 2 to 4), and the
/// stream-related frames they need sent.
/// </summary>
internal sealed class StreamTable(QuicClientOptions options)
{
    private readonly Queue<QuicStreamState> _inbound = new();
    private readonly List<QuicStreamState> _sendOrder = [];
    private readonly Dictionary<long, QuicStreamState> _streams = [];
    private long _advertisedBidirectionalLimit = options.MaximumInboundBidirectionalStreams;
    private long _advertisedUnidirectionalLimit = options.MaximumInboundUnidirectionalStreams;
    private long _closedInboundBidirectional;
    private long _closedInboundUnidirectional;
    private long _consumedData;
    private long _inboundBidirectionalCount;
    private long _inboundUnidirectionalCount;
    private long _nextBidirectionalIndex;
    private long _nextUnidirectionalIndex;
    private TransportParameters? _peer;
    private long _receivedData;
    private int _sendCursor;
    private long _sentData;

    public bool HasInbound => _inbound.Count > 0;

    public bool MaximumDataPending { get; private set; }

    public bool MaximumStreamsBidirectionalPending { get; private set; }

    public bool MaximumStreamsUnidirectionalPending { get; private set; }

    public long PeerMaximumBidirectional { get; private set; }

    public long PeerMaximumData { get; private set; }

    public long PeerMaximumUnidirectional { get; private set; }

    public long ReceiveLimit { get; private set; } = options.ReceiveWindow;

    public void AbortRead(QuicStreamState stream, ulong errorCode)
    {
        if (stream.IsReceiveDone)
            return;

        stream.ReadAborted = true;
        stream.StopSendingCode = errorCode;
        stream.StopSendingPending = true;
        ReturnCredit(stream.Receive.HighestOffset - stream.Receive.ReadOffset);
    }

    public void ApplyPeerParameters(TransportParameters parameters)
    {
        _peer = parameters;
        PeerMaximumData = parameters.InitialMaximumData;
        PeerMaximumBidirectional = parameters.InitialMaximumStreamsBidirectional;
        PeerMaximumUnidirectional = parameters.InitialMaximumStreamsUnidirectional;
    }

    public void OnAcknowledged(SentFrame frame)
    {
        if (!_streams.TryGetValue(frame.StreamId, out QuicStreamState? stream))
            return;

        if (frame.Kind == SentFrameKind.Stream)
            stream.Send.OnAcknowledged(frame.Offset, frame.Length, frame.Fin);
        else if (frame.Kind == SentFrameKind.ResetStream)
            stream.ResetAcknowledged = true;

        TryRemove(stream);
    }

    public void OnLost(SentFrame frame)
    {
        switch (frame.Kind)
        {
            case SentFrameKind.MaximumData:
                {
                    MaximumDataPending = true;

                    break;
                }
            case SentFrameKind.MaximumStreamsBidirectional:
                {
                    MaximumStreamsBidirectionalPending = true;

                    break;
                }
            case SentFrameKind.MaximumStreamsUnidirectional:
                {
                    MaximumStreamsUnidirectionalPending = true;

                    break;
                }
            default:
                {
                    if (_streams.TryGetValue(frame.StreamId, out QuicStreamState? stream))
                        OnLost(stream, frame);

                    break;
                }
        }
    }

    public void OnMaximumData(long limit)
    {
        PeerMaximumData = Math.Max(PeerMaximumData, limit);
    }

    public void OnMaximumStreamData(long streamId, long limit)
    {
        QuicStreamState? stream = Find(streamId, forSending: true);

        stream?.SendLimit = Math.Max(stream.SendLimit, limit);
    }

    public void OnMaximumStreams(bool bidirectional, long limit)
    {
        if ((ulong)limit > 1UL << 60)
            throw new QuicTransportException(QuicTransportException.FrameEncodingError, message: "The server allowed an impossible number of streams.");

        if (bidirectional)
            PeerMaximumBidirectional = Math.Max(PeerMaximumBidirectional, limit);
        else
            PeerMaximumUnidirectional = Math.Max(PeerMaximumUnidirectional, limit);
    }

    public void OnResetStream(long streamId, ulong errorCode, long finalSize)
    {
        QuicStreamState? stream = Find(streamId, forSending: false);

        if (stream is null || stream.PeerResetCode is not null)
            return;

        CheckFinalSize(stream, finalSize, fin: true);
        long before = stream.Receive.HighestOffset;

        stream.FinalSize = finalSize;
        ObserveReceived(stream, finalSize);
        stream.PeerResetCode = errorCode;

        // The application will never read what is left, so its connection-level credit comes back now; an aborted read
        // already returned everything received before the reset.
        ReturnCredit(stream.ReadAborted ? stream.Receive.HighestOffset - before : finalSize - stream.Receive.ReadOffset);
        TryRemove(stream);
    }

    public void OnStopSending(long streamId, ulong errorCode)
    {
        QuicStreamState? stream = Find(streamId, forSending: true);

        if (stream is null)
            return;

        stream.PeerStopSendingCode = errorCode;
        stream.AbortWrite(errorCode);
    }

    public void OnStreamFrame(long streamId, long offset, ReadOnlySpan<byte> data, bool fin)
    {
        QuicStreamState? stream = Find(streamId, forSending: false);

        if (stream is null)
            return;

        long end = offset + data.Length;

        if (end > stream.ReceiveLimit)
            throw new QuicTransportException(QuicTransportException.FlowControlError, message: "The server overran a stream's flow-control limit.");

        CheckFinalSize(stream, end, fin);

        if (fin)
            stream.FinalSize = end;

        long before = stream.Receive.HighestOffset;

        if (stream.ReadAborted || stream.PeerResetCode is not null)
        {
            // Nobody will read this data, so it is counted and its credit returned without buffering it.
            ObserveReceived(stream, end);
            ReturnCredit(stream.Receive.HighestOffset - before);

            return;
        }

        stream.Receive.Insert(offset, data);
        AccountReceived(stream, before);
    }

    public void Release(QuicStreamState stream)
    {
        stream.IsReleased = true;
        TryRemove(stream);
    }

    public QuicStreamState? TryAccept()
    {
        return _inbound.TryDequeue(out QuicStreamState? stream) ? stream : null;
    }

    public QuicStreamState? TryOpen(bool bidirectional)
    {
        long index = bidirectional ? _nextBidirectionalIndex : _nextUnidirectionalIndex;
        long limit = bidirectional ? PeerMaximumBidirectional : PeerMaximumUnidirectional;

        if (_peer is null || index >= limit)
            return null;

        long id = (index << 2) | (bidirectional ? 0L : 2L);
        long sendLimit = bidirectional ? _peer.InitialMaximumStreamDataBidirectionalRemote : _peer.InitialMaximumStreamDataUnidirectional;
        QuicStreamState stream = new(id, sendLimit, options.StreamReceiveWindow);

        if (bidirectional)
            _nextBidirectionalIndex++;
        else
            _nextUnidirectionalIndex++;

        Add(stream);

        return stream;
    }

    /// <summary>
    /// Handles a stream or flow-control frame, or returns <see langword="false"/> for any other frame type.
    /// </summary>
    public bool TryProcessFrame(QuicReader reader, ulong type)
    {
        switch (type)
        {
            case FrameType.ResetStream:
                {
                    long streamId = reader.ReadVariableLengthLong();
                    ulong errorCode = reader.ReadVariableLengthInteger();

                    OnResetStream(streamId, errorCode, reader.ReadVariableLengthLong());

                    return true;
                }
            case FrameType.StopSending:
                {
                    long streamId = reader.ReadVariableLengthLong();

                    OnStopSending(streamId, reader.ReadVariableLengthInteger());

                    return true;
                }
            case >= FrameType.Stream and <= FrameType.StreamTypeLast:
                {
                    long streamId = reader.ReadVariableLengthLong();
                    long offset = (type & FrameType.StreamOffset) != 0 ? reader.ReadVariableLengthLong() : 0;
                    int length = (type & FrameType.StreamLength) != 0 ? reader.ReadLength() : reader.Remaining;
                    ReadOnlyMemory<byte> data = reader.ReadBytes(length);

                    if (offset + length >= 1L << 62)
                        throw new QuicTransportException(QuicTransportException.FrameEncodingError, message: "The server sent stream data beyond the largest offset.");

                    OnStreamFrame(streamId, offset, data.Span, (type & FrameType.StreamFin) != 0);

                    return true;
                }
            case FrameType.MaximumData:
                {
                    OnMaximumData(reader.ReadVariableLengthLong());

                    return true;
                }
            case FrameType.MaximumStreamData:
                {
                    long streamId = reader.ReadVariableLengthLong();

                    OnMaximumStreamData(streamId, reader.ReadVariableLengthLong());

                    return true;
                }
            case FrameType.MaximumStreamsBidirectional or FrameType.MaximumStreamsUnidirectional:
                {
                    OnMaximumStreams(type == FrameType.MaximumStreamsBidirectional, reader.ReadVariableLengthLong());

                    return true;
                }
            case FrameType.DataBlocked or FrameType.StreamsBlockedBidirectional or FrameType.StreamsBlockedUnidirectional:
                {
                    reader.SkipVariableLengthInteger();

                    return true;
                }
            case FrameType.StreamDataBlocked:
                {
                    reader.SkipVariableLengthInteger();
                    reader.SkipVariableLengthInteger();

                    return true;
                }
            default:
                return false;
        }
    }

    public bool TryRead(QuicStreamState stream, Span<byte> destination, out int read)
    {
        if (stream.PeerResetCode is ulong code)
            throw new QuicTransportException(code, $"The server reset stream {stream.Id} with error 0x{code:X}.", isApplicationError: true);

        if (stream.ReadAborted)
            throw new InvalidOperationException(message: "Reading from this stream was aborted.");

        read = stream.Receive.Read(destination);

        if (read == 0)
            return stream.IsReadComplete;

        ReturnCredit(read);

        bool windowLow = stream.FinalSize is null && stream.ReceiveLimit - stream.Receive.ReadOffset < stream.ReceiveWindow / 2;

        if (windowLow)
        {
            stream.ReceiveLimit = stream.Receive.ReadOffset + stream.ReceiveWindow;
            stream.MaximumStreamDataPending = true;
        }

        if (stream.IsReadComplete)
            TryRemove(stream);

        return true;
    }

    public void WriteControlFrames(QuicWriter writer, int limit, List<SentFrame> frames)
    {
        const int maximumControlFrameLength = 1 + 8 + 8 + 8;

        if (MaximumDataPending && writer.Length + maximumControlFrameLength <= limit)
        {
            FrameWriter.WriteInteger(writer, FrameType.MaximumData, ReceiveLimit);
            frames.Add(new SentFrame(SentFrameKind.MaximumData, StreamId: -1, Offset: 0, Length: 0, Fin: false));
            MaximumDataPending = false;
        }

        if (MaximumStreamsBidirectionalPending && writer.Length + maximumControlFrameLength <= limit)
        {
            FrameWriter.WriteInteger(writer, FrameType.MaximumStreamsBidirectional, _advertisedBidirectionalLimit);
            frames.Add(new SentFrame(SentFrameKind.MaximumStreamsBidirectional, StreamId: -1, Offset: 0, Length: 0, Fin: false));
            MaximumStreamsBidirectionalPending = false;
        }

        if (MaximumStreamsUnidirectionalPending && writer.Length + maximumControlFrameLength <= limit)
        {
            FrameWriter.WriteInteger(writer, FrameType.MaximumStreamsUnidirectional, _advertisedUnidirectionalLimit);
            frames.Add(new SentFrame(SentFrameKind.MaximumStreamsUnidirectional, StreamId: -1, Offset: 0, Length: 0, Fin: false));
            MaximumStreamsUnidirectionalPending = false;
        }

        foreach (QuicStreamState stream in _streams.Values)
        {
            if (writer.Length + maximumControlFrameLength > limit)
                return;

            WriteControlFrames(writer, stream, frames);
        }
    }

    public void WriteStreamData(QuicWriter writer, int limit, List<SentFrame> frames)
    {
        int count = _sendOrder.Count;

        for (int visited = 0; visited < count; visited++)
        {
            int room = limit - writer.Length - FrameWriter.MaximumStreamOverhead;

            if (room <= 0)
                break;

            QuicStreamState stream = _sendOrder[(_sendCursor + visited) % count];

            if (!stream.HasPendingSend)
                continue;

            long connectionCredit = Math.Max(val1: 0, PeerMaximumData - _sentData);
            long sendLimit = Math.Min(stream.SendLimit, stream.Send.NextOffset + connectionCredit);
            SendChunk? chunk = stream.Send.TakeChunk(room, sendLimit);

            if (chunk is null)
                continue;

            if (chunk.IsNewData)
                _sentData += chunk.Data.Length;

            FrameWriter.WriteStream(writer, stream.Id, chunk.Offset, chunk.Data, chunk.Fin);
            frames.Add(new SentFrame(SentFrameKind.Stream, stream.Id, chunk.Offset, chunk.Data.Length, chunk.Fin));
        }

        // Rotating the starting stream shares the connection fairly between busy streams.
        _sendCursor = count == 0 ? 0 : (_sendCursor + 1) % count;
    }

    private static void CheckFinalSize(QuicStreamState stream, long end, bool fin)
    {
        bool beyondFinal = stream.FinalSize is long finalSize && (end > finalSize || (fin && end != finalSize));
        bool belowReceived = fin && end < stream.Receive.HighestOffset;

        if (beyondFinal || belowReceived)
            throw new QuicTransportException(QuicTransportException.FinalSizeError, message: "The server changed a stream's final size.");
    }

    private static void OnLost(QuicStreamState stream, SentFrame frame)
    {
        switch (frame.Kind)
        {
            case SentFrameKind.Stream when stream.ResetCode is null:
                {
                    stream.Send.OnLost(frame.Offset, frame.Length, frame.Fin);

                    break;
                }
            case SentFrameKind.MaximumStreamData when !stream.IsReceiveDone:
                {
                    stream.MaximumStreamDataPending = true;

                    break;
                }
            case SentFrameKind.StopSending when stream.PeerResetCode is null && !stream.IsReadComplete:
                {
                    stream.StopSendingPending = true;

                    break;
                }
            case SentFrameKind.ResetStream when !stream.ResetAcknowledged:
                {
                    stream.ResetPending = true;

                    break;
                }
            default:
                break;
        }
    }

    private static void WriteControlFrames(QuicWriter writer, QuicStreamState stream, List<SentFrame> frames)
    {
        if (stream.ResetPending && stream.ResetCode is ulong resetCode)
        {
            FrameWriter.WriteResetStream(writer, stream.Id, resetCode, stream.Send.NextOffset);
            frames.Add(new SentFrame(SentFrameKind.ResetStream, stream.Id, Offset: 0, Length: 0, Fin: false));
            stream.ResetPending = false;
        }
        else if (stream.StopSendingPending)
        {
            FrameWriter.WriteStopSending(writer, stream.Id, stream.StopSendingCode);
            frames.Add(new SentFrame(SentFrameKind.StopSending, stream.Id, Offset: 0, Length: 0, Fin: false));
            stream.StopSendingPending = false;
        }
        else if (stream.MaximumStreamDataPending)
        {
            FrameWriter.WriteMaximumStreamData(writer, stream.Id, stream.ReceiveLimit);
            frames.Add(new SentFrame(SentFrameKind.MaximumStreamData, stream.Id, Offset: 0, Length: 0, Fin: false));
            stream.MaximumStreamDataPending = false;
        }
    }

    private void AccountReceived(QuicStreamState stream, long before)
    {
        _receivedData += stream.Receive.HighestOffset - before;

        if (_receivedData > ReceiveLimit)
            throw new QuicTransportException(QuicTransportException.FlowControlError, $"The server overran the connection's flow-control limit on stream {stream.Id}.");
    }

    private void Add(QuicStreamState stream)
    {
        _streams.Add(stream.Id, stream);

        if (stream.CanSend)
            _sendOrder.Add(stream);
    }

    // Returns the stream a frame refers to, opening peer streams implicitly, or null for a stream that is already gone.
    private QuicStreamState? Find(long streamId, bool forSending)
    {
        if (_streams.TryGetValue(streamId, out QuicStreamState? existing))
        {
            bool allowed = forSending ? existing.CanSend : existing.CanReceive;

            return allowed ? existing : throw new QuicTransportException(QuicTransportException.StreamStateError, message: "The server used a stream in a direction it does not have.");
        }

        bool local = (streamId & 0x1) == 0;
        bool bidirectional = (streamId & 0x2) == 0;
        long index = streamId >> 2;

        if (local)
        {
            long opened = bidirectional ? _nextBidirectionalIndex : _nextUnidirectionalIndex;

            return index < opened ? null : throw new QuicTransportException(QuicTransportException.StreamStateError, message: "The server used a stream this client never opened.");
        }

        return !bidirectional && forSending
            ? throw new QuicTransportException(QuicTransportException.StreamStateError, message: "The server asked about sending on its own unidirectional stream.")
            : OpenInbound(bidirectional, index, streamId);
    }

    private void ObserveReceived(QuicStreamState stream, long end)
    {
        long before = stream.Receive.HighestOffset;

        stream.Receive.Observe(end);
        AccountReceived(stream, before);
    }

    private QuicStreamState? OpenInbound(bool bidirectional, long index, long streamId)
    {
        long count = bidirectional ? _inboundBidirectionalCount : _inboundUnidirectionalCount;
        long limit = bidirectional ? _advertisedBidirectionalLimit : _advertisedUnidirectionalLimit;

        if (index < count)
            return null;

        if (index >= limit || _peer is null)
            throw new QuicTransportException(QuicTransportException.StreamLimitError, message: "The server opened more streams than allowed.");

        long sendLimit = bidirectional ? _peer.InitialMaximumStreamDataBidirectionalLocal : 0;

        for (long next = count; next <= index; next++)
        {
            QuicStreamState stream = new((next << 2) | (bidirectional ? 1L : 3L), sendLimit, options.StreamReceiveWindow);

            Add(stream);
            _inbound.Enqueue(stream);
        }

        if (bidirectional)
            _inboundBidirectionalCount = index + 1;
        else
            _inboundUnidirectionalCount = index + 1;

        return _streams[streamId];
    }

    private void ReturnCredit(long length)
    {
        _consumedData += Math.Max(val1: 0, length);

        if (ReceiveLimit - _consumedData >= options.ReceiveWindow / 2)
            return;

        ReceiveLimit = _consumedData + options.ReceiveWindow;
        MaximumDataPending = true;
    }

    private void TryRemove(QuicStreamState stream)
    {
        if (!stream.IsReleased || !stream.IsSendDone || !stream.IsReceiveDone || !_streams.Remove(stream.Id))
            return;

        int position = _sendOrder.IndexOf(stream);

        if (position >= 0)
            _sendOrder.RemoveAt(position);

        if (stream.IsLocal)
            return;

        // Each closed peer stream lets the server open another one; credit is returned in batches.
        if (stream.IsBidirectional)
        {
            _closedInboundBidirectional++;

            long limit = _closedInboundBidirectional + options.MaximumInboundBidirectionalStreams;

            if (limit - _advertisedBidirectionalLimit >= Math.Max(val1: 1, options.MaximumInboundBidirectionalStreams / 2))
            {
                _advertisedBidirectionalLimit = limit;
                MaximumStreamsBidirectionalPending = true;
            }
        }
        else
        {
            _closedInboundUnidirectional++;

            long limit = _closedInboundUnidirectional + options.MaximumInboundUnidirectionalStreams;

            if (limit - _advertisedUnidirectionalLimit >= Math.Max(val1: 1, options.MaximumInboundUnidirectionalStreams / 2))
            {
                _advertisedUnidirectionalLimit = limit;
                MaximumStreamsUnidirectionalPending = true;
            }
        }
    }
}
