using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

using Warp.Quic.Buffers;
using Warp.Quic.Crypto;
using Warp.Quic.Frames;
using Warp.Quic.Packets;
using Warp.Quic.Recovery;
using Warp.Quic.Tls;

namespace Warp.Quic;

/// <summary>
/// A QUIC v1 client connection (RFC 9000, 9001, 9002, 9221) as a state machine without I/O: datagrams and timer expiries go
/// in, datagrams to send come out. Callers serialize access.
/// </summary>
internal sealed class QuicConnectionCore : ISentFrameHandler
{
    private const int CryptoFrameOverhead = 1 + 8 + 2;
    private const int DatagramFrameOverhead = 1 + 2;
    private const int ImmediateAckThreshold = 2;
    private const int InitialConnectionIdLength = 8;
    private const int LocalAckDelayExponent = 3;
    private const long LocalMaximumAckDelay = 25;
    private const int MaximumAckRanges = 32;
    private const int MaximumBurst = 64;
    private const int MaximumConnectionIdLength = 20;
    private const int MaximumCryptoBuffer = 64 * 1024;
    private const int MinimumInitialDatagramSize = 1200;
    private const int MinimumPacketRoom = 64;
    private const int PathDataLength = 8;

    private readonly byte[] _clientHello;
    private readonly ConnectionIdManager _connectionIds;
    private readonly DatagramQueue _datagrams;
    private readonly KeyPhase _keyPhase = new();
    private readonly LossDetector _lossDetector;
    private readonly QuicClientOptions _options;
    private readonly byte[] _originalDestinationConnectionId;
    private readonly Queue<byte[]> _pathResponses = new();
    private readonly RecoveryState _recovery;
    private readonly byte[] _sourceConnectionId;
    private readonly PacketNumberSpace[] _spaces = [new(EncryptionLevel.Initial), new(EncryptionLevel.Handshake), new(EncryptionLevel.Application)];
    private readonly StreamTable _streams;
    private readonly TlsClientHandshake _tls;
    private CloseRequest? _closePending;
    private bool _handshakeConfirmed;
    private long _idleDeadline;
    private long _idleTimeout;
    private long _keepAliveDeadline = long.MaxValue;
    private int _maximumDatagramSize;
    private TransportParameters? _peer;
    private bool _receivedServerPacket;
    private byte[]? _retrySourceConnectionId;
    private byte[]? _serverSourceConnectionId;
    private byte[] _token = [];

    public QuicConnectionCore(QuicClientOptions options, long now)
    {
        _options = options;
        _maximumDatagramSize = Math.Max(options.MaximumDatagramSize, MinimumInitialDatagramSize);
        _recovery = new RecoveryState(_maximumDatagramSize);
        _lossDetector = new LossDetector(_recovery, _spaces, this);
        _streams = new StreamTable(options);
        _sourceConnectionId = RandomNumberGenerator.GetBytes(Math.Clamp(options.ConnectionIdLength, min: 0, MaximumConnectionIdLength));
        _originalDestinationConnectionId = RandomNumberGenerator.GetBytes(Math.Clamp(options.ConnectionIdLength, InitialConnectionIdLength, MaximumConnectionIdLength));
        _connectionIds = new ConnectionIdManager(_originalDestinationConnectionId);
        _datagrams = new DatagramQueue(options.DatagramReceiveQueueLength);
        _idleTimeout = (long)options.IdleTimeout.TotalMilliseconds;
        _idleDeadline = GetIdleDeadline(now);

        TransportParameters local = new()
        {
            MaximumIdleTimeout = _idleTimeout,
            InitialMaximumData = options.ReceiveWindow,
            InitialMaximumStreamDataBidirectionalLocal = options.StreamReceiveWindow,
            InitialMaximumStreamDataBidirectionalRemote = options.StreamReceiveWindow,
            InitialMaximumStreamDataUnidirectional = options.StreamReceiveWindow,
            InitialMaximumStreamsBidirectional = options.MaximumInboundBidirectionalStreams,
            InitialMaximumStreamsUnidirectional = options.MaximumInboundUnidirectionalStreams,
            MaximumDatagramFrameSize = options.DatagramsEnabled ? ushort.MaxValue : 0,
            InitialSourceConnectionId = _sourceConnectionId,
        };

        _tls = new TlsClientHandshake(options.ServerName, options.ApplicationProtocol, local.Encode(), options.PinnedPublicKey, options.Credential);
        _clientHello = _tls.CreateClientHello();

        PacketNumberSpace initial = _spaces[(int)EncryptionLevel.Initial];

        initial.SendKeys = PacketKeys.CreateInitial(_originalDestinationConnectionId, label: "client in");
        initial.ReceiveKeys = PacketKeys.CreateInitial(_originalDestinationConnectionId, label: "server in");
        initial.CryptoSend.Write(_clientHello);
    }

    public long DroppedDatagrams { get; private set; }

    public Exception? Failure { get; private set; }

    public bool IsClosed => Failure is not null;

    public bool IsHandshakeComplete { get; private set; }

    public int MaximumDatagramPayloadSize
    {
        get
        {
            long peerLimit = _peer?.MaximumDatagramFrameSize ?? 0;
            int packetRoom = _maximumDatagramSize - GetHeaderLength(EncryptionLevel.Application) - PacketKeys.TagLength - DatagramFrameOverhead;

            return (int)Math.Max(val1: 0, Math.Min(packetRoom, peerLimit - DatagramFrameOverhead));
        }
    }

    public long NextDeadline
    {
        get
        {
            if (IsClosed)
                return long.MaxValue;

            long deadline = Math.Min(_idleDeadline, _keepAliveDeadline);

            foreach (PacketNumberSpace space in _spaces)
            {
                if (space.AckPending && !space.IsDiscarded)
                    deadline = Math.Min(deadline, space.AckDeadline);
            }

            return Math.Min(deadline, _lossDetector.GetDeadline(IsHandshakeComplete, _handshakeConfirmed, PeerMaximumAckDelay));
        }
    }

    private long PeerMaximumAckDelay => _peer?.MaximumAckDelay ?? 0;

    // Ends the connection without telling the server, for when the path under it has failed.
    public void Abort(Exception reason)
    {
        if (!IsClosed)
            Failure = reason;
    }

    public void AbortRead(QuicStreamState stream, ulong errorCode)
    {
        _streams.AbortRead(stream, errorCode);
    }

    public void Close(ulong errorCode, bool application, string reason)
    {
        if (IsClosed)
            return;

        _closePending = new CloseRequest(errorCode, application, reason);
        Failure = new QuicTransportException(errorCode, message: "The QUIC connection was closed locally.", application);
    }

    public Exception CreateClosedException()
    {
        return Failure switch
        {
            AuthenticationException authentication => new AuthenticationException(authentication.Message, authentication),
            QuicTransportException transport => new QuicTransportException(transport.ErrorCode, transport.Message, transport.IsApplicationError),
            Exception other => new IOException(other.Message, other),
            null => new InvalidOperationException(message: "The QUIC connection is still open."),
        };
    }

    public List<byte[]> CreateDatagrams(long now)
    {
        List<byte[]> datagrams = [];

        if (_closePending is CloseRequest close)
        {
            _closePending = null;

            byte[]? closing = CreateCloseDatagram(close, now);

            if (closing is not null)
                datagrams.Add(closing);

            return datagrams;
        }

        while (!IsClosed && datagrams.Count < MaximumBurst)
        {
            byte[]? datagram = CreateDatagram(now);

            if (datagram is null)
                break;

            datagrams.Add(datagram);
        }

        return datagrams;
    }

    public bool HasSendCapacity(QuicStreamState stream)
    {
        return stream.Send.BufferedLength < _options.StreamSendBufferLength;
    }

    public void OnAcknowledged(PacketNumberSpace space, SentFrame frame)
    {
        if (frame.Kind == SentFrameKind.Crypto)
            space.CryptoSend.OnAcknowledged(frame.Offset, frame.Length, fin: false);
        else if (frame.Kind != SentFrameKind.RetireConnectionId)
            _streams.OnAcknowledged(frame);
    }

    public void OnLost(PacketNumberSpace space, SentFrame frame)
    {
        if (frame.Kind == SentFrameKind.Crypto)
            space.CryptoSend.OnLost(frame.Offset, frame.Length, fin: false);
        else if (frame.Kind == SentFrameKind.RetireConnectionId)
            _connectionIds.OnRetireLost(frame.StreamId);
        else
            _streams.OnLost(frame);
    }

    public void OnTimeout(long now)
    {
        if (IsClosed)
            return;

        if (now >= _idleDeadline)
        {
            Failure = new QuicTransportException(message: "The QUIC connection timed out because the server stopped responding.");

            return;
        }

        _lossDetector.OnTimeout(now, IsHandshakeComplete, _handshakeConfirmed, PeerMaximumAckDelay);

        if (now >= _keepAliveDeadline && _options.KeepAliveInterval is TimeSpan interval)
        {
            _spaces[(int)EncryptionLevel.Application].PingPending = true;
            _keepAliveDeadline = now + (long)interval.TotalMilliseconds;
        }
    }

    public void ReceiveDatagram(ReadOnlySpan<byte> datagram, long now)
    {
        try
        {
            int offset = 0;

            while (offset < datagram.Length && !IsClosed)
            {
                int consumed = ReceivePacket(datagram[offset..], now);

                if (consumed <= 0)
                    break;

                offset += consumed;
            }
        }
        catch (QuicTransportException exception)
        {
            Fail(exception, exception.ErrorCode);
        }
        catch (AuthenticationException exception)
        {
            // A failed server authentication is reported as the TLS bad_certificate alert.
            Fail(exception, QuicTransportException.CryptoErrorBase + 42);
        }
        catch (InvalidDataException)
        {
            // A header that cannot be parsed was never authenticated, so the rest of the datagram is dropped quietly.
            DroppedDatagrams++;
        }
    }

    public void Release(QuicStreamState stream)
    {
        _streams.Release(stream);
    }

    public void SendDatagram(ReadOnlySpan<byte> datagram)
    {
        ThrowIfClosed();

        if (datagram.Length > MaximumDatagramPayloadSize)
            throw new ArgumentException(message: "The datagram does not fit in one QUIC packet.", nameof(datagram));

        _datagrams.Enqueue(datagram);
    }

    public void ThrowIfClosed()
    {
        if (IsClosed)
            throw CreateClosedException();
    }

    public QuicStreamState? TryAcceptStream()
    {
        ThrowIfClosed();

        return _streams.TryAccept();
    }

    public QuicStreamState? TryOpenStream(bool bidirectional)
    {
        ThrowIfClosed();

        return IsHandshakeComplete ? _streams.TryOpen(bidirectional) : null;
    }

    public bool TryRead(QuicStreamState stream, Span<byte> destination, out int read)
    {
        if (_streams.TryRead(stream, destination, out read))
            return true;

        ThrowIfClosed();

        return false;
    }

    public byte[]? TryReceiveDatagram()
    {
        byte[]? datagram = _datagrams.TryReceive();

        if (datagram is null)
            ThrowIfClosed();

        return datagram;
    }

    public void Write(QuicStreamState stream, ReadOnlySpan<byte> data)
    {
        ThrowIfClosed();
        stream.Write(data);
    }

    private static bool AllowedBeforeApplication(ulong type)
    {
        return type is FrameType.Padding or FrameType.Ping or FrameType.Ack or FrameType.AckWithCounts or FrameType.Crypto or FrameType.ConnectionClose;
    }

    private static byte[] EncodeAck(PacketNumberSpace space, long now)
    {
        QuicWriter writer = new();
        long delay = space.Level == EncryptionLevel.Application ? (Math.Max(val1: 0, now - space.LargestReceivedAt) * 1000) >> LocalAckDelayExponent : 0;

        FrameWriter.WriteAck(writer, space.Received, delay);

        return writer.ToArray();
    }

    private static void WriteCrypto(PacketNumberSpace space, QuicWriter payload, int limit, List<SentFrame> frames)
    {
        while (space.CryptoSend.HasPendingData)
        {
            int room = limit - payload.Length - CryptoFrameOverhead;
            SendChunk? chunk = space.CryptoSend.TakeChunk(room, long.MaxValue);

            if (chunk is null)
                return;

            FrameWriter.WriteCrypto(payload, chunk.Offset, chunk.Data);
            frames.Add(new SentFrame(SentFrameKind.Crypto, StreamId: -1, chunk.Offset, chunk.Data.Length, Fin: false));
        }
    }

    private void ApplyPeerTransportParameters()
    {
        byte[] encoded = _tls.PeerTransportParameters ?? throw new QuicTransportException(QuicTransportException.TransportParameterError, message: "The server sent no transport parameters.");
        TransportParameters peer = TransportParameters.Decode(encoded);

        if (!peer.MatchesConnectionIds(_originalDestinationConnectionId, _serverSourceConnectionId, _retrySourceConnectionId))
        {
            throw new QuicTransportException(
                QuicTransportException.TransportParameterError,
                message: "The server's transport parameters do not match the connection IDs in use."
            );
        }

        _peer = peer;
        _streams.ApplyPeerParameters(peer);
        _maximumDatagramSize = (int)Math.Min(_maximumDatagramSize, peer.MaximumUdpPayloadSize);

        if (peer.MaximumIdleTimeout > 0)
            _idleTimeout = _idleTimeout > 0 ? Math.Min(_idleTimeout, peer.MaximumIdleTimeout) : peer.MaximumIdleTimeout;

        if (peer.StatelessResetToken is byte[] token)
            _connectionIds.AddResetToken(token);
    }

    private void ApplyTlsProgress(TlsProgress progress, long now)
    {
        if (progress.HandshakeSecrets is TrafficSecrets handshake)
        {
            PacketNumberSpace space = _spaces[(int)EncryptionLevel.Handshake];

            space.SendKeys = PacketKeys.FromSecret(handshake.Client);
            space.ReceiveKeys = PacketKeys.FromSecret(handshake.Server);
        }

        if (progress.ApplicationSecrets is TrafficSecrets application)
        {
            PacketNumberSpace space = _spaces[(int)EncryptionLevel.Application];

            space.SendKeys = PacketKeys.FromSecret(application.Client);
            space.ReceiveKeys = PacketKeys.FromSecret(application.Server);
        }

        if (progress.HandshakeData.Length > 0)
            _spaces[(int)EncryptionLevel.Handshake].CryptoSend.Write(progress.HandshakeData);

        if (!progress.Completed)
            return;

        ApplyPeerTransportParameters();
        IsHandshakeComplete = true;

        if (_options.KeepAliveInterval is TimeSpan interval)
            _keepAliveDeadline = now + (long)interval.TotalMilliseconds;
    }

    private byte[] BuildHeader(EncryptionLevel level, long packetNumber, int payloadLength)
    {
        QuicWriter writer = new();

        if (level == EncryptionLevel.Application)
        {
            writer.WriteByte((byte)(0x40 | (_keyPhase.SendPhase ? 0x04 : 0) | (PacketProtection.PacketNumberLength - 1)));
            writer.WriteBytes(_connectionIds.Destination);
        }
        else
        {
            int type = level == EncryptionLevel.Initial ? LongHeader.InitialType : LongHeader.HandshakeType;
            int remaining = PacketProtection.PacketNumberLength + payloadLength + PacketKeys.TagLength;

            LongHeader.Write(writer, type, _connectionIds.Destination, _sourceConnectionId, _token, remaining, PacketProtection.PacketNumberLength);
        }

        writer.WriteUInt32((uint)packetNumber);

        return writer.ToArray();
    }

    private PacketDraft? BuildPayload(PacketNumberSpace space, int limit, long now)
    {
        PacketKeys keys = space.SendKeys ?? throw new InvalidOperationException(message: "The packet number space has no keys.");
        QuicWriter payload = new();
        List<SentFrame> frames = [];
        bool probing = space.ProbesPending > 0;
        byte[]? ack = space.AckPending ? EncodeAck(space, now) : null;
        bool ackDue = ack is not null && space.AckDeadline <= now;
        int frameLimit = limit - (ack?.Length ?? 0);
        bool application = space.Level == EncryptionLevel.Application;

        if (probing || _recovery.CanSend)
        {
            if (application)
                WriteApplicationControl(payload, frameLimit, frames);

            WriteCrypto(space, payload, frameLimit, frames);

            if (application && IsHandshakeComplete)
            {
                ackDue |= _datagrams.Write(payload, frameLimit, limit);
                _streams.WriteStreamData(payload, frameLimit, frames);
            }

            if (space.PingPending || (probing && payload.Length == 0))
            {
                payload.WriteVariableLengthInteger(FrameType.Ping);
                space.PingPending = false;
            }
        }

        bool ackEliciting = payload.Length > 0;

        if (!ackEliciting && (!ackDue || ack is null))
            return null;

        if (ack is not null)
        {
            payload.WriteBytes(ack);
            space.AckPending = false;
            space.AckDeadline = long.MaxValue;
            space.AckElicitingSinceAck = 0;
        }

        if (ackEliciting && probing)
            space.ProbesPending--;

        long packetNumber = space.NextPacketNumber;

        space.NextPacketNumber++;

        return new PacketDraft(space, keys, packetNumber, payload, frames, ackEliciting);
    }

    private void CheckStatelessReset(ReadOnlySpan<byte> datagram)
    {
        if (_connectionIds.IsStatelessReset(datagram))
            Failure = new QuicTransportException(message: "The server reset the QUIC connection because it lost its state.");
    }

    private byte[]? CreateCloseDatagram(CloseRequest close, long now)
    {
        List<PacketDraft> drafts = [];

        foreach (PacketNumberSpace space in _spaces)
        {
            bool usable = space.CanSend && (IsHandshakeComplete ? space.Level == EncryptionLevel.Application : space.Level != EncryptionLevel.Application);

            if (!usable || space.SendKeys is not PacketKeys keys)
                continue;

            // Application errors are hidden before the handshake completes, since the peer is not yet authenticated.
            CloseRequest request = space.Level == EncryptionLevel.Application || !close.Application
                ? close
                : new CloseRequest(QuicTransportException.ApplicationError, Application: false, string.Empty);

            QuicWriter payload = new();

            // Outstanding acknowledgments go first, so the server learns its last data arrived before it stops.
            if (space.AckPending)
                payload.WriteBytes(EncodeAck(space, now));

            FrameWriter.WriteConnectionClose(payload, request);
            drafts.Add(new PacketDraft(space, keys, space.NextPacketNumber, payload, [], AckEliciting: false));
            space.NextPacketNumber++;
        }

        return drafts.Count == 0 ? null : SealDatagram(drafts, now);
    }

    private byte[]? CreateDatagram(long now)
    {
        List<PacketDraft> drafts = [];
        int used = 0;

        foreach (PacketNumberSpace space in _spaces)
        {
            if (!space.CanSend)
                continue;

            int overhead = GetHeaderLength(space.Level) + PacketKeys.TagLength;
            int limit = _maximumDatagramSize - used - overhead;

            if (limit < MinimumPacketRoom)
                break;

            PacketDraft? draft = BuildPayload(space, limit, now);

            if (draft is null)
                continue;

            drafts.Add(draft);
            used += overhead + draft.Payload.Length;
        }

        if (drafts.Count == 0)
            return null;

        byte[] datagram = SealDatagram(drafts, now);

        // A client stops using Initial keys once it sends its first Handshake packet (RFC 9001 section 4.9.1).
        bool sentHandshake = drafts.Exists(static draft => draft.Space.Level == EncryptionLevel.Handshake);

        if (sentHandshake && !_spaces[(int)EncryptionLevel.Initial].IsDiscarded)
            _lossDetector.Discard(_spaces[(int)EncryptionLevel.Initial]);

        return datagram;
    }

    private void Fail(Exception exception, ulong errorCode)
    {
        if (IsClosed)
            return;

        string reason = exception.Message.Length > 64 ? exception.Message[..64] : exception.Message;

        _closePending = new CloseRequest(errorCode, Application: false, reason);
        Failure = exception;
    }

    private int GetHeaderLength(EncryptionLevel level)
    {
        if (level == EncryptionLevel.Application)
            return 1 + _connectionIds.Destination.Length + PacketProtection.PacketNumberLength;

        int type = level == EncryptionLevel.Initial ? LongHeader.InitialType : LongHeader.HandshakeType;

        return LongHeader.GetLength(type, _connectionIds.Destination.Length, _sourceConnectionId.Length, _token.Length, PacketProtection.PacketNumberLength);
    }

    private long GetIdleDeadline(long now)
    {
        return _idleTimeout > 0 ? now + _idleTimeout : long.MaxValue;
    }

    private void HandleRetry(ReadOnlySpan<byte> packet, byte[] retrySourceConnectionId, int tokenOffset)
    {
        // Only one Retry is honored, and only before the server has sent anything else (RFC 9000 section 17.2.5.2).
        if (_receivedServerPacket || _retrySourceConnectionId is not null || packet.Length <= tokenOffset + PacketKeys.TagLength)
            return;

        if (!RetryIntegrity.IsValid(_originalDestinationConnectionId, packet))
            return;

        PacketNumberSpace initial = _spaces[(int)EncryptionLevel.Initial];

        _token = packet[tokenOffset..^PacketKeys.TagLength].ToArray();
        _retrySourceConnectionId = retrySourceConnectionId;
        _connectionIds.Destination = retrySourceConnectionId;
        _lossDetector.Forget(initial);
        initial.SendKeys = PacketKeys.CreateInitial(retrySourceConnectionId, label: "client in");
        initial.ReceiveKeys = PacketKeys.CreateInitial(retrySourceConnectionId, label: "server in");
        initial.CryptoSend = new SendBuffer();
        initial.CryptoSend.Write(_clientHello);
    }

    private void OnAck(QuicReader reader, PacketNumberSpace space, bool withCounts, long now)
    {
        AckFrame frame = AckFrame.Read(reader, withCounts);

        if (frame.Ranges[index: 0].End > space.NextPacketNumber)
            throw new QuicTransportException(QuicTransportException.ProtocolViolation, message: "The server acknowledged a packet that was never sent.");

        // Only 1-RTT acknowledgments report a delay; it is capped by what the server promised once the handshake is confirmed.
        long ackDelay = 0;

        if (space.Level == EncryptionLevel.Application && _peer is not null)
        {
            ackDelay = (Math.Min(frame.EncodedDelay, 1L << 40) << _peer.AckDelayExponent) / 1000;

            if (_handshakeConfirmed)
                ackDelay = Math.Min(ackDelay, _peer.MaximumAckDelay);
        }

        _lossDetector.OnAckReceived(space, frame.Ranges, ackDelay, now);

        if (space.Level == EncryptionLevel.Application)
            _keyPhase.OnAcknowledged(space.LargestAcknowledged);
    }

    private void OnCrypto(PacketNumberSpace space, long offset, ReadOnlySpan<byte> data, long now)
    {
        if (offset + data.Length > space.CryptoReceive.ReadOffset + MaximumCryptoBuffer)
            throw new QuicTransportException(QuicTransportException.CryptoBufferExceeded, message: "The server sent more handshake data than this client buffers.");

        space.CryptoReceive.Insert(offset, data);

        if (space.CryptoReceive.AvailableLength == 0)
            return;

        byte[] chunk = new byte[space.CryptoReceive.AvailableLength];
        int read = space.CryptoReceive.Read(chunk);

        ApplyTlsProgress(_tls.Receive(space.Level, chunk.AsSpan(start: 0, read)), now);
    }

    private void OnHandshakeDone()
    {
        if (_handshakeConfirmed)
            return;

        _handshakeConfirmed = true;
        _lossDetector.Discard(_spaces[(int)EncryptionLevel.Handshake]);
    }

    private void OnPeerClose(QuicReader reader, bool application)
    {
        ulong code = reader.ReadVariableLengthInteger();

        if (!application)
            reader.SkipVariableLengthInteger();

        string reason = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadLength()).Span);
        string kind = application ? "application" : "transport";

        Failure = new QuicTransportException(code, $"The server closed the QUIC connection with {kind} error 0x{code:X}: {reason}", application);
    }

    private void ProcessFrame(QuicReader reader, ulong type, PacketNumberSpace space, long now)
    {
        switch (type)
        {
            case FrameType.Padding or FrameType.Ping:
                break;
            case FrameType.Ack or FrameType.AckWithCounts:
                {
                    OnAck(reader, space, type == FrameType.AckWithCounts, now);

                    break;
                }
            case FrameType.Crypto:
                {
                    long offset = reader.ReadVariableLengthLong();

                    OnCrypto(space, offset, reader.ReadBytes(reader.ReadLength()).Span, now);

                    break;
                }
            case FrameType.NewToken:
                {
                    reader.Skip(reader.ReadLength());

                    break;
                }
            case FrameType.RetireConnectionId:
                {
                    reader.SkipVariableLengthInteger();

                    break;
                }
            case FrameType.NewConnectionId:
                {
                    long sequence = reader.ReadVariableLengthLong();
                    long retirePriorTo = reader.ReadVariableLengthLong();
                    byte[] connectionId = reader.ReadVector8().ToArray();

                    _connectionIds.OnNewConnectionId(sequence, retirePriorTo, connectionId, reader.ReadBytes(ConnectionIdManager.StatelessResetTokenLength).ToArray());

                    break;
                }
            case FrameType.PathChallenge:
                {
                    _pathResponses.Enqueue(reader.ReadBytes(PathDataLength).ToArray());

                    break;
                }
            case FrameType.PathResponse:
                {
                    reader.Skip(PathDataLength);

                    break;
                }
            case FrameType.ConnectionClose or FrameType.ApplicationClose:
                {
                    OnPeerClose(reader, type == FrameType.ApplicationClose);

                    break;
                }
            case FrameType.HandshakeDone:
                {
                    OnHandshakeDone();

                    break;
                }
            case FrameType.Datagram or FrameType.DatagramWithLength:
                {
                    ReadOnlyMemory<byte> datagram = type == FrameType.Datagram ? reader.ReadRemaining() : reader.ReadBytes(reader.ReadLength());

                    if (!_options.DatagramsEnabled)
                        throw new QuicTransportException(QuicTransportException.ProtocolViolation, message: "The server sent a datagram this client did not ask for.");

                    _datagrams.OnReceived(datagram.Span);

                    break;
                }
            default:
                {
                    if (!_streams.TryProcessFrame(reader, type))
                        throw new QuicTransportException(QuicTransportException.FrameEncodingError, $"The server sent unknown frame type 0x{type:X}.");

                    break;
                }
        }
    }

    private bool ProcessFrames(PacketNumberSpace space, ReadOnlyMemory<byte> payload, long now)
    {
        if (payload.IsEmpty)
            throw new QuicTransportException(QuicTransportException.ProtocolViolation, message: "The server sent a packet without frames.");

        QuicReader reader = new(payload);
        bool ackEliciting = false;
        bool application = space.Level == EncryptionLevel.Application;

        try
        {
            while (!reader.IsEnd && !IsClosed)
            {
                ulong type = reader.ReadVariableLengthInteger();

                if (!application && !AllowedBeforeApplication(type))
                    throw new QuicTransportException(QuicTransportException.ProtocolViolation, message: "The server sent a frame not allowed before the handshake completes.");

                ackEliciting |= type is not (FrameType.Padding or FrameType.Ack or FrameType.AckWithCounts or FrameType.ConnectionClose or FrameType.ApplicationClose);
                ProcessFrame(reader, type, space, now);
            }
        }
        catch (InvalidDataException exception)
        {
            // The packet authenticated, so malformed content is the server's error and ends the connection.
            throw new QuicTransportException(QuicTransportException.FrameEncodingError, exception.Message);
        }

        return ackEliciting;
    }

    private void ProcessPacket(PacketNumberSpace space, long packetNumber, byte[] payload, long now)
    {
        bool duplicate = space.Received.Contains(packetNumber) || packetNumber < space.DuplicateFloor;

        if (duplicate)
            return;

        bool ackEliciting = ProcessFrames(space, payload, now);

        space.Received.Add(packetNumber, packetNumber + 1);
        space.Received.KeepNewest(MaximumAckRanges);
        space.DuplicateFloor = space.Received.Count == MaximumAckRanges ? space.Received.Ranges[index: 0].Start : space.DuplicateFloor;

        bool outOfOrder = packetNumber < space.LargestReceived;

        if (packetNumber > space.LargestReceived)
        {
            space.LargestReceived = packetNumber;
            space.LargestReceivedAt = now;
        }

        _idleDeadline = GetIdleDeadline(now);

        if (_options.KeepAliveInterval is TimeSpan interval && IsHandshakeComplete)
            _keepAliveDeadline = now + (long)interval.TotalMilliseconds;

        if (!ackEliciting)
            return;

        space.AckPending = true;
        space.AckElicitingSinceAck++;

        bool immediate = space.Level != EncryptionLevel.Application || space.AckElicitingSinceAck >= ImmediateAckThreshold || outOfOrder;

        space.AckDeadline = immediate ? now : Math.Min(space.AckDeadline, now + LocalMaximumAckDelay);
    }

    private int ReceiveLongPacket(ReadOnlySpan<byte> data, long now)
    {
        LongHeader header = LongHeader.Parse(data);

        if (header.Version == 0)
        {
            // Version negotiation is only meaningful before the server has answered at all.
            if (!_receivedServerPacket)
                Failure = new QuicTransportException(message: "The server does not support QUIC version 1.");

            return data.Length;
        }

        if (header.Version != LongHeader.Version1)
            return data.Length;

        if (header.Type == LongHeader.RetryType)
        {
            HandleRetry(data, header.Source, header.TokenOffset);

            return data.Length;
        }

        PacketNumberSpace? space = header.Type switch
        {
            LongHeader.InitialType => _spaces[(int)EncryptionLevel.Initial],
            LongHeader.HandshakeType => _spaces[(int)EncryptionLevel.Handshake],
            _ => null,
        };

        bool usable = space is not null && !space.IsDiscarded && header.Destination.AsSpan().SequenceEqual(_sourceConnectionId);

        if (!usable || space?.ReceiveKeys is not PacketKeys keys)
            return header.End;

        byte[] packet = data[..header.End].ToArray();

        bool unmasked = PacketProtection.TryRemoveHeaderProtection(keys, packet, header.PacketNumberOffset, space.LargestReceived, out long packetNumber, out int headerLength);

        if (!unmasked)
            return header.End;

        byte[]? payload = keys.Open(packetNumber, packet.AsSpan(start: 0, headerLength), packet.AsSpan(headerLength));

        if (payload is null)
            return header.End;

        if ((packet[0] & 0x0C) != 0)
            throw new QuicTransportException(QuicTransportException.ProtocolViolation, message: "The server set reserved header bits.");

        // The server's first Initial fixes the connection ID this client addresses it by from then on.
        if (!_receivedServerPacket)
        {
            _receivedServerPacket = true;
            _serverSourceConnectionId = header.Source;
            _connectionIds.Destination = header.Source;
        }

        ProcessPacket(space, packetNumber, payload, now);

        return header.End;
    }

    private int ReceivePacket(ReadOnlySpan<byte> data, long now)
    {
        if ((data[index: 0] & 0x80) != 0)
            return data.Length < 7 ? 0 : ReceiveLongPacket(data, now);

        ReceiveShortPacket(data, now);

        return data.Length;
    }

    private void ReceiveShortPacket(ReadOnlySpan<byte> data, long now)
    {
        PacketNumberSpace space = _spaces[(int)EncryptionLevel.Application];
        int packetNumberOffset = 1 + _sourceConnectionId.Length;
        bool addressed = (data[index: 0] & 0x40) != 0 && data.Length > packetNumberOffset && data[1..packetNumberOffset].SequenceEqual(_sourceConnectionId);

        if (!addressed || space.ReceiveKeys is not PacketKeys current)
        {
            CheckStatelessReset(data);

            return;
        }

        byte[] packet = data.ToArray();

        bool unmasked = PacketProtection.TryRemoveHeaderProtection(current, packet, packetNumberOffset, space.LargestReceived, out long packetNumber, out int headerLength);

        if (!unmasked)
            return;

        bool keyPhase = (packet[0] & 0x04) != 0;
        PacketKeys keys = _keyPhase.SelectReceiveKeys(current, keyPhase);
        byte[]? payload = keys.Open(packetNumber, packet.AsSpan(start: 0, headerLength), packet.AsSpan(headerLength));

        if (payload is null)
        {
            CheckStatelessReset(data);

            return;
        }

        if ((packet[0] & 0x18) != 0)
            throw new QuicTransportException(QuicTransportException.ProtocolViolation, message: "The server set reserved header bits.");

        _keyPhase.OnDecrypted(space, keys, keyPhase);

        ProcessPacket(space, packetNumber, payload, now);
    }

    private byte[] SealDatagram(List<PacketDraft> drafts, long now)
    {
        // Every datagram carrying an Initial packet is padded to 1200 bytes, which proves the path can carry them.
        if (drafts.Exists(draft => draft.Space.Level == EncryptionLevel.Initial))
        {
            int total = drafts.Sum(draft => GetHeaderLength(draft.Space.Level) + draft.Payload.Length + PacketKeys.TagLength);

            if (total < MinimumInitialDatagramSize)
                drafts[^1].Payload.WriteBytes(new byte[MinimumInitialDatagramSize - total]);
        }

        QuicWriter datagram = new();

        foreach (PacketDraft draft in drafts)
        {
            byte[] header = BuildHeader(draft.Space.Level, draft.PacketNumber, draft.Payload.Length);
            byte[] packet = PacketProtection.Protect(draft.Keys, draft.PacketNumber, header, draft.Payload.WrittenSpan);

            datagram.WriteBytes(packet);

            if (draft.AckEliciting)
                _lossDetector.OnPacketSent(draft.Space, new SentPacket(draft.PacketNumber, now, packet.Length, draft.Frames));

            if (draft.Space.Level == EncryptionLevel.Application)
                _keyPhase.OnPacketSent();
        }

        _keyPhase.StartIfDue(_spaces[(int)EncryptionLevel.Application], _handshakeConfirmed);

        return datagram.ToArray();
    }

    private void WriteApplicationControl(QuicWriter payload, int limit, List<SentFrame> frames)
    {
        while (payload.Length + 1 + PathDataLength <= limit && _pathResponses.TryDequeue(out byte[]? response))
        {
            payload.WriteVariableLengthInteger(FrameType.PathResponse);
            payload.WriteBytes(response);
        }

        _connectionIds.WriteRetireFrames(payload, limit, frames);
        _streams.WriteControlFrames(payload, limit, frames);
    }
}
