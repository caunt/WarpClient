using System.Security.Cryptography;

using Nito.AsyncEx;

using Warp.Networking.Packets;

namespace Warp.Networking.Tcp;

/// <summary>
/// Client side of one TCP connection whose segments travel as IPv4 packets through a tunnel.
/// </summary>
/// <remarks>
/// Deliberately small: no congestion control, selective acknowledgments or window scaling. Lost segments are recovered by
/// go-back-N retransmission with exponential backoff, which is enough for a reliable, low-loss tunnel.
/// </remarks>
internal sealed class TcpConnection
{
    private const int DefaultMaximumSegmentSize = 536;
    private const int MaximumBytesInFlight = 64 * 1024;
    private const int MaximumRetransmissions = 7;
    private const int ReceiveCapacity = 256 * 1024;
    private const int SendCapacity = 256 * 1024;
    private static readonly TimeSpan InitialRetransmissionTimeout = TimeSpan.FromSeconds(seconds: 1);
    private static readonly TimeSpan MaximumRetransmissionTimeout = TimeSpan.FromSeconds(seconds: 30);
    private static readonly TimeSpan CloseTimeout = TimeSpan.FromSeconds(seconds: 5);
    private static readonly TimeSpan TimerInterval = TimeSpan.FromMilliseconds(milliseconds: 100);

    private readonly AsyncConditionVariable _changed;
    private readonly int _localMaximumSegmentSize;
    private readonly AsyncLock _mutex = new();
    private readonly ByteQueue _sendBuffer = new();
    private readonly ByteQueue _receiveBuffer = new();
    private readonly UserspaceNetworkStack _stack;
    private int _advertisedWindow;
    private long _closeDeadline;
    private volatile bool _closeRequested;
    private Exception? _failure;
    private bool _finishAcknowledged;
    private bool _finishAssigned;
    private bool _finishQueued;
    private bool _finishSent;
    private uint _finishSequence;
    private TcpConnectionState _state = TcpConnectionState.Closed;
    private int _peerWindow;
    private bool _receiveCompleted;
    private uint _receiveNext;
    private long _retransmissionDeadline;
    private int _peerMaximumSegmentSize = DefaultMaximumSegmentSize;
    private int _retransmissions;
    private uint _sendHighest;
    private uint _sendNext;
    private uint _sendUnacknowledged;
    private TimeSpan _retransmissionTimeout = InitialRetransmissionTimeout;
    private Task _timer = Task.CompletedTask;

    public TcpConnection(UserspaceNetworkStack stack, ConnectionKey key, int localMaximumSegmentSize)
    {
        this._stack = stack;
        this._localMaximumSegmentSize = localMaximumSegmentSize;
        Key = key;
        _changed = new AsyncConditionVariable(_mutex);
    }

    public ConnectionKey Key { get; }

    public async ValueTask AbortAsync(Exception reason)
    {
        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
            Fail(reason);
    }

    public async ValueTask CloseAsync()
    {
        _closeRequested = true;
        await _timer.ConfigureAwait(continueOnCapturedContext: false);
    }

    public async ValueTask ConnectAsync(CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            uint initialSequence = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);

            _state = TcpConnectionState.SynchronizeSent;
            _sendUnacknowledged = initialSequence;
            _sendNext = initialSequence + 1;
            _sendHighest = _sendNext;
            await SendSegmentAsync(initialSequence, TcpControlBits.Synchronize, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            ArmRetransmission();
            _timer = RunTimerAsync();

            while (_state == TcpConnectionState.SynchronizeSent)
                await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (_failure is not null)
                throw new IOException(message: "The TCP connection could not be established through the tunnel.", _failure);
        }
    }

    public async ValueTask HandleSegmentAsync(TcpSegment segment, CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            try
            {
                if (_state == TcpConnectionState.Closed)
                    return;

                if (_state == TcpConnectionState.SynchronizeSent)
                    await HandleHandshakeAsync(segment, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                else if ((segment.ControlBits & TcpControlBits.Reset) != 0)
                    Fail(new IOException(message: "The remote host reset the TCP connection."));
                else
                    await HandleSynchronizedAsync(segment, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (IOException exception)
            {
                Fail(exception);
            }
        }
    }

    public async ValueTask<int> ReadAsync(Memory<byte> destination, CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            while (_receiveBuffer.Count == 0 && !_receiveCompleted && _failure is null)
                await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            if (_receiveBuffer.Count > 0)
            {
                int read = _receiveBuffer.Dequeue(destination.Span);

                await AnnounceReopenedWindowAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                return read;
            }

            return _receiveCompleted ? 0 : throw new IOException(message: "The TCP connection failed.", _failure);
        }
    }

    public void RequestClose()
    {
        _closeRequested = true;
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        int offset = 0;

        while (offset < data.Length)
        {
            using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
            {
                while (_sendBuffer.Count >= SendCapacity && _failure is null)
                    await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                if (_failure is not null)
                    throw new IOException(message: "The TCP connection failed.", _failure);

                if (_closeRequested || _state is not (TcpConnectionState.Established or TcpConnectionState.CloseWait))
                    throw new IOException(message: "The TCP connection is closed for writing.");

                int length = Math.Min(data.Length - offset, SendCapacity - _sendBuffer.Count);

                _sendBuffer.Enqueue(data.Span.Slice(offset, length));
                offset += length;
                await TransmitPendingAsync(probing: false, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            }
        }
    }

    private static bool IsBefore(uint first, uint second)
    {
        return (int)(first - second) < 0;
    }

    private void AcknowledgeFinish()
    {
        _finishAcknowledged = true;
        _state = _state switch
        {
            TcpConnectionState.FinishWait1 when _receiveCompleted => TcpConnectionState.Closed,
            TcpConnectionState.FinishWait1 => TcpConnectionState.FinishWait2,
            TcpConnectionState.Closing or TcpConnectionState.LastAcknowledgment => TcpConnectionState.Closed,
            _ => _state,
        };
    }

    private void Advance(int length)
    {
        if (_retransmissionDeadline == 0)
            ArmRetransmission();

        _sendNext += (uint)length;

        if (IsBefore(_sendHighest, _sendNext))
            _sendHighest = _sendNext;
    }

    private async ValueTask AnnounceReopenedWindowAsync(CancellationToken cancellationToken)
    {
        int window = Math.Min(ushort.MaxValue, ReceiveCapacity - _receiveBuffer.Count);
        bool reopened = window - _advertisedWindow >= _peerMaximumSegmentSize * 2;
        bool synchronized = _state is TcpConnectionState.Established or TcpConnectionState.FinishWait1 or TcpConnectionState.FinishWait2;

        if (reopened && synchronized)
            await SendSegmentAsync(_sendNext, TcpControlBits.Acknowledgment, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private void ArmRetransmission()
    {
        _retransmissionDeadline = Environment.TickCount64 + (long)_retransmissionTimeout.TotalMilliseconds;
    }

    private async ValueTask<bool> ContinueClosingAsync(long now)
    {
        if (_finishAcknowledged || _state == TcpConnectionState.SynchronizeSent)
        {
            if (_state == TcpConnectionState.SynchronizeSent)
                await SendSegmentAsync(_sendNext, TcpControlBits.Reset, ReadOnlyMemory<byte>.Empty, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);

            _state = TcpConnectionState.Closed;
            _changed.NotifyAll();

            return false;
        }

        if (!_finishQueued)
        {
            _finishQueued = true;
            _closeDeadline = now + (long)CloseTimeout.TotalMilliseconds;
            await TransmitPendingAsync(probing: false, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);
        }

        if (now < _closeDeadline)
            return true;

        await SendSegmentAsync(_sendNext, TcpControlBits.Reset, ReadOnlyMemory<byte>.Empty, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);
        Fail(new IOException(message: "The remote host did not acknowledge the end of the TCP connection in time."));

        return false;
    }

    private void Fail(Exception reason)
    {
        _failure ??= reason;
        _state = TcpConnectionState.Closed;
        _retransmissionDeadline = 0;
        _changed.NotifyAll();
    }

    private async ValueTask HandleHandshakeAsync(TcpSegment segment, CancellationToken cancellationToken)
    {
        bool acknowledgesSynchronize = (segment.ControlBits & TcpControlBits.Acknowledgment) != 0 && segment.AcknowledgmentNumber == _sendNext;

        if (!acknowledgesSynchronize)
            return;

        if ((segment.ControlBits & TcpControlBits.Reset) != 0)
        {
            Fail(new IOException(message: "The remote host refused the TCP connection."));

            return;
        }

        if ((segment.ControlBits & TcpControlBits.Synchronize) == 0)
            return;

        bool sizeAnnounced = segment.MaximumSegmentSize > 0;

        _receiveNext = segment.SequenceNumber + 1;
        _sendUnacknowledged = segment.AcknowledgmentNumber;
        _peerWindow = segment.Window;
        _peerMaximumSegmentSize = sizeAnnounced ? Math.Min(segment.MaximumSegmentSize, _localMaximumSegmentSize) : DefaultMaximumSegmentSize;
        _state = TcpConnectionState.Established;
        ResetRetransmission();
        await SendSegmentAsync(_sendNext, TcpControlBits.Acknowledgment, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        _changed.NotifyAll();
    }

    private async ValueTask HandleSynchronizedAsync(TcpSegment segment, CancellationToken cancellationToken)
    {
        if ((segment.ControlBits & TcpControlBits.Acknowledgment) != 0)
            ProcessAcknowledgment(segment);

        if (ReceivePayload(segment))
            await SendSegmentAsync(_sendNext, TcpControlBits.Acknowledgment, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        await TransmitPendingAsync(probing: false, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        _changed.NotifyAll();
    }

    private void ProcessAcknowledgment(TcpSegment segment)
    {
        uint acknowledgment = segment.AcknowledgmentNumber;
        bool advances = IsBefore(_sendUnacknowledged, acknowledgment) && !IsBefore(_sendHighest, acknowledgment);

        if (advances)
        {
            bool coversFinish = _finishAssigned && !_finishAcknowledged && IsBefore(_finishSequence, acknowledgment);
            int acknowledgedLength = (int)(acknowledgment - _sendUnacknowledged) - (coversFinish ? 1 : 0);

            _sendBuffer.Discard(Math.Min(acknowledgedLength, _sendBuffer.Count));
            _sendUnacknowledged = acknowledgment;

            if (IsBefore(_sendNext, acknowledgment))
                _sendNext = acknowledgment;

            if (coversFinish)
                AcknowledgeFinish();

            ResetRetransmission();
        }

        if (acknowledgment == _sendUnacknowledged)
            _peerWindow = segment.Window;
    }

    private bool ReceivePayload(TcpSegment segment)
    {
        bool finishing = (segment.ControlBits & TcpControlBits.Finish) != 0;

        if (segment.Payload.IsEmpty && !finishing)
            return false;

        // Anything after the peer's FIN is a duplicate; acknowledging it again is all that is needed.
        if (_receiveCompleted)
            return true;

        int alreadyReceived = (int)(_receiveNext - segment.SequenceNumber);

        if (alreadyReceived < 0 || alreadyReceived > segment.Payload.Length)
            return true;

        int fresh = segment.Payload.Length - alreadyReceived;
        int accepted = Math.Min(fresh, ReceiveCapacity - _receiveBuffer.Count);

        _receiveBuffer.Enqueue(segment.Payload.Span.Slice(alreadyReceived, accepted));
        _receiveNext += (uint)accepted;

        if (finishing && accepted == fresh)
        {
            _receiveNext++;
            _receiveCompleted = true;
            _state = _state switch
            {
                TcpConnectionState.Established => TcpConnectionState.CloseWait,
                TcpConnectionState.FinishWait1 => TcpConnectionState.Closing,
                TcpConnectionState.FinishWait2 => TcpConnectionState.Closed,
                _ => _state,
            };
        }

        return true;
    }

    private void ResetRetransmission()
    {
        _retransmissions = 0;
        _retransmissionTimeout = InitialRetransmissionTimeout;
        _retransmissionDeadline = 0;

        if (_sendUnacknowledged != _sendHighest)
            ArmRetransmission();
    }

    private async ValueTask RetransmitAsync(long now)
    {
        _retransmissions++;

        if (_retransmissions > MaximumRetransmissions)
        {
            Fail(new IOException(message: "The remote host stopped acknowledging TCP segments."));

            return;
        }

        TimeSpan doubled = _retransmissionTimeout * 2;

        _retransmissionTimeout = doubled < MaximumRetransmissionTimeout ? doubled : MaximumRetransmissionTimeout;
        _retransmissionDeadline = now + (long)_retransmissionTimeout.TotalMilliseconds;

        if (_state == TcpConnectionState.SynchronizeSent)
        {
            await SendSegmentAsync(_sendUnacknowledged, TcpControlBits.Synchronize, ReadOnlyMemory<byte>.Empty, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);

            return;
        }

        bool outstanding = _sendUnacknowledged != _sendHighest;

        if (outstanding)
        {
            _sendNext = _sendUnacknowledged;
            _finishSent = false;
        }

        await TransmitPendingAsync(!outstanding, CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async Task RunTimerAsync()
    {
        using PeriodicTimer ticker = new(TimerInterval);

        bool running = true;

        while (running && await ticker.WaitForNextTickAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
                running = await TickAsync().ConfigureAwait(continueOnCapturedContext: false);
        }

        await _stack.RemoveAsync(Key).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask SendFinishAsync(CancellationToken cancellationToken)
    {
        if (!_finishAssigned)
        {
            _finishSequence = _sendNext;
            _finishAssigned = true;
        }

        await SendSegmentAsync(_finishSequence, TcpControlBits.Finish | TcpControlBits.Acknowledgment, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        _finishSent = true;
        Advance(length: 1);
        _state = _state switch
        {
            TcpConnectionState.Established => TcpConnectionState.FinishWait1,
            TcpConnectionState.CloseWait => TcpConnectionState.LastAcknowledgment,
            _ => _state,
        };
    }

    private async ValueTask SendSegmentAsync(uint sequenceNumber, TcpControlBits controlBits, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        bool synchronizing = (controlBits & TcpControlBits.Synchronize) != 0;
        bool acknowledging = (controlBits & TcpControlBits.Acknowledgment) != 0;

        _advertisedWindow = Math.Min(ushort.MaxValue, ReceiveCapacity - _receiveBuffer.Count);

        TcpSegment segment = new(
            Key.LocalPort,
            Key.RemotePort,
            sequenceNumber,
            acknowledging ? _receiveNext : 0,
            controlBits,
            (ushort)_advertisedWindow,
            synchronizing ? _localMaximumSegmentSize : 0,
            payload
        );

        await _stack.SendSegmentAsync(Key.RemoteAddress, segment, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    private async ValueTask<bool> TickAsync()
    {
        try
        {
            if (_state == TcpConnectionState.Closed)
                return false;

            long now = Environment.TickCount64;

            if (_closeRequested && !await ContinueClosingAsync(now).ConfigureAwait(continueOnCapturedContext: false))
                return false;

            if (_retransmissionDeadline != 0 && now >= _retransmissionDeadline)
                await RetransmitAsync(now).ConfigureAwait(continueOnCapturedContext: false);

            return _state != TcpConnectionState.Closed;
        }
        catch (IOException exception)
        {
            Fail(exception);

            return false;
        }
    }

    private async ValueTask TransmitPendingAsync(bool probing, CancellationToken cancellationToken)
    {
        bool transmitting = _state is TcpConnectionState.Established or TcpConnectionState.CloseWait or TcpConnectionState.FinishWait1
            or TcpConnectionState.Closing or TcpConnectionState.LastAcknowledgment;

        if (!transmitting)
            return;

        int inFlight = (int)(_sendNext - _sendUnacknowledged) - (_finishSent ? 1 : 0);
        int window = Math.Min(probing ? Math.Max(_peerWindow, val2: 1) : _peerWindow, MaximumBytesInFlight);

        while (inFlight < _sendBuffer.Count && inFlight < window)
        {
            int length = Math.Min(Math.Min(_sendBuffer.Count - inFlight, window - inFlight), _peerMaximumSegmentSize);
            byte[] payload = new byte[length];

            _sendBuffer.CopyTo(inFlight, payload);
            await SendSegmentAsync(_sendNext, TcpControlBits.Acknowledgment | TcpControlBits.Push, payload, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
            Advance(length);
            inFlight += length;
        }

        bool finishPending = _finishQueued && !_finishSent && !_finishAcknowledged && inFlight == _sendBuffer.Count;

        if (finishPending)
            await SendFinishAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

        // Data waiting behind a closed window needs a deadline too, or nothing would ever probe the window open again.
        if (_retransmissionDeadline == 0 && inFlight < _sendBuffer.Count)
            ArmRetransmission();
    }
}
