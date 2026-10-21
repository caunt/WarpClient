using System.Collections.Concurrent;
using System.Net.Sockets;

using Nito.AsyncEx;

namespace Warp.Quic;

/// <summary>
/// A QUIC client connection written entirely in managed code, carried over any <see cref="IUdpConnection"/>. A receive loop
/// and a timer loop drive the protocol core; streams and datagrams are exposed asynchronously.
/// </summary>
internal sealed class ManagedQuicConnection : IAsyncDisposable
{
    private const int ReceiveBufferLength = 65536;
    private static readonly TimeSpan SocketErrorBackoff = TimeSpan.FromMilliseconds(milliseconds: 10);

    private readonly AsyncConditionVariable _changed;
    private readonly QuicConnectionCore _core;
    private readonly AsyncLock _mutex = new();
    private readonly ConcurrentQueue<QuicStreamState> _releases = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly ulong _streamErrorCode;
    private readonly AsyncAutoResetEvent _timerChanged = new();
    private readonly IUdpConnection _transport;
    private int _disposed;
    private Exception? _lastNetworkError;
    private Task _receiving = Task.CompletedTask;
    private Task _timing = Task.CompletedTask;

    private ManagedQuicConnection(IUdpConnection transport, QuicClientOptions options)
    {
        _transport = transport;
        _streamErrorCode = options.StreamErrorCode;
        _core = new QuicConnectionCore(options, Now);
        _changed = new AsyncConditionVariable(_mutex);
    }

    public bool IsClosed => _core.IsClosed;

    public int MaximumDatagramPayloadSize => _core.MaximumDatagramPayloadSize;

    private static long Now => Environment.TickCount64;

    /// <summary>
    /// Performs the handshake over <paramref name="transport"/>, which the connection owns from then on, even on failure.
    /// </summary>
    public static async ValueTask<ManagedQuicConnection> ConnectAsync(IUdpConnection transport, QuicClientOptions options, CancellationToken cancellationToken)
    {
        ManagedQuicConnection connection = new(transport, options);

        try
        {
            connection.Start();
            await connection.WaitForHandshakeAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);

            throw;
        }
    }

    public async ValueTask<ManagedQuicStream> AcceptInboundStreamAsync(CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            QuicStreamState? state = _core.TryAcceptStream();

            while (state is null)
            {
                await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                state = _core.TryAcceptStream();
            }

            return new ManagedQuicStream(this, state);
        }
    }

    public async ValueTask CloseAsync(ulong errorCode, CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            _core.Close(errorCode, application: true, string.Empty);
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
            _changed.NotifyAll();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, value: 1) != 0)
            return;

        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            _core.Close(QuicTransportException.NoError, application: false, string.Empty);
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
            _changed.NotifyAll();
        }

        await _stopping.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
        await _receiving.ConfigureAwait(continueOnCapturedContext: false);
        await _timing.ConfigureAwait(continueOnCapturedContext: false);
        await _transport.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
        _stopping.Dispose();
    }

    public async ValueTask<ManagedQuicStream> OpenStreamAsync(bool bidirectional, CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            // A stream past the server's limit waits until the server allows more.
            QuicStreamState? state = _core.TryOpenStream(bidirectional);

            while (state is null)
            {
                await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                state = _core.TryOpenStream(bidirectional);
            }

            return new ManagedQuicStream(this, state);
        }
    }

    public async ValueTask<byte[]> ReceiveDatagramAsync(CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            byte[]? datagram = _core.TryReceiveDatagram();

            while (datagram is null)
            {
                await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                datagram = _core.TryReceiveDatagram();
            }

            return datagram;
        }
    }

    public async ValueTask SendDatagramAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            _core.SendDatagram(datagram.Span);
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
        }

        _timerChanged.Set();
    }

    internal async ValueTask AbortAsync(QuicStreamState state, ulong errorCode)
    {
        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            if (_core.IsClosed)
                return;

            _core.AbortRead(state, errorCode);
            state.AbortWrite(errorCode);
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
            _changed.NotifyAll();
        }

        _timerChanged.Set();
    }

    internal async ValueTask CompleteWritesAsync(QuicStreamState state, CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            _core.ThrowIfClosed();
            state.CompleteWrites();
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
        }

        _timerChanged.Set();
    }

    internal async ValueTask<int> ReadAsync(QuicStreamState state, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int read;

        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            while (!_core.TryRead(state, buffer.Span, out read))
                await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

            // Reading may have opened the flow-control window, which the server has to hear about.
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
        }

        _timerChanged.Set();

        return read;
    }

    internal async ValueTask ReleaseAsync(QuicStreamState state)
    {
        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            if (_core.IsClosed)
                return;

            ReleaseStream(state);
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
        }

        _timerChanged.Set();
    }

    // Synchronous disposal cannot take the lock, so the timer loop releases the stream shortly afterwards.
    internal void RequestRelease(QuicStreamState state)
    {
        _releases.Enqueue(state);
        _timerChanged.Set();
    }

    internal async ValueTask WriteAsync(QuicStreamState state, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            int offset = 0;

            while (offset < data.Length)
            {
                // Writers wait while too much is unacknowledged, which is what pushes back on a fast producer.
                while (!_core.HasSendCapacity(state))
                {
                    _core.ThrowIfClosed();
                    await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                }

                int length = Math.Min(data.Length - offset, ReceiveBufferLength);

                _core.Write(state, data.Span.Slice(offset, length));
                offset += length;
                await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
            }
        }

        _timerChanged.Set();
    }

    private async ValueTask FlushAsync()
    {
        foreach (byte[] datagram in _core.CreateDatagrams(Now))
        {
            try
            {
                await _transport.SendAsync(datagram, _stopping.Token).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch (SocketException exception)
            {
                // A datagram the network refused is simply lost; loss recovery sends its contents again.
                _lastNetworkError = exception;
            }
        }
    }

    private async Task ReceiveAsync(CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[ReceiveBufferLength];
        Exception? reason = null;

        try
        {
            while (!_core.IsClosed)
            {
                int length;

                try
                {
                    length = await _transport.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                }
                catch (SocketException exception)
                {
                    // Connected UDP sockets report ICMP errors for earlier sends; they are transient and only cost a pause.
                    _lastNetworkError = exception;
                    await Task.Delay(SocketErrorBackoff, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                    continue;
                }

                using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
                {
                    _core.ReceiveDatagram(buffer.AsSpan(start: 0, length), Now);
                    await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
                    _changed.NotifyAll();
                }

                _timerChanged.Set();
            }
        }
        catch (OperationCanceledException exception)
        {
            reason = exception;
        }
        catch (IOException exception)
        {
            reason = exception;
        }
        catch (ObjectDisposedException exception)
        {
            reason = exception;
        }

        if (reason is not null)
            await StopAsync(reason).ConfigureAwait(continueOnCapturedContext: false);
    }

    private void ReleaseStream(QuicStreamState state)
    {
        // Disposing a stream completes its writes and stops reading whatever the server still sends.
        state.CompleteWrites();
        _core.AbortRead(state, _streamErrorCode);
        _core.Release(state);
    }

    private async Task RunTimerAsync(CancellationToken cancellationToken)
    {
        Exception? reason = null;

        try
        {
            long previousDeadline = long.MinValue;

            while (!cancellationToken.IsCancellationRequested)
            {
                long deadline;

                using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
                {
                    while (_releases.TryDequeue(out QuicStreamState? state))
                    {
                        if (!_core.IsClosed)
                            ReleaseStream(state);
                    }

                    await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);

                    if (_core.IsClosed)
                        return;

                    deadline = _core.NextDeadline;
                }

                // A deadline that did not move after firing waits a millisecond, so a stuck timer cannot spin.
                long delay = deadline == previousDeadline ? Math.Max(deadline - Now, val2: 1) : deadline - Now;

                long wait = deadline == long.MaxValue ? Timeout.Infinite : delay;
                bool changed = delay > 0 && await WaitForTimerChangeAsync(wait, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);

                if (changed)
                    continue;

                previousDeadline = deadline;

                using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
                {
                    _core.OnTimeout(Now);
                    await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
                    _changed.NotifyAll();
                }
            }
        }
        catch (OperationCanceledException exception)
        {
            reason = exception;
        }

        if (reason is not null)
            await StopAsync(reason).ConfigureAwait(continueOnCapturedContext: false);
    }

    private void Start()
    {
        _receiving = ReceiveAsync(_stopping.Token);
        _timing = RunTimerAsync(_stopping.Token);
    }

    private async ValueTask StopAsync(Exception reason)
    {
        using (await _mutex.LockAsync().ConfigureAwait(continueOnCapturedContext: false))
        {
            _core.Abort(reason);
            _changed.NotifyAll();
        }
    }

    private async ValueTask WaitForHandshakeAsync(CancellationToken cancellationToken)
    {
        using (await _mutex.LockAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
        {
            await FlushAsync().ConfigureAwait(continueOnCapturedContext: false);
            _timerChanged.Set();

            try
            {
                while (!_core.IsHandshakeComplete)
                {
                    _core.ThrowIfClosed();
                    await _changed.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
                }
            }
            catch (OperationCanceledException exception) when (_lastNetworkError is not null)
            {
                throw new IOException($"The QUIC server did not answer the handshake; the network reported: {_lastNetworkError.Message}", exception);
            }
        }
    }

    // Returns true when something changed the timers before the delay ran out.
    private async ValueTask<bool> WaitForTimerChangeAsync(long delay, CancellationToken cancellationToken)
    {
        using CancellationTokenSource waiting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        Task changed = _timerChanged.WaitAsync(waiting.Token);
        Task elapsed = Task.Delay(TimeSpan.FromMilliseconds(Math.Min(delay, int.MaxValue)), waiting.Token);
        Task first = await Task.WhenAny(changed, elapsed).ConfigureAwait(continueOnCapturedContext: false);

        await waiting.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
        cancellationToken.ThrowIfCancellationRequested();

        return first == changed;
    }
}
