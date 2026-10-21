using System.Net;
using System.Threading.Channels;

namespace Warp.Networking;

/// <summary>
/// A UDP association bound to one local port of the tunnel stack.
/// </summary>
internal sealed class TunnelUdpConnection(UserspaceNetworkStack stack, ushort localPort, IPEndPoint remoteEndPoint) : IUdpConnection
{
    private const int QueueCapacity = 256;

    // Like a socket receive buffer, a full queue drops datagrams instead of stalling the tunnel.
    private readonly Channel<byte[]> _inbound = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(QueueCapacity) { FullMode = BoundedChannelFullMode.DropOldest });
    private int _completed;

    // A connected UDP association only accepts datagrams from the endpoint it was opened for.
    public bool Accepts(IPAddress source, ushort sourcePort)
    {
        return remoteEndPoint.Port == sourcePort && remoteEndPoint.Address.Equals(source);
    }

    public async ValueTask DeliverAsync(byte[] datagram, CancellationToken cancellationToken)
    {
        await _inbound.Writer.WriteAsync(datagram, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
    }

    public async ValueTask DisposeAsync()
    {
        Fail(new ObjectDisposedException(nameof(TunnelUdpConnection)));
        await stack.RemoveDatagramAsync(localPort).ConfigureAwait(continueOnCapturedContext: false);
    }

    public void Fail(Exception reason)
    {
        if (Interlocked.Exchange(ref _completed, value: 1) == 0)
            _inbound.Writer.Complete(reason);
    }

    public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        byte[] datagram;

        try
        {
            datagram = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
        }
        catch (ChannelClosedException exception)
        {
            throw new IOException(message: "The UDP connection is closed.", exception.InnerException ?? exception);
        }

        int length = Math.Min(datagram.Length, buffer.Length);

        datagram.AsSpan(start: 0, length).CopyTo(buffer.Span);

        return length;
    }

    public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken)
    {
        return stack.SendDatagramAsync(localPort, remoteEndPoint, datagram, cancellationToken);
    }
}
