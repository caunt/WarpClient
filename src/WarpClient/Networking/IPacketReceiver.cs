namespace Warp.Networking;

internal interface IPacketReceiver
{
    ValueTask ReceiveAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken);

    ValueTask StopAsync(Exception reason);
}
