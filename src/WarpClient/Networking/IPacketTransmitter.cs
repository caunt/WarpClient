namespace Warp.Networking;

internal interface IPacketTransmitter
{
    ValueTask TransmitAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken);
}
