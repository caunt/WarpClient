namespace Warp.Networking;

/// <summary>
/// A layer-3 tunnel that carries raw IP packets to Cloudflare, such as MASQUE over HTTP/2 or WireGuard over UDP.
/// </summary>
internal interface IPacketTunnel : IPacketTransmitter, IAsyncDisposable
{
    bool IsClosed { get; }

    void StartReceiving(IPacketReceiver receiver);
}
