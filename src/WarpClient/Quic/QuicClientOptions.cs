using Warp.Quic.Crypto;

namespace Warp.Quic;

/// <summary>
/// Settings for one managed QUIC client connection.
/// </summary>
internal sealed class QuicClientOptions
{
    public required string ApplicationProtocol { get; init; }

    // The official WARP client uses 20-byte connection IDs, the longest QUIC v1 allows.
    public int ConnectionIdLength { get; init; } = 20;

    public ClientCredential? Credential { get; init; }

    public int DatagramReceiveQueueLength { get; init; } = 1024;

    public bool DatagramsEnabled { get; init; }

    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromSeconds(seconds: 30);

    public TimeSpan? KeepAliveInterval { get; init; }

    public int MaximumDatagramSize { get; init; } = 1350;

    public int MaximumInboundBidirectionalStreams { get; init; }

    public int MaximumInboundUnidirectionalStreams { get; init; } = 16;

    public required byte[] PinnedPublicKey { get; init; }

    public long ReceiveWindow { get; init; } = 16 * 1024 * 1024;

    public required string ServerName { get; init; }

    public long StreamReceiveWindow { get; init; } = 1024 * 1024;

    public int StreamSendBufferLength { get; init; } = 256 * 1024;
}
