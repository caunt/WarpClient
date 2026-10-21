namespace Warp.Quic.Recovery;

/// <summary>
/// Receives the outcome of every retransmittable frame once loss detection knows whether its packet arrived.
/// </summary>
internal interface ISentFrameHandler
{
    void OnAcknowledged(PacketNumberSpace space, SentFrame frame);

    void OnLost(PacketNumberSpace space, SentFrame frame);
}
