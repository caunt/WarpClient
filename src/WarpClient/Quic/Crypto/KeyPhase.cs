namespace Warp.Quic.Crypto;

/// <summary>
/// 1-RTT key updates (RFC 9001 section 6): follows the server's updates and starts its own before AES-GCM keys reach their
/// confidentiality limit.
/// </summary>
internal sealed class KeyPhase
{
    private const long UpdateInterval = 1L << 22;

    private bool _currentPhaseAcknowledged;
    private long _firstPacketInCurrentPhase;
    private PacketKeys? _nextReceiveKeys;
    private long _packetsWithCurrentKeys;
    private bool _receivePhase;

    public bool SendPhase { get; private set; }

    public void OnAcknowledged(long largestAcknowledged)
    {
        if (largestAcknowledged >= _firstPacketInCurrentPhase)
            _currentPhaseAcknowledged = true;
    }

    // Called once a packet authenticated with the keys SelectReceiveKeys returned for its phase bit.
    public void OnDecrypted(PacketNumberSpace space, PacketKeys keys, bool phase)
    {
        if (phase == _receivePhase)
            return;

        space.ReceiveKeys = keys;
        _nextReceiveKeys = null;
        _receivePhase = phase;

        // A phase change this client did not start is the server's key update, which this client must follow.
        if (SendPhase != phase)
            Advance(space);
    }

    public void OnPacketSent()
    {
        _packetsWithCurrentKeys++;
    }

    public PacketKeys SelectReceiveKeys(PacketKeys current, bool phase)
    {
        return phase == _receivePhase ? current : _nextReceiveKeys ??= current.CreateNextGeneration();
    }

    // A new phase starts only after the server acknowledged a packet from the current one.
    public void StartIfDue(PacketNumberSpace space, bool handshakeConfirmed)
    {
        bool due = handshakeConfirmed && _packetsWithCurrentKeys >= UpdateInterval && SendPhase == _receivePhase && _currentPhaseAcknowledged;

        if (due)
            Advance(space);
    }

    private void Advance(PacketNumberSpace space)
    {
        if (space.SendKeys is not PacketKeys keys)
            return;

        space.SendKeys = keys.CreateNextGeneration();
        SendPhase = !SendPhase;
        _packetsWithCurrentKeys = 0;
        _firstPacketInCurrentPhase = space.NextPacketNumber;
        _currentPhaseAcknowledged = false;
    }
}
