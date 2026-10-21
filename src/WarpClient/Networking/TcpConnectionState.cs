namespace Warp.Networking;

internal enum TcpConnectionState
{
    Closed,
    SynchronizeSent,
    Established,
    FinishWait1,
    FinishWait2,
    CloseWait,
    Closing,
    LastAcknowledgment,
}
