namespace Warp.Networking;

[Flags]
internal enum TcpControlBits
{
    None = 0,
    Finish = 1,
    Synchronize = 2,
    Reset = 4,
    Push = 8,
    Acknowledgment = 16,
    Urgent = 32,
}
