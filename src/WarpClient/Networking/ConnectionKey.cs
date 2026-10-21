using System.Net;

namespace Warp.Networking;

internal readonly record struct ConnectionKey(ushort LocalPort, IPAddress RemoteAddress, ushort RemotePort);
