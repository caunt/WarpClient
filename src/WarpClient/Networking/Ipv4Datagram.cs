using System.Net;

namespace Warp.Networking;

internal readonly record struct Ipv4Datagram(IPAddress Source, IPAddress Destination, byte Protocol, int PayloadOffset, int PayloadLength);
