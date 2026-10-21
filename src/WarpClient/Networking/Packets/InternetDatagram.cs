using System.Net;

namespace Warp.Networking.Packets;

internal readonly record struct InternetDatagram(IPAddress Source, IPAddress Destination, byte Protocol, int PayloadOffset, int PayloadLength);
