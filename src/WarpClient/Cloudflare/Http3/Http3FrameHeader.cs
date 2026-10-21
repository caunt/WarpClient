namespace Warp.Cloudflare.Http3;

internal readonly record struct Http3FrameHeader(ulong Type, long Length);
