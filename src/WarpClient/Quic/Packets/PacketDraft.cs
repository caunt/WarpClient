using Warp.Quic.Crypto;

using Warp.Quic.Recovery;

namespace Warp.Quic.Packets;

/// <summary>
/// A packet's plaintext payload and bookkeeping, built before the datagram it travels in is sealed.
/// </summary>
internal sealed record PacketDraft(PacketNumberSpace Space, PacketKeys Keys, long PacketNumber, QuicWriter Payload, List<SentFrame> Frames, bool AckEliciting);
