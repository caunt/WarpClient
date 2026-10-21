using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Warp.Quic.Crypto;

/// <summary>
/// Verifies the integrity tag of a Retry packet (RFC 9001 section 5.8), so an off-path attacker cannot redirect the handshake.
/// </summary>
internal static class RetryIntegrity
{
    private static readonly byte[] Key = Convert.FromHexString(s: "BE0C690B9F66575A1D766B54E368C84E");
    private static readonly byte[] Nonce = Convert.FromHexString(s: "461599D35D632BF2239825BB");

    public static bool IsValid(ReadOnlySpan<byte> originalDestinationConnectionId, ReadOnlySpan<byte> retryPacket)
    {
        if (retryPacket.Length < PacketKeys.TagLength)
            return false;

        byte[] pseudoPacket = [(byte)originalDestinationConnectionId.Length, .. originalDestinationConnectionId, .. retryPacket[..^PacketKeys.TagLength]];
        GcmBlockCipher cipher = new(AesUtilities.CreateEngine());
        byte[] tag = new byte[PacketKeys.TagLength];

        cipher.Init(forEncryption: true, new AeadParameters(new KeyParameter(Key), PacketKeys.TagLength * 8, Nonce, pseudoPacket));

        int written = cipher.DoFinal(tag, outOff: 0);

        return written == tag.Length && CryptographicOperations.FixedTimeEquals(tag, retryPacket[^PacketKeys.TagLength..]);
    }
}
