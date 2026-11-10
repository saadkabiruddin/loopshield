using System.Security.Cryptography;

namespace LoopShield.Shared;

/// <summary>Truncated HMAC-SHA256 used by the protocol layer. Key must match
/// SG_HMAC_KEY in firmware/main/sg_config.h. The attacker never uses this.</summary>
public static class SgMac
{
    public static readonly byte[] Key =
    [
        0x53, 0x70, 0x6f, 0x6f, 0x66, 0x47, 0x75, 0x61, 0x72, 0x64, 0x2d, 0x6c, 0x61, 0x62, 0x2d, 0x6b,
        0x65, 0x79, 0x2d, 0x30, 0x31, 0x9a, 0x3c, 0x7e, 0x11, 0xd4, 0x58, 0xb2, 0x06, 0xef, 0x83, 0x2d,
    ];

    /// <summary>Encodes the message with the MAC flag set and a valid MAC.</summary>
    public static byte[] EncodeSigned(SgMessage msg)
    {
        var buf = (msg with { Flags = (ushort)(msg.Flags | SgMessage.FlagMac), Mac = 0 }).Encode();
        var full = HMACSHA256.HashData(Key, buf.AsSpan(0, SgMessage.MacOffset));
        full.AsSpan(0, SgMessage.MacLength).CopyTo(buf.AsSpan(SgMessage.MacOffset));
        return buf;
    }

    public static bool Verify(ReadOnlySpan<byte> buf)
    {
        if (buf.Length != SgMessage.Length) return false;
        Span<byte> full = stackalloc byte[32];
        HMACSHA256.HashData(Key, buf[..SgMessage.MacOffset], full);
        return CryptographicOperations.FixedTimeEquals(full[..SgMessage.MacLength], buf.Slice(SgMessage.MacOffset, SgMessage.MacLength));
    }
}
