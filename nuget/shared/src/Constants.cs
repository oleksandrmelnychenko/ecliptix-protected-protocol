#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server;
#else
namespace Ecliptix.Protocol.Client;
#endif

internal static class Constants
{
    public const int X_25519_KEY_SIZE = 32;
    public const int ED_25519_KEY_SIZE = 32;

    public const int ED_25519_PUBLIC_KEY_SIZE = 32;
    public const int ED_25519_SECRET_KEY_SIZE = 64;
    public const int ED_25519_SIGNATURE_SIZE = 64;
    public const int X_25519_PUBLIC_KEY_SIZE = 32;
    public const int X_25519_PRIVATE_KEY_SIZE = 32;
    public const int AES_KEY_SIZE = 32;
    public const int AES_GCM_NONCE_SIZE = 12;
    public const int AES_GCM_TAG_SIZE = 16;

    public static readonly byte[] MsgInfo = [UtilityConstants.ProtocolBytes.MSG_INFO_VALUE];
    public static readonly byte[] ChainInfo = [UtilityConstants.ProtocolBytes.CHAIN_INFO_VALUE];

    public static ReadOnlySpan<byte> X3DhInfo => System.Text.Encoding.UTF8.GetBytes(UtilityConstants.ProtocolNames.X_3DH_INFO);

    public const int CURVE_25519_FIELD_ELEMENT_SIZE = 32;
    public const int WORD_SIZE = 4;
    public const int FIELD_256_WORD_COUNT = 8;
    public const uint FIELD_ELEMENT_MASK = 0x7FFFFFFF;
    public const int SMALL_BUFFER_THRESHOLD = 64;

    public const int U_INT_32_LITTLE_ENDIAN_OFFSET = 8;
}
