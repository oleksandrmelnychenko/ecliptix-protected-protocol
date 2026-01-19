
namespace EPP;




internal static class Constants
{
    public const int X25519SharedSecretBytes = 32;
    public const int X25519PublicKeyBytes = 32;
    public const int X25519PrivateKeyBytes = 32;

    public const int Ed25519PublicKeyBytes = 32;
    public const int Ed25519SecretKeyBytes = 64;
    public const int Ed25519SignatureBytes = 64;

    public const int AesKeyBytes = 32;
    public const int AesGcmNonceBytes = 12;
    public const int AesGcmTagBytes = 16;

    public static readonly byte[] MessageInfo = [UtilityConstants.ProtocolBytes.MSG_INFO_VALUE];
    public static readonly byte[] ChainInfo = [UtilityConstants.ProtocolBytes.CHAIN_INFO_VALUE];

    public static ReadOnlySpan<byte> X3dhInfo => System.Text.Encoding.UTF8.GetBytes(UtilityConstants.ProtocolNames.X_3DH_INFO);

    public const int Curve25519FieldElementBytes = 32;
    public const int WordBytes = 4;
    public const int Field256WordCount = 8;
    public const uint FieldElementMask = 0x7FFFFFFF;
    public const int SmallBufferThreshold = 64;

    public const int UInt32LittleEndianOffsetBits = 8;
}
