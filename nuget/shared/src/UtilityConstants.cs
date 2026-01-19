
namespace EPP;




internal static class UtilityConstants
{
    internal static class Hash
    {
        public const int INITIAL_HASH_SEED = 17;
        public const int HASH_MULTIPLIER = 31;
    }

    internal static class ErrorMessages
    {
        public const string CANNOT_UNWRAP_ERR = "Cannot unwrap an Err result";
        public const string CANNOT_UNWRAP_OK = "Cannot unwrap an Ok result";
        public const string ERROR_MAPPER_RETURNED_NULL = "ERROR mapper returned null, violating TE : notnull";
    }

    internal static class UnitType
    {
        public const int HASH_CODE = 0;
        public const string STRING_REPRESENTATION = "()";
    }

    internal static class ResultType
    {
        public const string OK_STRING = "Ok";
        public const string ERR_STRING = "Err";
    }

    internal static class ProtocolNames
    {
        public const string X_3DH_INFO = "Ecliptix-X3DH";
    }

    internal static class ProtocolBytes
    {
        public const byte MSG_INFO_VALUE = 0x01;
        public const byte CHAIN_INFO_VALUE = 0x02;
    }
}
