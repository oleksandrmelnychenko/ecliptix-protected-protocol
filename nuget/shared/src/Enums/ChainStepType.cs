#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Enums;
#else
namespace Ecliptix.Protocol.Client.Enums;
#endif

internal enum ChainStepType
{
    SENDER,
    RECEIVER
}
