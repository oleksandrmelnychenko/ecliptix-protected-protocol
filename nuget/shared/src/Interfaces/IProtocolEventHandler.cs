#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Interfaces;
#else
namespace Ecliptix.Protocol.Client.Interfaces;
#endif

internal interface IProtocolEventHandler
{
    void OnProtocolStateChanged(uint connectId);
}
