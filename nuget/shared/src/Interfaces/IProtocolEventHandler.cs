
namespace EPP.Interfaces;




internal interface IProtocolEventHandler
{
    void OnProtocolStateChanged(uint connectId);
}
