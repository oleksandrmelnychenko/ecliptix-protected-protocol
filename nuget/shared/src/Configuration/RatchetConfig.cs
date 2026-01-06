#if ECLIPTIX_SERVER
namespace Ecliptix.Protocol.Server.Configuration;
#else
namespace Ecliptix.Protocol.Client.Configuration;
#endif

internal sealed class RatchetConfig
{
    public static readonly RatchetConfig Default = CreateDefault();

    public required uint DhRatchetEveryNMessages { get; init; }

    public required uint MaxMessagesWithoutRatchet { get; init; }

    public bool ShouldRatchet(uint messageIndex, bool receivedNewDhKey) =>
        receivedNewDhKey ||
        messageIndex % DhRatchetEveryNMessages == 0 ||
        messageIndex >= MaxMessagesWithoutRatchet;

    public static RatchetConfig Create(uint dhRatchetEveryNMessages, uint maxMessagesWithoutRatchet)
    {
        ValidateParameters(dhRatchetEveryNMessages, maxMessagesWithoutRatchet);

        return new RatchetConfig
        {
            DhRatchetEveryNMessages = dhRatchetEveryNMessages,
            MaxMessagesWithoutRatchet = maxMessagesWithoutRatchet
        };
    }

    private static RatchetConfig CreateDefault() => new()
    {
        DhRatchetEveryNMessages = 10,
        MaxMessagesWithoutRatchet = 1000
    };

    private static void ValidateParameters(uint dhRatchetEveryNMessages, uint maxMessagesWithoutRatchet)
    {
        if (dhRatchetEveryNMessages == 0)
        {
            throw new ArgumentException(
                "DhRatchetEveryNMessages cannot be 0 (would cause division by zero in ratchet logic)",
                nameof(dhRatchetEveryNMessages));
        }

        if (maxMessagesWithoutRatchet < dhRatchetEveryNMessages)
        {
            throw new ArgumentException(
                string.Format(
                    global::System.Globalization.CultureInfo.InvariantCulture,
                    "MaxMessagesWithoutRatchet ({0}) cannot be less than DhRatchetEveryNMessages ({1}). This creates a conflicting configuration.",
                    maxMessagesWithoutRatchet,
                    dhRatchetEveryNMessages),
                nameof(maxMessagesWithoutRatchet));
        }
    }
}
