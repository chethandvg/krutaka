using System.Text.Json.Serialization;

namespace Krutaka.Telegram;

/// <summary>
/// Represents the compact payload for inline keyboard callback data with HMAC signature.
/// Kept minimal (&lt;64 bytes) to comply with Telegram's callback_data limit.
/// Full context is stored server-side and retrieved via ApprovalId.
/// Uses ultra-short field names ("i" and "s") to minimize JSON size.
/// </summary>
public sealed record CallbackPayload(
    [property: JsonPropertyName("i")] string ApprovalId,
    [property: JsonPropertyName("s")] string? Hmac);
