namespace Krutaka.Telegram;

/// <summary>
/// Represents the compact payload for inline keyboard callback data with HMAC signature.
/// Kept minimal (&lt;64 bytes) to comply with Telegram's callback_data limit.
/// Full context is stored server-side and retrieved via ApprovalId.
/// </summary>
/// <param name="ApprovalId">Short identifier to retrieve approval context from server-side store.</param>
/// <param name="Hmac">HMAC-SHA256 signature of the approval ID.</param>
public sealed record CallbackPayload(
    string ApprovalId,
    string? Hmac);
