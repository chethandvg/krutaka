namespace Krutaka.Telegram;

/// <summary>
/// Represents the payload for inline keyboard callback data with HMAC signature.
/// Used for secure approval flow in Telegram bot.
/// </summary>
/// <param name="Action">The action to perform (approve/deny/always).</param>
/// <param name="ToolUseId">The tool use ID or empty string for directory/command approvals.</param>
/// <param name="SessionId">The session identifier.</param>
/// <param name="UserId">The Telegram user ID authorized to perform this action.</param>
/// <param name="Timestamp">Unix timestamp when this callback was created.</param>
/// <param name="Nonce">One-time nonce for replay prevention.</param>
/// <param name="Hmac">HMAC-SHA256 signature of the payload (excluding this field).</param>
public sealed record CallbackPayload(
    string Action,
    string ToolUseId,
    Guid SessionId,
    long UserId,
    long Timestamp,
    string Nonce,
    string? Hmac);
