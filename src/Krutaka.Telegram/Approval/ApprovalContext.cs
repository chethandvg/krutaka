namespace Krutaka.Telegram;

/// <summary>
/// Server-side approval context stored to keep callback data under Telegram's 64-byte limit.
/// </summary>
internal sealed record ApprovalContext(
    Guid SessionId,
    long UserId,
    string Action,
    string ToolUseId,
    long Timestamp,
    string Nonce);
