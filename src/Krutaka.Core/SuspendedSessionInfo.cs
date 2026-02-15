namespace Krutaka.Core;

/// <summary>
/// Metadata for a suspended session.
/// Stored in SessionManager's suspended session tracking dictionary.
/// </summary>
/// <param name="SessionId">The unique session identifier.</param>
/// <param name="ProjectPath">The project directory path for this session.</param>
/// <param name="ExternalKey">Optional external identifier (e.g., Telegram chatId).</param>
/// <param name="UserId">Optional user identifier for per-user session limits.</param>
/// <param name="CreatedAt">Timestamp when the session was originally created.</param>
/// <param name="SuspendedAt">Timestamp when the session was suspended.</param>
/// <param name="LastActivity">Timestamp of the last activity before suspension.</param>
/// <param name="TokensUsed">Number of tokens consumed before suspension.</param>
/// <param name="TurnsUsed">Number of turns processed before suspension.</param>
public record SuspendedSessionInfo(
    Guid SessionId,
    string ProjectPath,
    string? ExternalKey,
    string? UserId,
    DateTimeOffset CreatedAt,
    DateTimeOffset SuspendedAt,
    DateTimeOffset LastActivity,
    int TokensUsed,
    int TurnsUsed);
