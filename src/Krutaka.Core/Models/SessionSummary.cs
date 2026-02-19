namespace Krutaka.Core;

/// <summary>
/// Lightweight summary of a session for listing operations.
/// </summary>
/// <param name="SessionId">The unique session identifier.</param>
/// <param name="State">The current session state.</param>
/// <param name="ProjectPath">The project directory path for this session.</param>
/// <param name="ExternalKey">Optional external identifier (e.g., Telegram chatId).</param>
/// <param name="UserId">Optional user identifier.</param>
/// <param name="CreatedAt">Timestamp when the session was created.</param>
/// <param name="LastActivity">Timestamp of the last activity in this session.</param>
/// <param name="TokensUsed">Number of tokens consumed by this session.</param>
/// <param name="TurnsUsed">Number of turns processed by this session.</param>
public record SessionSummary(
    Guid SessionId,
    SessionState State,
    string ProjectPath,
    string? ExternalKey,
    string? UserId,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastActivity,
    int TokensUsed,
    int TurnsUsed);
