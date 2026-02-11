namespace Krutaka.Core;

/// <summary>
/// Provides correlation IDs for request tracing and audit logging.
/// Tracks SessionId, TurnId, and RequestId for each operation.
/// </summary>
public sealed class CorrelationContext
{
    /// <summary>
    /// Session identifier (GUID, per session).
    /// Generated once per session and remains constant throughout.
    /// </summary>
    public Guid SessionId { get; }

    /// <summary>
    /// Turn identifier (incrementing integer, per user turn within session).
    /// Increments each time the user provides input.
    /// </summary>
    public int TurnId { get; private set; }

    /// <summary>
    /// Request identifier from Claude API response header.
    /// Set after each Claude API call.
    /// </summary>
    public string? RequestId { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="CorrelationContext"/> class.
    /// </summary>
    /// <param name="sessionId">The session identifier. If not provided, a new GUID is generated.</param>
    public CorrelationContext(Guid? sessionId = null)
    {
        SessionId = sessionId ?? Guid.NewGuid();
        TurnId = 0;
    }

    /// <summary>
    /// Increments the turn ID for the next user turn.
    /// Call this at the start of each user turn.
    /// </summary>
    public void IncrementTurn()
    {
        TurnId++;
    }

    /// <summary>
    /// Sets the request ID from the Claude API response.
    /// </summary>
    /// <param name="requestId">The request ID from the response header.</param>
    public void SetRequestId(string? requestId)
    {
        RequestId = requestId;
    }

    /// <summary>
    /// Clears the request ID. Call this before starting a new request.
    /// </summary>
    public void ClearRequestId()
    {
        RequestId = null;
    }
}
