namespace Krutaka.Core;

/// <summary>
/// Provides correlation IDs for request tracing and audit logging.
/// Tracks SessionId, TurnId, and RequestId for each operation.
/// </summary>
public sealed class CorrelationContext
{
    /// <summary>
    /// Session identifier (GUID, per session).
    /// Can be reset when starting a new session via <see cref="ResetSession"/>.
    /// </summary>
    public Guid SessionId { get; private set; }

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
    /// Agent identifier (GUID, per agent instance).
    /// Null in single-agent mode (v0.4.0). Will be set in v0.9.0 multi-agent coordination.
    /// </summary>
    public Guid? AgentId { get; private set; }

    /// <summary>
    /// Parent agent identifier (GUID, for hierarchical agent relationships).
    /// Null in single-agent mode or for root agents. Will be set in v0.9.0 multi-agent coordination.
    /// </summary>
    public Guid? ParentAgentId { get; private set; }

    /// <summary>
    /// Agent role identifier (e.g., "coordinator", "researcher", "executor").
    /// Null in single-agent mode. Will be set in v0.9.0 multi-agent coordination.
    /// </summary>
    public string? AgentRole { get; private set; }

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

    /// <summary>
    /// Sets the agent context for multi-agent coordination scenarios.
    /// All three fields must be provided together to ensure consistency.
    /// </summary>
    /// <param name="agentId">The agent identifier.</param>
    /// <param name="parentAgentId">The parent agent identifier (null for root agents).</param>
    /// <param name="role">The agent role identifier.</param>
    public void SetAgentContext(Guid agentId, Guid? parentAgentId, string role)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(role);

        AgentId = agentId;
        ParentAgentId = parentAgentId;
        AgentRole = role;
    }

    /// <summary>
    /// Resets the session with a new session ID and resets the turn counter.
    /// Used by the /new command to start a fresh session while reusing
    /// the same DI-registered CorrelationContext instance.
    /// </summary>
    /// <param name="newSessionId">The new session identifier.</param>
    public void ResetSession(Guid newSessionId)
    {
        SessionId = newSessionId;
        TurnId = 0;
        RequestId = null;
        AgentId = null;
        ParentAgentId = null;
        AgentRole = null;
    }
}
