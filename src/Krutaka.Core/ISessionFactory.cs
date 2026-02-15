namespace Krutaka.Core;

/// <summary>
/// Factory for creating fully isolated session instances.
/// Each session contains its own per-session components (orchestrator, correlation context, stores, etc.).
/// Shared stateless services (IClaudeClient, ISecurityPolicy, etc.) remain singleton.
/// </summary>
public interface ISessionFactory
{
    /// <summary>
    /// Creates a new managed session with fully isolated per-session components.
    /// </summary>
    /// <param name="request">The session creation request containing project path, budgets, and external keys.</param>
    /// <returns>A new managed session instance.</returns>
    /// <remarks>
    /// This method instantiates:
    /// - AgentOrchestrator (per-session)
    /// - CorrelationContext (per-session)
    /// - SessionStore (per-session, JSONL file scoped to session)
    /// - ISessionAccessStore (per-session, in-memory directory grants)
    /// - ICommandApprovalCache (per-session, command approval cache)
    /// - IToolRegistry (per-session, tools scoped to ProjectPath)
    /// - ContextCompactor (per-session, references per-session CorrelationContext)
    /// - SessionBudget (per-session, token/tool-call tracking)
    /// 
    /// Shared singletons are injected but not created:
    /// - IClaudeClient
    /// - ISecurityPolicy
    /// - IAuditLogger
    /// - IAccessPolicyEngine
    /// - ICommandRiskClassifier
    /// - ToolOptions
    /// </remarks>
    ManagedSession Create(SessionRequest request);

    /// <summary>
    /// Creates a new managed session with a specific session ID (typically when resuming a suspended session).
    /// </summary>
    /// <param name="request">The session creation request containing project path, budgets, and external keys.</param>
    /// <param name="sessionId">The session ID to use for this session. Must not be Guid.Empty.
    /// Use this when resuming a suspended session to preserve the original session ID for external key mapping, 
    /// audit log continuity, JSONL file linkage, and resource governance.</param>
    /// <returns>A new managed session instance with the specified session ID.</returns>
    /// <exception cref="ArgumentException">Thrown when sessionId is Guid.Empty.</exception>
    /// <remarks>
    /// This overload is used when resuming a suspended session to ensure external mappings 
    /// (e.g., Telegram chatId → sessionId), audit logs, and JSONL files remain consistent 
    /// across suspend/resume cycles.
    /// 
    /// The session ID must be a valid, non-empty GUID. Passing Guid.Empty will result in 
    /// an ArgumentException to prevent ID collisions and maintain session identity invariants.
    /// </remarks>
    ManagedSession Create(SessionRequest request, Guid sessionId);
}
