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
}
