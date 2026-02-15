using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Factory for creating fully isolated session instances.
/// Each session contains its own per-session components (orchestrator, correlation context, stores, etc.).
/// Shared stateless services (IClaudeClient, ISecurityPolicy, etc.) remain singleton.
/// </summary>
public sealed class SessionFactory : ISessionFactory
{
    private readonly IClaudeClient _claudeClient;
    private readonly ISecurityPolicy _securityPolicy;
    private readonly IAuditLogger? _auditLogger;
    private readonly IAccessPolicyEngine _accessPolicyEngine;
    private readonly ICommandRiskClassifier _commandRiskClassifier;
    private readonly ToolOptions _toolOptions;

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionFactory"/> class.
    /// </summary>
    /// <param name="claudeClient">The Claude API client (shared singleton).</param>
    /// <param name="securityPolicy">The security policy (shared singleton).</param>
    /// <param name="accessPolicyEngine">The access policy engine (shared singleton).</param>
    /// <param name="commandRiskClassifier">The command risk classifier (shared singleton).</param>
    /// <param name="toolOptions">The tool options (shared singleton).</param>
    /// <param name="auditLogger">The audit logger (shared singleton, optional).</param>
    public SessionFactory(
        IClaudeClient claudeClient,
        ISecurityPolicy securityPolicy,
        IAccessPolicyEngine accessPolicyEngine,
        ICommandRiskClassifier commandRiskClassifier,
        ToolOptions toolOptions,
        IAuditLogger? auditLogger = null)
    {
        _claudeClient = claudeClient ?? throw new ArgumentNullException(nameof(claudeClient));
        _securityPolicy = securityPolicy ?? throw new ArgumentNullException(nameof(securityPolicy));
        _accessPolicyEngine = accessPolicyEngine ?? throw new ArgumentNullException(nameof(accessPolicyEngine));
        _commandRiskClassifier = commandRiskClassifier ?? throw new ArgumentNullException(nameof(commandRiskClassifier));
        _toolOptions = toolOptions ?? throw new ArgumentNullException(nameof(toolOptions));
        _auditLogger = auditLogger;
    }

    /// <inheritdoc/>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The sessionAccessStore and orchestrator are owned by ManagedSession and will be disposed via ManagedSession.DisposeAsync()")]
    public ManagedSession Create(SessionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Validate ProjectPath is not a system directory (Layer 1 hard deny check)
        var validationRequest = new DirectoryAccessRequest(request.ProjectPath, AccessLevel.ReadWrite, "Session initialization");
        var validationResult = _accessPolicyEngine.EvaluateAsync(validationRequest, CancellationToken.None).GetAwaiter().GetResult();

        if (validationResult.Outcome == AccessOutcome.Denied)
        {
            throw new InvalidOperationException(
                $"Cannot create session with ProjectPath '{request.ProjectPath}': {string.Join(", ", validationResult.DeniedReasons)}");
        }

        // Generate new session ID
        var sessionId = Guid.NewGuid();

        // Create per-session CorrelationContext
        var correlationContext = new CorrelationContext(sessionId);

        // Create per-session InMemorySessionAccessStore
        var sessionAccessStore = new InMemorySessionAccessStore(_toolOptions.MaxConcurrentGrants);

        // Create per-session CommandApprovalCache
        var commandApprovalCache = new CommandApprovalCache();

        // Create per-session IToolRegistry with tools scoped to ProjectPath
        var toolRegistry = CreateSessionToolRegistry(request.ProjectPath, commandApprovalCache, correlationContext);

        // Create per-session ContextCompactor
        var contextCompactor = new ContextCompactor(
            _claudeClient,
            maxTokens: 200_000,
            compactionThreshold: 0.80,
            messagesToKeep: 6,
            auditLogger: _auditLogger,
            correlationContext: correlationContext,
            compactionClient: null);

        // Create per-session AgentOrchestrator
        var orchestrator = new AgentOrchestrator(
            claudeClient: _claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: _securityPolicy,
            toolTimeoutSeconds: 30,
            approvalTimeoutSeconds: 300,
            maxToolResultCharacters: 200_000,
            sessionAccessStore: sessionAccessStore,
            auditLogger: _auditLogger,
            correlationContext: correlationContext,
            contextCompactor: contextCompactor,
            commandApprovalCache: commandApprovalCache);

        // Create SessionBudget from request parameters
        var budget = new SessionBudget(
            maxTokens: request.MaxTokenBudget,
            maxToolCalls: request.MaxToolCallBudget);

        // Create and return ManagedSession
        return new ManagedSession(
            sessionId: sessionId,
            projectPath: request.ProjectPath,
            externalKey: request.ExternalKey,
            orchestrator: orchestrator,
            correlationContext: correlationContext,
            budget: budget,
            sessionAccessStore: sessionAccessStore);
    }

    /// <summary>
    /// Creates a per-session tool registry with tools scoped to the session's working directory.
    /// </summary>
    /// <param name="projectPath">The project directory path for this session.</param>
    /// <param name="commandApprovalCache">The per-session command approval cache.</param>
    /// <param name="correlationContext">The per-session correlation context.</param>
    /// <returns>A tool registry with tools scoped to the session's working directory.</returns>
    private ToolRegistry CreateSessionToolRegistry(
        string projectPath,
        ICommandApprovalCache commandApprovalCache,
        CorrelationContext correlationContext)
    {
        var registry = new ToolRegistry();

        // Create IFileOperations for this session
        var fileOperations = new SafeFileOperations(_auditLogger);

        // Create ICommandPolicy for this session
        var commandPolicy = new GraduatedCommandPolicy(
            _commandRiskClassifier,
            _securityPolicy,
            _accessPolicyEngine,
            _auditLogger,
            _toolOptions.CommandPolicy);

        // Create ICorrelationContextAccessor for this session
        var correlationContextAccessor = new CorrelationContextAccessor
        {
            Current = correlationContext
        };

        // Register read-only tools (auto-approve)
        registry.Register(new ReadFileTool(projectPath, fileOperations, _accessPolicyEngine));
        registry.Register(new ListFilesTool(projectPath, fileOperations, _accessPolicyEngine));
        registry.Register(new SearchFilesTool(projectPath, fileOperations, _accessPolicyEngine));

        // Register write tools (require approval)
        registry.Register(new WriteFileTool(projectPath, fileOperations, _accessPolicyEngine));
        registry.Register(new EditFileTool(projectPath, fileOperations, _accessPolicyEngine));

        // Register command execution tool (graduated approval)
        registry.Register(new RunCommandTool(
            projectPath,
            _securityPolicy,
            _toolOptions.CommandTimeoutSeconds,
            _accessPolicyEngine,
            commandPolicy,
            commandApprovalCache,
            correlationContextAccessor));

        return registry;
    }
}
