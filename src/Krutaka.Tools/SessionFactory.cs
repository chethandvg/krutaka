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
        return CreateInternal(request, sessionId: null);
    }

    /// <inheritdoc/>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The sessionAccessStore and orchestrator are owned by ManagedSession and will be disposed via ManagedSession.DisposeAsync()")]
    public ManagedSession Create(SessionRequest request, Guid sessionId)
    {
        // Validate sessionId is not Guid.Empty to prevent ID collisions and maintain session identity invariant
        if (sessionId == Guid.Empty)
        {
            throw new ArgumentException("Session ID cannot be Guid.Empty. A valid non-empty GUID is required for session identity.", nameof(sessionId));
        }

        return CreateInternal(request, sessionId);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The sessionAccessStore and orchestrator are owned by ManagedSession and will be disposed via ManagedSession.DisposeAsync()")]
    private ManagedSession CreateInternal(SessionRequest request, Guid? sessionId)
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

        // Use provided session ID or generate new GUID
        var actualSessionId = sessionId ?? Guid.NewGuid();

        // Create per-session CorrelationContext
        var correlationContext = new CorrelationContext(actualSessionId);

        // Create per-session InMemorySessionAccessStore
        var sessionAccessStore = new InMemorySessionAccessStore(_toolOptions.MaxConcurrentGrants);

        // Create per-session IAccessPolicyEngine wired to the session's access store (Layer 3 grants)
        // This ensures directory grants approved during this session are visible to tools and command policy
        var fileOperations = new SafeFileOperations(_auditLogger);
        var sessionAccessPolicyEngine = new LayeredAccessPolicyEngine(
            fileOperations,
            _toolOptions.CeilingDirectory,
            _toolOptions.AutoGrantPatterns,
            sessionAccessStore);

        // Create per-session CommandApprovalCache
        var commandApprovalCache = new CommandApprovalCache();

        // Create per-session IToolRegistry with tools scoped to ProjectPath
        var toolRegistry = CreateSessionToolRegistry(request.ProjectPath, sessionAccessPolicyEngine, commandApprovalCache, correlationContext);

        // Create per-session ContextCompactor with optional memory writer from request
        var contextCompactor = new ContextCompactor(
            _claudeClient,
            maxTokens: 200_000,
            compactionThreshold: 0.80,
            messagesToKeep: 6,
            auditLogger: _auditLogger,
            correlationContext: correlationContext,
            compactionClient: null,
            memoryWriter: request.MemoryWriter);

        // Create per-session AgentOrchestrator
        var orchestrator = new AgentOrchestrator(
            claudeClient: _claudeClient,
            toolRegistry: toolRegistry,
            securityPolicy: _securityPolicy,
            toolTimeoutSeconds: _toolOptions.ToolTimeoutSeconds,
            approvalTimeoutSeconds: _toolOptions.ApprovalTimeoutSeconds,
            maxToolResultCharacters: _toolOptions.MaxToolResultCharacters,
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
            sessionId: actualSessionId,
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
    /// <param name="sessionAccessPolicyEngine">The per-session access policy engine wired to the session's access store.</param>
    /// <param name="commandApprovalCache">The per-session command approval cache.</param>
    /// <param name="correlationContext">The per-session correlation context.</param>
    /// <returns>A tool registry with tools scoped to the session's working directory.</returns>
    private ToolRegistry CreateSessionToolRegistry(
        string projectPath,
        IAccessPolicyEngine sessionAccessPolicyEngine,
        ICommandApprovalCache commandApprovalCache,
        CorrelationContext correlationContext)
    {
        var registry = new ToolRegistry();

        // Create IFileOperations for this session
        var fileOperations = new SafeFileOperations(_auditLogger);

        // Create ICommandPolicy for this session (using per-session access policy engine)
        var commandPolicy = new GraduatedCommandPolicy(
            _commandRiskClassifier,
            _securityPolicy,
            sessionAccessPolicyEngine,
            _auditLogger,
            _toolOptions.CommandPolicy);

        // Create ICorrelationContextAccessor for this session
        var correlationContextAccessor = new CorrelationContextAccessor
        {
            Current = correlationContext
        };

        // Register read-only tools (auto-approve) - using per-session access policy engine
        registry.Register(new ReadFileTool(projectPath, fileOperations, sessionAccessPolicyEngine));
        registry.Register(new ListFilesTool(projectPath, fileOperations, sessionAccessPolicyEngine));
        registry.Register(new SearchFilesTool(projectPath, fileOperations, sessionAccessPolicyEngine));

        // Register write tools (require approval) - using per-session access policy engine
        registry.Register(new WriteFileTool(projectPath, fileOperations, sessionAccessPolicyEngine));
        registry.Register(new EditFileTool(projectPath, fileOperations, sessionAccessPolicyEngine));

        // Register command execution tool (graduated approval) - using per-session access policy engine
        registry.Register(new RunCommandTool(
            projectPath,
            _securityPolicy,
            _toolOptions.CommandTimeoutSeconds,
            sessionAccessPolicyEngine,
            commandPolicy,
            commandApprovalCache,
            correlationContextAccessor));

        return registry;
    }
}
