using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace Krutaka.Core;

/// <summary>
/// Orchestrates the agentic loop: sends messages to Claude, processes tool calls,
/// enforces security policies, and manages conversation state.
/// Implements Pattern A (manual loop with full control) for transparency, audit logging,
/// and human-in-the-loop approvals.
/// </summary>
/// <remarks>
/// This class is split across multiple partial files:
/// <list type="bullet">
///   <item><term>AgentOrchestrator.cs</term><description>Core fields, constructor, public API, and records.</description></item>
///   <item><term>AgentOrchestrator.ToolCallLoop.cs</term><description>Agentic loop and per-tool-call pipeline.</description></item>
///   <item><term>AgentOrchestrator.StateMachine.cs</term><description>State machine helpers (pause/resume polling).</description></item>
///   <item><term>AgentOrchestrator.Helpers.cs</term><description>Message factories and context compaction.</description></item>
///   <item><term>AgentOrchestrator.ToolExecution.cs</term><description>Tool execution, result truncation, and pruning.</description></item>
/// </list>
/// </remarks>
public sealed partial class AgentOrchestrator : IDisposable
{
    private readonly IClaudeClient _claudeClient;
    private readonly IToolRegistry _toolRegistry;
    private readonly ISecurityPolicy _securityPolicy;
    private readonly ISessionAccessStore? _sessionAccessStore;
    private readonly IAuditLogger? _auditLogger;
    private readonly CorrelationContext? _correlationContext;
    private readonly ContextCompactor? _contextCompactor;
    private readonly int _maxToolResultCharacters;
    private readonly TimeSpan _toolTimeout;
    private readonly TimeSpan _approvalTimeout;
    private readonly int _pruneToolResultsAfterTurns;
    private readonly int _pruneToolResultMinChars;
    private readonly SemaphoreSlim _turnLock;
    private readonly List<object> _conversationHistory;
    private readonly object _conversationHistoryLock = new(); // Protects conversation history for thread-safe access
    private readonly ConcurrentDictionary<string, bool> _approvalCache; // Tracks approved tools for session (thread-safe)
    private readonly ICommandApprovalCache? _commandApprovalCache; // Tracks approved command signatures (v0.3.0, injected from DI)
    private readonly IAgentStateManager? _stateManager; // Optional state machine for pause/resume/abort (v0.5.0)
    private readonly IAutonomyLevelProvider? _autonomyLevelProvider; // Optional autonomy level provider for auto-approval decisions (v0.5.0)
    private readonly ITaskBudgetTracker? _budgetTracker; // Optional per-session budget tracker (v0.5.0)
    private readonly HashSet<BudgetDimension> _budgetWarnedDimensions = []; // Tracks which dimensions have already fired BudgetWarning
    private bool _budgetExhausted; // Set when TryConsume actually fails mid-loop; drives inner/outer loop exit regardless of _stateManager presence
    private readonly ConcurrentDictionary<string, bool> _sessionCommandApprovals = new(); // Tracks session-level "Always" command approvals (v0.3.0)
    private readonly object _approvalStateLock = new(); // Protects approval state fields from race conditions
    private TaskCompletionSource<bool>? _pendingApproval; // Blocks until approval/denial decision for tools
    private string? _pendingToolUseId; // Tracks the tool_use_id of the pending approval request
    private string? _pendingToolName; // Tracks the tool name of the pending approval request
    private TaskCompletionSource<DirectoryAccessApprovalResult>? _pendingDirectoryApproval; // Blocks until directory access approval/denial
    private TaskCompletionSource<bool>? _pendingCommandApproval; // Blocks until command approval/denial (v0.3.0)
    private bool _pendingCommandAlwaysApprove; // Tracks if "Always" was selected for pending command approval
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentOrchestrator"/> class.
    /// </summary>
    /// <param name="claudeClient">The Claude API client.</param>
    /// <param name="toolRegistry">The tool registry for executing tools.</param>
    /// <param name="securityPolicy">The security policy for approval checks.</param>
    /// <param name="toolTimeoutSeconds">Timeout for tool execution in seconds (default: 30).</param>
    /// <param name="approvalTimeoutSeconds">Timeout for human approval waits in seconds (default: 300 = 5 minutes, 0 = infinite).</param>
    /// <param name="maxToolResultCharacters">Maximum characters allowed in a single tool result before truncation.
    /// Defaults to 200,000 (~50K tokens). Values less than or equal to 0 use the default.</param>
    /// <param name="sessionAccessStore">Optional session access store for directory access grants (v0.2.0).</param>
    /// <param name="auditLogger">Optional audit logger for structured logging.</param>
    /// <param name="correlationContext">Optional correlation context for request tracing.</param>
    /// <param name="contextCompactor">Optional context compactor for automatic context window management.</param>
    /// <param name="commandApprovalCache">Optional command approval cache for graduated command execution (v0.3.0).</param>
    /// <param name="pruneToolResultsAfterTurns">Number of turns after which large tool results are pruned (default: 6). v0.4.5 feature.</param>
    /// <param name="pruneToolResultMinChars">Minimum character count for tool result pruning (default: 1000). v0.4.5 feature.</param>
    /// <param name="stateManager">Optional state manager for pause/resume/abort lifecycle control (v0.5.0).</param>
    /// <param name="autonomyLevelProvider">Optional autonomy level provider for graduated auto-approval decisions (v0.5.0).</param>
    /// <param name="budgetTracker">Optional per-session task budget tracker for enforcing token/tool/file/process limits (v0.5.0).</param>
    public AgentOrchestrator(
        IClaudeClient claudeClient,
        IToolRegistry toolRegistry,
        ISecurityPolicy securityPolicy,
        int toolTimeoutSeconds = 30,
        int approvalTimeoutSeconds = 300,
        int maxToolResultCharacters = DefaultMaxToolResultCharacters,
        ISessionAccessStore? sessionAccessStore = null,
        IAuditLogger? auditLogger = null,
        CorrelationContext? correlationContext = null,
        ContextCompactor? contextCompactor = null,
        ICommandApprovalCache? commandApprovalCache = null,
        int pruneToolResultsAfterTurns = 6,
        int pruneToolResultMinChars = 1000,
        IAgentStateManager? stateManager = null,
        IAutonomyLevelProvider? autonomyLevelProvider = null,
        ITaskBudgetTracker? budgetTracker = null)
    {
        _claudeClient = claudeClient ?? throw new ArgumentNullException(nameof(claudeClient));
        _toolRegistry = toolRegistry ?? throw new ArgumentNullException(nameof(toolRegistry));
        _securityPolicy = securityPolicy ?? throw new ArgumentNullException(nameof(securityPolicy));
        _sessionAccessStore = sessionAccessStore;
        _auditLogger = auditLogger;
        _correlationContext = correlationContext;
        _commandApprovalCache = commandApprovalCache;
        _contextCompactor = contextCompactor;
        _stateManager = stateManager;
        _autonomyLevelProvider = autonomyLevelProvider;
        _budgetTracker = budgetTracker;
        _maxToolResultCharacters = maxToolResultCharacters > 0 ? maxToolResultCharacters : DefaultMaxToolResultCharacters;
        _toolTimeout = TimeSpan.FromSeconds(toolTimeoutSeconds);
        if (approvalTimeoutSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(approvalTimeoutSeconds), "Approval timeout must be non-negative (0 = infinite).");
        }

        if (pruneToolResultsAfterTurns < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pruneToolResultsAfterTurns), "Prune tool results after turns must be non-negative.");
        }

        if (pruneToolResultMinChars < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(pruneToolResultMinChars), "Prune tool result minimum characters must be non-negative.");
        }

        _approvalTimeout = approvalTimeoutSeconds == 0 ? Timeout.InfiniteTimeSpan : TimeSpan.FromSeconds(approvalTimeoutSeconds);
        _pruneToolResultsAfterTurns = pruneToolResultsAfterTurns;
        _pruneToolResultMinChars = pruneToolResultMinChars;
        _turnLock = new SemaphoreSlim(1, 1);
        _conversationHistory = [];
        _approvalCache = new ConcurrentDictionary<string, bool>();
    }

    /// <summary>
    /// Gets the current conversation history.
    /// Thread-safe: Returns a defensive copy of the conversation history.
    /// Uses a dedicated lock to avoid deadlocks during event handling.
    /// </summary>
    public IReadOnlyList<object> ConversationHistory
    {
        get
        {
            lock (_conversationHistoryLock)
            {
                // Return a defensive copy to prevent concurrent modification during enumeration
                return _conversationHistory.ToList().AsReadOnly();
            }
        }
    }

    /// <summary>
    /// Restores conversation history from a previous session.
    /// Used by the /resume command to continue previous conversations.
    /// Acquires the turn lock to prevent races with concurrent RunAsync calls.
    /// </summary>
    /// <param name="messages">The messages to restore from a previous session.</param>
    public void RestoreConversationHistory(IReadOnlyList<object> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ObjectDisposedException.ThrowIf(_disposed, this);

        _turnLock.Wait();
        try
        {
            lock (_conversationHistoryLock)
            {
                _conversationHistory.Clear();
                _conversationHistory.AddRange(messages);
            }
        }
        finally
        {
            _turnLock.Release();
        }
    }

    /// <summary>
    /// Clears the conversation history.
    /// Used by the /new command to start a fresh session.
    /// </summary>
    public void ClearConversationHistory()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _turnLock.Wait();
        try
        {
            lock (_conversationHistoryLock)
            {
                _conversationHistory.Clear();
            }

            _approvalCache.Clear();
        }
        finally
        {
            _turnLock.Release();
        }
    }

    /// <summary>
    /// Runs the agentic loop for a single user turn.
    /// Sends the user prompt to Claude, processes tool calls, and yields events.
    /// </summary>
    /// <param name="userPrompt">The user's prompt/message.</param>
    /// <param name="systemPrompt">The system prompt defining agent behavior.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>An async stream of agent events.</returns>
    public async IAsyncEnumerable<AgentEvent> RunAsync(
        string userPrompt,
        string systemPrompt,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (string.IsNullOrWhiteSpace(userPrompt))
        {
            throw new ArgumentException("User prompt cannot be null or whitespace.", nameof(userPrompt));
        }

        if (string.IsNullOrWhiteSpace(systemPrompt))
        {
            throw new ArgumentException("System prompt cannot be null or whitespace.", nameof(systemPrompt));
        }

        // Acquire turn lock to serialize execution
        await _turnLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            // Add user message to conversation history
            var userMessage = CreateUserMessage(userPrompt);
            lock (_conversationHistoryLock)
            {
                _conversationHistory.Add(userMessage);
            }

            // Run the agentic loop until we get a final response
            await foreach (var evt in RunAgenticLoopAsync(systemPrompt, cancellationToken).ConfigureAwait(false))
            {
                yield return evt;
            }
        }
        finally
        {
            _turnLock.Release();
        }
    }

    /// <summary>
    /// Approves a pending tool call. This should be called in response to HumanApprovalRequired events.
    /// Unblocks the orchestrator to proceed with tool execution.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    /// <param name="toolUseId">The tool use ID to approve (must match the pending request).</param>
    /// <param name="alwaysApprove">Whether to always approve this tool for the session.</param>
    public void ApproveTool(string toolUseId, bool alwaysApprove = false)
    {
        if (string.IsNullOrWhiteSpace(toolUseId))
        {
            throw new ArgumentException("Tool use ID cannot be null or whitespace.", nameof(toolUseId));
        }

        // Lock to prevent race conditions between approval validation and TCS completion
        lock (_approvalStateLock)
        {
            // Validate that the approval matches the currently pending tool request
            if (_pendingToolUseId != null && _pendingToolUseId != toolUseId)
            {
                throw new InvalidOperationException(
                    $"Approval for tool use '{toolUseId}' does not match the pending request '{_pendingToolUseId}'.");
            }

            // Check if there's actually a pending approval (could be cancelled or already handled)
            if (_pendingApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            if (alwaysApprove && _pendingToolName != null)
            {
                _approvalCache[_pendingToolName] = true;
            }

            // Signal the pending approval to proceed
            _pendingApproval.TrySetResult(true);
        }
    }

    /// <summary>
    /// Denies a pending tool call. This should be called in response to HumanApprovalRequired events.
    /// The tool will not be executed and a denial message is returned to Claude.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    /// <param name="toolUseId">The tool use ID to deny (must match the pending request).</param>
    public void DenyTool(string toolUseId)
    {
        if (string.IsNullOrWhiteSpace(toolUseId))
        {
            throw new ArgumentException("Tool use ID cannot be null or whitespace.", nameof(toolUseId));
        }

        // Lock to prevent race conditions between denial validation and TCS completion
        lock (_approvalStateLock)
        {
            // Validate that the denial matches the currently pending tool request
            if (_pendingToolUseId != null && _pendingToolUseId != toolUseId)
            {
                throw new InvalidOperationException(
                    $"Denial for tool use '{toolUseId}' does not match the pending request '{_pendingToolUseId}'.");
            }

            // Check if there's actually a pending approval (could be cancelled or already handled)
            if (_pendingApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Signal the pending approval as denied
            _pendingApproval.TrySetResult(false);
        }
    }

    /// <summary>
    /// Approves a pending directory access request. This should be called in response to DirectoryAccessRequested events.
    /// Unblocks the orchestrator to retry tool execution with the granted access.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    /// <param name="grantedLevel">The access level to grant (may be downgraded from requested).</param>
    /// <param name="createSessionGrant">Whether to create a session-wide grant for this path.</param>
    public void ApproveDirectoryAccess(AccessLevel grantedLevel, bool createSessionGrant = false)
    {
        // Lock to prevent race conditions with cancellation
        lock (_approvalStateLock)
        {
            // Check if there's actually a pending directory approval
            if (_pendingDirectoryApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Signal the pending directory approval to proceed
            _pendingDirectoryApproval.TrySetResult(new DirectoryAccessApprovalResult(true, grantedLevel, createSessionGrant));
        }
    }

    /// <summary>
    /// Denies a pending directory access request. This should be called in response to DirectoryAccessRequested events.
    /// The tool will fail with a denial message.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    public void DenyDirectoryAccess()
    {
        // Lock to prevent race conditions with cancellation
        lock (_approvalStateLock)
        {
            // Check if there's actually a pending directory approval
            if (_pendingDirectoryApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Signal the pending directory approval as denied
            _pendingDirectoryApproval.TrySetResult(new DirectoryAccessApprovalResult(false, null, false));
        }
    }

    /// <summary>
    /// Approves a pending command execution request. This should be called in response to CommandApprovalRequested events.
    /// Unblocks the orchestrator to execute the command.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    /// <param name="alwaysApprove">If true, caches this command signature for session-level auto-approval (Moderate tier only).</param>
    public void ApproveCommand(bool alwaysApprove = false)
    {
        // Lock to prevent race conditions with cancellation
        lock (_approvalStateLock)
        {
            // Check if there's actually a pending command approval
            if (_pendingCommandApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Store the alwaysApprove flag for the orchestrator to use when adding to cache
            _pendingCommandAlwaysApprove = alwaysApprove;

            // Signal the pending command approval to proceed
            _pendingCommandApproval.TrySetResult(true);
        }
    }

    /// <summary>
    /// Denies a pending command execution request. This should be called in response to CommandApprovalRequested events.
    /// The tool will fail with a denial message.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    public void DenyCommand()
    {
        // Lock to prevent race conditions with cancellation
        lock (_approvalStateLock)
        {
            // Check if there's actually a pending command approval
            if (_pendingCommandApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Signal the pending command approval as denied
            _pendingCommandApproval.TrySetResult(false);
        }
    }

    /// <summary>
    /// Disposes the orchestrator and releases resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _turnLock.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Default maximum number of characters allowed in a single tool result before truncation.
    /// Approximately 200K characters ≈ 50K tokens, leaving ample room for the rest of the
    /// conversation, system prompt, and tool definitions within the 200K token API limit.
    /// Configurable via <c>Agent:MaxToolResultCharacters</c> in appsettings.json.
    /// </summary>
    public const int DefaultMaxToolResultCharacters = 200_000;

    /// <summary>
    /// Represents a tool call extracted from the assistant's response.
    /// </summary>
    private sealed record ToolCall(string Name, string Id, string Input);

    /// <summary>
    /// Represents the result of a tool execution.
    /// </summary>
    private sealed record ToolResult(string Content, bool IsError);
}
