using System.Globalization;
using Krutaka.AI;
using Krutaka.Core;
using Krutaka.Memory;
using Krutaka.Skills;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Spectre.Console;

namespace Krutaka.Console;

/// <summary>
/// Main console application logic, extracted for testability.
/// Handles session lifecycle, command processing, and user interactions.
/// </summary>
internal sealed class ConsoleApplication : IAsyncDisposable
{
    private readonly IConsoleUI _ui;
    private readonly ISessionManager _sessionManager;
    private readonly ISessionFactory _sessionFactory;
    private readonly IAuditLogger _auditLogger;
    private readonly IServiceProvider _serviceProvider;
    private readonly string _workingDirectory;

    private ManagedSession? _currentSession;
    private SessionStore? _currentSessionStore;
    private SystemPromptBuilder? _systemPromptBuilder;
    private IToolRegistry? _sessionToolRegistry;

    public ConsoleApplication(
        IConsoleUI ui,
        ISessionManager sessionManager,
        ISessionFactory sessionFactory,
        IAuditLogger auditLogger,
        IServiceProvider serviceProvider,
        string workingDirectory)
    {
        _ui = ui ?? throw new ArgumentNullException(nameof(ui));
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));
        _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        _workingDirectory = workingDirectory ?? throw new ArgumentNullException(nameof(workingDirectory));
    }

    /// <summary>
    /// Runs the main console application loop.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Initialize session
            await InitializeSessionAsync(cancellationToken).ConfigureAwait(false);

            // Display banner
            _ui.DisplayBanner();

            // Main interaction loop
            while (!cancellationToken.IsCancellationRequested)
            {
                var input = _ui.GetUserInput();

                // Handle Ctrl+C or null input
                if (input == null || cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                // Handle empty input
                if (string.IsNullOrWhiteSpace(input))
                {
                    continue;
                }

                // Handle commands
                if (input.StartsWith('/'))
                {
                    var shouldContinue = await HandleCommandAsync(input, cancellationToken).ConfigureAwait(false);
                    if (!shouldContinue)
                    {
                        break;
                    }

                    continue;
                }

                // Handle normal user input
                await ProcessUserInputAsync(input, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await ShutdownAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Initializes or resumes a session on startup.
    /// Implements the three-step resume pattern:
    /// 1. Create/resume session via SessionManager/SessionFactory
    /// 2. Load conversation history from SessionStore
    /// 3. Restore history into orchestrator
    /// </summary>
    private async Task InitializeSessionAsync(CancellationToken cancellationToken)
    {
        // Check if there's an existing session to auto-resume from disk
        Guid? existingSessionId = null;
        try
        {
            existingSessionId = SessionStore.FindMostRecentSession(_workingDirectory);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.Warning(ex, "Failed to discover existing sessions, will create new session");
        }

        if (existingSessionId.HasValue)
        {
            // Found a persisted session on disk - create a new session with the same ID to preserve identity
            Log.Information("Found existing session {SessionId}, creating with preserved ID", existingSessionId.Value);

            var sessionRequest = new SessionRequest(
                ProjectPath: _workingDirectory,
                MaxTokenBudget: 200_000,
                MaxToolCallBudget: 1000);

            // Use SessionFactory directly to create with preserved session ID
            _currentSession = _sessionFactory.Create(sessionRequest, existingSessionId.Value);

            // Step 2: Load conversation history from JSONL on disk
            _currentSessionStore = new SessionStore(_workingDirectory, _currentSession.SessionId);

            try
            {
                var messages = await _currentSessionStore.ReconstructMessagesAsync(cancellationToken).ConfigureAwait(false);

                // Step 3: Restore history into the new orchestrator
                if (messages.Count > 0)
                {
                    _currentSession.Orchestrator.RestoreConversationHistory(messages);
                    AnsiConsole.MarkupLine($"[dim]✓ Resumed session with {messages.Count} messages[/]");
                    Log.Information("Auto-resumed session with {MessageCount} messages", messages.Count);
                }
            }
            catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or UnauthorizedAccessException)
            {
                Log.Warning(ex, "Failed to auto-resume session history, continuing with empty session");
            }
        }
        else
        {
            // Create new session
            Log.Information("No previous session found, creating new session");
            var sessionRequest = new SessionRequest(
                ProjectPath: _workingDirectory,
                MaxTokenBudget: 200_000,
                MaxToolCallBudget: 1000);
            _currentSession = await _sessionManager.CreateSessionAsync(sessionRequest, cancellationToken).ConfigureAwait(false);
            _currentSessionStore = new SessionStore(_workingDirectory, _currentSession.SessionId);
            Log.Information("Created new session {SessionId}", _currentSession.SessionId);
        }

        // Create SystemPromptBuilder using the session's tool registry
        _sessionToolRegistry = ExtractToolRegistryFromSession(_currentSession);
        _systemPromptBuilder = CreateSystemPromptBuilder(_sessionToolRegistry);
    }

    /// <summary>
    /// Handles console commands like /new, /resume, /sessions, /exit, etc.
    /// </summary>
    /// <returns>True to continue the main loop, false to exit.</returns>
    private async Task<bool> HandleCommandAsync(string input, CancellationToken cancellationToken)
    {
        var command = input.ToUpperInvariant().Trim();

        if (command is "/EXIT" or "/QUIT")
        {
            return false;
        }
        else if (command == "/HELP")
        {
            DisplayHelp();
            return true;
        }
        else if (command == "/SESSIONS")
        {
            DisplaySessions();
            return true;
        }
        else if (command == "/NEW")
        {
            await HandleNewCommandAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        else if (command == "/RESUME")
        {
            await HandleResumeCommandAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        else
        {
            AnsiConsole.MarkupLine($"[yellow]Unknown command: {Markup.Escape(input)}[/]");
            AnsiConsole.MarkupLine("[dim]Type /help for available commands[/]");
            AnsiConsole.WriteLine();
            return true;
        }
    }

    /// <summary>
    /// Handles the /new command - terminates current session and creates a new one.
    /// </summary>
    private async Task HandleNewCommandAsync(CancellationToken cancellationToken)
    {
        if (_currentSession == null || _currentSessionStore == null)
        {
            throw new InvalidOperationException("No active session");
        }

        // Terminate the current session and dispose resources
        await _sessionManager.TerminateSessionAsync(_currentSession.SessionId, cancellationToken).ConfigureAwait(false);
        _currentSessionStore.Dispose();

        // Create new session via SessionManager
        var sessionRequest = new SessionRequest(
            ProjectPath: _workingDirectory,
            MaxTokenBudget: 200_000,
            MaxToolCallBudget: 1000);
        _currentSession = await _sessionManager.CreateSessionAsync(sessionRequest, cancellationToken).ConfigureAwait(false);
        _currentSessionStore = new SessionStore(_workingDirectory, _currentSession.SessionId);

        // Recreate SystemPromptBuilder with new session's tool registry
        _sessionToolRegistry = ExtractToolRegistryFromSession(_currentSession);
        _systemPromptBuilder = CreateSystemPromptBuilder(_sessionToolRegistry);

        AnsiConsole.MarkupLine("[green]✓ Started new session[/]");
        Log.Information("User started new session {SessionId}", _currentSession.SessionId);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Handles the /resume command - reloads current session from disk.
    /// </summary>
    private async Task HandleResumeCommandAsync(CancellationToken cancellationToken)
    {
        if (_currentSession == null || _currentSessionStore == null)
        {
            throw new InvalidOperationException("No active session");
        }

        try
        {
            // Reload current session from disk using three-step pattern
            var messages = await _currentSessionStore.ReconstructMessagesAsync(cancellationToken).ConfigureAwait(false);
            if (messages.Count == 0)
            {
                AnsiConsole.MarkupLine("[yellow]Current session is empty.[/]");
            }
            else
            {
                _currentSession.Orchestrator.RestoreConversationHistory(messages);
                AnsiConsole.MarkupLine($"[green]✓ Reloaded {messages.Count} messages from disk[/]");
                Log.Information("Session reloaded with {MessageCount} messages", messages.Count);
            }
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
#pragma warning restore CA1031
        {
            AnsiConsole.MarkupLine($"[red]Error reloading session: {Markup.Escape(ex.Message)}[/]");
            Log.Error(ex, "Failed to reload session");
        }

        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Displays help message with available commands.
    /// </summary>
    private static void DisplayHelp()
    {
        AnsiConsole.MarkupLine("[bold cyan]Available Commands:[/]");
        AnsiConsole.MarkupLine("  [cyan]/help[/]     - Show this help message");
        AnsiConsole.MarkupLine("  [cyan]/sessions[/] - List recent sessions for this project");
        AnsiConsole.MarkupLine("  [cyan]/new[/]      - Start a fresh session");
        AnsiConsole.MarkupLine("  [cyan]/resume[/]   - Reload current session from disk");
        AnsiConsole.MarkupLine("  [cyan]/exit[/]     - Exit the application");
        AnsiConsole.MarkupLine("  [cyan]/quit[/]     - Exit the application");
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Displays list of active and persisted sessions.
    /// </summary>
    private void DisplaySessions()
    {
        // Combine active sessions from SessionManager with persisted sessions from disk
        var activeSessions = _sessionManager.ListActiveSessions();
        var persistedSessions = SessionStore.ListSessions(_workingDirectory, limit: 10);

        if (persistedSessions.Count == 0 && activeSessions.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No previous sessions found for this project.[/]");
        }
        else
        {
            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Grey)
                .AddColumn("#")
                .AddColumn("Session ID")
                .AddColumn("Last Modified")
                .AddColumn("Messages")
                .AddColumn("Preview");

            for (int i = 0; i < persistedSessions.Count; i++)
            {
                var session = persistedSessions[i];
                var isCurrent = session.SessionId == _currentSession?.SessionId ? "[green]►[/] " : "";
                var shortId = session.SessionId.ToString("N")[..8]; // N format is 32 chars without hyphens
                var preview = session.FirstUserMessage ?? "(empty)";

                table.AddRow(
                    $"{i + 1}",
                    $"{isCurrent}{shortId}...",
                    session.LastModified.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
                    session.MessageCount.ToString(CultureInfo.InvariantCulture),
                    Markup.Escape(preview)
                );
            }

            AnsiConsole.Write(table);
            AnsiConsole.MarkupLine("[dim]Tip: Use /new to start a fresh session[/]");
        }

        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Processes normal user input (not a command).
    /// </summary>
    private async Task ProcessUserInputAsync(string input, CancellationToken cancellationToken)
    {
        if (_currentSession == null || _currentSessionStore == null || _systemPromptBuilder == null)
        {
            throw new InvalidOperationException("Session not initialized");
        }

        try
        {
            // Increment turn ID for new user input
            _currentSession.CorrelationContext.IncrementTurn();

            // Log user input
            _auditLogger.LogUserInput(_currentSession.CorrelationContext, input);

            // Build system prompt
            var systemPrompt = await _systemPromptBuilder.BuildAsync(input, cancellationToken).ConfigureAwait(false);

            // Log session event
            await _currentSessionStore.AppendAsync(
                new SessionEvent("user", "user", input, DateTimeOffset.UtcNow),
                cancellationToken).ConfigureAwait(false);

            // Run agent orchestrator and display streaming response
            var rawEvents = _currentSession.Orchestrator.RunAsync(input, systemPrompt, cancellationToken);
            var events = WrapWithSessionPersistence(rawEvents, _currentSessionStore, cancellationToken);
            await _ui.DisplayStreamingResponseAsync(events,
                onApprovalDecision: (toolUseId, approved, alwaysApprove) =>
                {
                    if (approved)
                    {
                        _currentSession.Orchestrator.ApproveTool(toolUseId, alwaysApprove);
                    }
                    else
                    {
                        _currentSession.Orchestrator.DenyTool(toolUseId);
                    }
                },
                onDirectoryAccessDecision: (approved, grantedLevel, createSessionGrant) =>
                {
                    if (approved && grantedLevel.HasValue)
                    {
                        _currentSession.Orchestrator.ApproveDirectoryAccess(grantedLevel.Value, createSessionGrant);
                    }
                    else
                    {
                        _currentSession.Orchestrator.DenyDirectoryAccess();
                    }
                },
                onCommandApprovalDecision: (approved, alwaysApprove) =>
                {
                    if (approved)
                    {
                        _currentSession.Orchestrator.ApproveCommand(alwaysApprove);
                    }
                    else
                    {
                        _currentSession.Orchestrator.DenyCommand();
                    }
                },
                cancellationToken: cancellationToken).ConfigureAwait(false);

            AnsiConsole.WriteLine();
            AnsiConsole.WriteLine();
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]⚠ Operation cancelled[/]");
            AnsiConsole.WriteLine();
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
#pragma warning restore CA1031
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[red]Error: {Markup.Escape(ex.Message)}[/]");
            Log.Error(ex, "Unhandled exception in main loop");
            AnsiConsole.WriteLine();
        }
    }

    /// <summary>
    /// Extracts the tool registry from a session using reflection.
    /// </summary>
    private static IToolRegistry ExtractToolRegistryFromSession(ManagedSession session)
    {
        var orchestratorType = session.Orchestrator.GetType();
        var toolRegistryField = orchestratorType.GetField("_toolRegistry", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        if (toolRegistryField != null)
        {
            var registry = toolRegistryField.GetValue(session.Orchestrator) as IToolRegistry;
            if (registry != null)
            {
                return registry;
            }
        }

        throw new InvalidOperationException("Unable to extract tool registry from session. This is a programming error.");
    }

    /// <summary>
    /// Creates a SystemPromptBuilder for the current session.
    /// </summary>
    private SystemPromptBuilder CreateSystemPromptBuilder(IToolRegistry toolRegistry)
    {
        // Try to locate AGENTS.md in multiple locations
        var agentsPromptPath = Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..", // Navigate to repo root from bin/Debug/net10.0-windows
            "prompts", "AGENTS.md");

        // Normalize the path
        agentsPromptPath = Path.GetFullPath(agentsPromptPath);

        // Fallback 1: Check if running from published location
        if (!File.Exists(agentsPromptPath))
        {
            agentsPromptPath = Path.Combine(AppContext.BaseDirectory, "prompts", "AGENTS.md");
        }

        // Fallback 2: Try current working directory
        if (!File.Exists(agentsPromptPath))
        {
            agentsPromptPath = Path.Combine(_workingDirectory, "prompts", "AGENTS.md");
        }

        // Final check - if still not found, log warning and use empty path (will fail at runtime)
        if (!File.Exists(agentsPromptPath))
        {
            Log.Warning("AGENTS.md not found. SystemPromptBuilder may fail at runtime. Searched: {BaseDir}, {WorkingDir}",
                AppContext.BaseDirectory, _workingDirectory);
            agentsPromptPath = "prompts/AGENTS.md"; // Let it fail with a clear error
        }

        var skillRegistry = _serviceProvider.GetService<ISkillRegistry>();
        var memoryService = _serviceProvider.GetService<IMemoryService>();
        var memoryFileService = _serviceProvider.GetService<MemoryFileService>();
        var commandRiskClassifier = _serviceProvider.GetService<ICommandRiskClassifier>();

        Func<CancellationToken, Task<string>>? memoryFileReader = null;
        if (memoryFileService != null)
        {
            memoryFileReader = async (ct) => await memoryFileService.ReadMemoryAsync(ct).ConfigureAwait(false);
        }

        return new SystemPromptBuilder(
            toolRegistry,
            agentsPromptPath,
            skillRegistry,
            memoryService,
            memoryFileReader,
            commandRiskClassifier);
    }

    /// <summary>
    /// Wraps an event stream with session persistence.
    /// </summary>
    private static async IAsyncEnumerable<AgentEvent> WrapWithSessionPersistence(
        IAsyncEnumerable<AgentEvent> events,
        SessionStore sessionStore,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var textAccumulator = new System.Text.StringBuilder();

        await foreach (var evt in events.WithCancellation(cancellationToken))
        {
            switch (evt)
            {
                case TextDelta delta:
                    textAccumulator.Append(delta.Text);
                    break;

                case ToolCallStarted tool:
                    // Flush accumulated assistant text before tool_use event
                    if (textAccumulator.Length > 0)
                    {
                        await sessionStore.AppendAsync(
                            new SessionEvent("assistant", "assistant", textAccumulator.ToString(), DateTimeOffset.UtcNow),
                            cancellationToken).ConfigureAwait(false);
                        textAccumulator.Clear();
                    }

                    await sessionStore.AppendAsync(
                        new SessionEvent("tool_use", "assistant", tool.Input, DateTimeOffset.UtcNow, tool.ToolName, tool.ToolUseId),
                        cancellationToken).ConfigureAwait(false);
                    break;

                case ToolCallCompleted tool:
                    await sessionStore.AppendAsync(
                        new SessionEvent("tool_result", "user", tool.Result, DateTimeOffset.UtcNow, tool.ToolName, tool.ToolUseId),
                        cancellationToken).ConfigureAwait(false);
                    break;

                case ToolCallFailed tool:
                    await sessionStore.AppendAsync(
                        new SessionEvent("tool_error", "user", tool.Error, DateTimeOffset.UtcNow, tool.ToolName, tool.ToolUseId),
                        cancellationToken).ConfigureAwait(false);
                    break;

                case FinalResponse final:
                    if (textAccumulator.Length > 0 || !string.IsNullOrEmpty(final.Content))
                    {
                        var content = textAccumulator.Length > 0 ? textAccumulator.ToString() : final.Content;
                        await sessionStore.AppendAsync(
                            new SessionEvent("assistant", "assistant", content, DateTimeOffset.UtcNow),
                            cancellationToken).ConfigureAwait(false);
                    }

                    textAccumulator.Clear();
                    break;
            }

            yield return evt;
        }
    }

    /// <summary>
    /// Performs graceful shutdown, disposing resources.
    /// </summary>
    private async Task ShutdownAsync()
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[dim]Shutting down...[/]");

        Log.Information("Krutaka shutting down");

        // Dispose current session store
        _currentSessionStore?.Dispose();

        // Dispose current session
        if (_currentSession != null)
        {
            await _currentSession.DisposeAsync().ConfigureAwait(false);
        }

        // Dispose session manager (terminates all active sessions)
        await _sessionManager.DisposeAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await ShutdownAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
}
