using System.Globalization;
using Anthropic.Exceptions;
using Krutaka.AI;
using Krutaka.Core;
using Krutaka.Memory;
using Serilog;
using Spectre.Console;

#pragma warning disable CA1031 // Some catch blocks intentionally catch Exception to prevent loop crashes

namespace Krutaka.Console;

/// <summary>
/// Encapsulates the main interactive console loop, including command handling,
/// agent turn execution, and error recovery.
/// </summary>
internal sealed class ConsoleRunLoop : IDisposable
{
    private readonly ConsoleUI _ui;
    private readonly ISessionManager _sessionManager;
    private readonly IAuditLogger _auditLogger;
    private readonly IServiceProvider _serviceProvider;
    private readonly string _workingDirectory;
    private readonly int _maxTokenBudget;
    private readonly int _maxToolCallBudget;

    private ManagedSession _currentSession;
    private SessionStore _currentSessionStore;
    private SystemPromptBuilder _systemPromptBuilder;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConsoleRunLoop"/> class.
    /// </summary>
    internal ConsoleRunLoop(
        ConsoleUI ui,
        ISessionManager sessionManager,
        IAuditLogger auditLogger,
        IServiceProvider serviceProvider,
        string workingDirectory,
        int maxTokenBudget,
        int maxToolCallBudget,
        ManagedSession initialSession,
        SessionStore initialSessionStore,
        SystemPromptBuilder initialSystemPromptBuilder)
    {
        _ui = ui;
        _sessionManager = sessionManager;
        _auditLogger = auditLogger;
        _serviceProvider = serviceProvider;
        _workingDirectory = workingDirectory;
        _maxTokenBudget = maxTokenBudget;
        _maxToolCallBudget = maxToolCallBudget;
        _currentSession = initialSession;
        _currentSessionStore = initialSessionStore;
        _systemPromptBuilder = initialSystemPromptBuilder;
    }

    /// <summary>
    /// Displays the banner and runs the main interaction loop until cancelled or the user exits.
    /// </summary>
    internal async Task RunAsync(CancellationToken cancellationToken)
    {
        _ui.DisplayBanner();

        while (!cancellationToken.IsCancellationRequested)
        {
            var input = _ui.GetUserInput();

            if (input == null || cancellationToken.IsCancellationRequested)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(input))
            {
                continue;
            }

            if (input.StartsWith('/'))
            {
                var shouldExit = await HandleCommandAsync(input.ToUpperInvariant().Trim(), cancellationToken).ConfigureAwait(false);
                if (shouldExit)
                {
                    break;
                }

                continue;
            }

            await ExecuteTurnAsync(input, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Handles a slash command. Returns <c>true</c> when the loop should exit.
    /// </summary>
    private async Task<bool> HandleCommandAsync(string command, CancellationToken cancellationToken)
    {
        if (command is "/EXIT" or "/QUIT")
        {
            return true;
        }

        if (command == "/HELP")
        {
            AnsiConsole.MarkupLine("[bold cyan]Available Commands:[/]");
            AnsiConsole.MarkupLine("  [cyan]/help[/]     - Show this help message");
            AnsiConsole.MarkupLine("  [cyan]/budget[/]   - Show task budget consumption");
            AnsiConsole.MarkupLine("  [cyan]/sessions[/] - List recent sessions for this project");
            AnsiConsole.MarkupLine("  [cyan]/new[/]      - Start a fresh session");
            AnsiConsole.MarkupLine("  [cyan]/resume[/]   - Reload current session from disk");
            AnsiConsole.MarkupLine("  [cyan]/autonomy[/] - Show current autonomy level");
            AnsiConsole.MarkupLine("  [cyan]/exit[/]     - Exit the application");
            AnsiConsole.MarkupLine("  [cyan]/quit[/]     - Exit the application");
            AnsiConsole.WriteLine();
            return false;
        }

        if (command == "/SESSIONS")
        {
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
                    var isCurrent = session.SessionId == _currentSession.SessionId ? "[green]►[/] " : "";
                    var shortId = session.SessionId.ToString("N")[..8];
                    var preview = session.FirstUserMessage ?? "(empty)";

                    table.AddRow(
                        $"{i + 1}",
                        $"{isCurrent}{shortId}...",
                        session.LastModified.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
                        session.MessageCount.ToString(CultureInfo.InvariantCulture),
                        Markup.Escape(preview));
                }

                AnsiConsole.Write(table);
                AnsiConsole.MarkupLine("[dim]Tip: Use /new to start a fresh session[/]");
            }

            AnsiConsole.WriteLine();
            return false;
        }

        if (command == "/NEW")
        {
            await StartNewSessionAsync(cancellationToken).ConfigureAwait(false);
            AnsiConsole.MarkupLine("[green]✓ Started new session[/]");
            Log.Information("User started new session {SessionId}", _currentSession.SessionId);
            AnsiConsole.WriteLine();
            return false;
        }

        if (command == "/RESUME")
        {
            try
            {
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
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Error reloading session: {Markup.Escape(ex.Message)}[/]");
                Log.Error(ex, "Failed to reload session");
            }

            AnsiConsole.WriteLine();
            return false;
        }

        if (command == "/AUTONOMY")
        {
            _ui.DisplayAutonomyLevel(_currentSession.AutonomyLevelProvider);
            return false;
        }

        if (command == "/BUDGET")
        {
            _ui.DisplayBudget(_currentSession.TaskBudgetTracker);
            return false;
        }

        AnsiConsole.MarkupLine($"[yellow]Unknown command: {Markup.Escape(command)}[/]");
        AnsiConsole.MarkupLine("[dim]Type /help for available commands[/]");
        AnsiConsole.WriteLine();
        return false;
    }

    /// <summary>
    /// Executes a single agent turn for the given user input.
    /// </summary>
    private async Task ExecuteTurnAsync(string input, CancellationToken cancellationToken)
    {
        try
        {
            _currentSession.CorrelationContext.IncrementTurn();
            _auditLogger.LogUserInput(_currentSession.CorrelationContext, input);

            var systemPrompt = await _systemPromptBuilder.BuildAsync(input, cancellationToken).ConfigureAwait(false);

            await _currentSessionStore.AppendAsync(
                new SessionEvent("user", "user", input, DateTimeOffset.UtcNow),
                cancellationToken).ConfigureAwait(false);

            var rawEvents = _currentSession.Orchestrator.RunAsync(input, systemPrompt, cancellationToken);
            var events = SessionEventPersistence.WrapWithSessionPersistence(rawEvents, _currentSessionStore, cancellationToken);
            await _ui.DisplayStreamingResponseAsync(
                events,
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
        catch (AnthropicBadRequestException ex)
        {
            await HandleApiErrorAsync(ex, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[red]Error: {Markup.Escape(ex.Message)}[/]");
            Log.Error(ex, "Unhandled exception in main loop");
            AnsiConsole.MarkupLine("[dim]Tip: If this error persists, try /new to start a fresh session[/]");
            AnsiConsole.WriteLine();
        }
    }

    /// <summary>
    /// Handles an <see cref="AnthropicBadRequestException"/> by offering the user reload or new-session recovery.
    /// </summary>
    private async Task HandleApiErrorAsync(AnthropicBadRequestException ex, CancellationToken cancellationToken)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[red]Error: The API returned a bad request error[/]");
        AnsiConsole.MarkupLine($"[dim]{Markup.Escape(ex.Message)}[/]");
        Log.Error(ex, "AnthropicBadRequestException in main loop");
        AnsiConsole.WriteLine();

        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<RecoveryOption>()
                .Title("How would you like to proceed?")
                .AddChoices(RecoveryOption.ReloadSession, RecoveryOption.StartNew)
                .UseConverter(option => option switch
                {
                    RecoveryOption.ReloadSession => "[yellow][[R]]eload session - Repair and reload from disk[/]",
                    RecoveryOption.StartNew => "[green][[N]]ew session - Start fresh[/]",
                    _ => option.ToString()
                }));

        if (choice == RecoveryOption.ReloadSession)
        {
            try
            {
                AnsiConsole.MarkupLine("[yellow]Reloading session from disk...[/]");
                var messages = await _currentSessionStore.ReconstructMessagesAsync(cancellationToken).ConfigureAwait(false);
                if (messages.Count == 0)
                {
                    // Intentionally restore with empty list to clear the in-memory conversation
                    // that caused the API error, preventing it from being retried.
                    _currentSession.Orchestrator.RestoreConversationHistory(messages);
                    AnsiConsole.MarkupLine("[yellow]Session is empty on disk. In-memory conversation cleared to recover from API error.[/]");
                    Log.Information("Session reloaded after API error with empty history - conversation cleared");
                }
                else
                {
                    _currentSession.Orchestrator.RestoreConversationHistory(messages);
                    AnsiConsole.MarkupLine($"[green]✓ Reloaded {messages.Count} messages from disk[/]");
                    Log.Information("Session reloaded after API error with {MessageCount} messages", messages.Count);
                }
            }
            catch (Exception reloadEx)
            {
                AnsiConsole.MarkupLine($"[red]Error reloading session: {Markup.Escape(reloadEx.Message)}[/]");
                AnsiConsole.MarkupLine("[yellow]Consider using /new to start a fresh session[/]");
                Log.Error(reloadEx, "Failed to reload session after API error");
            }
        }
        else
        {
            try
            {
                await StartNewSessionAsync(cancellationToken).ConfigureAwait(false);
                AnsiConsole.MarkupLine("[green]✓ Started new session[/]");
                Log.Information("User started new session after API error {SessionId}", _currentSession.SessionId);
            }
            catch (OperationCanceledException)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[yellow]⚠ Session creation cancelled during recovery[/]");
                Log.Information("Session creation cancelled during error recovery");
                throw;
            }
        }

        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Terminates the current session, creates a new one, and refreshes dependent builders.
    /// </summary>
    private async Task StartNewSessionAsync(CancellationToken cancellationToken)
    {
        await _sessionManager.TerminateSessionAsync(_currentSession.SessionId, cancellationToken).ConfigureAwait(false);
        _currentSessionStore.Dispose();

        var memoryWriter = ConsoleSessionHelpers.CreateMemoryWriter(_serviceProvider);
        var sessionRequest = new SessionRequest(
            ProjectPath: _workingDirectory,
            MaxTokenBudget: _maxTokenBudget,
            MaxToolCallBudget: _maxToolCallBudget,
            MemoryWriter: memoryWriter);

#pragma warning disable CA2000 // disposed on next /new or in Dispose()
        _currentSession = await _sessionManager.CreateSessionAsync(sessionRequest, cancellationToken).ConfigureAwait(false);
        _currentSessionStore = new SessionStore(_workingDirectory, _currentSession.SessionId);
#pragma warning restore CA2000

        var sessionToolRegistry = ConsoleSessionHelpers.CreateSessionToolRegistry(_currentSession);
        _systemPromptBuilder = ConsoleSessionHelpers.CreateSystemPromptBuilder(
            sessionToolRegistry, _workingDirectory, _serviceProvider);
    }

    /// <summary>Disposes the current session store.</summary>
    public void Dispose()
    {
        _currentSessionStore.Dispose();
    }
}
