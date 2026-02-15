using System.Globalization;
using Krutaka.AI;
using Krutaka.Console;
using Krutaka.Console.Logging;
using Krutaka.Core;
using Krutaka.Memory;
using Krutaka.Skills;
using Krutaka.Tools;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Spectre.Console;

// ========================================
// Serilog Configuration
// ========================================

// Configure log path in ~/.krutaka/logs/
var krutakaDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".krutaka");
var logsDir = Path.Combine(krutakaDir, "logs");
Directory.CreateDirectory(logsDir);

var logPath = Path.Combine(logsDir, "krutaka-.log");
var auditLogPath = Path.Combine(logsDir, "audit-.json");

// Create Serilog logger with file output and redaction
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("System", Serilog.Events.LogEventLevel.Warning)
    .Enrich.With<LogRedactionEnricher>()
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}",
        formatProvider: CultureInfo.InvariantCulture)
    .WriteTo.File(
        logPath,
        rollingInterval: RollingInterval.Day,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
        retainedFileCountLimit: 30,
        formatProvider: CultureInfo.InvariantCulture)
    .WriteTo.Logger(lc => lc
        .Filter.ByIncludingOnly(evt => 
            evt.Properties.ContainsKey("EventType") && 
            evt.MessageTemplate.Text.StartsWith("Audit:", StringComparison.Ordinal))
        .WriteTo.File(
            new Serilog.Formatting.Json.JsonFormatter(),
            auditLogPath,
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 30))
    .CreateLogger();

try
{
    // ========================================
    // First-Run Detection
    // ========================================

    // Check if API key exists, run setup wizard if not
    if (!SecretsProvider.HasStoredCredential())
    {
        AnsiConsole.MarkupLine("[yellow]⚠ No API key found. Running first-time setup...[/]");
        AnsiConsole.WriteLine();

        var setupSuccess = SetupWizard.Run();
        if (!setupSuccess)
        {
            AnsiConsole.MarkupLine("[red]Setup was not completed. Exiting.[/]");
            return 1;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[green]Setup complete! Starting Krutaka...[/]");
        AnsiConsole.WriteLine();
        await Task.Delay(1500).ConfigureAwait(false); // Brief pause for user to see the message
    }

    // ========================================
    // Host Builder and DI Configuration
    // ========================================

    var builder = Host.CreateApplicationBuilder(args);

    // Warn if appsettings.json is missing — all settings will use code defaults
    var appSettingsPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
    if (!File.Exists(appSettingsPath))
    {
        Log.Warning("appsettings.json not found at {Path}. Using default configuration values.", appSettingsPath);
    }

    // Add Serilog to host
    builder.Services.AddSerilog();

    // Register IAuditLogger
    builder.Services.AddSingleton<IAuditLogger>(sp =>
    {
        return new AuditLogger(Log.Logger);
    });

    // Register ISecretsProvider (WindowsSecretsProvider)
    builder.Services.AddSingleton<ISecretsProvider, WindowsSecretsProvider>();

    // Register AI services (Claude client)
    builder.Services.AddClaudeAI(builder.Configuration);

    // Register Tools with options
    var workingDirectory = builder.Configuration["Agent:WorkingDirectory"];
    if (string.IsNullOrWhiteSpace(workingDirectory))
    {
        workingDirectory = Environment.CurrentDirectory;
    }

    // Register Tools with options (includes ISessionFactory and ISessionManager)
    builder.Services.AddAgentTools(options =>
    {
        // Bind ToolOptions from configuration (CeilingDirectory, AutoGrantPatterns, etc.)
        builder.Configuration.GetSection("ToolOptions").Bind(options);

        // Override DefaultWorkingDirectory from Agent section for backward compatibility
        options.DefaultWorkingDirectory = workingDirectory;
    });

    // Register SessionManagerOptions for multi-session management
    builder.Services.AddSingleton(sp =>
    {
        // Console runs as single-session client, but uses SessionManager for consistency
        return new SessionManagerOptions
        {
            MaxActiveSessions = 1, // Console only needs one active session
            MaxSessionsPerUser = 1,
            GlobalMaxTokensPerHour = int.MaxValue, // No global limit for Console
            IdleTimeout = TimeSpan.Zero, // No idle detection for Console
            SuspendedTtl = TimeSpan.FromDays(30),
            EvictionStrategy = EvictionStrategy.RejectNew
        };
    });

    // Register Memory services
    builder.Services.AddMemory(options =>
    {
        options.DatabasePath = Path.Combine(krutakaDir, "memory.db");
    });

    // Register Skills (placeholder for now)
    builder.Services.AddSkills();

    // Register ApprovalHandler
    builder.Services.AddSingleton(sp =>
    {
        var fileOps = sp.GetRequiredService<IFileOperations>();
        return new ApprovalHandler(workingDirectory, fileOps);
    });

    // Register ConsoleUI
    builder.Services.AddSingleton<ConsoleUI>();

    // Build the host
    var host = builder.Build();

    // ========================================
    // Main Application Entry Point
    // ========================================

    Log.Information("Krutaka starting...");

    var ui = host.Services.GetRequiredService<ConsoleUI>();
    var sessionManager = host.Services.GetRequiredService<ISessionManager>();
    var auditLogger = host.Services.GetRequiredService<IAuditLogger>();

    // Create SystemPromptBuilder (needs to be created after host is built to resolve dependencies)
    var systemPromptBuilder = CreateSystemPromptBuilder(host.Services, workingDirectory);

    // Initialize session using SessionManager (three-step resume pattern)
    ManagedSession currentSession;
    SessionStore sessionStore;

    // Find or create session identifier
    Guid? existingSessionId = null;
    try
    {
        existingSessionId = SessionStore.FindMostRecentSession(workingDirectory);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        Log.Warning(ex, "Failed to discover existing sessions, will create new session");
    }

    if (existingSessionId.HasValue)
    {
        // Three-step resume pattern: ResumeSessionAsync + SessionStore.ReconstructMessagesAsync + RestoreConversationHistory
        Log.Information("Found existing session {SessionId}, attempting auto-resume", existingSessionId.Value);
        
        try
        {
            // Step 1: Resume the session (creates new orchestrator, no history)
            currentSession = await sessionManager.ResumeSessionAsync(
                existingSessionId.Value,
                workingDirectory,
                ui.ShutdownToken).ConfigureAwait(false);

            // Step 2: Load conversation history from JSONL on disk
#pragma warning disable CA2000 // SessionStore will be disposed in shutdown or /new command
            sessionStore = new SessionStore(workingDirectory, existingSessionId.Value);
#pragma warning restore CA2000

            var messages = await sessionStore.ReconstructMessagesAsync(ui.ShutdownToken).ConfigureAwait(false);

            // Step 3: Restore history into the new orchestrator
            if (messages.Count > 0)
            {
                currentSession.Orchestrator.RestoreConversationHistory(messages);
                AnsiConsole.MarkupLine($"[dim]✓ Resumed session with {messages.Count} messages[/]");
                Log.Information("Auto-resumed session {SessionId} with {MessageCount} messages",
                    currentSession.SessionId, messages.Count);
            }
            else
            {
                AnsiConsole.MarkupLine("[dim]✓ Resumed session (empty)[/]");
                Log.Information("Auto-resumed session {SessionId} with no messages", currentSession.SessionId);
            }
        }
#pragma warning disable CA1031 // Do not catch general exception types - this is a fallback for any resume failure
        catch (Exception ex)
#pragma warning restore CA1031
        {
            Log.Warning(ex, "Failed to auto-resume session {SessionId}, creating new session", existingSessionId.Value);
            
            // Fallback: Create new session
            var request = new SessionRequest(
                ProjectPath: workingDirectory,
                ExternalKey: null,
                UserId: null);
            currentSession = await sessionManager.CreateSessionAsync(request, ui.ShutdownToken).ConfigureAwait(false);

#pragma warning disable CA2000 // SessionStore will be disposed in shutdown or /new command
            sessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000
            
            Log.Information("Created new session {SessionId}", currentSession.SessionId);
        }
    }
    else
    {
        // Create new session
        Log.Information("No previous session found, creating new session");
        
        var request = new SessionRequest(
            ProjectPath: workingDirectory,
            ExternalKey: null,
            UserId: null);
        currentSession = await sessionManager.CreateSessionAsync(request, ui.ShutdownToken).ConfigureAwait(false);

#pragma warning disable CA2000 // SessionStore will be disposed in shutdown or /new command
        sessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000
        
        Log.Information("Created new session {SessionId}", currentSession.SessionId);
    }

    // Display banner
    ui.DisplayBanner();

    // Main interaction loop
    while (!ui.ShutdownToken.IsCancellationRequested)
    {
        var input = ui.GetUserInput();

        // Handle Ctrl+C or null input
        if (input == null || ui.ShutdownToken.IsCancellationRequested)
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
            var command = input.ToUpperInvariant().Trim();

            if (command is "/EXIT" or "/QUIT")
            {
                break;
            }
            else if (command == "/HELP")
            {
                AnsiConsole.MarkupLine("[bold cyan]Available Commands:[/]");
                AnsiConsole.MarkupLine("  [cyan]/help[/]     - Show this help message");
                AnsiConsole.MarkupLine("  [cyan]/sessions[/] - List recent sessions for this project");
                AnsiConsole.MarkupLine("  [cyan]/new[/]      - Start a fresh session");
                AnsiConsole.MarkupLine("  [cyan]/resume[/]   - Reload current session from disk");
                AnsiConsole.MarkupLine("  [cyan]/exit[/]     - Exit the application");
                AnsiConsole.MarkupLine("  [cyan]/quit[/]     - Exit the application");
                AnsiConsole.WriteLine();
                continue;
            }
            else if (command == "/SESSIONS")
            {
                // Combine active sessions from SessionManager with persisted sessions from SessionStore
                var activeSessions = sessionManager.ListActiveSessions();
                var persistedSessions = SessionStore.ListSessions(workingDirectory, limit: 10);

                // Merge: active sessions + persisted sessions (excluding duplicates)
                var allSessions = new List<(Guid SessionId, DateTimeOffset LastModified, int MessageCount, string? Preview, bool IsActive)>();

                // Add active sessions
                foreach (var active in activeSessions)
                {
                    allSessions.Add((
                        active.SessionId,
                        active.LastActivity,
                        active.TurnsUsed,
                        "(active)",
                        true));
                }

                // Add persisted sessions (skip if already in active list)
                var activeIds = new HashSet<Guid>(activeSessions.Select(s => s.SessionId));
                foreach (var persisted in persistedSessions)
                {
                    if (!activeIds.Contains(persisted.SessionId))
                    {
                        allSessions.Add((
                            persisted.SessionId,
                            persisted.LastModified,
                            persisted.MessageCount,
                            persisted.FirstUserMessage,
                            false));
                    }
                }

                if (allSessions.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No sessions found for this project.[/]");
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

                    for (int i = 0; i < allSessions.Count; i++)
                    {
                        var session = allSessions[i];
                        var isCurrent = session.SessionId == currentSession.SessionId ? "[green]►[/] " : "";
                        var shortId = session.SessionId.ToString("N")[..8]; // N format is 32 chars without hyphens
                        var preview = session.Preview ?? "(empty)";

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
                continue;
            }
            else if (command == "/NEW")
            {
                // Terminate the current session
                await sessionManager.TerminateSessionAsync(currentSession.SessionId, ui.ShutdownToken).ConfigureAwait(false);
                sessionStore.Dispose();

                // Create new session
                var request = new SessionRequest(
                    ProjectPath: workingDirectory,
                    ExternalKey: null,
                    UserId: null);
                currentSession = await sessionManager.CreateSessionAsync(request, ui.ShutdownToken).ConfigureAwait(false);

#pragma warning disable CA2000 // SessionStore will be disposed in shutdown or next /new command
                sessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000

                AnsiConsole.MarkupLine("[green]✓ Started new session[/]");
                Log.Information("User started new session {SessionId}", currentSession.SessionId);
                AnsiConsole.WriteLine();
                continue;
            }
            else if (command == "/RESUME")
            {
                try
                {
                    // Three-step resume pattern: reload JSONL + restore history
                    // (Unlike auto-resume on startup, this reloads the CURRENT session from disk)
                    sessionStore.Dispose();

#pragma warning disable CA2000 // SessionStore will be disposed in shutdown or /new command
                    sessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000
                    
                    var messages = await sessionStore.ReconstructMessagesAsync(ui.ShutdownToken).ConfigureAwait(false);
                    if (messages.Count == 0)
                    {
                        AnsiConsole.MarkupLine("[yellow]Current session is empty.[/]");
                    }
                    else
                    {
                        currentSession.Orchestrator.RestoreConversationHistory(messages);
                        AnsiConsole.MarkupLine($"[green]✓ Reloaded {messages.Count} messages from disk[/]");
                        Log.Information("Session {SessionId} reloaded with {MessageCount} messages",
                            currentSession.SessionId, messages.Count);
                    }
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    AnsiConsole.MarkupLine($"[red]Error reloading session: {Markup.Escape(ex.Message)}[/]");
                    Log.Error(ex, "Failed to reload session {SessionId}", currentSession.SessionId);
                }

                AnsiConsole.WriteLine();
                continue;
            }
            else
            {
                AnsiConsole.MarkupLine($"[yellow]Unknown command: {Markup.Escape(input)}[/]");
                AnsiConsole.MarkupLine("[dim]Type /help for available commands[/]");
                AnsiConsole.WriteLine();
                continue;
            }
        }

        try
        {
            // Increment turn ID for new user input
            currentSession.CorrelationContext.IncrementTurn();

            // Log user input
            auditLogger.LogUserInput(currentSession.CorrelationContext, input);

            // Build system prompt (using session's tool registry)
            var systemPrompt = await systemPromptBuilder.BuildAsync(input, ui.ShutdownToken).ConfigureAwait(false);

            // Log session event
            await sessionStore.AppendAsync(
                new SessionEvent("user", "user", input, DateTimeOffset.UtcNow),
                ui.ShutdownToken).ConfigureAwait(false);

            // Run agent orchestrator and display streaming response
            // Wrap events to persist assistant responses and tool events to session store
            var rawEvents = currentSession.Orchestrator.RunAsync(input, systemPrompt, ui.ShutdownToken);
            var events = WrapWithSessionPersistence(rawEvents, sessionStore, ui.ShutdownToken);
            await ui.DisplayStreamingResponseAsync(events,
                onApprovalDecision: (toolUseId, approved, alwaysApprove) =>
                {
                    if (approved)
                    {
                        currentSession.Orchestrator.ApproveTool(toolUseId, alwaysApprove);
                    }
                    else
                    {
                        currentSession.Orchestrator.DenyTool(toolUseId);
                    }
                },
                onDirectoryAccessDecision: (approved, grantedLevel, createSessionGrant) =>
                {
                    if (approved && grantedLevel.HasValue)
                    {
                        currentSession.Orchestrator.ApproveDirectoryAccess(grantedLevel.Value, createSessionGrant);
                    }
                    else
                    {
                        currentSession.Orchestrator.DenyDirectoryAccess();
                    }
                },
                onCommandApprovalDecision: (approved, alwaysApprove) =>
                {
                    if (approved)
                    {
                        currentSession.Orchestrator.ApproveCommand(alwaysApprove);
                    }
                    else
                    {
                        currentSession.Orchestrator.DenyCommand();
                    }
                },
                cancellationToken: ui.ShutdownToken).ConfigureAwait(false);

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

    // ========================================
    // Graceful Shutdown
    // ========================================

    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[dim]Shutting down...[/]");

    Log.Information("Krutaka shutting down");
    
    // Dispose session store
    sessionStore.Dispose();
    
    // Terminate all sessions via SessionManager
    using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    await sessionManager.DisposeAsync().ConfigureAwait(false);
    
    await host.StopAsync(shutdownCts.Token).ConfigureAwait(false);

    return 0;
}
#pragma warning disable CA1031 // Do not catch general exception types
catch (Exception ex)
#pragma warning restore CA1031
{
    Log.Fatal(ex, "Application terminated unexpectedly");
    AnsiConsole.WriteException(ex);
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync().ConfigureAwait(false);
}

/// <summary>
/// Wraps an event stream with session persistence, appending assistant responses
/// and tool events to the session store as they flow through.
/// </summary>
static async IAsyncEnumerable<AgentEvent> WrapWithSessionPersistence(
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
                // Flush any accumulated assistant text before the tool_use event so that
                // resume reconstructs content blocks in the same order Claude produced them
                // (text first, then tool_use).
                if (textAccumulator.Length > 0)
                {
                    await sessionStore.AppendAsync(
                        new SessionEvent("assistant", "assistant", textAccumulator.ToString(), DateTimeOffset.UtcNow),
                        cancellationToken).ConfigureAwait(false);
                    textAccumulator.Clear();
                }

                // CRITICAL TIMING WINDOW: The tool_use event is persisted IMMEDIATELY when emitted by Claude.
                // If the process crashes/terminates between this point and the corresponding
                // ToolCallCompleted/ToolCallFailed event being persisted, the session will have
                // an orphaned tool_use block. This is handled by SessionStore.RepairOrphanedToolUseBlocks()
                // which detects missing tool_result blocks and injects synthetic error responses during resume.
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
                // Use "tool_error" type so resume can reconstruct the is_error flag
                await sessionStore.AppendAsync(
                    new SessionEvent("tool_error", "user", tool.Error, DateTimeOffset.UtcNow, tool.ToolName, tool.ToolUseId),
                    cancellationToken).ConfigureAwait(false);
                break;

            case FinalResponse final:
                // Persist any remaining assistant text that wasn't flushed before a tool call.
                // In non-tool-use turns the text is only emitted here.
                if (textAccumulator.Length > 0 || !string.IsNullOrEmpty(final.Content))
                {
                    var content = textAccumulator.Length > 0 ? textAccumulator.ToString() : final.Content;
                    await sessionStore.AppendAsync(
                        new SessionEvent("assistant", "assistant", content, DateTimeOffset.UtcNow),
                        cancellationToken).ConfigureAwait(false);
                }
                // Reset for next response in the same turn (multi-turn tool calls)
                textAccumulator.Clear();
                break;
        }

        yield return evt;
    }
}

/// <summary>
/// Creates a SystemPromptBuilder with all necessary dependencies.
/// This is called after the host is built to resolve services from DI.
/// </summary>
static SystemPromptBuilder CreateSystemPromptBuilder(IServiceProvider services, string workingDirectory)
{
    var toolRegistry = services.GetRequiredService<IToolRegistry>();
    
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
        agentsPromptPath = Path.Combine(workingDirectory, "prompts", "AGENTS.md");
    }

    // Final check - if still not found, log warning and use empty path (will fail at runtime)
    if (!File.Exists(agentsPromptPath))
    {
        Log.Warning("AGENTS.md not found. SystemPromptBuilder may fail at runtime. Searched: {BaseDir}, {WorkingDir}",
            AppContext.BaseDirectory, workingDirectory);
        agentsPromptPath = "prompts/AGENTS.md"; // Let it fail with a clear error
    }

    var skillRegistry = services.GetService<ISkillRegistry>();
    var memoryService = services.GetService<IMemoryService>();
    var memoryFileService = services.GetService<MemoryFileService>();
    var commandRiskClassifier = services.GetService<ICommandRiskClassifier>();

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

