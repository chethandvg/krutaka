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

    // Note: CorrelationContext is created per-session by SessionFactory (not registered globally)
    // Note: ICorrelationContextAccessor is created per-session by SessionFactory (not registered globally)
    // v0.4.0: Per-session components are created by SessionFactory via ISessionManager

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

    // Register Tools with options
    builder.Services.AddAgentTools(options =>
    {
        // Bind ToolOptions from configuration (CeilingDirectory, AutoGrantPatterns, etc.)
        builder.Configuration.GetSection("ToolOptions").Bind(options);

        // Override DefaultWorkingDirectory from Agent section for backward compatibility
        options.DefaultWorkingDirectory = workingDirectory;
        
        // Read orchestrator configuration from Agent section (v0.4.0: preserve user configuration)
        options.ToolTimeoutSeconds = builder.Configuration.GetValue<int>("Agent:ToolTimeoutSeconds", 30);
        options.ApprovalTimeoutSeconds = builder.Configuration.GetValue<int>("Agent:ApprovalTimeoutSeconds", 300);
        
        // Read MaxToolResultCharacters with derivation logic if not explicitly set
        var maxTokens = builder.Configuration.GetValue<int>("Claude:MaxTokens", 8192);
        var configuredMaxToolResultChars = builder.Configuration.GetValue<int>("Agent:MaxToolResultCharacters", 0);
        if (configuredMaxToolResultChars > 0)
        {
            options.MaxToolResultCharacters = configuredMaxToolResultChars;
        }
        else
        {
            // Derive from MaxTokens: 1 token ≈ 4 characters, minimum 100,000
            var derivedMaxToolResultChars = Math.Clamp((long)maxTokens * 4L, 100_000L, int.MaxValue);
            options.MaxToolResultCharacters = (int)derivedMaxToolResultChars;
        }
    });

    // Register Memory services
    builder.Services.AddMemory(options =>
    {
        options.DatabasePath = Path.Combine(krutakaDir, "memory.db");
    });

    // Register Skills (placeholder for now)
    builder.Services.AddSkills();

    // Note: SessionStore is created per-session (not registered globally)
    // Note: SystemPromptBuilder is created per-session using the session's IToolRegistry (not registered globally)
    // Note: ContextCompactor is created per-session by SessionFactory (not registered globally)
    // Note: AgentOrchestrator is created per-session by SessionFactory (not registered globally)
    // v0.4.0: Per-session components are created by SessionFactory via ISessionManager

    // ========================================
    // Mode Resolution and Configuration
    // ========================================

    // Resolve host mode from configuration and CLI arguments
    var hostMode = HostModeConfigurator.ResolveMode(builder.Configuration, args);
    Log.Information("Starting Krutaka in {Mode} mode", hostMode);

    // Register SessionManagerOptions based on mode
    var sessionManagerOptions = HostModeConfigurator.ConfigureSessionManager(hostMode, builder.Configuration);
    builder.Services.AddSingleton(sessionManagerOptions);

    // Register mode-specific services (ConsoleUI, TelegramBotService, ApprovalHandler)
    HostModeConfigurator.RegisterModeSpecificServices(builder.Services, hostMode, builder.Configuration, workingDirectory);

    // Build the host
    var host = builder.Build();

    // ========================================
    // Main Application Entry Point
    // ========================================

    Log.Information("Krutaka starting in {Mode} mode...", hostMode);

    // Mode-specific execution
    switch (hostMode)
    {
        case HostMode.Telegram:
            // Telegram mode: Just start the host and let TelegramBotService run
            await host.RunAsync().ConfigureAwait(false);
            return 0;

        case HostMode.Both:
            // Both mode: Start the host (starts TelegramBotService in background) then run console
            await host.StartAsync().ConfigureAwait(false);
            
            // Link host lifetime to console UI shutdown token so /killswitch from Telegram can stop console
            var hostLifetime = host.Services.GetRequiredService<IHostApplicationLifetime>();
            
            // Register callback to trigger UI shutdown when host is stopping
            var consoleUi = host.Services.GetRequiredService<ConsoleUI>();
            hostLifetime.ApplicationStopping.Register(() =>
            {
                // Trigger console shutdown when Telegram requests shutdown via /killswitch
#pragma warning disable CA1031 // Do not catch general exception types - during shutdown, we want to continue even if disposal fails
                try
                {
                    consoleUi.Dispose();
                }
                catch
                {
                    // Ignore disposal errors during shutdown
                }
#pragma warning restore CA1031
            });
            
            // Fall through to console logic
            break;

        case HostMode.Console:
            // Console mode: Run console logic directly (no need to start host separately)
            break;

        default:
            throw new InvalidOperationException($"Unexpected host mode: {hostMode}");
    }

    // Console mode execution (also used by Both mode)
    var ui = host.Services.GetRequiredService<ConsoleUI>();
    var sessionManager = host.Services.GetRequiredService<ISessionManager>();
    var auditLogger = host.Services.GetRequiredService<IAuditLogger>();

    // Helper function to create SystemPromptBuilder using session's tool registry
    static SystemPromptBuilder CreateSystemPromptBuilder(IToolRegistry toolRegistry, string workingDirectory, IServiceProvider serviceProvider)
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
            agentsPromptPath = Path.Combine(workingDirectory, "prompts", "AGENTS.md");
        }

        // Final check - if still not found, log warning and use empty path (will fail at runtime)
        if (!File.Exists(agentsPromptPath))
        {
            Log.Warning("AGENTS.md not found. SystemPromptBuilder may fail at runtime. Searched: {BaseDir}, {WorkingDir}",
                AppContext.BaseDirectory, workingDirectory);
            agentsPromptPath = "prompts/AGENTS.md"; // Let it fail with a clear error
        }

        var skillRegistry = serviceProvider.GetService<ISkillRegistry>();
        var memoryService = serviceProvider.GetService<IMemoryService>();
        var memoryFileService = serviceProvider.GetService<MemoryFileService>();
        var commandRiskClassifier = serviceProvider.GetService<ICommandRiskClassifier>();

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

    // Three-step resume pattern for disk sessions: Create with preserved ID + SessionStore.ReconstructMessagesAsync + RestoreConversationHistory
    // Check if there's an existing session to auto-resume from disk
    Guid? existingSessionId = null;
    try
    {
        existingSessionId = SessionStore.FindMostRecentSession(workingDirectory);
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
    {
        Log.Warning(ex, "Failed to discover existing sessions, will create new session");
    }

    ManagedSession currentSession;
    SessionStore currentSessionStore;
    SystemPromptBuilder systemPromptBuilder;
    IToolRegistry sessionToolRegistry;

    if (existingSessionId.HasValue)
    {
        // Found a persisted session on disk - create a new session with the same ID to preserve identity
        // After a process restart, SessionManager won't have this session in its suspended map,
        // so we use SessionFactory directly to create with the preserved ID
        Log.Information("Found existing session {SessionId}, creating with preserved ID", existingSessionId.Value);
        
        var sessionRequest = new SessionRequest(
            ProjectPath: workingDirectory,
            MaxTokenBudget: 200_000,
            MaxToolCallBudget: 1000);
        
        // Use SessionFactory directly to create with preserved session ID
        var sessionFactory = host.Services.GetRequiredService<ISessionFactory>();
        currentSession = sessionFactory.Create(sessionRequest, existingSessionId.Value);
        
        // Step 2: Load conversation history from JSONL on disk
#pragma warning disable CA2000 // SessionStore will be disposed in shutdown section
        currentSessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000
        
        try
        {
            var messages = await currentSessionStore.ReconstructMessagesAsync(ui.ShutdownToken).ConfigureAwait(false);
            
            // Step 3: Restore history into the new orchestrator
            if (messages.Count > 0)
            {
                currentSession.Orchestrator.RestoreConversationHistory(messages);
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
            ProjectPath: workingDirectory,
            MaxTokenBudget: 200_000,
            MaxToolCallBudget: 1000);
        currentSession = await sessionManager.CreateSessionAsync(sessionRequest, ui.ShutdownToken).ConfigureAwait(false);
#pragma warning disable CA2000 // SessionStore will be disposed in shutdown section
        currentSessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000
        Log.Information("Created new session {SessionId}", currentSession.SessionId);
    }

    // Create SystemPromptBuilder using the session's tool registry
    // We need to access the tool registry from the session's orchestrator
    // Since AgentOrchestrator doesn't expose IToolRegistry, we'll need to use reflection or create it inline
    // For now, let's extract the tool registry creation logic to a helper
    sessionToolRegistry = CreateSessionToolRegistry(currentSession);
    systemPromptBuilder = CreateSystemPromptBuilder(sessionToolRegistry, workingDirectory, host.Services);

    // Helper to extract tool registry from session (via reflection since it's not exposed)
    static IToolRegistry CreateSessionToolRegistry(ManagedSession session)
    {
        // The SessionFactory creates the tool registry and passes it to the orchestrator
        // We need to extract it from the orchestrator using reflection
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
        
        // Fallback: this should never happen, but if reflection fails, throw an error
        throw new InvalidOperationException("Unable to extract tool registry from session. This is a programming error.");
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
                // Combine active sessions from SessionManager with persisted sessions from disk
                var activeSessions = sessionManager.ListActiveSessions();
                var persistedSessions = SessionStore.ListSessions(workingDirectory, limit: 10);

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
                        var isCurrent = session.SessionId == currentSession.SessionId ? "[green]►[/] " : "";
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
                continue;
            }
            else if (command == "/NEW")
            {
                // Terminate the current session and dispose resources
                await sessionManager.TerminateSessionAsync(currentSession.SessionId, ui.ShutdownToken).ConfigureAwait(false);
                currentSessionStore.Dispose();

                // Create new session via SessionManager
                var sessionRequest = new SessionRequest(
                    ProjectPath: workingDirectory,
                    MaxTokenBudget: 200_000,
                    MaxToolCallBudget: 1000);
                currentSession = await sessionManager.CreateSessionAsync(sessionRequest, ui.ShutdownToken).ConfigureAwait(false);
#pragma warning disable CA2000 // SessionStore will be disposed in shutdown section or on next /new
                currentSessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000
                
                // Recreate SystemPromptBuilder with new session's tool registry
                sessionToolRegistry = CreateSessionToolRegistry(currentSession);
                systemPromptBuilder = CreateSystemPromptBuilder(sessionToolRegistry, workingDirectory, host.Services);

                AnsiConsole.MarkupLine("[green]✓ Started new session[/]");
                Log.Information("User started new session {SessionId}", currentSession.SessionId);
                AnsiConsole.WriteLine();
                continue;
            }
            else if (command == "/RESUME")
            {
                try
                {
                    // Reload current session from disk using three-step pattern
                    var messages = await currentSessionStore.ReconstructMessagesAsync(ui.ShutdownToken).ConfigureAwait(false);
                    if (messages.Count == 0)
                    {
                        AnsiConsole.MarkupLine("[yellow]Current session is empty.[/]");
                    }
                    else
                    {
                        currentSession.Orchestrator.RestoreConversationHistory(messages);
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

            // Build system prompt
            var systemPrompt = await systemPromptBuilder.BuildAsync(input, ui.ShutdownToken).ConfigureAwait(false);

            // Log session event
            await currentSessionStore.AppendAsync(
                new SessionEvent("user", "user", input, DateTimeOffset.UtcNow),
                ui.ShutdownToken).ConfigureAwait(false);

            // Run agent orchestrator and display streaming response
            // Wrap events to persist assistant responses and tool events to session store
            var rawEvents = currentSession.Orchestrator.RunAsync(input, systemPrompt, ui.ShutdownToken);
            var events = WrapWithSessionPersistence(rawEvents, currentSessionStore, ui.ShutdownToken);
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
    
    // Dispose current session store
    currentSessionStore.Dispose();
    
    // Dispose session manager (terminates all active sessions)
    await sessionManager.DisposeAsync().ConfigureAwait(false);
    
    using var shutdownCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
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

