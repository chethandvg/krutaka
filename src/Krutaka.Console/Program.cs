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

    // Session ID will be determined after we know the working directory
    // Initialize with empty value - will be properly set below
    Guid sessionId = Guid.Empty;
    bool isResumingSession = false;

    // Register CorrelationContext (scoped per session)
    builder.Services.AddSingleton(sp =>
    {
        return new CorrelationContext(sessionId);
    });

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

    // Find or create session identifier (now that we have workingDirectory)
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
        sessionId = existingSessionId.Value;
        isResumingSession = true;
        Log.Information("Found existing session {SessionId}, will auto-resume", sessionId);
    }
    else
    {
        sessionId = Guid.NewGuid();
        Log.Information("No previous session found, created new session {SessionId}", sessionId);
    }

    // Register Tools with options
    builder.Services.AddAgentTools(options =>
    {
        options.DefaultWorkingDirectory = workingDirectory;
    });

    // Register Memory services
    builder.Services.AddMemory(options =>
    {
        options.DatabasePath = Path.Combine(krutakaDir, "memory.db");
    });

    // Register Skills (placeholder for now)
    builder.Services.AddSkills();

    // Register SessionStore as factory (using the same session ID as CorrelationContext)
    builder.Services.AddSingleton(sp =>
    {
        return new SessionStore(workingDirectory, sessionId);
    });

    // Register SystemPromptBuilder
    builder.Services.AddSingleton(sp =>
    {
        var toolRegistry = sp.GetRequiredService<IToolRegistry>();
        
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

        var skillRegistry = sp.GetService<ISkillRegistry>();
        var memoryService = sp.GetService<IMemoryService>();
        var memoryFileService = sp.GetService<MemoryFileService>();

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
            memoryFileReader);
    });

    // Register ContextCompactor
    builder.Services.AddSingleton(sp =>
    {
        var claudeClient = sp.GetRequiredService<IClaudeClient>();
        var auditLogger = sp.GetService<IAuditLogger>();
        var correlationContext = sp.GetService<CorrelationContext>();

        return new ContextCompactor(
            claudeClient,
            auditLogger: auditLogger,
            correlationContext: correlationContext);
    });

    // Register AgentOrchestrator
    var toolTimeoutSeconds = builder.Configuration.GetValue<int>("Agent:ToolTimeoutSeconds", 30);

    builder.Services.AddSingleton(sp =>
    {
        var claudeClient = sp.GetRequiredService<IClaudeClient>();
        var toolRegistry = sp.GetRequiredService<IToolRegistry>();
        var securityPolicy = sp.GetRequiredService<ISecurityPolicy>();
        var auditLogger = sp.GetRequiredService<IAuditLogger>();
        var correlationContext = sp.GetRequiredService<CorrelationContext>();
        var sessionAccessStore = sp.GetService<ISessionAccessStore>(); // Optional in v0.2.0
        var contextCompactor = sp.GetService<ContextCompactor>();

        return new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            toolTimeoutSeconds,
            approvalTimeoutSeconds: 300, // 5 minutes default
            sessionAccessStore,
            auditLogger,
            correlationContext,
            contextCompactor);
    });

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
    var orchestrator = host.Services.GetRequiredService<AgentOrchestrator>();
    var systemPromptBuilder = host.Services.GetRequiredService<SystemPromptBuilder>();
    var sessionStore = host.Services.GetRequiredService<SessionStore>();
    var correlationContext = host.Services.GetRequiredService<CorrelationContext>();
    var auditLogger = host.Services.GetRequiredService<IAuditLogger>();

    // Auto-load previous session messages if resuming
    if (isResumingSession)
    {
        try
        {
            var messages = await sessionStore.ReconstructMessagesAsync(ui.ShutdownToken).ConfigureAwait(false);
            if (messages.Count > 0)
            {
                orchestrator.RestoreConversationHistory(messages);
                AnsiConsole.MarkupLine($"[dim]✓ Resumed session with {messages.Count} messages[/]");
                Log.Information("Auto-resumed session with {MessageCount} messages", messages.Count);
            }
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or UnauthorizedAccessException)
        {
            Log.Warning(ex, "Failed to auto-resume session, continuing with empty session");
        }
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
                var sessions = SessionStore.ListSessions(workingDirectory, limit: 10);

                if (sessions.Count == 0)
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

                    for (int i = 0; i < sessions.Count; i++)
                    {
                        var session = sessions[i];
                        var isCurrent = session.SessionId == sessionId ? "[green]►[/] " : "";
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
                // Dispose the previous session store to avoid resource leaks
                sessionStore.Dispose();

                // Create new session
                sessionId = Guid.NewGuid();
                correlationContext.ResetSession(sessionId);
#pragma warning disable CA2000 // New SessionStore will be disposed when app exits or on next /new
                sessionStore = new SessionStore(workingDirectory, sessionId);
#pragma warning restore CA2000
                orchestrator.ClearConversationHistory();

                AnsiConsole.MarkupLine("[green]✓ Started new session[/]");
                Log.Information("User started new session {SessionId}", sessionId);
                AnsiConsole.WriteLine();
                continue;
            }
            else if (command == "/RESUME")
            {
                try
                {
                    // Reload current session from disk (useful if externally modified)
                    var messages = await sessionStore.ReconstructMessagesAsync(ui.ShutdownToken).ConfigureAwait(false);
                    if (messages.Count == 0)
                    {
                        AnsiConsole.MarkupLine("[yellow]Current session is empty.[/]");
                    }
                    else
                    {
                        orchestrator.RestoreConversationHistory(messages);
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
            correlationContext.IncrementTurn();

            // Log user input
            auditLogger.LogUserInput(correlationContext, input);

            // Build system prompt
            var systemPrompt = await systemPromptBuilder.BuildAsync(input, ui.ShutdownToken).ConfigureAwait(false);

            // Log session event
            await sessionStore.AppendAsync(
                new SessionEvent("user", "user", input, DateTimeOffset.UtcNow),
                ui.ShutdownToken).ConfigureAwait(false);

            // Run agent orchestrator and display streaming response
            // Wrap events to persist assistant responses and tool events to session store
            var rawEvents = orchestrator.RunAsync(input, systemPrompt, ui.ShutdownToken);
            var events = WrapWithSessionPersistence(rawEvents, sessionStore, ui.ShutdownToken);
            await ui.DisplayStreamingResponseAsync(events,
                onApprovalDecision: (toolUseId, approved, alwaysApprove) =>
                {
                    if (approved)
                    {
                        orchestrator.ApproveTool(toolUseId, alwaysApprove);
                    }
                    else
                    {
                        orchestrator.DenyTool(toolUseId);
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

