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
    // Build AutonomyLevelOptions from Agent configuration section (v0.5.0)
    var autonomyLevelOptions = new Krutaka.Core.AutonomyLevelOptions();
    builder.Configuration.GetSection("Agent").Bind(autonomyLevelOptions);

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
    }, autonomyLevelOptions);

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

    // Read session configuration from appsettings.json
    var configuration = host.Services.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
    var maxTokenBudget = configuration.GetValue<int>("Agent:MaxTokenBudget", 200_000);
    var maxToolCallBudget = configuration.GetValue<int>("Agent:MaxToolCallBudget", 1000);

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
        
        var memoryWriter = ConsoleSessionHelpers.CreateMemoryWriter(host.Services);
        var sessionRequest = new SessionRequest(
            ProjectPath: workingDirectory,
            MaxTokenBudget: maxTokenBudget,
            MaxToolCallBudget: maxToolCallBudget,
            MemoryWriter: memoryWriter);
        
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
        var memoryWriter = ConsoleSessionHelpers.CreateMemoryWriter(host.Services);
        var sessionRequest = new SessionRequest(
            ProjectPath: workingDirectory,
            MaxTokenBudget: maxTokenBudget,
            MaxToolCallBudget: maxToolCallBudget,
            MemoryWriter: memoryWriter);
        currentSession = await sessionManager.CreateSessionAsync(sessionRequest, ui.ShutdownToken).ConfigureAwait(false);
#pragma warning disable CA2000 // SessionStore will be disposed in shutdown section
        currentSessionStore = new SessionStore(workingDirectory, currentSession.SessionId);
#pragma warning restore CA2000
        Log.Information("Created new session {SessionId}", currentSession.SessionId);
    }

    // Create the session tool registry and system prompt builder
    sessionToolRegistry = ConsoleSessionHelpers.CreateSessionToolRegistry(currentSession);
    systemPromptBuilder = ConsoleSessionHelpers.CreateSystemPromptBuilder(sessionToolRegistry, workingDirectory, host.Services);

    // Run the main interaction loop
    var runLoop = new ConsoleRunLoop(
        ui,
        sessionManager,
        auditLogger,
        host.Services,
        workingDirectory,
        maxTokenBudget,
        maxToolCallBudget,
        currentSession,
        currentSessionStore,
        systemPromptBuilder);
    await runLoop.RunAsync(ui.ShutdownToken).ConfigureAwait(false);

    // ========================================
    // Graceful Shutdown
    // ========================================

    AnsiConsole.WriteLine();
    AnsiConsole.MarkupLine("[dim]Shutting down...[/]");

    Log.Information("Krutaka shutting down");
    
    // Dispose current session store
    runLoop.Dispose();
    
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
