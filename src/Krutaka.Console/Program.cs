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

    // Register SessionManagerOptions for Console single-session mode
    builder.Services.AddSingleton(new SessionManagerOptions
    {
        MaxActiveSessions = 1, // Console is single-session
        EvictionStrategy = EvictionStrategy.TerminateOldest,
        IdleTimeout = TimeSpan.Zero, // No idle timeout for Console
        GlobalMaxTokensPerHour = 1_000_000, // 1M tokens/hour
        MaxSessionsPerUser = 1 // Single user in Console mode
    });

    // Register ConsoleUI
    builder.Services.AddSingleton<IConsoleUI>(sp =>
    {
        var fileOps = sp.GetRequiredService<IFileOperations>();
        var approvalHandler = new ApprovalHandler(workingDirectory, fileOps);
        return new ConsoleUI(approvalHandler);
    });

    // Build the host
    var host = builder.Build();

    // ========================================
    // Main Application Entry Point
    // ========================================

    Log.Information("Krutaka starting...");

    var ui = host.Services.GetRequiredService<IConsoleUI>();
    var sessionManager = host.Services.GetRequiredService<ISessionManager>();
    var sessionFactory = host.Services.GetRequiredService<ISessionFactory>();
    var auditLogger = host.Services.GetRequiredService<IAuditLogger>();

    // Create and run the console application
    var app = new ConsoleApplication(
        ui,
        sessionManager,
        sessionFactory,
        auditLogger,
        host.Services,
        workingDirectory);

    await using (app.ConfigureAwait(false))
    {
        await app.RunAsync(ui.ShutdownToken).ConfigureAwait(false);
    }

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
