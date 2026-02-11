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

    // Add Serilog to host
    builder.Services.AddSerilog();

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

    // Note: CommandTimeoutSeconds is not currently used by RunCommandTool (hardcoded 30s timeout)
    // This configuration is reserved for future implementation
    builder.Services.AddAgentTools(options =>
    {
        options.WorkingDirectory = workingDirectory;
    });

    // Register Memory services
    builder.Services.AddMemory(options =>
    {
        options.DatabasePath = Path.Combine(krutakaDir, "memory.db");
    });

    // Register Skills (placeholder for now)
    builder.Services.AddSkills();

    // Register SessionStore as factory
    builder.Services.AddSingleton(sp =>
    {
        var sessionId = Guid.NewGuid();
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

    // Register AgentOrchestrator
    var toolTimeoutSeconds = builder.Configuration.GetValue<int>("Agent:ToolTimeoutSeconds", 30);

    builder.Services.AddSingleton(sp =>
    {
        var claudeClient = sp.GetRequiredService<IClaudeClient>();
        var toolRegistry = sp.GetRequiredService<IToolRegistry>();
        var securityPolicy = sp.GetRequiredService<ISecurityPolicy>();

        return new AgentOrchestrator(
            claudeClient,
            toolRegistry,
            securityPolicy,
            toolTimeoutSeconds);
    });

    // Register ApprovalHandler
    builder.Services.AddSingleton(sp =>
    {
        return new ApprovalHandler(workingDirectory);
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
                AnsiConsole.MarkupLine("  [cyan]/help[/]  - Show this help message");
                AnsiConsole.MarkupLine("  [cyan]/exit[/]  - Exit the application");
                AnsiConsole.MarkupLine("  [cyan]/quit[/]  - Exit the application");
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
            // Build system prompt
            var systemPrompt = await systemPromptBuilder.BuildAsync(input, ui.ShutdownToken).ConfigureAwait(false);

            // Log session event
            await sessionStore.AppendAsync(
                new SessionEvent("user", "user", input, DateTimeOffset.UtcNow),
                ui.ShutdownToken).ConfigureAwait(false);

            // Run agent orchestrator and display streaming response
            var events = orchestrator.RunAsync(input, systemPrompt, ui.ShutdownToken);
            await ui.DisplayStreamingResponseAsync(events, ui.ShutdownToken).ConfigureAwait(false);

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

