using System.Globalization;
using System.Reflection;
using System.Text;
using Krutaka.Core;
using Spectre.Console;

namespace Krutaka.Console;

/// <summary>
/// Console UI for the Krutaka agent with streaming token display,
/// tool call indicators, Markdown rendering, and command handling.
/// </summary>
internal sealed class ConsoleUI : IDisposable
{
    private readonly MarkdownRenderer _markdownRenderer;
    private readonly ApprovalHandler _approvalHandler;
    private readonly CancellationTokenSource _shutdownCts;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="ConsoleUI"/> class.
    /// </summary>
    /// <param name="approvalHandler">The approval handler for human-in-the-loop approvals.</param>
    public ConsoleUI(ApprovalHandler approvalHandler)
    {
        ArgumentNullException.ThrowIfNull(approvalHandler);

        _markdownRenderer = new MarkdownRenderer();
        _approvalHandler = approvalHandler;
        _shutdownCts = new CancellationTokenSource();

        // Setup Ctrl+C handling
        System.Console.CancelKeyPress += OnCancelKeyPress;
    }

    /// <summary>
    /// Gets a cancellation token that is triggered when the user presses Ctrl+C.
    /// </summary>
    public CancellationToken ShutdownToken => _shutdownCts.Token;

    /// <summary>
    /// Displays the startup banner with FigletText and version information.
    /// </summary>
    public void DisplayBanner()
    {
        var version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "0.1.0";

        AnsiConsole.Write(
            new FigletText("Krutaka")
                .Color(Color.Blue));

        AnsiConsole.MarkupLine($"[dim]Version {Markup.Escape(version)}[/]");
        AnsiConsole.MarkupLine("[dim]OpenClaw-inspired AI agent for Windows[/]");
        AnsiConsole.MarkupLine("[dim]Type /help for commands[/]");
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Prompts the user for input with a styled prompt.
    /// </summary>
    /// <returns>The user's input, or null if cancelled.</returns>
    public string? GetUserInput()
    {
        try
        {
            return AnsiConsole.Prompt(
                new TextPrompt<string>("[blue]>[/]")
                    .AllowEmpty());
        }
        catch (InvalidOperationException)
        {
            // Ctrl+C was pressed
            return null;
        }
    }

    /// <summary>
    /// Displays a streaming agent response with real-time token display.
    /// </summary>
    /// <param name="events">The stream of agent events.</param>
    /// <param name="onApprovalDecision">Optional callback invoked when a human approval decision is made. 
    /// Parameters: toolUseId, approved, alwaysApprove.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task DisplayStreamingResponseAsync(
        IAsyncEnumerable<AgentEvent> events,
        Action<string, bool, bool>? onApprovalDecision = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(events);

        var fullText = new StringBuilder();
        bool firstToken = true;
        bool hasError = false;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("[dim]Thinking...[/]", async ctx =>
            {
                await foreach (var evt in events.WithCancellation(cancellationToken))
                {
                    switch (evt)
                    {
                        case TextDelta delta:
                            if (firstToken)
                            {
                                // Stop spinner and start streaming text
                                ctx.Status(string.Empty);
                                ctx.Spinner(Spinner.Known.Default);
                                AnsiConsole.WriteLine();
                                firstToken = false;
                            }
                            // Raw console write for streaming speed
                            System.Console.Write(delta.Text);
                            fullText.Append(delta.Text);
                            break;

                        case ToolCallStarted tool:
                            if (!firstToken)
                            {
                                AnsiConsole.WriteLine();
                            }

                            AnsiConsole.MarkupLine(
                                $"[dim]⚙ Calling [bold]{Markup.Escape(tool.ToolName)}[/]...[/]");

                            firstToken = false;
                            break;

                        case ToolCallCompleted tool:
                            AnsiConsole.MarkupLine(
                                $"[green]✓ {Markup.Escape(tool.ToolName)} complete[/]");
                            break;

                        case ToolCallFailed tool:
                            AnsiConsole.MarkupLine(
                                $"[red]✗ {Markup.Escape(tool.ToolName)} failed: {Markup.Escape(tool.Error)}[/]");
                            hasError = true;
                            break;

                        case HumanApprovalRequired approval:
                            if (!firstToken)
                            {
                                AnsiConsole.WriteLine();
                            }

                            // Display approval request and get the user's decision
                            var decision = _approvalHandler.RequestApproval(
                                approval.ToolName,
                                approval.Input);

                            // Notify the orchestrator of the approval decision
                            onApprovalDecision?.Invoke(
                                approval.ToolUseId,
                                decision.Approved,
                                decision.AlwaysApprove);

                            firstToken = false;
                            break;

                        case FinalResponse final:
                            if (!firstToken && fullText.Length > 0)
                            {
                                // Re-render with Markdown formatting
                                AnsiConsole.WriteLine();
                                AnsiConsole.WriteLine();
                                _markdownRenderer.Render(fullText.ToString());
                            }
                            else if (!string.IsNullOrWhiteSpace(final.Content))
                            {
                                AnsiConsole.WriteLine();
                                _markdownRenderer.Render(final.Content);
                            }

                            break;
                    }
                }
            }).ConfigureAwait(false);

        if (hasError)
        {
            AnsiConsole.WriteLine();
        }
    }

    /// <summary>
    /// Displays an error message in a red-bordered panel.
    /// </summary>
    /// <param name="errorMessage">The error message to display.</param>
    public void DisplayError(string errorMessage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(errorMessage);

        var panel = new Panel(Markup.Escape(errorMessage))
            .Header("[red]Error[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Red);

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Displays help information for available commands.
    /// </summary>
    public void DisplayHelp()
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn("[bold]Command[/]")
            .AddColumn("[bold]Description[/]");

        table.AddRow("/exit, /quit", "Exit the application");
        table.AddRow("/compact", "Manually trigger context compaction");
        table.AddRow("/memory", "Display current memory statistics");
        table.AddRow("/session", "Display session information");
        table.AddRow("/help", "Show this help message");

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Displays memory statistics.
    /// </summary>
    /// <param name="stats">Memory statistics to display.</param>
    public void DisplayMemoryStats(MemoryStats stats)
    {
        ArgumentNullException.ThrowIfNull(stats);

        var panel = new Panel(
            $"""
            [bold]Total Facts:[/] {stats.TotalFacts.ToString(CultureInfo.InvariantCulture)}
            [bold]Total Chunks:[/] {stats.TotalChunks.ToString(CultureInfo.InvariantCulture)}
            [bold]Database Size:[/] {FormatBytes(stats.DatabaseSizeBytes)}
            """)
            .Header("[blue]Memory Statistics[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Blue);

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Displays session information.
    /// </summary>
    /// <param name="info">Session information to display.</param>
    public void DisplaySessionInfo(SessionInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        var panel = new Panel(
            $"""
            [bold]Session ID:[/] {Markup.Escape(info.SessionId)}
            [bold]Started:[/] {info.StartTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)}
            [bold]Project:[/] {Markup.Escape(info.ProjectPath)}
            [bold]Model:[/] {Markup.Escape(info.ModelId)}
            [bold]Turn Count:[/] {info.TurnCount.ToString(CultureInfo.InvariantCulture)}
            """)
            .Header("[blue]Session Information[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Blue);

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Displays a confirmation that compaction has been triggered.
    /// </summary>
    /// <param name="beforeTokens">Token count before compaction.</param>
    /// <param name="afterTokens">Token count after compaction.</param>
    public void DisplayCompactionResult(int beforeTokens, int afterTokens)
    {
        var saved = beforeTokens - afterTokens;
        var percentSaved = beforeTokens > 0
            ? (saved * 100.0) / beforeTokens
            : 0;

        AnsiConsole.MarkupLine(
            $"[green]✓ Context compacted: {beforeTokens.ToString(CultureInfo.InvariantCulture)} → " +
            $"{afterTokens.ToString(CultureInfo.InvariantCulture)} tokens " +
            $"({percentSaved.ToString("F1", CultureInfo.InvariantCulture)}% reduction)[/]");
        AnsiConsole.WriteLine();
    }

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB"];
        double len = bytes;
        int order = 0;

        while (len >= 1024 && order < sizes.Length - 1)
        {
            order++;
            len /= 1024;
        }

        return string.Format(CultureInfo.InvariantCulture, "{0:0.##} {1}", len, sizes[order]);
    }

    private void OnCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
    {
        // Prevent default termination
        e.Cancel = true;

        // Signal shutdown
        if (!_shutdownCts.IsCancellationRequested)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]Shutting down gracefully...[/]");
            _shutdownCts.Cancel();
        }
    }

    /// <summary>
    /// Disposes resources used by the ConsoleUI.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        System.Console.CancelKeyPress -= OnCancelKeyPress;
        _shutdownCts.Dispose();
        _disposed = true;
    }
}

/// <summary>
/// Represents memory statistics for display.
/// </summary>
/// <param name="TotalFacts">Total number of facts in memory.</param>
/// <param name="TotalChunks">Total number of chunks indexed.</param>
/// <param name="DatabaseSizeBytes">Size of the database in bytes.</param>
internal sealed record MemoryStats(
    int TotalFacts,
    int TotalChunks,
    long DatabaseSizeBytes);

/// <summary>
/// Represents session information for display.
/// </summary>
/// <param name="SessionId">The session identifier.</param>
/// <param name="StartTime">When the session started.</param>
/// <param name="ProjectPath">The project path for this session.</param>
/// <param name="ModelId">The Claude model being used.</param>
/// <param name="TurnCount">Number of turns in this session.</param>
internal sealed record SessionInfo(
    string SessionId,
    DateTimeOffset StartTime,
    string ProjectPath,
    string ModelId,
    int TurnCount);
