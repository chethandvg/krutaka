using System.Globalization;
using System.Security;
using System.Text.Json;
using Krutaka.Core;
using Krutaka.Tools;
using Spectre.Console;

namespace Krutaka.Console;

/// <summary>
/// Represents the available user choices for approval prompts.
/// </summary>
internal enum ApprovalChoice
{
    /// <summary>Approve this single operation.</summary>
    Yes,
    /// <summary>Deny this operation.</summary>
    No,
    /// <summary>Approve all operations of this type for the session.</summary>
    Always,
    /// <summary>View full content before deciding.</summary>
    View
}

/// <summary>
/// Handles human-in-the-loop approval for destructive tool operations.
/// Displays tool information, previews content, and captures user decisions.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Class will be instantiated for human-in-the-loop approval flow integration")]
internal sealed class ApprovalHandler
{
    private readonly Dictionary<string, bool> _alwaysApproveCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _projectRoot;
    private readonly IFileOperations _fileOps;

    /// <summary>
    /// Initializes a new instance of the <see cref="ApprovalHandler"/> class.
    /// </summary>
    /// <param name="projectRoot">The project root directory for path validation.</param>
    /// <param name="fileOps">The file operations service for path validation.</param>
    public ApprovalHandler(string projectRoot, IFileOperations fileOps)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectRoot);
        ArgumentNullException.ThrowIfNull(fileOps);
        _projectRoot = projectRoot;
        _fileOps = fileOps;
    }

    /// <summary>
    /// Requests approval for a tool invocation.
    /// </summary>
    /// <param name="toolName">The name of the tool requiring approval.</param>
    /// <param name="input">The JSON input parameters for the tool.</param>
    /// <returns>An approval decision indicating whether to proceed and if always approve was selected.</returns>
    public ApprovalDecision RequestApproval(string toolName, string input)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);
        ArgumentException.ThrowIfNullOrWhiteSpace(input);

        // Check if user previously selected "Always approve" for this tool
        if (_alwaysApproveCache.ContainsKey(toolName))
        {
            AnsiConsole.MarkupLine($"[dim]⚙ Auto-approving {Markup.Escape(toolName)} (user selected 'Always' for this session)[/]");
            return new ApprovalDecision(true, true);
        }

        // Parse the input JSON
        JsonElement inputElement;
        try
        {
            using var doc = JsonDocument.Parse(input);
            inputElement = doc.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to parse tool input: {Markup.Escape(ex.Message)}[/]");
            return new ApprovalDecision(false, false);
        }

        // Display the approval prompt
        DisplayApprovalPrompt(toolName, inputElement);

        // Get user decision
        var decision = GetUserDecision(toolName, inputElement);

        // Update cache if "Always" was selected
        if (decision.AlwaysApprove)
        {
            _alwaysApproveCache[toolName] = true;
        }

        return decision;
    }

    /// <summary>
    /// Handles a command approval request from the agent (v0.3.0 tiered command execution).
    /// Displays tier-specific approval prompt or auto-approval message.
    /// </summary>
    /// <param name="request">The command execution request requiring approval.</param>
    /// <param name="decision">The policy decision containing tier and reason.</param>
    /// <returns>An approval decision indicating whether to proceed and if always approve was selected.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Method kept as instance method for consistency with other approval methods and potential future use of instance state.")]
    public ApprovalDecision HandleCommandApproval(CommandExecutionRequest request, CommandDecision decision)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(decision);

        // Build command string for display
        var commandString = BuildCommandString(request.Executable, request.Arguments);

        // Display tier-aware approval prompt
        DisplayCommandApprovalPrompt(request, decision, commandString);

        // Get user decision (tier-specific options)
        var userDecision = GetCommandUserDecision(decision.Tier);

        return userDecision;
    }

    /// <summary>
    /// Displays an auto-approval message for commands that don't require human approval.
    /// Used for Safe tier and Moderate tier in trusted directories.
    /// </summary>
    /// <param name="request">The command execution request that was auto-approved.</param>
    /// <param name="decision">The policy decision containing tier and reason.</param>
    public static void DisplayAutoApprovalMessage(CommandExecutionRequest request, CommandDecision decision)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(decision);

        var commandString = BuildCommandString(request.Executable, request.Arguments);
        var tierDescription = decision.Tier switch
        {
            CommandRiskTier.Safe => "Safe",
            CommandRiskTier.Moderate => "Moderate — trusted dir",
            _ => decision.Tier.ToString()
        };

        AnsiConsole.MarkupLine($"[dim]⚙ Auto-approved ({tierDescription}): {Markup.Escape(commandString)}[/]");
    }

    /// <summary>
    /// Creates a denial message to send back to Claude when a tool is denied.
    /// This is sent as a tool result (not an error) so Claude can adjust its approach.
    /// </summary>
    /// <param name="toolName">The name of the tool that was denied.</param>
    /// <returns>A descriptive message explaining the denial.</returns>
    public static string CreateDenialMessage(string toolName)
    {
        return $"The user denied execution of {toolName}. The user chose not to allow this operation. Please try a different approach or ask the user for clarification.";
    }

    /// <summary>
    /// Handles a directory access approval request from the agent.
    /// Displays an interactive prompt with path, requested access level, and justification.
    /// </summary>
    /// <param name="path">The directory path being requested.</param>
    /// <param name="requestedLevel">The access level being requested.</param>
    /// <param name="justification">The agent's justification for the request.</param>
    /// <returns>A directory access approval result with the user's decision.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Method kept as instance method for consistency with other approval methods and potential future use of instance state.")]
    public DirectoryAccessApproval HandleDirectoryAccess(string path, AccessLevel requestedLevel, string justification)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(justification);

        // Display the approval prompt
        DisplayDirectoryAccessPrompt(path, requestedLevel, justification);

        // Get user decision
        var decision = GetDirectoryAccessDecision(requestedLevel);

        return decision;
    }

    /// <summary>
    /// Creates a denial message for directory access.
    /// </summary>
    /// <param name="path">The path that was denied.</param>
    /// <returns>A descriptive message explaining the denial.</returns>
    public static string CreateDirectoryAccessDenialMessage(string path)
    {
        return $"The user denied access to directory: {path}. Please try a different approach or request access to a different directory.";
    }

    /// <summary>
    /// Displays the approval prompt with tool information and input parameters.
    /// </summary>
    private void DisplayApprovalPrompt(string toolName, JsonElement input)
    {
        AnsiConsole.WriteLine();

        var escapedToolName = Markup.Escape(toolName);
        var panel = new Panel(BuildPromptContent(toolName, input))
            .Border(BoxBorder.Rounded)
            .BorderColor(GetRiskColor(toolName))
            .Header($"[bold]{GetRiskIcon(toolName)} Claude wants to use: {escapedToolName}[/]");

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Builds the content for the approval prompt based on the tool and its input.
    /// </summary>
    private string BuildPromptContent(string toolName, JsonElement input)
    {
        var content = new System.Text.StringBuilder();

        // Add risk level
        content.AppendLine(CultureInfo.InvariantCulture, $"[bold]Risk Level:[/] {GetRiskLevel(toolName)}");
        content.AppendLine();

        // Add parameters
        content.AppendLine("[bold]Parameters:[/]");

        switch (toolName)
        {
            case "write_file":
                BuildWriteFilePrompt(content, input);
                break;
            case "edit_file":
                BuildEditFilePrompt(content, input);
                break;
            case "run_command":
                BuildRunCommandPrompt(content, input);
                break;
            default:
                BuildGenericPrompt(content, input);
                break;
        }

        return content.ToString();
    }

    /// <summary>
    /// Builds the prompt content for write_file tool.
    /// </summary>
    private static void BuildWriteFilePrompt(System.Text.StringBuilder content, JsonElement input)
    {
        var path = input.TryGetProperty("path", out var pathProp) ? pathProp.GetString() : "(not specified)";
        var fileContent = input.TryGetProperty("content", out var contentProp) ? contentProp.GetString() : "";

        content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]path:[/] {Markup.Escape(path ?? "(not specified)")}");
        content.AppendLine();

        // Show content preview
        content.AppendLine("[bold]Content preview:[/]");

        if (string.IsNullOrEmpty(fileContent))
        {
            content.AppendLine("  [dim](empty file)[/]");
        }
        else
        {
            var lines = fileContent.Split('\n');
            var previewLines = lines.Length > 50 ? lines.Take(50).ToArray() : lines;
            var isTruncated = lines.Length > 50;

            foreach (var line in previewLines)
            {
                content.AppendLine(CultureInfo.InvariantCulture, $"  [dim]{Markup.Escape(line)}[/]");
            }

            if (isTruncated)
            {
                content.AppendLine(CultureInfo.InvariantCulture, $"  [yellow]... ({lines.Length - 50} more lines)[/]");
            }

            content.AppendLine();
            content.AppendLine(CultureInfo.InvariantCulture, $"[dim]Total lines: {lines.Length}[/]");
        }
    }

    /// <summary>
    /// Builds the prompt content for edit_file tool.
    /// </summary>
    private void BuildEditFilePrompt(System.Text.StringBuilder content, JsonElement input)
    {
        var path = input.TryGetProperty("path", out var pathProp) ? pathProp.GetString() : "(not specified)";
        var newContent = input.TryGetProperty("content", out var contentProp) ? contentProp.GetString() : "";
        var startLine = input.TryGetProperty("start_line", out var startProp) ? startProp.GetInt32() : 0;
        var endLine = input.TryGetProperty("end_line", out var endProp) ? endProp.GetInt32() : 0;

        content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]path:[/] {Markup.Escape(path ?? "(not specified)")}");
        content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]start_line:[/] {startLine}");
        content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]end_line:[/] {endLine}");
        content.AppendLine();

        // Show diff preview
        content.AppendLine("[bold]Changes to be made:[/]");

        if (!string.IsNullOrEmpty(path))
        {
            try
            {
                // Validate the path using IFileOperations before accessing the file
                var validatedPath = _fileOps.ValidatePath(path, _projectRoot);

                if (File.Exists(validatedPath))
                {
                    var fileLines = File.ReadAllLines(validatedPath);

                    // Show lines being replaced
                    if (startLine > 0 && endLine > 0 && startLine <= fileLines.Length)
                    {
                        content.AppendLine("  [red]- Lines to remove:[/]");
                        var actualEndLine = Math.Min(endLine, fileLines.Length);
                        for (int i = startLine - 1; i < actualEndLine; i++)
                        {
                            content.AppendLine(CultureInfo.InvariantCulture, $"  [red]- {Markup.Escape(fileLines[i])}[/]");
                        }

                        content.AppendLine();
                        content.AppendLine("  [green]+ New content:[/]");
                        var newLines = newContent?.Split('\n') ?? [];
                        foreach (var line in newLines)
                        {
                            content.AppendLine(CultureInfo.InvariantCulture, $"  [green]+ {Markup.Escape(line)}[/]");
                        }
                    }
                    else
                    {
                        content.AppendLine("  [yellow](line range is outside file bounds)[/]");
                    }
                }
                else
                {
                    content.AppendLine("  [yellow](file does not exist)[/]");
                }
            }
            catch (SecurityException ex)
            {
                content.AppendLine(CultureInfo.InvariantCulture, $"  [yellow](path validation failed: {Markup.Escape(ex.Message)})[/]");
            }
            catch (IOException ex)
            {
                content.AppendLine(CultureInfo.InvariantCulture, $"  [yellow](unable to preview: {Markup.Escape(ex.Message)})[/]");
            }
            catch (UnauthorizedAccessException ex)
            {
                content.AppendLine(CultureInfo.InvariantCulture, $"  [yellow](unable to preview: {Markup.Escape(ex.Message)})[/]");
            }
        }
        else
        {
            content.AppendLine("  [yellow](path not specified)[/]");
        }
    }

    /// <summary>
    /// Builds the prompt content for run_command tool.
    /// </summary>
    private static void BuildRunCommandPrompt(System.Text.StringBuilder content, JsonElement input)
    {
        var executable = input.TryGetProperty("executable", out var exeProp) ? exeProp.GetString() : "(not specified)";
        var workingDir = input.TryGetProperty("working_directory", out var wdProp) ? wdProp.GetString() : "(project root)";

        content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]executable:[/] {Markup.Escape(executable ?? "(not specified)")}");

        if (input.TryGetProperty("arguments", out var argsProp) && argsProp.ValueKind == JsonValueKind.Array)
        {
            var args = argsProp.EnumerateArray().Select(a => a.GetString() ?? "").ToArray();
            if (args.Length > 0)
            {
                content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]arguments:[/] {Markup.Escape(string.Join(" ", args))}");
            }
        }

        content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]working_directory:[/] {Markup.Escape(workingDir ?? "(project root)")}");
        content.AppendLine();
        content.AppendLine("[yellow]⚠ This will execute a shell command on your system.[/]");
    }

    /// <summary>
    /// Builds the prompt content for generic tools.
    /// </summary>
    private static void BuildGenericPrompt(System.Text.StringBuilder content, JsonElement input)
    {
        foreach (var prop in input.EnumerateObject())
        {
            var valueStr = prop.Value.ValueKind == JsonValueKind.String
                ? prop.Value.GetString()
                : prop.Value.ToString();

            content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]{Markup.Escape(prop.Name)}:[/] {Markup.Escape(valueStr ?? "(null)")}");
        }
    }

    /// <summary>
    /// Gets the user's approval decision.
    /// </summary>
    private static ApprovalDecision GetUserDecision(string toolName, JsonElement input)
    {
        // For run_command, only allow Yes/No (no "Always" option per security policy)
        if (toolName == "run_command")
        {
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<ApprovalChoice>()
                    .Title("Allow this operation?")
                    .AddChoices(ApprovalChoice.Yes, ApprovalChoice.No)
                    .UseConverter(choice => choice switch
                    {
                        ApprovalChoice.Yes => "[green][[Y]]es - Execute this command[/]",
                        ApprovalChoice.No => "[red][[N]]o - Deny this command[/]",
                        _ => choice.ToString()
                    }));

            return choice == ApprovalChoice.Yes
                ? new ApprovalDecision(true, false)
                : new ApprovalDecision(false, false);
        }

        // For write_file, show additional options based on content length
        if (toolName == "write_file" && input.TryGetProperty("content", out var contentProp))
        {
            var content = contentProp.GetString();
            var lines = content?.Split('\n') ?? [];

            if (lines.Length > 50)
            {
                while (true)
                {
                    var choice = AnsiConsole.Prompt(
                        new SelectionPrompt<ApprovalChoice>()
                            .Title("Allow this operation?")
                            .AddChoices(ApprovalChoice.Yes, ApprovalChoice.No, ApprovalChoice.Always, ApprovalChoice.View)
                            .UseConverter(c => c switch
                            {
                                ApprovalChoice.Yes => "[green][[Y]]es - Write this file[/]",
                                ApprovalChoice.No => "[red][[N]]o - Deny this operation[/]",
                                ApprovalChoice.Always => "[yellow][[A]]lways - Approve all write_file operations this session[/]",
                                ApprovalChoice.View => "[cyan][[V]]iew - View full content[/]",
                                _ => c.ToString()
                            }));

                    switch (choice)
                    {
                        case ApprovalChoice.View:
                            DisplayFullContent(content ?? "");
                            continue;
                        case ApprovalChoice.Yes:
                            return new ApprovalDecision(true, false);
                        case ApprovalChoice.Always:
                            return new ApprovalDecision(true, true);
                        case ApprovalChoice.No:
                            return new ApprovalDecision(false, false);
                        default:
                            // Should never happen, but return denial as safe default
                            return new ApprovalDecision(false, false);
                    }
                }
            }
        }

        // For other tools (write_file with <= 50 lines, edit_file), offer Yes/No/Always
        var standardChoice = AnsiConsole.Prompt(
            new SelectionPrompt<ApprovalChoice>()
                .Title("Allow this operation?")
                .AddChoices(ApprovalChoice.Yes, ApprovalChoice.No, ApprovalChoice.Always)
                .UseConverter(c => c switch
                {
                    ApprovalChoice.Yes => "[green][[Y]]es - Approve this operation[/]",
                    ApprovalChoice.No => "[red][[N]]o - Deny this operation[/]",
                    ApprovalChoice.Always => "[yellow][[A]]lways - Approve all operations of this type this session[/]",
                    _ => c.ToString()
                }));

        return standardChoice switch
        {
            ApprovalChoice.Yes => new ApprovalDecision(true, false),
            ApprovalChoice.Always => new ApprovalDecision(true, true),
            _ => new ApprovalDecision(false, false)
        };
    }

    /// <summary>
    /// Displays the full content of a file.
    /// </summary>
    private static void DisplayFullContent(string content)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Full content:[/]");
        AnsiConsole.WriteLine();

        var panel = new Panel(Markup.Escape(content))
            .Border(BoxBorder.Rounded)
            .Header("[cyan]File Content[/]");

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Gets the risk level for a tool.
    /// </summary>
    private static string GetRiskLevel(string toolName) => toolName switch
    {
        "run_command" => "[red]Critical[/]",
        "write_file" => "[yellow]High[/]",
        "edit_file" => "[yellow]High[/]",
        _ => "[blue]Medium[/]"
    };

    /// <summary>
    /// Gets the risk icon for a tool.
    /// </summary>
    private static string GetRiskIcon(string toolName) => toolName switch
    {
        "run_command" => "🔴",
        "write_file" => "⚠️",
        "edit_file" => "⚠️",
        _ => "⚙️"
    };

    /// <summary>
    /// Gets the border color for the approval prompt based on risk level.
    /// </summary>
    private static Color GetRiskColor(string toolName) => toolName switch
    {
        "run_command" => Color.Red,
        "write_file" => Color.Yellow,
        "edit_file" => Color.Yellow,
        _ => Color.Cyan1
    };

    /// <summary>
    /// Displays the directory access approval prompt.
    /// </summary>
    private static void DisplayDirectoryAccessPrompt(string path, AccessLevel requestedLevel, string justification)
    {
        AnsiConsole.WriteLine();

        var content = new System.Text.StringBuilder();
        content.AppendLine(CultureInfo.InvariantCulture, $"[bold]Path:[/] {Markup.Escape(path)}");
        content.AppendLine(CultureInfo.InvariantCulture, $"[bold]Requested Access Level:[/] {requestedLevel}");
        content.AppendLine();
        content.AppendLine(CultureInfo.InvariantCulture, $"[bold]Agent's Justification:[/]");
        content.AppendLine(CultureInfo.InvariantCulture, $"  {Markup.Escape(justification)}");

        var panel = new Panel(content.ToString())
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Yellow)
            .Header("[bold]🔐 Directory Access Request[/]");

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Gets the user's directory access decision.
    /// </summary>
    private static DirectoryAccessApproval GetDirectoryAccessDecision(AccessLevel requestedLevel)
    {
        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Allow directory access?")
                .AddChoices("Y", "R", "N", "S")
                .UseConverter(c => c switch
                {
                    "Y" => $"[green][[Y]]es - Allow at {Markup.Escape(requestedLevel.ToString())} level[/]",
                    "R" => "[yellow][[R]]ead-only - Downgrade to ReadOnly access[/]",
                    "N" => "[red][[N]]o - Deny access[/]",
                    "S" => "[cyan][[S]]ession - Allow for entire session[/]",
                    _ => c
                }));

        return choice switch
        {
            "Y" => new DirectoryAccessApproval(true, requestedLevel, false),
            "R" => new DirectoryAccessApproval(true, AccessLevel.ReadOnly, false),
            "N" => new DirectoryAccessApproval(false, null, false),
            "S" => new DirectoryAccessApproval(true, requestedLevel, true),
            _ => new DirectoryAccessApproval(false, null, false) // Safe default
        };
    }

    /// <summary>
    /// Displays the command approval prompt with tier-specific formatting.
    /// </summary>
    private static void DisplayCommandApprovalPrompt(CommandExecutionRequest request, CommandDecision decision, string commandString)
    {
        AnsiConsole.WriteLine();

        var content = new System.Text.StringBuilder();

        // Add tier with emoji and label
        var tierLabel = GetTierLabel(decision.Tier, decision.Reason);
        var tierEmoji = GetTierEmoji(decision.Tier);
        content.AppendLine(CultureInfo.InvariantCulture, $"[bold]Risk Tier:[/] {tierEmoji} {tierLabel}");
        content.AppendLine();

        // Add working directory
        var workingDir = string.IsNullOrWhiteSpace(request.WorkingDirectory)
            ? "(project root)"
            : request.WorkingDirectory;
        content.AppendLine(CultureInfo.InvariantCulture, $"[bold]Working Directory:[/] {Markup.Escape(workingDir)}");
        content.AppendLine();

        // Add justification
        content.AppendLine("[bold]Justification:[/]");
        content.AppendLine(CultureInfo.InvariantCulture, $"  {Markup.Escape(request.Justification)}");

        var panel = new Panel(content.ToString())
            .Border(BoxBorder.Rounded)
            .BorderColor(GetTierBorderColor(decision.Tier))
            .Header($"[bold]⚙ Claude wants to run: {Markup.Escape(commandString)}[/]");

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Gets the user's decision for a command approval based on the tier.
    /// </summary>
    private static ApprovalDecision GetCommandUserDecision(CommandRiskTier tier)
    {
        // For Elevated tier, only allow Yes/No (no "Always" option per security policy)
        if (tier == CommandRiskTier.Elevated)
        {
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<ApprovalChoice>()
                    .Title("Allow this command?")
                    .AddChoices(ApprovalChoice.Yes, ApprovalChoice.No)
                    .UseConverter(choice => choice switch
                    {
                        ApprovalChoice.Yes => "[green][[Y]]es - Execute this command[/]",
                        ApprovalChoice.No => "[red][[N]]o - Deny this command[/]",
                        _ => choice.ToString()
                    }));

            return choice == ApprovalChoice.Yes
                ? new ApprovalDecision(true, false)
                : new ApprovalDecision(false, false);
        }

        // For Moderate tier (outside trusted directory), offer Yes/No/Always
        var moderateChoice = AnsiConsole.Prompt(
            new SelectionPrompt<ApprovalChoice>()
                .Title("Allow this command?")
                .AddChoices(ApprovalChoice.Yes, ApprovalChoice.No, ApprovalChoice.Always)
                .UseConverter(c => c switch
                {
                    ApprovalChoice.Yes => "[green][[Y]]es - Execute this command[/]",
                    ApprovalChoice.No => "[red][[N]]o - Deny this command[/]",
                    ApprovalChoice.Always => "[yellow][[A]]lways - Approve this command for this session[/]",
                    _ => c.ToString()
                }));

        return moderateChoice switch
        {
            ApprovalChoice.Yes => new ApprovalDecision(true, false),
            ApprovalChoice.Always => new ApprovalDecision(true, true),
            _ => new ApprovalDecision(false, false)
        };
    }

    /// <summary>
    /// Builds a human-readable command string from executable and arguments.
    /// </summary>
    private static string BuildCommandString(string executable, IReadOnlyList<string> arguments)
    {
        if (arguments == null || arguments.Count == 0)
        {
            return executable;
        }

        return $"{executable} {string.Join(" ", arguments)}";
    }

    /// <summary>
    /// Gets the tier label for display.
    /// </summary>
    private static string GetTierLabel(CommandRiskTier tier, string reason) => tier switch
    {
        CommandRiskTier.Safe => "[green]SAFE[/]",
        CommandRiskTier.Moderate => GetModerateTierLabel(reason),
        CommandRiskTier.Elevated => "[red]ELEVATED[/]",
        CommandRiskTier.Dangerous => "[red]DANGEROUS[/]",
        _ => "[grey]UNKNOWN[/]"
    };

    /// <summary>
    /// Gets the Moderate tier label with context from the decision reason.
    /// </summary>
    private static string GetModerateTierLabel(string reason)
    {
        // Extract context from reason to provide more accurate label
        if (reason.Contains("untrusted directory", StringComparison.OrdinalIgnoreCase))
        {
            return "[yellow]MODERATE (not in trusted directory)[/]";
        }
        else if (reason.Contains("no working directory", StringComparison.OrdinalIgnoreCase))
        {
            return "[yellow]MODERATE (no working directory specified)[/]";
        }
        else if (reason.Contains("auto-approval disabled", StringComparison.OrdinalIgnoreCase))
        {
            return "[yellow]MODERATE (auto-approval disabled)[/]";
        }
        else if (reason.Contains("no access policy engine", StringComparison.OrdinalIgnoreCase))
        {
            return "[yellow]MODERATE (directory trust not configured)[/]";
        }
        else
        {
            // Fallback to generic MODERATE label
            return "[yellow]MODERATE[/]";
        }
    }

    /// <summary>
    /// Gets the tier emoji for display.
    /// </summary>
    private static string GetTierEmoji(CommandRiskTier tier) => tier switch
    {
        CommandRiskTier.Safe => "🟢",
        CommandRiskTier.Moderate => "🟢",
        CommandRiskTier.Elevated => "🟡",
        CommandRiskTier.Dangerous => "🔴",
        _ => "⚪"
    };

    /// <summary>
    /// Gets the border color for the approval prompt based on tier.
    /// </summary>
    private static Color GetTierBorderColor(CommandRiskTier tier) => tier switch
    {
        CommandRiskTier.Safe => Color.Green,
        CommandRiskTier.Moderate => Color.Yellow,
        CommandRiskTier.Elevated => Color.Red,
        CommandRiskTier.Dangerous => Color.Red,
        _ => Color.Grey
    };
}

/// <summary>
/// Represents a user's approval decision for a tool invocation.
/// </summary>
/// <param name="Approved">Whether the user approved the operation.</param>
/// <param name="AlwaysApprove">Whether the user selected "Always approve" for this tool type.</param>
internal sealed record ApprovalDecision(bool Approved, bool AlwaysApprove);

/// <summary>
/// Represents a user's approval decision for directory access.
/// </summary>
/// <param name="Approved">Whether the user approved the access request.</param>
/// <param name="GrantedLevel">The access level granted (may be downgraded from requested); null if denied.</param>
/// <param name="SessionGrant">Whether to create a session-wide grant (user selected 'S' option).</param>
internal sealed record DirectoryAccessApproval(bool Approved, AccessLevel? GrantedLevel, bool SessionGrant);
