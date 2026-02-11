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
                        ApprovalChoice.Yes => "[green][Y]es - Execute this command[/]",
                        ApprovalChoice.No => "[red][N]o - Deny this command[/]",
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
                                ApprovalChoice.Yes => "[green][Y]es - Write this file[/]",
                                ApprovalChoice.No => "[red][N]o - Deny this operation[/]",
                                ApprovalChoice.Always => "[yellow][A]lways - Approve all write_file operations this session[/]",
                                ApprovalChoice.View => "[cyan][V]iew - View full content[/]",
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
                    ApprovalChoice.Yes => "[green][Y]es - Approve this operation[/]",
                    ApprovalChoice.No => "[red][N]o - Deny this operation[/]",
                    ApprovalChoice.Always => "[yellow][A]lways - Approve all operations of this type this session[/]",
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
}

/// <summary>
/// Represents a user's approval decision for a tool invocation.
/// </summary>
/// <param name="Approved">Whether the user approved the operation.</param>
/// <param name="AlwaysApprove">Whether the user selected "Always approve" for this tool type.</param>
internal sealed record ApprovalDecision(bool Approved, bool AlwaysApprove);
