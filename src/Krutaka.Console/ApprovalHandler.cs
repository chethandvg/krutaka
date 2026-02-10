using System.Globalization;
using System.Text.Json;
using Spectre.Console;

namespace Krutaka.Console;

/// <summary>
/// Handles human-in-the-loop approval for destructive tool operations.
/// Displays tool information, previews content, and captures user decisions.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "Class will be instantiated for human-in-the-loop approval flow integration")]
internal sealed class ApprovalHandler
{
    private readonly Dictionary<string, bool> _alwaysApproveCache = [];

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
            AnsiConsole.MarkupLine($"[dim]⚙ Auto-approving {toolName} (user selected 'Always' for this session)[/]");
            return new ApprovalDecision(true, false);
        }

        // Parse the input JSON
        JsonElement inputElement;
        try
        {
            inputElement = JsonDocument.Parse(input).RootElement;
        }
        catch (JsonException ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to parse tool input: {ex.Message}[/]");
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
    /// Displays the approval prompt with tool information and input parameters.
    /// </summary>
    private static void DisplayApprovalPrompt(string toolName, JsonElement input)
    {
        AnsiConsole.WriteLine();
        
        var panel = new Panel(BuildPromptContent(toolName, input))
            .Border(BoxBorder.Rounded)
            .BorderColor(GetRiskColor(toolName))
            .Header($"[bold]{GetRiskIcon(toolName)} Claude wants to use: {toolName}[/]");

        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Builds the content for the approval prompt based on the tool and its input.
    /// </summary>
    private static string BuildPromptContent(string toolName, JsonElement input)
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
    private static void BuildEditFilePrompt(System.Text.StringBuilder content, JsonElement input)
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
        
        if (!string.IsNullOrEmpty(path) && File.Exists(path))
        {
            try
            {
                var fileLines = File.ReadAllLines(path);
                
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
            content.AppendLine("  [yellow](file does not exist or path not specified)[/]");
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
            
            content.AppendLine(CultureInfo.InvariantCulture, $"  [cyan]{prop.Name}:[/] {Markup.Escape(valueStr ?? "(null)")}");
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
                new SelectionPrompt<string>()
                    .Title("Allow this operation?")
                    .AddChoices("[green][Y]es - Execute this command[/]", "[red][N]o - Deny this command[/]"));

            return choice.Contains("Yes", StringComparison.Ordinal)
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
                var choices = new List<string>
                {
                    "[green][Y]es - Write this file[/]",
                    "[red][N]o - Deny this operation[/]",
                    "[yellow][A]lways - Approve all write_file operations this session[/]",
                    "[cyan][V]iew - View full content[/]"
                };

                while (true)
                {
                    var choice = AnsiConsole.Prompt(
                        new SelectionPrompt<string>()
                            .Title("Allow this operation?")
                            .AddChoices(choices));

                    if (choice.Contains("View", StringComparison.Ordinal))
                    {
                        DisplayFullContent(content ?? "");
                        continue;
                    }

                    if (choice.Contains("Yes", StringComparison.Ordinal))
                    {
                        return new ApprovalDecision(true, false);
                    }

                    if (choice.Contains("Always", StringComparison.Ordinal))
                    {
                        return new ApprovalDecision(true, true);
                    }

                    if (choice.Contains("No", StringComparison.Ordinal))
                    {
                        return new ApprovalDecision(false, false);
                    }
                }
            }
        }

        // For other tools (write_file with <= 50 lines, edit_file), offer Yes/No/Always
        var standardChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Allow this operation?")
                .AddChoices(
                    "[green][Y]es - Approve this operation[/]",
                    "[red][N]o - Deny this operation[/]",
                    "[yellow][A]lways - Approve all operations of this type this session[/]"));

        if (standardChoice.Contains("Yes", StringComparison.Ordinal))
        {
            return new ApprovalDecision(true, false);
        }

        if (standardChoice.Contains("Always", StringComparison.Ordinal))
        {
            return new ApprovalDecision(true, true);
        }
        
        return new ApprovalDecision(false, false);
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
