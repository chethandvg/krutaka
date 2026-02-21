using Krutaka.Core;
using Serilog;
using Spectre.Console;

#pragma warning disable CA1031 // Some catch blocks intentionally catch Exception to prevent loop crashes

namespace Krutaka.Console;

internal sealed partial class ConsoleRunLoop
{
    /// <summary>
    /// Handles the /checkpoint command — creates a manual git checkpoint.
    /// </summary>
    private async Task HandleCheckpointCommandAsync(CancellationToken cancellationToken)
    {
        var checkpointService = _currentSession.GitCheckpointService;
        if (checkpointService is null)
        {
            AnsiConsole.MarkupLine("[yellow]⚠ Checkpoints not available — not a git repository[/]");
            AnsiConsole.WriteLine();
            return;
        }

        try
        {
            var checkpointId = await checkpointService.CreateCheckpointAsync("Manual checkpoint", cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(checkpointId))
            {
                AnsiConsole.MarkupLine("[yellow]⚠ Nothing to checkpoint — working tree is clean or repository has no commits[/]");
                Log.Information("Manual checkpoint skipped: nothing to checkpoint (clean working tree or no commits)");
            }
            else
            {
                AnsiConsole.MarkupLine($"[green]✓ Checkpoint created: {Markup.Escape(checkpointId)} \"Manual checkpoint\"[/]");
                Log.Information("Manual checkpoint created: {CheckpointId}", checkpointId);
            }
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ Failed to create checkpoint: {Markup.Escape(ex.Message)}[/]");
            Log.Warning(ex, "Failed to create manual checkpoint");
        }

        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Handles the /rollback command — rolls back to a previous git checkpoint.
    /// </summary>
    private async Task HandleRollbackCommandAsync(string? argument, CancellationToken cancellationToken)
    {
        var checkpointService = _currentSession.GitCheckpointService;
        if (checkpointService is null)
        {
            AnsiConsole.MarkupLine("[yellow]⚠ Checkpoints not available — not a git repository[/]");
            AnsiConsole.WriteLine();
            return;
        }

        IReadOnlyList<CheckpointInfo> checkpoints;
        try
        {
            checkpoints = await checkpointService.ListCheckpointsAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine("[yellow]⚠ Checkpoints not available — not a git repository[/]");
            Log.Warning(ex, "Failed to list checkpoints");
            AnsiConsole.WriteLine();
            return;
        }

        if (checkpoints.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No checkpoints available for this session.[/]");
            AnsiConsole.WriteLine();
            return;
        }

        CheckpointInfo? target = null;

        if (string.IsNullOrWhiteSpace(argument))
        {
            // No argument — show interactive selection via numbered table + numeric prompt
            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Grey)
                .AddColumn("#")
                .AddColumn("ID")
                .AddColumn("Message");

            for (int i = 0; i < checkpoints.Count; i++)
            {
                var cp = checkpoints[i];
                table.AddRow(
                    (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    Markup.Escape(cp.CheckpointId),
                    Markup.Escape(cp.Message));
            }

            AnsiConsole.Write(table);

            var maxIndex = checkpoints.Count;
            var selectedNumber = AnsiConsole.Prompt(
                new TextPrompt<int>($"Select checkpoint [1-{maxIndex}] (0 = cancel):")
                    .ValidationErrorMessage("[red]Please enter a valid number.[/]")
                    .Validate(n => n is >= 0 && n <= maxIndex
                        ? ValidationResult.Success()
                        : ValidationResult.Error($"Value must be between 0 and {maxIndex}.")));

            if (selectedNumber == 0)
            {
                AnsiConsole.WriteLine();
                return;
            }

            target = checkpoints[selectedNumber - 1];
        }
        else if (argument.Equals("LATEST", StringComparison.OrdinalIgnoreCase))
        {
            target = checkpoints[^1];
        }
        else
        {
            target = checkpoints.FirstOrDefault(cp => cp.CheckpointId.Equals(argument, StringComparison.OrdinalIgnoreCase));
            if (target is null)
            {
                AnsiConsole.MarkupLine($"[yellow]⚠ Checkpoint '{Markup.Escape(argument)}' not found.[/]");
                AnsiConsole.WriteLine();
                return;
            }
        }

        // Confirmation prompt
        var label = argument?.Equals("LATEST", StringComparison.OrdinalIgnoreCase) == true
            ? $"{target.CheckpointId} (latest)"
            : target.CheckpointId;

        AnsiConsole.MarkupLine($"[yellow]⚠ Rollback to {Markup.Escape(label)}? This will restore files to that state.[/]");

        var confirmed = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .AddChoices("Yes", "No"));

        if (confirmed != "Yes")
        {
            AnsiConsole.MarkupLine("[dim]Rollback cancelled.[/]");
            AnsiConsole.WriteLine();
            return;
        }

        try
        {
            await checkpointService.RollbackToCheckpointAsync(target.CheckpointId, cancellationToken).ConfigureAwait(false);
            AnsiConsole.MarkupLine($"[green]✓ Rolled back to {Markup.Escape(target.CheckpointId)}[/]");
            Log.Information("Rolled back to checkpoint {CheckpointId}", target.CheckpointId);
        }
        catch (Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error during rollback: {Markup.Escape(ex.Message)}[/]");
            Log.Error(ex, "Failed to rollback to checkpoint {CheckpointId}", target.CheckpointId);
        }

        AnsiConsole.WriteLine();
    }
}
