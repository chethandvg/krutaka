using Spectre.Console;

namespace Krutaka.Console;

/// <summary>
/// First-run setup wizard for configuring the Anthropic API key.
/// </summary>
internal static class SetupWizard
{
    /// <summary>
    /// Runs the interactive setup wizard to collect and store the API key.
    /// </summary>
    /// <returns>True if setup completed successfully, false if cancelled.</returns>
    public static bool Run()
    {
        AnsiConsole.Clear();
        
        AnsiConsole.Write(
            new FigletText("Krutaka")
                .Centered()
                .Color(Color.Cyan1));

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold cyan]Welcome to Krutaka Setup[/]");
        AnsiConsole.WriteLine();

        if (SecretsProvider.HasStoredCredential())
        {
            var overwrite = AnsiConsole.Confirm(
                "[yellow]An API key is already configured. Do you want to replace it?[/]",
                defaultValue: false);

            if (!overwrite)
            {
                AnsiConsole.MarkupLine("[green]Setup cancelled. Existing API key will be used.[/]");
                return false;
            }
        }

        AnsiConsole.MarkupLine("[dim]This wizard will help you securely store your Anthropic API key.[/]");
        AnsiConsole.MarkupLine("[dim]Your API key will be encrypted using Windows Credential Manager (DPAPI).[/]");
        AnsiConsole.WriteLine();

        string? apiKey = null;
        var isValid = false;

        while (!isValid)
        {
            apiKey = AnsiConsole.Prompt(
                new TextPrompt<string>("[cyan]Enter your Anthropic API key:[/]")
                    .PromptStyle("green")
                    .Secret('*'));

            if (SecretsProvider.IsValidApiKey(apiKey))
            {
                isValid = true;
            }
            else
            {
                AnsiConsole.MarkupLine("[red]Invalid API key format. API key must start with 'sk-ant-'.[/]");
                AnsiConsole.MarkupLine("[dim]You can get your API key from: https://console.anthropic.com/settings/keys[/]");
                AnsiConsole.WriteLine();

                var retry = AnsiConsole.Confirm("[yellow]Would you like to try again?[/]", defaultValue: true);
                if (!retry)
                {
                    AnsiConsole.MarkupLine("[red]Setup cancelled.[/]");
                    return false;
                }
            }
        }

        try
        {
            SecretsProvider.WriteCredential(apiKey!);
            
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[green]✓ API key saved successfully![/]");
            AnsiConsole.MarkupLine("[dim]Your API key has been securely stored in Windows Credential Manager.[/]");
            
            return true;
        }
        catch (InvalidOperationException ex)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[red]✗ Failed to save API key: {ex.Message}[/]");
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[red]✗ Access denied: {ex.Message}[/]");
            AnsiConsole.MarkupLine("[yellow]Please ensure you have permission to access Windows Credential Manager.[/]");
            return false;
        }
    }
}
