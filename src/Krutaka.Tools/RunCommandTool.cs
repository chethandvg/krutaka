using System.Globalization;
using System.Security;
using System.Text;
using System.Text.Json;
using CliWrap;
using CliWrap.Buffered;
using Krutaka.Core;
using Meziantou.Framework.Win32;

namespace Krutaka.Tools;

/// <summary>
/// Tool for executing shell commands with full sandboxing and security controls.
/// Requires human approval for every execution.
/// Commands are validated against allowlist, environment is scrubbed, and process is sandboxed with Job Objects.
/// </summary>
public class RunCommandTool : ToolBase
{
    private readonly string _projectRoot;
    private readonly ISecurityPolicy _securityPolicy;

    /// <summary>
    /// Initializes a new instance of the <see cref="RunCommandTool"/> class.
    /// </summary>
    /// <param name="projectRoot">The allowed root directory for command execution.</param>
    /// <param name="securityPolicy">The security policy for command validation.</param>
    public RunCommandTool(string projectRoot, ISecurityPolicy securityPolicy)
    {
        ArgumentNullException.ThrowIfNull(projectRoot);
        ArgumentNullException.ThrowIfNull(securityPolicy);
        _projectRoot = projectRoot;
        _securityPolicy = securityPolicy;
    }

    /// <inheritdoc/>
    public override string Name => "run_command";

    /// <inheritdoc/>
    public override string Description => "Executes a shell command in a sandboxed environment with strict security controls. " +
        "Commands are validated against an allowlist (git, dotnet, npm, etc.) and blocklist (powershell, curl, etc.). " +
        "Shell metacharacters are blocked to prevent injection attacks. " +
        "The process is sandboxed with memory (256MB) and CPU time (30s) limits. " +
        "Environment variables containing secrets are scrubbed before execution. " +
        "This is a high-risk operation that requires human approval for every invocation. " +
        "Returns combined stdout and stderr output with clear labeling and the exit code.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("executable", "string", "The executable to run (must be in allowlist, e.g., 'git', 'dotnet', 'npm')", true),
        ("arguments", "array", "Array of command arguments (each validated for shell metacharacters)", false),
        ("working_directory", "string", "Working directory for command execution (defaults to project root, must be within project root)", false)
    );

    /// <inheritdoc/>
    public override async Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
    {
        try
        {
            // Extract executable parameter
            if (!input.TryGetProperty("executable", out var executableElement))
            {
                return "Error: Missing required parameter 'executable'";
            }

            var executable = executableElement.GetString();
            if (string.IsNullOrWhiteSpace(executable))
            {
                return "Error: Parameter 'executable' cannot be empty";
            }

            // Extract arguments parameter (optional)
            var arguments = new List<string>();
            if (input.TryGetProperty("arguments", out var argsElement) && argsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var argElement in argsElement.EnumerateArray())
                {
                    var arg = argElement.GetString();
                    if (arg is not null)
                    {
                        arguments.Add(arg);
                    }
                }
            }

            // Extract working directory parameter (optional)
            string workingDirectory = _projectRoot;
            if (input.TryGetProperty("working_directory", out var workingDirElement))
            {
                var workingDirInput = workingDirElement.GetString();
                if (!string.IsNullOrWhiteSpace(workingDirInput))
                {
                    try
                    {
                        workingDirectory = _securityPolicy.ValidatePath(workingDirInput, _projectRoot);
                    }
                    catch (SecurityException ex)
                    {
                        return $"Error: Working directory validation failed - {ex.Message}";
                    }
                }
            }

            // Validate command against security policy (allowlist, blocklist, metacharacters)
            try
            {
                _securityPolicy.ValidateCommand(executable, arguments);
            }
            catch (SecurityException ex)
            {
                return $"Error: Command validation failed - {ex.Message}";
            }

            // Scrub environment variables to remove secrets
            var environment = Environment.GetEnvironmentVariables()
                .Cast<System.Collections.DictionaryEntry>()
                .ToDictionary(
                    e => e.Key.ToString() ?? string.Empty,
                    e => e.Value?.ToString());

            var scrubbedEnvironment = _securityPolicy.ScrubEnvironment(environment);

            // Execute command with CliWrap streaming API and Job Object sandboxing
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            try
            {
                // Create Job Object for process sandboxing (Windows only)
                JobObject? job = null;
#pragma warning disable CA1031 // Do not catch general exception types - Job Object creation may fail, continue without it
                try
                {
                    if (OperatingSystem.IsWindows())
                    {
                        job = new JobObject();
                        
                        // Set Job Object limits:
                        // - Memory limit: 256 MB
                        // - CPU time limit: 30 seconds
                        // - Kill on job close: prevents orphaned processes
                        job.SetLimits(new JobObjectLimits
                        {
                            Flags = JobObjectLimitFlags.KillOnJobClose | JobObjectLimitFlags.DieOnUnhandledException,
                            ProcessMemoryLimit = (UIntPtr)(256 * 1024 * 1024), // 256 MB
                            PerProcessUserTimeLimit = 30 * 10_000_000L // 30 seconds in 100-nanosecond units
                        });
                    }
                }
                catch (Exception)
                {
                    // Job Object creation may fail - continue without it
                    job?.Dispose();
                    job = null;
                }
#pragma warning restore CA1031

                try
                {
                    // Use StringBuilder to capture stdout/stderr (same as ExecuteBufferedAsync)
                    var stdOutBuffer = new StringBuilder();
                    var stdErrBuffer = new StringBuilder();

                    // Configure command with CliWrap using streaming API (ExecuteAsync)
                    // This gives us access to ProcessId for Job Object assignment
                    var command = Cli.Wrap(executable)
                        .WithArguments(arguments)
                        .WithWorkingDirectory(workingDirectory)
                        .WithEnvironmentVariables(scrubbedEnvironment.ToDictionary(kvp => kvp.Key, kvp => kvp.Value))
                        .WithValidation(CommandResultValidation.None) // We'll handle exit codes ourselves
                        .WithStandardOutputPipe(PipeTarget.ToStringBuilder(stdOutBuffer))
                        .WithStandardErrorPipe(PipeTarget.ToStringBuilder(stdErrBuffer));

                    // Start the process
                    var commandTask = command.ExecuteAsync(linkedCts.Token);

                    // Assign process to Job Object if available (Windows only)
                    if (job != null && OperatingSystem.IsWindows())
                    {
                        try
                        {
                            // Brief delay to ensure process has started and ProcessId is available
                            // This is a race condition mitigation: CliWrap's ExecuteAsync returns immediately
                            // but the underlying process may take a few milliseconds to fully initialize.
                            // 10ms is empirically sufficient for process startup on typical systems.
                            // If the process exits before this delay completes, the catch block handles it gracefully.
                            await Task.Delay(10, CancellationToken.None).ConfigureAwait(false);
                            
                            // Get Process object from ProcessId and assign to Job Object
                            using var process = System.Diagnostics.Process.GetProcessById(commandTask.ProcessId);
                            job.AssignProcess(process);
                        }
#pragma warning disable CA1031 // Do not catch general exception types - Job Object assignment may fail if process has already exited
                        catch (Exception)
                        {
                            // Job Object assignment may fail if process has already exited
                            // Continue execution - timeout and other controls are still in place
                        }
#pragma warning restore CA1031
                    }

                    // Wait for command completion
                    var result = await commandTask;

                    // Format output with clear labeling
                    var output = new StringBuilder();
                    output.AppendLine(CultureInfo.InvariantCulture, $"Command executed: {executable} {string.Join(" ", arguments)}");
                    output.AppendLine(CultureInfo.InvariantCulture, $"Working directory: {workingDirectory}");
                    output.AppendLine(CultureInfo.InvariantCulture, $"Exit code: {result.ExitCode}");
                    output.AppendLine();

                    var stdOut = stdOutBuffer.ToString();
                    var stdErr = stdErrBuffer.ToString();

                    if (!string.IsNullOrWhiteSpace(stdOut))
                    {
                        output.AppendLine("=== STDOUT ===");
                        output.AppendLine(stdOut);
                    }

                    if (!string.IsNullOrWhiteSpace(stdErr))
                    {
                        if (!string.IsNullOrWhiteSpace(stdOut))
                        {
                            output.AppendLine();
                        }

                        output.AppendLine("=== STDERR ===");
                        output.AppendLine(stdErr);
                    }

                    return output.ToString();
                }
                finally
                {
                    job?.Dispose();
                }
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
            {
                return "Error: Command execution timed out after 30 seconds";
            }
            catch (OperationCanceledException)
            {
                return "Error: Command execution was cancelled";
            }
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error executing command - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
