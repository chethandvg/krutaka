using System.Globalization;
using System.Security;
using System.Text;
using System.Text.Json;
using CliWrap;
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
            var arguments = input.TryGetProperty("arguments", out var argsElement) && argsElement.ValueKind == JsonValueKind.Array
                ? argsElement.EnumerateArray()
                    .Select(argElement => argElement.GetString())
                    .Where(arg => arg is not null)
                    .Cast<string>()
                    .ToList()
                : new List<string>();

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

            var sandboxingWarnings = new List<string>();

            try
            {
                // Use StringBuilder to capture stdout/stderr
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

                // Create Job Object for process sandboxing (Windows only)
                using JobObject? job = OperatingSystem.IsWindows() ? CreateJobObject(sandboxingWarnings) : null;

                // Start the process
                var commandTask = command.ExecuteAsync(linkedCts.Token);

                // Assign process to Job Object if available (Windows only)
                if (job != null && OperatingSystem.IsWindows())
                {
                    AssignProcessToJobObject(job, commandTask.ProcessId, sandboxingWarnings, linkedCts.Token);
                }

                // Wait for command completion
                var result = await commandTask;

                // Format output with clear labeling and untrusted content wrapping
                var output = new StringBuilder();
                output.AppendLine(CultureInfo.InvariantCulture, $"Command executed: {executable} {string.Join(" ", arguments)}");
                output.AppendLine(CultureInfo.InvariantCulture, $"Working directory: {workingDirectory}");
                output.AppendLine(CultureInfo.InvariantCulture, $"Exit code: {result.ExitCode}");
                
                // Include sandboxing warnings if any
                if (sandboxingWarnings.Count > 0)
                {
                    output.AppendLine(CultureInfo.InvariantCulture, $"Sandboxing warnings: {string.Join("; ", sandboxingWarnings)}");
                }
                
                output.AppendLine();

                var stdOut = stdOutBuffer.ToString();
                var stdErr = stdErrBuffer.ToString();

                if (!string.IsNullOrWhiteSpace(stdOut))
                {
                    output.AppendLine("=== STDOUT ===");
                    output.AppendLine("<untrusted_command_output>");
                    output.AppendLine(stdOut);
                    output.AppendLine("</untrusted_command_output>");
                }

                if (!string.IsNullOrWhiteSpace(stdErr))
                {
                    if (!string.IsNullOrWhiteSpace(stdOut))
                    {
                        output.AppendLine();
                    }

                    output.AppendLine("=== STDERR ===");
                    output.AppendLine("<untrusted_command_output>");
                    output.AppendLine(stdErr);
                    output.AppendLine("</untrusted_command_output>");
                }

                return output.ToString();
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

    /// <summary>
    /// Creates and configures a Job Object with memory and CPU limits.
    /// </summary>
    /// <param name="warnings">List to collect warnings if Job Object creation fails.</param>
    /// <returns>A configured Job Object, or null if creation failed.</returns>
    private static JobObject? CreateJobObject(List<string> warnings)
    {
#pragma warning disable CA1031 // Do not catch general exception types - Job Object creation may fail, we track warnings
        try
        {
            var job = new JobObject();
            
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
            
            return job;
        }
        catch (Exception ex)
        {
            // Job Object creation failed - command will run without sandboxing limits
            warnings.Add($"Job Object creation failed: {ex.Message}. Process will run without memory/CPU limits.");
            return null;
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Assigns a process to a Job Object with bounded retry logic.
    /// </summary>
    /// <param name="job">The Job Object to assign the process to.</param>
    /// <param name="processId">The process ID to assign.</param>
    /// <param name="warnings">List to collect warnings if assignment fails.</param>
    /// <param name="cancellationToken">Cancellation token to respect during retry.</param>
    private static void AssignProcessToJobObject(JobObject job, int processId, List<string> warnings, CancellationToken cancellationToken)
    {
        // Bounded retry to ensure process is observable before Job Object assignment.
        // CliWrap's ExecuteAsync returns immediately, but the underlying process may take
        // some time to fully initialize and become visible to Process APIs, especially on
        // slower or heavily loaded machines.
        const int maxAssignAttempts = 50; // ~500ms total with 10ms delay between attempts
        var retryDelay = TimeSpan.FromMilliseconds(10);

        for (var attempt = 0; attempt < maxAssignAttempts; attempt++)
        {
            try
            {
                // Respect cancellation while attempting assignment
                cancellationToken.ThrowIfCancellationRequested();

                // Get Process object from ProcessId and assign to Job Object
                using var process = System.Diagnostics.Process.GetProcessById(processId);
                job.AssignProcess(process);
                return; // Success - exit the method
            }
#pragma warning disable CA1031 // Do not catch general exception types - we handle specific exceptions inline
            catch (ArgumentException) when (attempt < maxAssignAttempts - 1)
            {
                // Process not yet observable; wait briefly then retry
                Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch (System.ComponentModel.Win32Exception) when (attempt < maxAssignAttempts - 1)
            {
                // Transient OS error while process is starting; wait briefly then retry
                Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                // Unexpected error or process has already exited
                warnings.Add($"Job Object assignment failed: {ex.Message}. Process will run without sandboxing limits.");
                return;
            }
#pragma warning restore CA1031
        }

        // All retry attempts exhausted
        warnings.Add("Job Object assignment failed after all retry attempts. Process will run without sandboxing limits.");
    }
}
