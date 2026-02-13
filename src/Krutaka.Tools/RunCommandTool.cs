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
/// In v0.3.0, uses ICommandPolicy for graduated approval based on risk tiers:
/// - Safe commands (git status, dotnet --version) execute without approval
/// - Moderate commands (git commit, dotnet build) auto-approve in trusted directories
/// - Elevated commands (git push, npm install) always require approval
/// - Dangerous commands are always blocked
/// Commands are validated against allowlist, environment is scrubbed, and process is sandboxed with Job Objects.
/// In v0.2.0, supports dynamic directory scoping via IAccessPolicyEngine.
/// </summary>
public class RunCommandTool : ToolBase
{
    private readonly string _defaultRoot;
    private readonly ISecurityPolicy _securityPolicy;
    private readonly int _commandTimeoutSeconds;
    private readonly IAccessPolicyEngine? _policyEngine;
    private readonly ICommandPolicy _commandPolicy;
    private readonly ICommandApprovalCache? _approvalCache;

    /// <summary>
    /// Initializes a new instance of the <see cref="RunCommandTool"/> class.
    /// </summary>
    /// <param name="defaultRoot">The default root directory (fallback when policy engine is null).</param>
    /// <param name="securityPolicy">The security policy for command validation.</param>
    /// <param name="commandTimeoutSeconds">Timeout in seconds for command execution (default: 30).</param>
    /// <param name="policyEngine">The access policy engine for dynamic directory scoping (v0.2.0). If null, falls back to static root.</param>
    /// <param name="commandPolicy">The command policy for graduated approval decisions (v0.3.0).</param>
    /// <param name="approvalCache">The command approval cache for checking pre-approved commands (v0.3.0). If null, all commands requiring approval will throw exception.</param>
    public RunCommandTool(string defaultRoot, ISecurityPolicy securityPolicy, int commandTimeoutSeconds = 30, IAccessPolicyEngine? policyEngine = null, ICommandPolicy commandPolicy = null!, ICommandApprovalCache? approvalCache = null)
    {
        ArgumentNullException.ThrowIfNull(defaultRoot);
        ArgumentNullException.ThrowIfNull(securityPolicy);
        ArgumentNullException.ThrowIfNull(commandPolicy);
        _defaultRoot = defaultRoot;
        _securityPolicy = securityPolicy;
        _commandTimeoutSeconds = commandTimeoutSeconds > 0 ? commandTimeoutSeconds : 30;
        _policyEngine = policyEngine;
        _commandPolicy = commandPolicy;
        _approvalCache = approvalCache;
    }

    /// <inheritdoc/>
    public override string Name => "run_command";

    /// <inheritdoc/>
    public override string Description => "Executes a shell command in a sandboxed environment with strict security controls. " +
        "Commands are validated against an allowlist (git, dotnet, npm, etc.) and blocklist (powershell, curl, etc.). " +
        "Shell metacharacters are blocked to prevent injection attacks. " +
        "Commands are classified into risk tiers (Safe, Moderate, Elevated, Dangerous). " +
        "Safe commands (git status, dotnet --version) execute automatically without approval. " +
        "Moderate commands (git commit, dotnet build) auto-approve in trusted directories, require approval elsewhere. " +
        "Elevated commands (git push, npm install) always require approval. " +
        "Dangerous commands are blocked. " +
        "The process is sandboxed with memory (256MB) and CPU time (30s) limits. " +
        "Environment variables containing secrets are scrubbed before execution. " +
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
            string workingDirectory;
            if (input.TryGetProperty("working_directory", out var workingDirElement))
            {
                var workingDirInput = workingDirElement.GetString();
                if (!string.IsNullOrWhiteSpace(workingDirInput))
                {
                    // Determine the directory to validate against
                    if (_policyEngine != null)
                    {
                        // v0.2.0: Dynamic directory scoping via policy engine
                        var request = new DirectoryAccessRequest(
                            Path: workingDirInput,
                            Level: AccessLevel.Execute,
                            Justification: $"Executing command: {executable}"
                        );

                        var decision = await _policyEngine.EvaluateAsync(request, cancellationToken).ConfigureAwait(false);

                        if (decision.Outcome == AccessOutcome.Denied)
                        {
                            var reasons = string.Join("; ", decision.DeniedReasons);
                            return $"Error: Access denied - {reasons}";
                        }

                        if (decision.Outcome == AccessOutcome.RequiresApproval)
                        {
                            // Throw exception to trigger interactive approval flow in AgentOrchestrator
                            // Use canonical scoped path so orchestrator grant matches session store lookup
                            throw new DirectoryAccessRequiredException(decision.ScopedPath ?? workingDirInput, AccessLevel.Execute, $"Executing command: {executable}");
                        }

                        // Use the granted scoped path as the validation root
                        workingDirectory = _securityPolicy.ValidatePath(workingDirInput, decision.ScopedPath!);
                    }
                    else
                    {
                        // v0.1.x: Static root fallback (backward compatibility)
                        workingDirectory = _securityPolicy.ValidatePath(workingDirInput, _defaultRoot);
                    }
                }
                else
                {
                    workingDirectory = _defaultRoot;
                }
            }
            else
            {
                workingDirectory = _defaultRoot;
            }

            // v0.3.0: Graduated command policy evaluation
            // Build command execution request
            var commandRequest = new CommandExecutionRequest(
                Executable: executable,
                Arguments: arguments,
                WorkingDirectory: workingDirectory,
                Justification: $"AI agent request: {executable} {string.Join(" ", arguments)}"
            );

            // Check if this command was recently approved (retry after user approval)
            var wasPreApproved = false;
            if (_approvalCache != null)
            {
                var commandSignature = BuildCommandSignature(commandRequest);
                wasPreApproved = _approvalCache.IsApproved(commandSignature);
            }

            // Evaluate command through graduated policy (unless pre-approved)
            // This internally calls ISecurityPolicy.ValidateCommand() for security pre-check,
            // then classifies the command risk tier and determines approval requirements
            if (!wasPreApproved)
            {
                CommandDecision commandDecision;
                try
                {
                    commandDecision = await _commandPolicy.EvaluateAsync(commandRequest, cancellationToken).ConfigureAwait(false);
                }
                catch (SecurityException ex)
                {
                    // Security pre-check failed (blocklist, metacharacters, etc.)
                    return $"Error: Command validation failed - {ex.Message}";
                }

                // Handle policy decision
                if (commandDecision.IsDenied)
                {
                    // Command is denied (Dangerous tier or directory access denied)
                    return $"Error: Command denied - {commandDecision.Reason}";
                }

                if (commandDecision.RequiresApproval)
                {
                    // Command requires human approval (Moderate in untrusted dir or Elevated tier)
                    // Throw exception to trigger interactive approval flow in AgentOrchestrator
                    throw new CommandApprovalRequiredException(commandRequest, commandDecision);
                }
            }

            // Command is approved for execution (Safe tier, Moderate in trusted dir, or pre-approved)
            // Continue with execution...

            // Scrub environment variables to remove secrets
            var environment = Environment.GetEnvironmentVariables()
                .Cast<System.Collections.DictionaryEntry>()
                .ToDictionary(
                    e => e.Key.ToString() ?? string.Empty,
                    e => e.Value?.ToString());

            var scrubbedEnvironment = _securityPolicy.ScrubEnvironment(environment);

            // Execute command with CliWrap streaming API and Job Object sandboxing
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(_commandTimeoutSeconds));
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
                return $"Error: Command execution timed out after {_commandTimeoutSeconds} seconds";
            }
            catch (OperationCanceledException)
            {
                return "Error: Command execution was cancelled";
            }
        }
        catch (DirectoryAccessRequiredException)
        {
            // Must propagate to AgentOrchestrator for interactive approval flow
            throw;
        }
        catch (CommandApprovalRequiredException)
        {
            // Must propagate to AgentOrchestrator for interactive approval flow
            throw;
        }
        catch (SecurityException ex)
        {
            return $"Error: Security validation failed - {ex.Message}";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Unexpected error executing command - {ex.Message}";
        }
#pragma warning restore CA1031
    }

    /// <summary>
    /// Builds a command signature for approval cache lookup.
    /// Format: "executable arg1 arg2 arg3..."
    /// NOTE: This method is also present in AgentOrchestrator.cs and must stay in sync.
    /// </summary>
    private static string BuildCommandSignature(CommandExecutionRequest request)
    {
        var args = string.Join(" ", request.Arguments);
        return string.IsNullOrEmpty(args) ? request.Executable : $"{request.Executable} {args}";
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
                // Process not yet observable; wait briefly then retry (cancellation-aware)
                cancellationToken.WaitHandle.WaitOne(retryDelay);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (System.ComponentModel.Win32Exception) when (attempt < maxAssignAttempts - 1)
            {
                // Transient OS error while process is starting; wait briefly then retry (cancellation-aware)
                cancellationToken.WaitHandle.WaitOne(retryDelay);
                cancellationToken.ThrowIfCancellationRequested();
            }
            catch (OperationCanceledException)
            {
                // Propagate cancellation cleanly without masking it as a warning
                throw;
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
