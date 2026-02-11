namespace Krutaka.Tools;

/// <summary>
/// Configuration options for tool execution.
/// </summary>
public sealed class ToolOptions
{
    /// <summary>
    /// Gets or sets the working directory for command execution and file operations.
    /// This is the root directory that tools are restricted to operate within.
    /// </summary>
    public string WorkingDirectory { get; set; } = Environment.CurrentDirectory;

    /// <summary>
    /// Gets or sets the command timeout in seconds.
    /// Commands exceeding this timeout will be terminated.
    /// Wired into RunCommandTool via ServiceExtensions.AddAgentTools().
    /// </summary>
    public int CommandTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Gets or sets whether write operations (write_file, edit_file, run_command) require human approval.
    /// NOTE: This configuration is reserved for future human-approval mechanism implementation.
    /// Currently, approval requirements are determined by CommandPolicy.ToolsRequiringApproval and
    /// enforced in the agentic loop (not yet implemented). This option should not be relied on for
    /// security behavior yet.
    /// </summary>
    public bool RequireApprovalForWrites { get; set; } = true;
}
