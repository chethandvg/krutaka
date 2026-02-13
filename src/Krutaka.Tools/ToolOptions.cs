namespace Krutaka.Tools;

/// <summary>
/// Configuration options for tool execution.
/// </summary>
public sealed class ToolOptions
{
    /// <summary>
    /// Gets or sets the default working directory for command execution and file operations.
    /// In v0.2.0, this serves as the default directory when no specific directory is requested.
    /// With dynamic directory scoping, tools can request access to multiple directories at runtime.
    /// </summary>
    public string DefaultWorkingDirectory { get; set; } = Environment.CurrentDirectory;

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

    /// <summary>
    /// Gets or sets the ceiling directory - the maximum ancestor directory the agent can access.
    /// The agent cannot access anything above this directory.
    /// v0.2.0 Dynamic Directory Scoping feature.
    /// </summary>
    public string CeilingDirectory { get; set; } = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    /// <summary>
    /// Gets or sets the glob patterns for auto-approved directory access.
    /// Matching paths are automatically granted without prompting (Layer 2).
    /// v0.2.0 Dynamic Directory Scoping feature.
    /// </summary>
#pragma warning disable CA1819 // Properties should not return arrays - this is configuration data
    public string[] AutoGrantPatterns { get; set; } = [];
#pragma warning restore CA1819

    /// <summary>
    /// Gets or sets the maximum number of concurrent directory access grants per session.
    /// v0.2.0 Dynamic Directory Scoping feature.
    /// </summary>
    public int MaxConcurrentGrants { get; set; } = 10;

    /// <summary>
    /// Gets or sets the default time-to-live (in minutes) for session grants.
    /// Null means grants last for the session lifetime.
    /// v0.2.0 Dynamic Directory Scoping feature.
    /// </summary>
    public int? DefaultGrantTtlMinutes { get; set; }

    /// <summary>
    /// Gets or sets the command policy configuration for tier overrides.
    /// v0.3.0 Graduated Command Execution feature.
    /// </summary>
    public CommandPolicyOptions CommandPolicy { get; set; } = new();
}
