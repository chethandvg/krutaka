using System.Security;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Enforces command execution security policies.
/// Validates commands against allowlists, blocklists, and shell metacharacter injection.
/// Logs security violations to the audit trail when audit logger is configured.
/// </summary>
public class CommandPolicy : ISecurityPolicy
{
    private readonly IAuditLogger? _auditLogger;
    private readonly IFileOperations _fileOperations;

    private static readonly HashSet<string> AllowedExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "git", "dotnet", "node", "npm", "npx", "python", "python3", "pip",
        "cat", "type", "find", "dir", "where", "grep", "findstr", "tree",
        "echo", "sort", "head", "tail", "wc", "diff", "mkdir"
    };

    internal static readonly HashSet<string> BlockedExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "pwsh", "cmd",
        "reg", "regedit", "netsh", "netstat",
        "certutil", "bitsadmin",
        "format", "diskpart", "chkdsk",
        "rundll32", "regsvr32", "mshta", "wscript", "cscript",
        "msiexec", "sc", "schtasks", "taskkill",
        "net", "net1", "runas", "icacls", "takeown",
        "curl", "wget", "invoke-webrequest"
    };

    private static readonly char[] ShellMetacharacters =
    [
        '|', '>', '<', '&', ';', '`', '$', '%', '^'
    ];

    private static readonly HashSet<string> ToolsRequiringApproval = new(StringComparer.OrdinalIgnoreCase)
    {
        "write_file", "edit_file", "run_command"
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="CommandPolicy"/> class.
    /// </summary>
    /// <param name="fileOperations">The file operations service for path validation.</param>
    /// <param name="auditLogger">Optional audit logger for security violation logging.</param>
    public CommandPolicy(IFileOperations fileOperations, IAuditLogger? auditLogger = null)
    {
        _fileOperations = fileOperations ?? throw new ArgumentNullException(nameof(fileOperations));
        _auditLogger = auditLogger;
    }

    public string ValidatePath(string path, string allowedRoot, CorrelationContext? correlationContext = null)
    {
        return _fileOperations.ValidatePath(path, allowedRoot, correlationContext);
    }

    public void ValidateCommand(string executable, IEnumerable<string> arguments, CorrelationContext? correlationContext = null)
    {
        ArgumentNullException.ThrowIfNull(executable);
        ArgumentNullException.ThrowIfNull(arguments);

        if (string.IsNullOrWhiteSpace(executable))
        {
            LogAndThrowSecurityViolation(
                "blocked_command",
                executable,
                "Executable name cannot be empty",
                correlationContext);
        }

        // Security: Reject any path with directory separators - only allow simple executable names
        // This prevents executing arbitrary binaries by providing a path to a maliciously named file
        if (executable.Contains(Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            executable.Contains(Path.AltDirectorySeparatorChar, StringComparison.Ordinal) ||
            Path.IsPathRooted(executable))
        {
            LogAndThrowSecurityViolation(
                "blocked_command",
                executable,
                $"Executable path must be a simple name without directory separators: '{executable}'. Only executables resolved from PATH are permitted.",
                correlationContext);
        }

        // Validate executable path doesn't contain shell metacharacters FIRST
        if (executable.Any(c => ShellMetacharacters.Contains(c)))
        {
            LogAndThrowSecurityViolation(
                "blocked_command",
                executable,
                $"Executable path contains shell metacharacters: '{executable}'. This is a potential command injection attack.",
                correlationContext);
        }

        // Extract just the executable name and preserve original casing for error messages
        var executableName = Path.GetFileName(executable);
        var executableNameForComparison = executableName;

        // Remove .exe extension if present for comparison
        if (executableName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            executableNameForComparison = executableName[..^4];
        }

        // Check blocklist (case-insensitive via HashSet comparer)
        if (BlockedExecutables.Contains(executableNameForComparison))
        {
            LogAndThrowSecurityViolation(
                "blocked_command",
                executableName,
                $"Blocked executable: '{executableName}'. This command is not permitted for security reasons.",
                correlationContext);
        }

        // Check allowlist (case-insensitive via HashSet comparer)
        if (!AllowedExecutables.Contains(executableNameForComparison))
        {
            LogAndThrowSecurityViolation(
                "blocked_command",
                executableName,
                $"Executable '{executableName}' is not in the allowlist. Only the following commands are permitted: {string.Join(", ", AllowedExecutables)}",
                correlationContext);
        }

        // Validate arguments don't contain shell metacharacters
        foreach (var arg in arguments)
        {
            if (arg is null)
            {
                continue;
            }

            if (arg.Any(c => ShellMetacharacters.Contains(c)))
            {
                LogAndThrowSecurityViolation(
                    "blocked_command_argument",
                    arg,
                    $"Argument contains shell metacharacters: '{arg}'. This is a potential command injection attack.",
                    correlationContext);
            }
        }
    }

    public IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
    {
        return EnvironmentScrubber.ScrubEnvironment(environment);
    }

    public bool IsApprovalRequired(string toolName)
    {
        ArgumentNullException.ThrowIfNull(toolName);
        return ToolsRequiringApproval.Contains(toolName);
    }

    /// <summary>
    /// Logs a security violation to the audit trail and throws a SecurityException.
    /// </summary>
    private void LogAndThrowSecurityViolation(
        string violationType,
        string blockedValue,
        string message,
        CorrelationContext? correlationContext)
    {
        // Log the violation if audit logger is configured
        if (_auditLogger != null && correlationContext != null)
        {
            _auditLogger.LogSecurityViolation(
                correlationContext,
                violationType,
                blockedValue,
                message);
        }

        // Always throw the security exception
        throw new SecurityException(message);
    }
}
