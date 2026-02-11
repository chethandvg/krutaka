using System.Security;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Enforces command execution security policies.
/// Validates commands against allowlists, blocklists, and shell metacharacter injection.
/// </summary>
public class CommandPolicy : ISecurityPolicy
{
    private static readonly HashSet<string> AllowedExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "git", "dotnet", "node", "npm", "npx", "python", "python3", "pip",
        "cat", "type", "find", "dir", "where", "grep", "findstr", "tree",
        "echo", "sort", "head", "tail", "wc", "diff", "mkdir"
    };

    private static readonly HashSet<string> BlockedExecutables = new(StringComparer.OrdinalIgnoreCase)
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

    public string ValidatePath(string path, string allowedRoot)
    {
        return SafeFileOperations.ValidatePath(path, allowedRoot);
    }

    public void ValidateCommand(string executable, IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(executable);
        ArgumentNullException.ThrowIfNull(arguments);

        if (string.IsNullOrWhiteSpace(executable))
        {
            throw new SecurityException("Executable name cannot be empty.");
        }

        // Security: Reject any path with directory separators - only allow simple executable names
        // This prevents executing arbitrary binaries by providing a path to a maliciously named file
        if (executable.Contains(Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            executable.Contains(Path.AltDirectorySeparatorChar, StringComparison.Ordinal) ||
            Path.IsPathRooted(executable))
        {
            throw new SecurityException(
                $"Executable path must be a simple name without directory separators: '{executable}'. Only executables resolved from PATH are permitted.");
        }

        // Validate executable path doesn't contain shell metacharacters FIRST
        if (executable.Any(c => ShellMetacharacters.Contains(c)))
        {
            throw new SecurityException(
                $"Executable path contains shell metacharacters: '{executable}'. This is a potential command injection attack.");
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
            throw new SecurityException(
                $"Blocked executable: '{executableName}'. This command is not permitted for security reasons.");
        }

        // Check allowlist (case-insensitive via HashSet comparer)
        if (!AllowedExecutables.Contains(executableNameForComparison))
        {
            throw new SecurityException(
                $"Executable '{executableName}' is not in the allowlist. Only the following commands are permitted: {string.Join(", ", AllowedExecutables)}");
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
                throw new SecurityException(
                    $"Argument contains shell metacharacters: '{arg}'. This is a potential command injection attack.");
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
}
