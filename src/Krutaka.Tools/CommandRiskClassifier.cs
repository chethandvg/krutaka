using System.Collections.ObjectModel;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Classifies commands into risk tiers based on executable name and arguments.
/// Uses a hardcoded ruleset for default commands, with argument-level granularity.
/// Classification is deterministic and does not depend on session state.
/// </summary>
public sealed class CommandRiskClassifier : ICommandRiskClassifier
{
    private readonly IReadOnlyList<CommandRiskRule> _defaultRules;
    private readonly Dictionary<string, IReadOnlyList<CommandRiskRule>> _rulesByExecutable;

    public CommandRiskClassifier()
    {
        _defaultRules = BuildDefaultRules();
        _rulesByExecutable = BuildRuleIndex(_defaultRules);
    }

    public CommandRiskTier Classify(CommandExecutionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        // 1. Security: Reject executables with path separators (same as CommandPolicy.ValidateCommand)
        // This prevents executing arbitrary binaries by providing a path
        if (request.Executable.Contains(Path.DirectorySeparatorChar, StringComparison.Ordinal) ||
            request.Executable.Contains(Path.AltDirectorySeparatorChar, StringComparison.Ordinal) ||
            Path.IsPathRooted(request.Executable))
        {
            return CommandRiskTier.Dangerous;
        }

        // 2. Normalize executable name (strip .exe, case-insensitive)
        var executableName = NormalizeExecutableName(request.Executable);

        // 3. Check blocklist → Dangerous (reference to CommandPolicy.BlockedExecutables)
        if (CommandPolicy.BlockedExecutables.Contains(executableName))
        {
            return CommandRiskTier.Dangerous;
        }

        // 4. Look up executable in default rules
        if (!_rulesByExecutable.TryGetValue(executableName, out var rules))
        {
            // Unknown executable → Dangerous (fail-closed)
            return CommandRiskTier.Dangerous;
        }

        // 5. Match argument patterns
        var tier = MatchArgumentPatterns(executableName, request.Arguments, rules);
        return tier;
    }

    public IReadOnlyList<CommandRiskRule> GetRules()
    {
        return _defaultRules;
    }

    /// <summary>
    /// Normalizes executable name by stripping .exe suffix.
    /// Comparisons are performed case-insensitively by callers.
    /// </summary>
    private static string NormalizeExecutableName(string executable)
    {
        var name = Path.GetFileName(executable);
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            name = name[..^4];
        }

        return name;
    }

    /// <summary>
    /// Matches argument patterns against rules for a given executable.
    /// Returns the tier from the first matching rule, or the executable's default tier if no match.
    /// </summary>
    private static CommandRiskTier MatchArgumentPatterns(
        string executableName,
        IReadOnlyList<string> arguments,
        IReadOnlyList<CommandRiskRule> rules)
    {
        // Special handling for dotnet: match first TWO arguments (e.g., "dotnet nuget push")
        if (executableName.Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            return MatchDotnetArguments(arguments, rules);
        }

        // For other executables: match first argument
        if (arguments.Count > 0)
        {
            var firstArg = arguments[0];
            foreach (var rule in rules)
            {
                if (rule.ArgumentPatterns is null)
                {
                    // This rule matches any arguments for this executable
                    return rule.Tier;
                }

                // Check if first argument matches any pattern (case-insensitive)
                if (rule.ArgumentPatterns.Any(pattern =>
                    pattern.Equals(firstArg, StringComparison.OrdinalIgnoreCase)))
                {
                    return rule.Tier;
                }
            }
        }
        else
        {
            // No arguments provided - check if there's a rule with null argument patterns (matches any)
            foreach (var rule in rules)
            {
                if (rule.ArgumentPatterns is null)
                {
                    return rule.Tier;
                }
            }
        }

        // No argument pattern matched → use executable's default tier
        // Default tier is the highest non-Safe tier for that executable
        return GetDefaultTierForExecutable(rules);
    }

    /// <summary>
    /// Special handling for dotnet commands: matches first TWO arguments.
    /// E.g., "dotnet nuget push" matches "nuget" and "push" together.
    /// </summary>
    private static CommandRiskTier MatchDotnetArguments(
        IReadOnlyList<string> arguments,
        IReadOnlyList<CommandRiskRule> rules)
    {
        // Try matching first argument only first
        if (arguments.Count > 0)
        {
            var firstArg = arguments[0];
            foreach (var rule in rules)
            {
                if (rule.ArgumentPatterns is null)
                {
                    return rule.Tier;
                }

                // Check if first argument matches any pattern in the list
                if (rule.ArgumentPatterns.Any(pattern =>
                    pattern.Equals(firstArg, StringComparison.OrdinalIgnoreCase)))
                {
                    return rule.Tier;
                }
            }
        }
        else
        {
            // No arguments - check for null pattern rules
            foreach (var rule in rules)
            {
                if (rule.ArgumentPatterns is null)
                {
                    return rule.Tier;
                }
            }
        }

        return GetDefaultTierForExecutable(rules);
    }

    /// <summary>
    /// Gets the default tier for an executable when no argument pattern matches.
    /// Default tier is the highest non-Safe tier for that executable.
    /// If only Safe tier rules exist, returns Safe.
    /// </summary>
    private static CommandRiskTier GetDefaultTierForExecutable(IReadOnlyList<CommandRiskRule> rules)
    {
        var highestTier = CommandRiskTier.Safe;
        foreach (var rule in rules)
        {
            if (rule.Tier > highestTier && rule.Tier != CommandRiskTier.Safe)
            {
                highestTier = rule.Tier;
            }
        }

        return highestTier;
    }

    /// <summary>
    /// Builds the index of rules grouped by executable name for fast lookup.
    /// </summary>
    private static Dictionary<string, IReadOnlyList<CommandRiskRule>> BuildRuleIndex(
        IReadOnlyList<CommandRiskRule> rules)
    {
        return rules
            .GroupBy(r => r.Executable, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => (IReadOnlyList<CommandRiskRule>)g.ToList(),
                StringComparer.OrdinalIgnoreCase);
    }

    // Static readonly arrays for argument patterns (CA1861)
    private static readonly string[] GitReadOnlyArgs = ["status", "log", "diff", "show", "rev-parse"];
    private static readonly string[] DotnetInfoArgs = ["--version", "--info", "--list-sdks", "--list-runtimes"];
    private static readonly string[] NodeVersionArg = ["--version"];
    private static readonly string[] NpmVersionArg = ["--version"];
    private static readonly string[] PythonVersionArg = ["--version"];
    private static readonly string[] PipReadOnlyArgs = ["--version", "list", "show", "freeze"];
    private static readonly string[] GitLocalArgs = ["add", "commit", "stash", "checkout", "switch", "merge"];
    private static readonly string[] DotnetBuildArgs = ["build", "test", "run", "restore", "clean", "format"];
    private static readonly string[] NpmScriptArgs = ["run", "test", "start", "lint", "build"];
    private static readonly string[] GitRemoteArgs = ["push", "pull", "fetch", "clone", "rebase", "reset", "cherry-pick", "branch", "tag", "remote"];
    private static readonly string[] DotnetPackageArgs = ["publish", "pack", "nuget", "new", "tool"];
    private static readonly string[] NpmDependencyArgs = ["install", "uninstall", "update", "publish", "link"];
    private static readonly string[] PipDependencyArgs = ["install", "uninstall", "download"];

    /// <summary>
    /// Builds the default hardcoded ruleset as specified in v0.3.0.
    /// </summary>
    private static ReadOnlyCollection<CommandRiskRule> BuildDefaultRules()
    {
        var rules = new List<CommandRiskRule>();

        // ===== SAFE TIER =====

        // git: read-only operations
        rules.Add(new CommandRiskRule(
            "git",
            GitReadOnlyArgs,
            CommandRiskTier.Safe,
            "Read-only git operations"));

        // dotnet: information queries
        rules.Add(new CommandRiskRule(
            "dotnet",
            DotnetInfoArgs,
            CommandRiskTier.Safe,
            "Dotnet information queries"));

        // node: version check
        rules.Add(new CommandRiskRule(
            "node",
            NodeVersionArg,
            CommandRiskTier.Safe,
            "Node version check"));

        // npm: version check
        rules.Add(new CommandRiskRule(
            "npm",
            NpmVersionArg,
            CommandRiskTier.Safe,
            "NPM version check"));

        // python/python3: version check
        rules.Add(new CommandRiskRule(
            "python",
            PythonVersionArg,
            CommandRiskTier.Safe,
            "Python version check"));

        rules.Add(new CommandRiskRule(
            "python3",
            PythonVersionArg,
            CommandRiskTier.Safe,
            "Python3 version check"));

        // pip: read-only operations
        rules.Add(new CommandRiskRule(
            "pip",
            PipReadOnlyArgs,
            CommandRiskTier.Safe,
            "Read-only pip operations"));

        // Read-only commands (any arguments)
        var readOnlyCommands = new[]
        {
            "cat", "type", "find", "dir", "where", "grep", "findstr",
            "tree", "echo", "sort", "head", "tail", "wc", "diff"
        };

        foreach (var cmd in readOnlyCommands)
        {
            rules.Add(new CommandRiskRule(
                cmd,
                null, // Any arguments
                CommandRiskTier.Safe,
                $"Read-only command: {cmd}"));
        }

        // ===== MODERATE TIER =====

        // git: local-only operations
        rules.Add(new CommandRiskRule(
            "git",
            GitLocalArgs,
            CommandRiskTier.Moderate,
            "Local-only git operations"));

        // dotnet: build/test operations
        rules.Add(new CommandRiskRule(
            "dotnet",
            DotnetBuildArgs,
            CommandRiskTier.Moderate,
            "Dotnet build and test operations"));

        // npm/npx: project script execution
        rules.Add(new CommandRiskRule(
            "npm",
            NpmScriptArgs,
            CommandRiskTier.Moderate,
            "NPM project script execution"));

        rules.Add(new CommandRiskRule(
            "npx",
            NpmScriptArgs,
            CommandRiskTier.Moderate,
            "NPX project script execution"));

        // python/python3: script execution (default for unmatched args)
        rules.Add(new CommandRiskRule(
            "python",
            null, // Default tier when no Safe pattern matches
            CommandRiskTier.Moderate,
            "Python script execution"));

        rules.Add(new CommandRiskRule(
            "python3",
            null, // Default tier when no Safe pattern matches
            CommandRiskTier.Moderate,
            "Python3 script execution"));

        // mkdir: directory creation
        rules.Add(new CommandRiskRule(
            "mkdir",
            null, // Any arguments
            CommandRiskTier.Moderate,
            "Directory creation"));

        // ===== ELEVATED TIER =====

        // git: remote or history-altering operations
        rules.Add(new CommandRiskRule(
            "git",
            GitRemoteArgs,
            CommandRiskTier.Elevated,
            "Remote or history-altering git operations"));

        // dotnet: package/project management
        rules.Add(new CommandRiskRule(
            "dotnet",
            DotnetPackageArgs,
            CommandRiskTier.Elevated,
            "Dotnet package and project management"));

        // npm: dependency management
        rules.Add(new CommandRiskRule(
            "npm",
            NpmDependencyArgs,
            CommandRiskTier.Elevated,
            "NPM dependency management"));

        // pip: dependency management
        rules.Add(new CommandRiskRule(
            "pip",
            PipDependencyArgs,
            CommandRiskTier.Elevated,
            "Pip dependency management"));

        return rules.AsReadOnly();
    }
}
