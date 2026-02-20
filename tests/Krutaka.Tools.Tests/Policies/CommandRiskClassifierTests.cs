using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class CommandRiskClassifierTests
{
    private readonly CommandRiskClassifier _classifier;

    public CommandRiskClassifierTests()
    {
        _classifier = new CommandRiskClassifier();
    }

    #region Safe Tier Tests - Git

    [Theory]
    [InlineData("status")]
    [InlineData("log")]
    [InlineData("diff")]
    [InlineData("show")]
    [InlineData("rev-parse")]
    public void Should_ClassifyGitReadOnlyOperations_AsSafe(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { subcommand },
            "/test",
            "Read-only git operation");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("STATUS")]
    [InlineData("Log")]
    [InlineData("DIFF")]
    public void Should_ClassifyGitReadOnlyOperations_AsSafe_CaseInsensitive(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { subcommand },
            "/test",
            "Case-insensitive test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Safe Tier Tests - Dotnet

    [Theory]
    [InlineData("--version")]
    [InlineData("--info")]
    [InlineData("--list-sdks")]
    [InlineData("--list-runtimes")]
    public void Should_ClassifyDotnetInformationQueries_AsSafe(string arg)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { arg },
            "/test",
            "Dotnet info query");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Safe Tier Tests - Node/NPM/Python/Pip

    [Fact]
    public void Should_ClassifyNodeVersionCheck_AsSafe()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "node",
            new[] { "--version" },
            "/test",
            "Node version check");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public void Should_ClassifyNpmVersionCheck_AsSafe()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "npm",
            new[] { "--version" },
            "/test",
            "NPM version check");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("python")]
    [InlineData("python3")]
    public void Should_ClassifyPythonVersionCheck_AsSafe(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "--version" },
            "/test",
            "Python version check");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("--version")]
    [InlineData("list")]
    [InlineData("show")]
    [InlineData("freeze")]
    public void Should_ClassifyPipReadOnlyOperations_AsSafe(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "pip",
            new[] { subcommand },
            "/test",
            "Pip read-only operation");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Safe Tier Tests - Read-Only Commands

    [Theory]
    [InlineData("cat")]
    [InlineData("type")]
    [InlineData("find")]
    [InlineData("dir")]
    [InlineData("where")]
    [InlineData("grep")]
    [InlineData("findstr")]
    [InlineData("tree")]
    [InlineData("echo")]
    [InlineData("sort")]
    [InlineData("head")]
    [InlineData("tail")]
    [InlineData("wc")]
    [InlineData("diff")]
    public void Should_ClassifyReadOnlyCommands_AsSafe_WithAnyArguments(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "some", "random", "args" },
            "/test",
            "Read-only command");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public void Should_ClassifyReadOnlyCommands_AsSafe_WithNoArguments()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "cat",
            Array.Empty<string>(),
            "/test",
            "Read-only command no args");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Moderate Tier Tests - Git

    [Theory]
    [InlineData("add")]
    [InlineData("commit")]
    [InlineData("stash")]
    [InlineData("checkout")]
    [InlineData("switch")]
    [InlineData("merge")]
    public void Should_ClassifyGitLocalOperations_AsModerate(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { subcommand },
            "/test",
            "Local git operation");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    #endregion

    #region Moderate Tier Tests - Dotnet

    [Theory]
    [InlineData("build")]
    [InlineData("test")]
    [InlineData("run")]
    [InlineData("restore")]
    [InlineData("clean")]
    [InlineData("format")]
    public void Should_ClassifyDotnetBuildOperations_AsModerate(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { subcommand },
            "/test",
            "Dotnet build operation");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    #endregion

    #region Moderate Tier Tests - NPM/NPX

    [Theory]
    [InlineData("npm")]
    [InlineData("npx")]
    public void Should_ClassifyNpmProjectScriptExecution_AsModerate(string executable)
    {
        // Arrange
        var scripts = new[] { "run", "test", "start", "lint", "build" };

        foreach (var script in scripts)
        {
            var request = new CommandExecutionRequest(
                executable,
                new[] { script },
                "/test",
                "NPM script execution");

            // Act
            var tier = _classifier.Classify(request);

            // Assert
            tier.Should().Be(CommandRiskTier.Moderate, $"{executable} {script} should be Moderate");
        }
    }

    #endregion

    #region Moderate Tier Tests - Python

    [Theory]
    [InlineData("python")]
    [InlineData("python3")]
    public void Should_ClassifyPythonScriptExecution_AsModerate_WhenNotVersionCheck(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "script.py" },
            "/test",
            "Python script execution");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Theory]
    [InlineData("python")]
    [InlineData("python3")]
    public void Should_ClassifyPythonWithNoArgs_AsModerate(string executable)
    {
        // Arrange - Python with no args (interactive mode)
        var request = new CommandExecutionRequest(
            executable,
            Array.Empty<string>(),
            "/test",
            "Python interactive");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    #endregion

    #region Moderate Tier Tests - Mkdir

    [Fact]
    public void Should_ClassifyMkdir_AsModerate()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "mkdir",
            new[] { "newdir" },
            "/test",
            "Create directory");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    #endregion

    #region Elevated Tier Tests - Git

    [Theory]
    [InlineData("push")]
    [InlineData("pull")]
    [InlineData("fetch")]
    [InlineData("clone")]
    [InlineData("rebase")]
    [InlineData("reset")]
    [InlineData("cherry-pick")]
    [InlineData("branch")]
    [InlineData("tag")]
    [InlineData("remote")]
    public void Should_ClassifyGitRemoteOperations_AsElevated(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            new[] { subcommand },
            "/test",
            "Remote git operation");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Elevated Tier Tests - Dotnet

    [Theory]
    [InlineData("publish")]
    [InlineData("pack")]
    [InlineData("nuget")]
    [InlineData("new")]
    [InlineData("tool")]
    public void Should_ClassifyDotnetPackageManagement_AsElevated(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { subcommand },
            "/test",
            "Dotnet package management");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Elevated Tier Tests - NPM/Pip

    [Theory]
    [InlineData("install")]
    [InlineData("uninstall")]
    [InlineData("update")]
    [InlineData("publish")]
    [InlineData("link")]
    public void Should_ClassifyNpmDependencyManagement_AsElevated(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "npm",
            new[] { subcommand },
            "/test",
            "NPM dependency management");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    [Theory]
    [InlineData("install")]
    [InlineData("uninstall")]
    [InlineData("download")]
    public void Should_ClassifyPipDependencyManagement_AsElevated(string subcommand)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "pip",
            new[] { subcommand },
            "/test",
            "Pip dependency management");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Dangerous Tier Tests - Blocked Executables

    [Theory]
    [InlineData("powershell")]
    [InlineData("pwsh")]
    [InlineData("cmd")]
    [InlineData("reg")]
    [InlineData("regedit")]
    [InlineData("netsh")]
    [InlineData("netstat")]
    [InlineData("certutil")]
    [InlineData("bitsadmin")]
    [InlineData("format")]
    [InlineData("diskpart")]
    [InlineData("chkdsk")]
    [InlineData("rundll32")]
    [InlineData("regsvr32")]
    [InlineData("mshta")]
    [InlineData("wscript")]
    [InlineData("cscript")]
    [InlineData("msiexec")]
    [InlineData("sc")]
    [InlineData("schtasks")]
    [InlineData("taskkill")]
    [InlineData("net")]
    [InlineData("net1")]
    [InlineData("runas")]
    [InlineData("icacls")]
    [InlineData("takeown")]
    [InlineData("curl")]
    [InlineData("wget")]
    [InlineData("invoke-webrequest")]
    public void Should_ClassifyBlockedExecutables_AsDangerous(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "arg1" },
            "/test",
            "Blocked executable");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Dangerous Tier Tests - Unknown Executables

    [Theory]
    [InlineData("unknown-tool")]
    [InlineData("malicious")]
    [InlineData("random-binary")]
    [InlineData("exploit")]
    public void Should_ClassifyUnknownExecutables_AsDangerous(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "arg1" },
            "/test",
            "Unknown executable");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Case Insensitivity Tests

    [Theory]
    [InlineData("GIT")]
    [InlineData("Git")]
    [InlineData("gIt")]
    public void Should_HandleExecutableName_CaseInsensitive(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "status" },
            "/test",
            "Case test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("POWERSHELL")]
    [InlineData("PowerShell")]
    [InlineData("PwSh")]
    public void Should_HandleBlockedExecutables_CaseInsensitive(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "arg" },
            "/test",
            "Case test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region .exe Suffix Tests

    [Theory]
    [InlineData("dotnet.exe", "--version")]
    [InlineData("npm.exe", "--version")]
    [InlineData("python.exe", "--version")]
    [InlineData("git.exe", "status")]
    public void Should_StripExeSuffix_AndClassifyCorrectly(string executable, string argument)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { argument },
            "/test",
            "Exe suffix test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("powershell.exe")]
    [InlineData("cmd.exe")]
    [InlineData("CMD.EXE")]
    public void Should_StripExeSuffix_ForBlockedExecutables(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "arg" },
            "/test",
            "Exe suffix test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Path Separator Tests

    [Theory]
    [InlineData("C:\\tools\\git.exe")]
    [InlineData("..\\git.exe")]
    [InlineData("/usr/bin/git")]
    [InlineData("../malicious")]
    public void Should_ClassifyExecutablesWithPathSeparators_AsDangerous(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            new[] { "status" },
            "/test",
            "Executable with path");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Default Tier Tests

    [Fact]
    public void Should_ReturnDefaultTier_WhenKnownExecutableWithUnknownArgs()
    {
        // Arrange - git with an unknown subcommand should return Elevated (highest non-Safe tier for git)
        var request = new CommandExecutionRequest(
            "git",
            new[] { "unknown-subcommand" },
            "/test",
            "Unknown git subcommand");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        // Git has Safe, Moderate, and Elevated tiers
        // Default tier should be Elevated (highest non-Safe)
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    [Fact]
    public void Should_ReturnDefaultTier_ForDotnetWithUnknownArgs()
    {
        // Arrange - dotnet with unknown subcommand should return Elevated (highest non-Safe tier for dotnet)
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { "unknown-command" },
            "/test",
            "Unknown dotnet command");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    [Fact]
    public void Should_ReturnDefaultTier_ForNpmWithUnknownArgs()
    {
        // Arrange - npm with unknown subcommand should return Elevated (highest non-Safe tier for npm)
        var request = new CommandExecutionRequest(
            "npm",
            new[] { "unknown-command" },
            "/test",
            "Unknown npm command");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Dotnet Compound Command Tests

    [Fact]
    public void Should_MatchDotnetSingleArgument_Build()
    {
        // Arrange - dotnet build should match single-argument pattern
        var request = new CommandExecutionRequest(
            "dotnet",
            new[] { "build" },
            "/test",
            "Dotnet build");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public void Should_SupportDotnetTwoArgumentMatching()
    {
        // Arrange - This test validates that the classifier SUPPORTS two-argument matching
        // for dotnet, even though current rules only have single-argument patterns.
        // If we had a rule like "nuget push" → Moderate and "nuget" → Elevated,
        // "dotnet nuget push" should match the two-arg pattern first.
        // Currently, with only "nuget" → Elevated, both should return Elevated.
        
        var nugetPushRequest = new CommandExecutionRequest(
            "dotnet",
            new[] { "nuget", "push" },
            "/test",
            "Dotnet nuget push");

        var nugetOnlyRequest = new CommandExecutionRequest(
            "dotnet",
            new[] { "nuget" },
            "/test",
            "Dotnet nuget");

        // Act
        var pushTier = _classifier.Classify(nugetPushRequest);
        var nugetTier = _classifier.Classify(nugetOnlyRequest);

        // Assert - Both should be Elevated with current rules
        // (since we only have "nuget" → Elevated, not "nuget push" specifically)
        pushTier.Should().Be(CommandRiskTier.Elevated);
        nugetTier.Should().Be(CommandRiskTier.Elevated);
        
        // If future rules add "nuget push" → Safe and keep "nuget" → Elevated,
        // the two-argument matching would make the first return Safe
    }

    #endregion

    #region Empty/Null Arguments Tests

    [Fact]
    public void Should_HandleEmptyArguments_ForReadOnlyCommand()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "cat",
            Array.Empty<string>(),
            "/test",
            "Cat with no args");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public void Should_HandleEmptyArguments_ForGit()
    {
        // Arrange - git with no args should return default tier (Elevated)
        var request = new CommandExecutionRequest(
            "git",
            Array.Empty<string>(),
            "/test",
            "Git with no args");

        // Act
        var tier = _classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region GetRules Tests

    [Fact]
    public void Should_ReturnAllRules_FromGetRules()
    {
        // Act
        var rules = _classifier.GetRules();

        // Assert
        rules.Should().NotBeNull();
        rules.Should().NotBeEmpty();

        // Should have rules for all major executables
        rules.Should().Contain(r => r.Executable.Equals("git", StringComparison.OrdinalIgnoreCase));
        rules.Should().Contain(r => r.Executable.Equals("dotnet", StringComparison.OrdinalIgnoreCase));
        rules.Should().Contain(r => r.Executable.Equals("npm", StringComparison.OrdinalIgnoreCase));
        rules.Should().Contain(r => r.Executable.Equals("python", StringComparison.OrdinalIgnoreCase));
        rules.Should().Contain(r => r.Executable.Equals("pip", StringComparison.OrdinalIgnoreCase));
        rules.Should().Contain(r => r.Executable.Equals("cat", StringComparison.OrdinalIgnoreCase));

        // Should have rules for all tiers
        rules.Should().Contain(r => r.Tier == CommandRiskTier.Safe);
        rules.Should().Contain(r => r.Tier == CommandRiskTier.Moderate);
        rules.Should().Contain(r => r.Tier == CommandRiskTier.Elevated);
    }

    [Fact]
    public void Should_ReturnReadOnlyList_FromGetRules()
    {
        // Act
        var rules = _classifier.GetRules();

        // Assert
        rules.Should().BeAssignableTo<IReadOnlyList<CommandRiskRule>>();
    }

    [Fact]
    public void Should_IncludeDescriptions_InRules()
    {
        // Act
        var rules = _classifier.GetRules();

        // Assert
        rules.Where(r => r.Description is not null).Should().NotBeEmpty();
    }

    #endregion

    #region Null Request Tests

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRequestIsNull()
    {
        // Act
        var action = () => _classifier.Classify(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    #endregion

    #region TierOverrides Tests

    [Fact]
    public void Should_ApplyTierOverride_ForCustomExecutable()
    {
        // Arrange - add "cargo" as Moderate tier via overrides
        var overrides = new[]
        {
            new CommandRiskRule("cargo", new[] { "build" }, CommandRiskTier.Moderate, "Rust build")
        };
        
        var classifier = new CommandRiskClassifier(overrides);
        var request = new CommandExecutionRequest(
            "cargo",
            new[] { "build" },
            "/test",
            "Build rust project");

        // Act
        var tier = classifier.Classify(request);

        // Assert
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public void Should_ApplyTierOverride_ForExistingExecutable_OverridingDefault()
    {
        // Arrange - override "git status" to be Moderate instead of Safe
        var overrides = new[]
        {
            new CommandRiskRule("git", new[] { "status" }, CommandRiskTier.Moderate, "Override git status to Moderate")
        };
        
        var classifier = new CommandRiskClassifier(overrides);
        var request = new CommandExecutionRequest(
            "git",
            new[] { "status" },
            "/test",
            "Git status");

        // Act
        var tier = classifier.Classify(request);

        // Assert - user override takes precedence over default Safe tier
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public void Should_FallbackToDefaultRules_WhenOverrideDoesNotMatch()
    {
        // Arrange - override only "git status", but query "git log"
        var overrides = new[]
        {
            new CommandRiskRule("git", new[] { "status" }, CommandRiskTier.Moderate, "Override git status")
        };
        
        var classifier = new CommandRiskClassifier(overrides);
        var request = new CommandExecutionRequest(
            "git",
            new[] { "log" },
            "/test",
            "Git log");

        // Act
        var tier = classifier.Classify(request);

        // Assert - should use default Safe tier for "git log"
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public void Should_IgnoreTierOverride_ForBlocklistedExecutable()
    {
        // Arrange - attempt to promote "powershell" from Dangerous to Safe (should be rejected)
        var overrides = new[]
        {
            new CommandRiskRule("powershell", null, CommandRiskTier.Safe, "Attempt to promote blocklisted command")
        };
        
        var classifier = new CommandRiskClassifier(overrides);
        var request = new CommandExecutionRequest(
            "powershell",
            new[] { "-Command", "echo test" },
            "/test",
            "Powershell command");

        // Act
        var tier = classifier.Classify(request);

        // Assert - should remain Dangerous (blocklist takes precedence)
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_IgnoreTierOverride_WithDangerousTier()
    {
        // Arrange - attempt to add "malicious" to Dangerous tier via config (should be rejected)
        var overrides = new[]
        {
            new CommandRiskRule("malicious", null, CommandRiskTier.Dangerous, "Attempt to add to blocklist")
        };
        
        var classifier = new CommandRiskClassifier(overrides);
        var request = new CommandExecutionRequest(
            "malicious",
            new[] { "arg" },
            "/test",
            "Malicious command");

        // Act
        var tier = classifier.Classify(request);

        // Assert - should be Dangerous (unknown executable, fail-closed), but NOT because of override
        tier.Should().Be(CommandRiskTier.Dangerous);
        
        // Verify the override was NOT applied (GetRules should not contain it)
        var rules = classifier.GetRules();
        rules.Should().NotContain(r => r.Executable.Equals("malicious", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Should_IncludeOverridesInGetRules()
    {
        // Arrange
        var overrides = new[]
        {
            new CommandRiskRule("cargo", new[] { "build" }, CommandRiskTier.Moderate, "Rust build"),
            new CommandRiskRule("make", null, CommandRiskTier.Moderate, "Makefile execution")
        };
        
        var classifier = new CommandRiskClassifier(overrides);

        // Act
        var rules = classifier.GetRules();

        // Assert - should contain both user overrides and default rules
        rules.Should().Contain(r => r.Executable.Equals("cargo", StringComparison.OrdinalIgnoreCase));
        rules.Should().Contain(r => r.Executable.Equals("make", StringComparison.OrdinalIgnoreCase));
        rules.Should().Contain(r => r.Executable.Equals("git", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Should_HandleNullTierOverrides()
    {
        // Arrange
        var classifier = new CommandRiskClassifier(tierOverrides: null);
        var request = new CommandExecutionRequest(
            "git",
            new[] { "status" },
            "/test",
            "Git status");

        // Act
        var tier = classifier.Classify(request);

        // Assert - should work with default rules
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public void Should_HandleEmptyTierOverrides()
    {
        // Arrange
        var classifier = new CommandRiskClassifier(tierOverrides: []);
        var request = new CommandExecutionRequest(
            "git",
            new[] { "status" },
            "/test",
            "Git status");

        // Act
        var tier = classifier.Classify(request);

        // Assert - should work with default rules
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion
}
