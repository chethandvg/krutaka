using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for CommandRiskClassifier - attempts to bypass tier classification
/// through argument aliasing, edge case handling, and malformed inputs.
/// These tests verify that the classification system is resistant to manipulation.
/// </summary>
public sealed class CommandRiskClassifierAdversarialTests
{
    private readonly CommandRiskClassifier _classifier;

    public CommandRiskClassifierAdversarialTests()
    {
        _classifier = new CommandRiskClassifier();
    }

    #region Argument Aliasing Bypass Attempts

    [Theory]
    [InlineData("git", new[] { "push", "-f" })]
    [InlineData("git", new[] { "push", "--force" })]
    [InlineData("git", new[] { "push", "--force-with-lease" })]
    public void Should_ClassifyGitPushWithAnyForceFlag_AsElevated(string executable, string[] arguments)
    {
        // Arrange - All force variants should be classified the same (Elevated)
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Force push");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Force flags don't downgrade tier; "push" itself is Elevated
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    [Theory]
    [InlineData("git", new[] { "commit", "-m" })]
    [InlineData("git", new[] { "commit", "--message" })]
    [InlineData("git", new[] { "commit", "-a" })]
    [InlineData("git", new[] { "commit", "--amend" })]
    public void Should_ClassifyGitCommitWithAnyFlag_AsModerate(string executable, string[] arguments)
    {
        // Arrange - Different commit flags should not change tier
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Commit");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - "commit" itself is Moderate regardless of flags
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Theory]
    [InlineData("npm", new[] { "install", "-g" })]
    [InlineData("npm", new[] { "install", "--global" })]
    [InlineData("npm", new[] { "install", "--save" })]
    public void Should_ClassifyNpmInstallWithAnyFlag_AsElevated(string executable, string[] arguments)
    {
        // Arrange - All install variants are Elevated
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Install");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - "install" is Elevated regardless of flags
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Empty Arguments Edge Cases

    [Theory]
    [InlineData("git")]
    [InlineData("dotnet")]
    [InlineData("npm")]
    [InlineData("cat")]
    public void Should_HandleEmptyArgumentList_OnKnownExecutable(string executable)
    {
        // Arrange - No arguments provided
        var request = new CommandExecutionRequest(executable, Array.Empty<string>(), "/test", "No args");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should return the default tier for that executable (not crash)
        tier.Should().BeOneOf(
            CommandRiskTier.Safe,
            CommandRiskTier.Moderate,
            CommandRiskTier.Elevated,
            CommandRiskTier.Dangerous);
    }

    [Theory]
    [InlineData("cat")]
    [InlineData("grep")]
    [InlineData("find")]
    public void Should_HandleEmptyArgumentList_OnReadOnlyCommand(string executable)
    {
        // Arrange - Read-only tools with no arguments
        var request = new CommandExecutionRequest(executable, Array.Empty<string>(), "/test", "Read-only");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - These read-only tools are Safe even with no arguments
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Very Long Arguments (Stress Testing)

    [Fact]
    public void Should_HandleVeryLongArgumentString_WithoutCrash()
    {
        // Arrange - Extremely long argument
        var longArg = new string('a', 10000);
        var request = new CommandExecutionRequest("git", new[] { "log", longArg }, "/test", "Long arg");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should classify based on first argument "log" (Safe)
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public void Should_HandleManyArguments_WithoutCrash()
    {
        // Arrange - Many arguments (100+)
        var manyArgs = Enumerable.Range(0, 100).Select(i => $"arg{i}").ToArray();
        var argsWithStatus = new[] { "status" }.Concat(manyArgs).ToArray();
        var request = new CommandExecutionRequest("git", argsWithStatus, "/test", "Many args");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should classify based on first argument "status" (Safe)
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Arguments with Shell Metacharacters

    [Theory]
    [InlineData("git", new[] { "status|rm" })]
    [InlineData("git", new[] { "status;ls" })]
    [InlineData("git", new[] { "status&&ls" })]
    [InlineData("git", new[] { "status$(ls)" })]
    public void Should_ClassifyCommandWithMetacharacterArguments_BeforeSecurityCheck(string executable, string[] arguments)
    {
        // Note: Shell metacharacters should be caught by ISecurityPolicy.ValidateCommand() BEFORE classification
        // The classifier still processes them and returns a tier (it doesn't validate security)
        // This test verifies the classifier doesn't crash on such inputs

        // Arrange
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Meta args");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Classifier returns a tier (security validation happens elsewhere)
        tier.Should().BeOneOf(
            CommandRiskTier.Safe,
            CommandRiskTier.Moderate,
            CommandRiskTier.Elevated,
            CommandRiskTier.Dangerous);
    }

    #endregion

    #region Unknown Executable Classification

    [Theory]
    [InlineData("unknown-tool")]
    [InlineData("evil-script")]
    [InlineData("malware.exe")]
    [InlineData("backdoor")]
    [InlineData("custom-binary")]
    public void Should_ClassifyUnknownExecutable_AsDangerous(string executable)
    {
        // Arrange - Fail-closed for unknown executables
        var request = new CommandExecutionRequest(executable, new[] { "arg" }, "/test", "Unknown");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Unknown executables are always Dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Executable Extension Normalization

    [Theory]
    [InlineData("git.exe", new[] { "status" })]
    [InlineData("dotnet.exe", new[] { "--version" })]
    [InlineData("npm.exe", new[] { "--version" })]
    [InlineData("node.exe", new[] { "--version" })]
    public void Should_NormalizeExeExtension_SameAsBareExecutable(string executable, string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(executable);
        ArgumentNullException.ThrowIfNull(arguments);

        // Arrange - .exe suffix should be stripped
        var requestWithExe = new CommandExecutionRequest(executable, arguments, "/test", "With exe");
        var requestWithoutExe = new CommandExecutionRequest(
            executable.Replace(".exe", "", StringComparison.OrdinalIgnoreCase),
            arguments,
            "/test",
            "Without exe");

        // Act
        var tierWithExe = _classifier.Classify(requestWithExe);
        var tierWithoutExe = _classifier.Classify(requestWithoutExe);

        // Assert - Both should be classified identically
        tierWithExe.Should().Be(tierWithoutExe);
    }

    [Theory]
    [InlineData("GIT.EXE")]
    [InlineData("Git.exe")]
    [InlineData("git.EXE")]
    public void Should_NormalizeExeExtension_CaseInsensitive(string executable)
    {
        // Arrange - .exe suffix is case-insensitive
        var request = new CommandExecutionRequest(executable, new[] { "status" }, "/test", "Case test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should recognize as "git" and classify as Safe
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Executable with Path Separators

    [Theory]
    [InlineData("C:\\tools\\git.exe")]
    [InlineData("/usr/bin/git")]
    [InlineData("..\\..\\git")]
    [InlineData("./local/bin/npm")]
    [InlineData("bin\\dotnet")]
    public void Should_ClassifyExecutableWithPathSeparators_AsDangerous(string executable)
    {
        // Arrange - Path separators indicate attempt to execute arbitrary binary
        var request = new CommandExecutionRequest(executable, new[] { "status" }, "/test", "Path separator");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should be classified as Dangerous (security risk)
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Theory]
    [InlineData("C:git.exe")]
    [InlineData("D:npm.exe")]
    public void Should_ClassifyRootedPath_AsDangerous(string executable)
    {
        // Arrange - Rooted paths (drive letter on Windows) indicate absolute path
        var request = new CommandExecutionRequest(executable, new[] { "status" }, "/test", "Rooted path");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should be classified as Dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Unicode and Special Characters

    [Theory]
    [InlineData("git", new[] { "status", "файл.txt" })] // Cyrillic
    [InlineData("git", new[] { "log", "文件.md" })] // Chinese
    [InlineData("git", new[] { "diff", "αρχείο.cs" })] // Greek
    [InlineData("cat", new[] { "café.txt" })] // Accented
    public void Should_HandleUnicodeArguments_WithoutCrash(string executable, string[] arguments)
    {
        // Arrange - Unicode arguments should be handled
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Unicode");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should classify based on first argument (not crash)
        tier.Should().BeOneOf(
            CommandRiskTier.Safe,
            CommandRiskTier.Moderate,
            CommandRiskTier.Elevated);
    }

    [Theory]
    [InlineData("git", new[] { "status\t--short" })] // Tab character
    [InlineData("git", new[] { "log\n" })] // Newline
    [InlineData("git", new[] { "diff\r\n" })] // CRLF
    public void Should_HandleWhitespaceInArguments_WithoutCrash(string executable, string[] arguments)
    {
        // Arrange - Special whitespace characters
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Whitespace");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should process without crashing
        tier.Should().BeOneOf(
            CommandRiskTier.Safe,
            CommandRiskTier.Moderate,
            CommandRiskTier.Elevated,
            CommandRiskTier.Dangerous);
    }

    #endregion

    #region Blocklisted Executable Verification

    [Theory]
    [InlineData("powershell")]
    [InlineData("pwsh")]
    [InlineData("cmd")]
    [InlineData("reg")]
    [InlineData("regedit")]
    [InlineData("netsh")]
    [InlineData("certutil")]
    [InlineData("bitsadmin")]
    [InlineData("format")]
    [InlineData("diskpart")]
    [InlineData("rundll32")]
    [InlineData("regsvr32")]
    [InlineData("mshta")]
    [InlineData("wscript")]
    [InlineData("cscript")]
    public void Should_ClassifyBlocklistedExecutable_AsDangerous(string executable)
    {
        // Arrange - All blocklisted executables must be Dangerous
        var request = new CommandExecutionRequest(executable, new[] { "arg" }, "/test", "Blocklisted");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Blocklisted executables are always Dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Theory]
    [InlineData("powershell.exe")]
    [InlineData("cmd.exe")]
    [InlineData("certutil.exe")]
    public void Should_ClassifyBlocklistedExecutableWithExe_AsDangerous(string executable)
    {
        // Arrange - .exe suffix should not bypass blocklist
        var request = new CommandExecutionRequest(executable, new[] { "arg" }, "/test", "Blocklisted exe");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Still Dangerous after normalization
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Case Sensitivity Tests

    [Theory]
    [InlineData("GIT", new[] { "status" })]
    [InlineData("Git", new[] { "status" })]
    [InlineData("git", new[] { "status" })]
    [InlineData("gIt", new[] { "status" })]
    public void Should_ClassifyExecutable_CaseInsensitive(string executable, string[] arguments)
    {
        // Arrange - Executable names are case-insensitive
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Case test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - All should classify as Safe
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("POWERSHELL")]
    [InlineData("PowerShell")]
    [InlineData("Cmd")]
    [InlineData("CMD")]
    public void Should_BlocklistCheck_BeCaseInsensitive(string executable)
    {
        // Arrange - Blocklist check is case-insensitive
        var request = new CommandExecutionRequest(executable, new[] { "arg" }, "/test", "Blocklist case");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Should be Dangerous regardless of case
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Theory]
    [InlineData("git", new[] { "STATUS" })]
    [InlineData("git", new[] { "Status" })]
    [InlineData("git", new[] { "status" })]
    [InlineData("git", new[] { "PUSH" })]
    [InlineData("git", new[] { "Push" })]
    [InlineData("git", new[] { "push" })]
    public void Should_ClassifyArguments_CaseInsensitive(string executable, string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);

        // Arrange - Argument matching is case-insensitive
        var request = new CommandExecutionRequest(executable, arguments, "/test", "Arg case");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - Case should not affect tier
        var firstArg = arguments[0].ToUpperInvariant(); // Use ToUpperInvariant per CA1308
        var expectedTier = firstArg == "STATUS" ? CommandRiskTier.Safe : CommandRiskTier.Elevated;
        tier.Should().Be(expectedTier);
    }

    #endregion

    #region Null and Boundary Validation

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRequestIsNull()
    {
        // Act
        var action = () => _classifier.Classify(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    #endregion
}
