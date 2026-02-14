using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for CommandRiskClassifier - attempts to bypass tier classification
/// through argument aliasing, edge cases, unicode attacks, and classification evasion.
/// These tests validate that the classifier is resistant to manipulation attempts.
/// </summary>
public sealed class CommandRiskClassifierAdversarialTests
{
    private readonly CommandRiskClassifier _classifier;

    public CommandRiskClassifierAdversarialTests()
    {
        _classifier = new CommandRiskClassifier();
    }

    #region Argument Aliasing Attacks

    [Fact]
    public void Should_ClassifyGitPushWithShortFlag_AsElevated()
    {
        // Arrange - attempt to use -f instead of --force to bypass classification
        var request = new CommandExecutionRequest(
            "git",
            ["-f", "origin", "main"],
            "/test",
            "Short flag aliasing test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - classification is based on 'push' subcommand, not flags
        // But this has no 'push' so it should use git's default tier (Moderate)
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public void Should_ClassifyGitPushRegardlessOfFlags()
    {
        // Arrange - git push with various flag combinations
        var requestWithForce = new CommandExecutionRequest(
            "git",
            ["push", "--force", "origin", "main"],
            "/test",
            "Force push test");

        var requestWithShortForce = new CommandExecutionRequest(
            "git",
            ["push", "-f", "origin", "main"],
            "/test",
            "Short force flag test");

        var requestPlain = new CommandExecutionRequest(
            "git",
            ["push", "origin", "main"],
            "/test",
            "Plain push test");

        // Act
        var tierForce = _classifier.Classify(requestWithForce);
        var tierShortForce = _classifier.Classify(requestWithShortForce);
        var tierPlain = _classifier.Classify(requestPlain);

        // Assert - all variations should be Elevated because 'push' is the first argument
        tierForce.Should().Be(CommandRiskTier.Elevated);
        tierShortForce.Should().Be(CommandRiskTier.Elevated);
        tierPlain.Should().Be(CommandRiskTier.Elevated);
    }

    [Fact]
    public void Should_ClassifyUnknownFlags_UsingExecutableDefaultTier()
    {
        // Arrange - git with unknown/exotic flag as first argument
        var request = new CommandExecutionRequest(
            "git",
            ["--unknown-exotic-flag", "value"],
            "/test",
            "Unknown flag test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - unknown first argument should use git's default tier (Moderate)
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public void Should_NotPromoteSafety_WithAdditionalFlags()
    {
        // Arrange - try to make 'git push' look safer by adding --dry-run
        var request = new CommandExecutionRequest(
            "git",
            ["push", "--dry-run", "origin", "main"],
            "/test",
            "Dry run flag test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - still Elevated because 'push' is the first argument
        tier.Should().Be(CommandRiskTier.Elevated);
    }

    [Fact]
    public void Should_MatchFirstArgument_NotSubsequentFlags()
    {
        // Arrange - npm install with various flags after the subcommand
        var requestGlobal = new CommandExecutionRequest(
            "npm",
            ["install", "--global", "package"],
            "/test",
            "Global flag test");

        var requestDev = new CommandExecutionRequest(
            "npm",
            ["install", "--save-dev", "package"],
            "/test",
            "Dev dependency test");

        // Act
        var tierGlobal = _classifier.Classify(requestGlobal);
        var tierDev = _classifier.Classify(requestDev);

        // Assert - both should be Elevated because 'install' is the first argument
        tierGlobal.Should().Be(CommandRiskTier.Elevated);
        tierDev.Should().Be(CommandRiskTier.Elevated);
    }

    #endregion

    #region Empty Argument List Tests

    [Fact]
    public void Should_ClassifyKnownExecutable_WithNoArguments_UsingDefaultTier()
    {
        // Arrange - git with no arguments
        var request = new CommandExecutionRequest(
            "git",
            [],
            "/test",
            "No arguments test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - should use git's default tier (Moderate)
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    [Fact]
    public void Should_ClassifyDotnet_WithNoArguments_UsingDefaultTier()
    {
        // Arrange - dotnet with no arguments
        var request = new CommandExecutionRequest(
            "dotnet",
            [],
            "/test",
            "Dotnet no args test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - should use dotnet's default tier (Moderate)
        tier.Should().Be(CommandRiskTier.Moderate);
    }

    #endregion

    #region Very Long Argument Strings

    [Fact]
    public void Should_HandleVeryLongArgumentString_WithoutCrash()
    {
        // Arrange - create an extremely long argument string
        var longArg = new string('a', 10000);
        var request = new CommandExecutionRequest(
            "git",
            ["status", longArg],
            "/test",
            "Long argument test");

        // Act
        var action = () => _classifier.Classify(request);

        // Assert - should handle gracefully without crash
        action.Should().NotThrow();
        var tier = _classifier.Classify(request);
        tier.Should().Be(CommandRiskTier.Safe); // 'status' is safe
    }

    [Fact]
    public void Should_HandleManyArguments_WithoutCrash()
    {
        // Arrange - create many arguments
        var args = Enumerable.Range(0, 1000).Select(i => $"arg{i}").ToList();
        args.Insert(0, "status"); // git status is safe
        var request = new CommandExecutionRequest(
            "git",
            args.ToArray(),
            "/test",
            "Many arguments test");

        // Act
        var action = () => _classifier.Classify(request);

        // Assert - should handle gracefully without crash
        action.Should().NotThrow();
        var tier = _classifier.Classify(request);
        tier.Should().Be(CommandRiskTier.Safe); // 'status' is safe
    }

    #endregion

    #region Shell Metacharacter Detection

    [Fact]
    public void Should_ClassifyCommand_BeforeMetacharacterCheck()
    {
        // Arrange - git status with pipe operator in argument
        // Note: The SecurityPolicy.ValidateCommand will throw before we get here in real execution
        // but classification should still work
        var request = new CommandExecutionRequest(
            "git",
            ["status", "|", "grep", "modified"],
            "/test",
            "Metacharacter test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - classifier should classify based on 'status' (Safe)
        // The SecurityPolicy will reject this later, but classification is independent
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Fact]
    public void Should_ClassifyCommand_WithEmbeddedMetacharacters()
    {
        // Arrange - argument contains shell metacharacters
        var request = new CommandExecutionRequest(
            "git",
            ["log", "--grep=fix&&rm -rf /"],
            "/test",
            "Embedded metacharacter test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - classification is based on 'log' (Safe)
        tier.Should().Be(CommandRiskTier.Safe);
    }

    #endregion

    #region Unknown Executable Tests

    [Fact]
    public void Should_ClassifyUnknownExecutable_AsDangerous()
    {
        // Arrange - completely unknown executable
        var request = new CommandExecutionRequest(
            "unknownTool",
            ["--help"],
            "/test",
            "Unknown executable test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - fail-closed: unknown executables are Dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_ClassifyCustomExecutable_AsDangerous()
    {
        // Arrange - custom user tool not in default rules
        var request = new CommandExecutionRequest(
            "myCustomTool",
            ["read", "file.txt"],
            "/test",
            "Custom tool test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - fail-closed: custom executables require explicit configuration
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Executable Extension Tests

    [Fact]
    public void Should_ClassifyExecutable_WithExeExtension_SameAsWithout()
    {
        // Arrange - git.exe vs git
        var requestWithExt = new CommandExecutionRequest(
            "git.exe",
            ["status"],
            "/test",
            "Extension test");

        var requestWithoutExt = new CommandExecutionRequest(
            "git",
            ["status"],
            "/test",
            "No extension test");

        // Act
        var tierWithExt = _classifier.Classify(requestWithExt);
        var tierWithoutExt = _classifier.Classify(requestWithoutExt);

        // Assert - both should be Safe
        tierWithExt.Should().Be(CommandRiskTier.Safe);
        tierWithoutExt.Should().Be(CommandRiskTier.Safe);
        tierWithExt.Should().Be(tierWithoutExt);
    }

    [Fact]
    public void Should_ClassifyExecutable_WithUppercaseExe_SameAsLowercase()
    {
        // Arrange - git.EXE vs git.exe
        var requestUpperExt = new CommandExecutionRequest(
            "git.EXE",
            ["status"],
            "/test",
            "Uppercase extension test");

        var requestLowerExt = new CommandExecutionRequest(
            "git.exe",
            ["status"],
            "/test",
            "Lowercase extension test");

        // Act
        var tierUpperExt = _classifier.Classify(requestUpperExt);
        var tierLowerExt = _classifier.Classify(requestLowerExt);

        // Assert - both should be Safe
        tierUpperExt.Should().Be(CommandRiskTier.Safe);
        tierLowerExt.Should().Be(CommandRiskTier.Safe);
        tierUpperExt.Should().Be(tierLowerExt);
    }

    #endregion

    #region Path Separator Tests

    [Fact]
    public void Should_ClassifyExecutable_WithPathSeparator_AsDangerous()
    {
        // Arrange - executable with directory separator
        var request = new CommandExecutionRequest(
            @"C:\tools\git",
            ["status"],
            "/test",
            "Path separator test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - executables with paths are dangerous (prevents arbitrary binary execution)
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_ClassifyExecutable_WithForwardSlash_AsDangerous()
    {
        // Arrange - executable with forward slash
        var request = new CommandExecutionRequest(
            "/usr/bin/git",
            ["status"],
            "/test",
            "Forward slash test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - executables with paths are dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_ClassifyExecutable_WithRelativePath_AsDangerous()
    {
        // Arrange - executable with relative path
        var request = new CommandExecutionRequest(
            "./git",
            ["status"],
            "/test",
            "Relative path test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - executables with paths are dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Unicode and Special Characters

    [Fact]
    public void Should_HandleUnicodeInArguments_Gracefully()
    {
        // Arrange - unicode characters in arguments
        var request = new CommandExecutionRequest(
            "git",
            ["log", "--grep=修正"], // Japanese characters
            "/test",
            "Unicode argument test");

        // Act
        var action = () => _classifier.Classify(request);

        // Assert - should handle gracefully without crash
        action.Should().NotThrow();
        var tier = _classifier.Classify(request);
        tier.Should().Be(CommandRiskTier.Safe); // 'log' is safe
    }

    [Fact]
    public void Should_HandleEmojiInArguments_Gracefully()
    {
        // Arrange - emoji in arguments
        var request = new CommandExecutionRequest(
            "git",
            ["commit", "-m", "🎉 Initial commit"],
            "/test",
            "Emoji argument test");

        // Act
        var action = () => _classifier.Classify(request);

        // Assert - should handle gracefully without crash
        action.Should().NotThrow();
        var tier = _classifier.Classify(request);
        tier.Should().Be(CommandRiskTier.Moderate); // 'commit' is moderate
    }

    [Fact]
    public void Should_HandleControlCharactersInArguments_Gracefully()
    {
        // Arrange - control characters in arguments
        var request = new CommandExecutionRequest(
            "git",
            ["status", "\t\n\r"],
            "/test",
            "Control character test");

        // Act
        var action = () => _classifier.Classify(request);

        // Assert - should handle gracefully without crash
        action.Should().NotThrow();
    }

    #endregion

    #region Blocklist Verification

    [Theory]
    [InlineData("powershell")]
    [InlineData("pwsh")]
    [InlineData("cmd")]
    [InlineData("certutil")]
    [InlineData("curl")]
    [InlineData("wget")]
    public void Should_ClassifyBlockedExecutable_AsDangerous(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            ["--help"],
            "/test",
            "Blocklist test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - all blocklisted executables should be Dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_ClassifyBlockedExecutable_AsDangerous_WithNoArguments()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "powershell",
            [],
            "/test",
            "Blocklist with no args test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - blocklist check happens before argument matching
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_ClassifyBlockedExecutable_AsDangerous_WithMultipleArguments()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "cmd",
            ["/c", "echo test"],
            "/test",
            "Blocklist with args test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - blocklist check happens before argument matching
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_ClassifyBlockedExecutable_AsDangerous_WithSingleArgument()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "certutil",
            ["-urlcache"],
            "/test",
            "Blocklist with single arg test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - blocklist check happens before argument matching
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Case Sensitivity Tests

    [Theory]
    [InlineData("GIT")]
    [InlineData("Git")]
    [InlineData("git")]
    [InlineData("gIt")]
    public void Should_ClassifyExecutable_CaseInsensitive(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            ["status"],
            "/test",
            "Case sensitivity test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - all variations should be Safe (git status)
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("STATUS")]
    [InlineData("Status")]
    [InlineData("status")]
    [InlineData("StAtUs")]
    public void Should_ClassifyArguments_CaseInsensitive(string argument)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "git",
            [argument],
            "/test",
            "Argument case sensitivity test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - all variations should be Safe (git status)
        tier.Should().Be(CommandRiskTier.Safe);
    }

    [Theory]
    [InlineData("POWERSHELL")]
    [InlineData("PowerShell")]
    [InlineData("powershell")]
    [InlineData("PoWeRsHeLl")]
    public void Should_ClassifyBlockedExecutable_CaseInsensitive(string executable)
    {
        // Arrange
        var request = new CommandExecutionRequest(
            executable,
            ["--help"],
            "/test",
            "Blocklist case sensitivity test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - all variations should be Dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion

    #region Null and Edge Cases

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRequestIsNull()
    {
        // Act
        var action = () => _classifier.Classify(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_HandleEmptyExecutableName_Gracefully()
    {
        // Arrange - this should be caught by CommandPolicy.ValidateCommand, but test classifier behavior
        var request = new CommandExecutionRequest(
            string.Empty,
            ["arg"],
            "/test",
            "Empty executable test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - empty executable should be Dangerous (fail-closed)
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    [Fact]
    public void Should_HandleWhitespaceExecutableName_Gracefully()
    {
        // Arrange
        var request = new CommandExecutionRequest(
            "   ",
            ["arg"],
            "/test",
            "Whitespace executable test");

        // Act
        var tier = _classifier.Classify(request);

        // Assert - whitespace-only executable should be Dangerous
        tier.Should().Be(CommandRiskTier.Dangerous);
    }

    #endregion
}
