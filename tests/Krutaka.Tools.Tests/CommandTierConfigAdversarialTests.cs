using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.Logging.Abstractions;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for CommandTierConfigValidator - attempts to tamper with command tier
/// configuration to bypass security controls or promote dangerous commands.
/// These tests verify that configuration validation prevents malicious or accidental misconfigurations.
/// </summary>
public sealed class CommandTierConfigAdversarialTests
{
    private readonly CommandTierConfigValidator _validator;

    public CommandTierConfigAdversarialTests()
    {
        _validator = new CommandTierConfigValidator(NullLogger<CommandTierConfigValidator>.Instance);
    }

    #region Blocklisted Command Promotion Attempts

    [Theory]
    [InlineData("powershell")]
    [InlineData("pwsh")]
    [InlineData("cmd")]
    [InlineData("reg")]
    [InlineData("regedit")]
    [InlineData("certutil")]
    [InlineData("format")]
    [InlineData("diskpart")]
    public void Should_RejectPromotingBlocklistedCommand_FromDangerousToSafe(string blockedExecutable)
    {
        // Arrange - Attempt to promote a blocklisted command to Safe
        var rule = new CommandRiskRule(
            Executable: blockedExecutable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: $"Attempt to promote {blockedExecutable}");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*blocklisted*");
        result.Errors.Should().ContainMatch($"*{blockedExecutable}*");
    }

    [Theory]
    [InlineData("powershell")]
    [InlineData("cmd")]
    [InlineData("certutil")]
    public void Should_RejectPromotingBlocklistedCommand_FromDangerousToModerate(string blockedExecutable)
    {
        // Arrange - Attempt to promote to Moderate
        var rule = new CommandRiskRule(
            Executable: blockedExecutable,
            ArgumentPatterns: new[] { "arg" },
            Tier: CommandRiskTier.Moderate,
            Description: "Promotion attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*");
    }

    [Theory]
    [InlineData("powershell")]
    [InlineData("cmd")]
    public void Should_RejectPromotingBlocklistedCommand_FromDangerousToElevated(string blockedExecutable)
    {
        // Arrange - Attempt to promote to Elevated
        var rule = new CommandRiskRule(
            Executable: blockedExecutable,
            ArgumentPatterns: new[] { "arg" },
            Tier: CommandRiskTier.Elevated,
            Description: "Promotion attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*");
    }

    [Theory]
    [InlineData("POWERSHELL")]
    [InlineData("Cmd")]
    [InlineData("CertUtil")]
    public void Should_RejectPromotingBlocklistedCommand_CaseInsensitive(string blockedExecutable)
    {
        // Arrange - Case variations should still be blocked
        var rule = new CommandRiskRule(
            Executable: blockedExecutable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Case bypass attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected regardless of case
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*");
    }

    #endregion

    #region Dangerous Tier Assignment Attempts

    [Theory]
    [InlineData("cargo")]
    [InlineData("make")]
    [InlineData("rustc")]
    public void Should_RejectSettingAnyExecutable_ToDangerousTier(string executable)
    {
        // Arrange - Users cannot add to blocklist via config
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Dangerous,
            Description: "Attempt to add to blocklist");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*Dangerous*");
        result.Errors.Should().ContainMatch("*code*"); // Must be done in code
    }

    #endregion

    #region Path Separator Attacks

    [Theory]
    [InlineData("/usr/bin/make")]
    [InlineData("./local/rustc")]
    public void Should_RejectExecutable_WithPathSeparators(string executable)
    {
        // Arrange - Executable must be simple name
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Path separator attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected for path separators
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*path separator*");
    }

    [Theory]
    [InlineData("C:\\tools\\cargo")]
    [InlineData("D:\\apps\\custom")]
    [InlineData("..\\..\\evil-tool")]
    [InlineData("bin\\dotnet")]
    public void Should_RejectExecutable_WithWindowsPathSeparators(string executable)
    {
        if (!OperatingSystem.IsWindows())
        {
            return; // Backslash is not a path separator on non-Windows
        }

        // Arrange - Executable must be simple name
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Path separator attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected for path separators
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*path separator*");
    }

    [Theory]
    [InlineData("cargo/build")]
    [InlineData("make/install")]
    public void Should_RejectExecutable_WithForwardOrBackslash(string executable)
    {
        // Arrange - Both slash types should be rejected
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Moderate,
            Description: "Slash attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected for path separators
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*path separator*");
    }

    #endregion

    #region Shell Metacharacter Attacks

    [Theory]
    [InlineData("cargo|evil")]
    [InlineData("make>output")]
    [InlineData("rustc&&malware")]
    [InlineData("dotnet;rm")]
    [InlineData("npm$(ls)")]
    [InlineData("node`whoami`")]
    [InlineData("python%PATH%")]
    public void Should_RejectExecutable_WithShellMetacharacters(string executable)
    {
        // Arrange - Executable name cannot contain shell metacharacters
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Metacharacter attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*metacharacter*");
    }

    [Theory]
    [InlineData("build|deploy")]
    [InlineData("test&&coverage")]
    [InlineData("run>log")]
    [InlineData("publish;notify")]
    [InlineData("install$(whoami)")]
    public void Should_RejectArgumentPattern_WithShellMetacharacters(string argumentPattern)
    {
        // Arrange - Argument patterns cannot contain shell metacharacters
        var rule = new CommandRiskRule(
            Executable: "cargo",
            ArgumentPatterns: new[] { argumentPattern },
            Tier: CommandRiskTier.Moderate,
            Description: "Arg metacharacter attempt");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*metacharacter*");
    }

    #endregion

    #region Empty/Null Value Attacks

    [Fact]
    public void Should_RejectRule_WithNullExecutable()
    {
        // Arrange
        var rule = new CommandRiskRule(
            Executable: null!,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Null executable");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty or null executable*");
    }

    [Fact]
    public void Should_RejectRule_WithEmptyExecutable()
    {
        // Arrange
        var rule = new CommandRiskRule(
            Executable: string.Empty,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Empty executable");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty or null executable*");
    }

    [Fact]
    public void Should_RejectRule_WithWhitespaceExecutable()
    {
        // Arrange
        var rule = new CommandRiskRule(
            Executable: "   ",
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Whitespace executable");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty or null executable*");
    }

    [Fact]
    public void Should_RejectArgumentPattern_WithEmptyString()
    {
        // Arrange - Empty string in argument patterns array
        var rule = new CommandRiskRule(
            Executable: "cargo",
            ArgumentPatterns: new[] { "build", string.Empty },
            Tier: CommandRiskTier.Moderate,
            Description: "Empty arg pattern");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty or null argument pattern*");
    }

    [Fact]
    public void Should_RejectArgumentPattern_WithNullString()
    {
        // Arrange - Null string in argument patterns array
        var rule = new CommandRiskRule(
            Executable: "cargo",
            ArgumentPatterns: new[] { "build", null! },
            Tier: CommandRiskTier.Moderate,
            Description: "Null arg pattern");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty or null argument pattern*");
    }

    [Fact]
    public void Should_WarnOnEmptyArgumentPatternsArray()
    {
        // Arrange - Empty array (not null, but contains no patterns)
        var rule = new CommandRiskRule(
            Executable: "cargo",
            ArgumentPatterns: Array.Empty<string>(),
            Tier: CommandRiskTier.Moderate,
            Description: "Empty array");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be valid but with warning
        result.IsValid.Should().BeTrue();
        result.Warnings.Should().NotBeEmpty();
        result.Warnings.Should().ContainMatch("*empty argument patterns array*");
    }

    #endregion

    #region Overly Broad Wildcard Warnings

    [Theory]
    [InlineData("cargo")]
    [InlineData("make")]
    [InlineData("rustc")]
    public void Should_WarnOnNullArgumentPatterns_MatchesAll(string executable)
    {
        // Arrange - Null argument patterns match ALL arguments
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Safe,
            Description: "Broad rule");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Valid but with warning
        result.IsValid.Should().BeTrue();
        result.Warnings.Should().NotBeEmpty();
        result.Warnings.Should().ContainMatch("*null argument patterns*");
        result.Warnings.Should().ContainMatch("*ALL arguments*");
    }

    #endregion

    #region Valid Custom Executable Tests

    [Theory]
    [InlineData("cargo", new[] { "build", "test", "check" }, CommandRiskTier.Moderate)]
    [InlineData("make", null, CommandRiskTier.Moderate)]
    [InlineData("rustc", new[] { "--version" }, CommandRiskTier.Safe)]
    [InlineData("go", new[] { "build", "test" }, CommandRiskTier.Moderate)]
    public void Should_AcceptValidCustomExecutable(string executable, string[]? argumentPatterns, CommandRiskTier tier)
    {
        // Arrange - Valid custom executable configuration
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: argumentPatterns,
            Tier: tier,
            Description: $"Custom {executable} rule");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be accepted (possibly with warnings for null patterns)
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptExecutableWithNumbers()
    {
        // Arrange - Executables can have numbers
        var rule = new CommandRiskRule(
            Executable: "python3",
            ArgumentPatterns: new[] { "--version" },
            Tier: CommandRiskTier.Safe,
            Description: "Python 3");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be accepted
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptExecutableWithHyphens()
    {
        // Arrange - Executables can have hyphens
        var rule = new CommandRiskRule(
            Executable: "custom-tool",
            ArgumentPatterns: new[] { "deploy" },
            Tier: CommandRiskTier.Elevated,
            Description: "Custom tool");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be accepted
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptExecutableWithUnderscores()
    {
        // Arrange - Executables can have underscores
        var rule = new CommandRiskRule(
            Executable: "my_tool",
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Moderate,
            Description: "Tool with underscore");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be accepted (with warning for null patterns)
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    #endregion

    #region Executable Extension Handling

    [Theory]
    [InlineData("cargo.exe")]
    [InlineData("make.exe")]
    [InlineData("rustc.EXE")]
    public void Should_RejectExecutable_WithExeExtension(string executable)
    {
        // Arrange - .exe suffix should be rejected (use base name)
        var rule = new CommandRiskRule(
            Executable: executable,
            ArgumentPatterns: null,
            Tier: CommandRiskTier.Moderate,
            Description: "Exe extension");

        // Act
        var result = _validator.ValidateRule(rule);

        // Assert - Should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*file extension*");
        result.Errors.Should().ContainMatch("*.exe*");
    }

    #endregion

    #region Multiple Rules Validation

    [Fact]
    public void Should_ValidateMultipleRules_RejectAllInvalid()
    {
        // Arrange - Mix of invalid rules
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "powershell", // Blocklisted
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Invalid 1"),
            new CommandRiskRule(
                Executable: "C:\\tools\\cargo.exe", // Path separator
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Invalid 2"),
            new CommandRiskRule(
                Executable: "make",
                ArgumentPatterns: new[] { "build|deploy" }, // Metacharacter
                Tier: CommandRiskTier.Moderate,
                Description: "Invalid 3")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - Should reject all
        result.IsValid.Should().BeFalse();
        result.Errors.Should().HaveCountGreaterOrEqualTo(3); // At least one error per invalid rule
    }

    [Fact]
    public void Should_ValidateMultipleRules_AcceptAllValid()
    {
        // Arrange - All valid rules
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: new[] { "build", "test" },
                Tier: CommandRiskTier.Moderate,
                Description: "Cargo build/test"),
            new CommandRiskRule(
                Executable: "make",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Make"),
            new CommandRiskRule(
                Executable: "rustc",
                ArgumentPatterns: new[] { "--version" },
                Tier: CommandRiskTier.Safe,
                Description: "Rustc version")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - Should accept all (may have warnings)
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRulesArrayIsNull()
    {
        // Act
        var action = () => _validator.ValidateRules(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    #endregion
}
