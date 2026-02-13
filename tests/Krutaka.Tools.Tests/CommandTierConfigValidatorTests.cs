using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.Logging;
using NSubstitute;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Tests for CommandTierConfigValidator - validates command tier override configuration at startup.
/// Tests cover security constraint enforcement, configuration tampering prevention, and edge cases.
/// </summary>
public sealed class CommandTierConfigValidatorTests
{
    private readonly CommandTierConfigValidator _validator;

    public CommandTierConfigValidatorTests()
    {
        // Create validator without logger for most tests
        _validator = new CommandTierConfigValidator();
    }

    #region Valid Configurations

    [Fact]
    public void Should_AcceptValidConfiguration_WithSpecificArgumentPatterns()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build", "test", "check"],
                Tier: CommandRiskTier.Moderate,
                Description: "Cargo build commands"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptValidConfiguration_MultipleRules()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build", "test"],
                Tier: CommandRiskTier.Moderate,
                Description: "Cargo build"
            ),
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["publish"],
                Tier: CommandRiskTier.Elevated,
                Description: "Cargo publish"
            ),
            new CommandRiskRule(
                Executable: "make",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "GNU Make"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptCustomExecutable_WithSafeTier()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "myCustomTool",
                ArgumentPatterns: ["read", "list"],
                Tier: CommandRiskTier.Safe,
                Description: "Custom read-only tool"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptEmptyRulesArray()
    {
        // Arrange
        var rules = Array.Empty<CommandRiskRule>();

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        result.Warnings.Should().BeEmpty();
    }

    #endregion

    #region Blocklisted Command Promotion Prevention

    [Fact]
    public void Should_RejectPromotingBlocklistedCommand_Powershell()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "powershell",
                ArgumentPatterns: ["Get-Process"],
                Tier: CommandRiskTier.Safe,
                Description: "Trying to promote powershell"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*powershell*");
        result.Errors.Should().ContainMatch("*cannot be promoted*");
    }

    [Fact]
    public void Should_RejectPromotingBlocklistedCommand_Cmd()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cmd",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Trying to promote cmd"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*cmd*");
    }

    [Fact]
    public void Should_RejectPromotingBlocklistedCommand_CaseInsensitive()
    {
        // Arrange - using different case variations
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "POWERSHELL",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Trying to promote PowerShell with uppercase"
            ),
            new CommandRiskRule(
                Executable: "ReGedit",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Trying to promote regedit with mixed case"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().HaveCount(2);
        result.Errors.Should().ContainMatch("*POWERSHELL*");
        result.Errors.Should().ContainMatch("*ReGedit*");
    }

    #endregion

    #region Dangerous Tier Assignment Prevention

    [Fact]
    public void Should_RejectSettingTierToDangerous()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "myApp",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Dangerous,
                Description: "Trying to add to blocklist"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*Cannot set tier to 'Dangerous'*myApp*");
        result.Errors.Should().ContainMatch("*must be done in code*");
    }

    #endregion

    #region Path Separator Validation

    [Fact]
    public void Should_RejectExecutable_WithWindowsPathSeparator()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "C:\\Tools\\cargo.exe",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Path with Windows separator"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        // Can be rejected as either path separator or shell metacharacter (both are valid security checks)
        result.Errors.Should().NotBeEmpty();
        result.Errors[0].Should().ContainAny("path separators", "shell metacharacters");
    }

    [Fact]
    public void Should_RejectExecutable_WithUnixPathSeparator()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "/usr/bin/cargo",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Path with Unix separator"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*path separators*");
    }

    [Fact]
    public void Should_RejectExecutable_WithRelativePath()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "subdir/cargo",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Relative path with forward slash"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*path separators*");
    }

    #endregion

    #region Shell Metacharacter Validation

    [Fact]
    public void Should_RejectExecutable_WithShellMetacharacters()
    {
        // Arrange
        var testCases = new[]
        {
            "cargo|bad",
            "cargo>file",
            "cargo&bad",
            "cargo;bad",
            "cargo`whoami`",
            "cargo$VAR",
            "cargo%bad",
            "cargo^bad"
        };

        foreach (var executable in testCases)
        {
            var rules = new[]
            {
                new CommandRiskRule(
                    Executable: executable,
                    ArgumentPatterns: null,
                    Tier: CommandRiskTier.Moderate,
                    Description: "Shell metacharacter test"
                )
            };

            // Act
            var result = _validator.ValidateRules(rules);

            // Assert
            result.IsValid.Should().BeFalse($"'{executable}' should be rejected");
            result.Errors.Should().ContainMatch("*shell metacharacters*");
        }
    }

    [Fact]
    public void Should_RejectArgumentPattern_WithShellMetacharacters()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build", "test|bad", "check"],
                Tier: CommandRiskTier.Moderate,
                Description: "Argument with shell metacharacter"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*test|bad*");
        result.Errors.Should().ContainMatch("*shell metacharacters*");
    }

    [Fact]
    public void Should_RejectArgumentPattern_WithMultipleMetacharacters()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build>output.txt", "test&echo bad", "check`whoami`"],
                Tier: CommandRiskTier.Moderate,
                Description: "Multiple bad arguments"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        // Validator returns on first error, so we get 1 error (fail-fast behavior)
        result.Errors.Should().ContainMatch("*shell metacharacters*");
    }

    #endregion

    #region Empty/Null/Whitespace Validation

    [Fact]
    public void Should_RejectExecutable_Empty()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Empty executable"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty*null*");
    }

    [Fact]
    public void Should_RejectExecutable_Whitespace()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "   ",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Whitespace executable"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty*null*");
    }

    [Fact]
    public void Should_RejectArgumentPattern_Empty()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build", "", "test"],
                Tier: CommandRiskTier.Moderate,
                Description: "Empty argument pattern"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty*null*argument pattern*");
    }

    [Fact]
    public void Should_RejectArgumentPattern_Whitespace()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build", "   ", "test"],
                Tier: CommandRiskTier.Moderate,
                Description: "Whitespace argument pattern"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty*null*argument pattern*");
    }

    #endregion

    #region Null Argument Pattern Warnings

    [Fact]
    public void Should_WarnForNullArgumentPatterns()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "make",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "GNU Make - broad rule"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        result.Warnings.Should().NotBeEmpty();
        result.Warnings.Should().ContainMatch("*null argument patterns*");
        result.Warnings.Should().ContainMatch("*make*");
    }

    #endregion

    #region Multiple Errors

    [Fact]
    public void Should_ReturnAllErrors_WhenMultipleRulesInvalid()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "powershell",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Blocklisted"
            ),
            new CommandRiskRule(
                Executable: "evil/bad/path",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Path separator"
            ),
            new CommandRiskRule(
                Executable: "danger",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Dangerous,
                Description: "Dangerous tier"
            )
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().HaveCount(3);
        result.Errors.Should().ContainMatch("*powershell*");
        result.Errors.Should().ContainMatch("*path separators*");
        result.Errors.Should().ContainMatch("*Dangerous*");
    }

    #endregion

    #region ArgumentNullException

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRulesIsNull()
    {
        // Arrange & Act
        var action = () => _validator.ValidateRules(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("rules");
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRuleIsNull()
    {
        // Arrange & Act
        var action = () => _validator.ValidateRule(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("rule");
    }

    #endregion
}
