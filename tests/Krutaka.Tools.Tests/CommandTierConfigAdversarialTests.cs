using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.Logging.Abstractions;

namespace Krutaka.Tools.Tests;

/// <summary>
/// Adversarial tests for CommandTierConfigValidator - attempts to bypass configuration
/// validation through blocklist promotion, shell metacharacter injection, path manipulation,
/// and invalid rule definitions. These tests validate that configuration tampering is prevented.
/// </summary>
public sealed class CommandTierConfigAdversarialTests
{
    private readonly CommandTierConfigValidator _validator;
    private readonly CommandTierConfigValidator _validatorWithLogger;

    public CommandTierConfigAdversarialTests()
    {
        _validator = new CommandTierConfigValidator();
        _validatorWithLogger = new CommandTierConfigValidator(NullLogger<CommandTierConfigValidator>.Instance);
    }

    #region Blocklist Promotion Prevention Tests

    [Fact]
    public void Should_RejectPromotion_OfPowerShell_FromDangerous()
    {
        // Arrange - attempt to promote powershell to Safe
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "powershell",
                ArgumentPatterns: ["Get-Process"],
                Tier: CommandRiskTier.Safe,
                Description: "Attempt to promote powershell")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*blocklisted*powershell*");
    }

    [Fact]
    public void Should_RejectPromotion_OfCmd_FromDangerous()
    {
        // Arrange - attempt to promote cmd to Moderate
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cmd",
                ArgumentPatterns: ["/c", "echo"],
                Tier: CommandRiskTier.Moderate,
                Description: "Attempt to promote cmd")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*cmd*");
    }

    [Fact]
    public void Should_RejectPromotion_OfCertutil_FromDangerous()
    {
        // Arrange - attempt to promote certutil
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "certutil",
                ArgumentPatterns: ["-verify"],
                Tier: CommandRiskTier.Safe,
                Description: "Attempt to promote certutil")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*certutil*");
    }

    [Fact]
    public void Should_RejectPromotion_OfCurl_FromDangerous()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "curl",
                ArgumentPatterns: ["--version"],
                Tier: CommandRiskTier.Safe,
                Description: "Attempt to promote curl")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*blocklisted*curl*");
    }

    [Fact]
    public void Should_RejectPromotion_OfMultipleBlocklistedExecutables()
    {
        // Arrange - attempt to promote multiple blocklisted executables
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "powershell",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Powershell promotion"),
            new CommandRiskRule(
                Executable: "cmd",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Cmd promotion"),
            new CommandRiskRule(
                Executable: "wget",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Wget promotion")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - all three should be rejected
        result.IsValid.Should().BeFalse();
        result.Errors.Should().HaveCountGreaterOrEqualTo(3);
        result.Errors.Should().ContainMatch("*blocklisted*powershell*");
        result.Errors.Should().ContainMatch("*blocklisted*cmd*");
        result.Errors.Should().ContainMatch("*blocklisted*wget*");
    }

    [Fact]
    public void Should_RejectSetting_AnyExecutable_ToDangerousTier()
    {
        // Arrange - cannot explicitly set executable to Dangerous tier
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "myTool",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Dangerous,
                Description: "Explicitly Dangerous")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - Dangerous tier cannot be set via config
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*Dangerous*");
    }

    #endregion

    #region Path Separator and Metacharacter Tests

    [Fact]
    public void Should_RejectExecutable_WithBackslash()
    {
        // Arrange - attempt path injection via backslash
        // Note: On Windows, backslash is a path separator; on Unix, it's a shell metacharacter
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: @"C:\tools\mytool",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Path with backslash")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - backslash is rejected (either as path separator on Windows or metacharacter on Unix)
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        // Accept either error message since it's OS-dependent
        var errorText = string.Join(" ", result.Errors);
        errorText.Should().MatchRegex("(path separator|metacharacter)",
            "backslash should be rejected as either a path separator (Windows) or shell metacharacter (Unix)");
    }

    [Fact]
    public void Should_RejectExecutable_WithForwardSlash_CrossPlatform()
    {
        // Arrange - forward slash is a path separator on both Windows and Unix
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "/usr/bin/mytool",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Path with forward slash")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - forward slash should always be rejected as a path separator on all platforms
        result.IsValid.Should().BeFalse();
        result.Errors.Should().NotBeEmpty();
        result.Errors.Should().ContainMatch("*path separator*");
    }

    [Fact]
    public void Should_RejectExecutable_WithRelativePath()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "./mytool",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Relative path")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*path separator*");
    }

    [Fact]
    public void Should_RejectExecutable_WithShellMetacharacters()
    {
        // Arrange - attempt injection via shell metacharacters in executable name
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "tool|malicious",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Pipe in executable")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*metacharacter*");
    }

    [Fact]
    public void Should_RejectArgumentPattern_WithShellMetacharacters()
    {
        // Arrange - attempt injection via metacharacters in argument patterns
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool",
                ArgumentPatterns: ["arg1 && rm -rf /"],
                Tier: CommandRiskTier.Safe,
                Description: "Metacharacter in pattern")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*metacharacter*");
    }

    [Fact]
    public void Should_RejectArgumentPattern_WithPipeOperator()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool",
                ArgumentPatterns: ["read | grep secret"],
                Tier: CommandRiskTier.Safe,
                Description: "Pipe in pattern")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*metacharacter*");
    }

    #endregion

    #region Empty/Null Validation Tests

    [Fact]
    public void Should_RejectRule_WithEmptyExecutable()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: string.Empty,
                ArgumentPatterns: ["arg"],
                Tier: CommandRiskTier.Safe,
                Description: "Empty executable")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty*");
    }

    [Fact]
    public void Should_RejectRule_WithWhitespaceExecutable()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "   ",
                ArgumentPatterns: ["arg"],
                Tier: CommandRiskTier.Safe,
                Description: "Whitespace executable")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*empty*");
    }

    [Fact]
    public void Should_AcceptRule_WithEmptyArgumentPatterns()
    {
        // Arrange - empty array is valid (different from null)
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool",
                ArgumentPatterns: [],
                Tier: CommandRiskTier.Safe,
                Description: "Empty patterns array")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - empty array should be accepted (matches no arguments)
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptRule_WithNullArgumentPatterns()
    {
        // Arrange - null means wildcard (matches any arguments)
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Null patterns (wildcard)")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - null should be accepted (wildcard)
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptRule_WithNullArgumentPatternsAndModerateTier()
    {
        // Arrange - null patterns + Moderate tier = less risky than Safe
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Wildcard Moderate tier")
        };

        // Act
        var result = _validatorWithLogger.ValidateRules(rules);

        // Assert - should be valid with warning
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        result.Warnings.Should().NotBeEmpty();
        result.Warnings.Should().ContainMatch("*null argument patterns*matches ALL*");
    }

    [Fact]
    public void Should_AcceptRule_WithDescription()
    {
        // Arrange - description is not validated (just metadata)
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool",
                ArgumentPatterns: ["arg"],
                Tier: CommandRiskTier.Safe,
                Description: "Valid description")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - description is optional metadata, not validated
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    #endregion

    #region Valid Configuration Tests

    [Fact]
    public void Should_AcceptValidCustomExecutable_WithSafeTier()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["check", "build", "test"],
                Tier: CommandRiskTier.Safe,
                Description: "Rust build commands")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptValidCustomExecutable_WithModerateTier()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "make",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "GNU Make")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptValidCustomExecutable_WithElevatedTier()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["publish"],
                Tier: CommandRiskTier.Elevated,
                Description: "Cargo publish")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptMultipleValidRules_ForDifferentExecutables()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build", "test"],
                Tier: CommandRiskTier.Moderate,
                Description: "Cargo build"),
            new CommandRiskRule(
                Executable: "make",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Moderate,
                Description: "Make"),
            new CommandRiskRule(
                Executable: "gradle",
                ArgumentPatterns: ["assemble"],
                Tier: CommandRiskTier.Safe,
                Description: "Gradle assemble")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    #endregion

    #region Duplicate Rule Handling Tests

    [Fact]
    public void Should_AcceptDuplicateExecutable_WithDifferentArgumentPatterns()
    {
        // Arrange - same executable, different argument patterns
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build", "test"],
                Tier: CommandRiskTier.Moderate,
                Description: "Cargo build"),
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["publish"],
                Tier: CommandRiskTier.Elevated,
                Description: "Cargo publish")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - this is valid (different tiers for different subcommands)
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_AcceptDuplicateExecutable_WithSameArgumentPatterns()
    {
        // Arrange - validator doesn't track duplicates (last one wins during processing)
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build"],
                Tier: CommandRiskTier.Moderate,
                Description: "First rule"),
            new CommandRiskRule(
                Executable: "cargo",
                ArgumentPatterns: ["build"],
                Tier: CommandRiskTier.Safe,
                Description: "Duplicate rule")
        };

        // Act
        var result = _validatorWithLogger.ValidateRules(rules);

        // Assert - validator accepts duplicates (they're processed in order, last wins)
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
        // No duplicate detection implemented in validator
    }

    #endregion

    #region File Extension Tests

    [Fact]
    public void Should_RejectExecutable_WithExeExtension()
    {
        // Arrange - executable should not include .exe extension
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool.exe",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Tool with .exe extension")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*.exe*");
    }

    [Fact]
    public void Should_RejectExecutable_WithUppercaseExeExtension()
    {
        // Arrange
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool.EXE",
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Tool with .EXE extension")
        };

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - case-insensitive check
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainMatch("*.exe*");
    }

    #endregion

    #region Edge Cases

    [Fact]
    public void Should_HandleEmptyRulesArray_Gracefully()
    {
        // Arrange - no rules to validate
        var rules = Array.Empty<CommandRiskRule>();

        // Act
        var result = _validator.ValidateRules(rules);

        // Assert - empty array is valid
        result.IsValid.Should().BeTrue();
        result.Errors.Should().BeEmpty();
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRulesIsNull()
    {
        // Act
        var action = () => _validator.ValidateRules(null!);

        // Assert
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_HandleVeryLongExecutableName_Gracefully()
    {
        // Arrange - very long executable name
        var longName = new string('a', 1000);
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: longName,
                ArgumentPatterns: null,
                Tier: CommandRiskTier.Safe,
                Description: "Long name test")
        };

        // Act
        var action = () => _validator.ValidateRules(rules);

        // Assert - should not crash
        action.Should().NotThrow();
    }

    [Fact]
    public void Should_HandleVeryLongArgumentPattern_Gracefully()
    {
        // Arrange - very long argument pattern
        var longArg = new string('b', 1000);
        var rules = new[]
        {
            new CommandRiskRule(
                Executable: "mytool",
                ArgumentPatterns: [longArg],
                Tier: CommandRiskTier.Safe,
                Description: "Long arg test")
        };

        // Act
        var action = () => _validator.ValidateRules(rules);

        // Assert - should not crash
        action.Should().NotThrow();
    }

    [Fact]
    public void Should_HandleManyRules_Efficiently()
    {
        // Arrange - many rules
        var rules = Enumerable.Range(0, 100).Select(i =>
            new CommandRiskRule(
                Executable: $"tool{i}",
                ArgumentPatterns: [$"arg{i}"],
                Tier: CommandRiskTier.Moderate,
                Description: $"Tool {i}")).ToArray();

        // Act
        var action = () => _validator.ValidateRules(rules);

        // Assert - should handle efficiently
        action.Should().NotThrow();
        var result = _validator.ValidateRules(rules);
        result.IsValid.Should().BeTrue();
    }

    #endregion
}
